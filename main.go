package main

import (
	"net/http"
	"time"

	"github.com/cernbox/cboxredirectd/api/proxy"
	"github.com/cernbox/cboxredirectd/api/redismigrator"
	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"

	"go.uber.org/zap"
)

func main() {

	gc := goconfig.New()
	gc.SetConfigName("cboxredirectd")
	gc.AddConfigurationPaths("/etc/cboxredirectd")
	gc.Add("tcp-address", "localhost:9999", "tcp addresss to listen for connections")
	gc.Add("app-log", "stderr", "file to log application information")
	gc.Add("http-log", "stderr", "file to log http log information")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error)")
	gc.Add("old-proxy", "", "server to forward requests for non-migrated users")
	gc.Add("new-proxy", "", "server to forward requests for migrated/new users")
	gc.Add("read-timeout", 90, "server read timeout")
	gc.Add("write-timeout", 90, "server write timeout")
	gc.Add("redis-tcp-address", "localhost:6379", "redis tcp address")
	gc.Add("redis-read-timeout", 0, "redis read timeout")
	gc.Add("redis-write-timeout", 0, "redis write timeout")
	gc.Add("redis-dial-timeout", 0, "redis dial timeout")
	gc.Add("redis-idle-check-frequency", 0, "redis idle check frequency")
	gc.Add("redis-idle-timeout", 0, "redis idle timeout")
	gc.Add("redis-max-retries", 0, "redis max retries")
	gc.Add("redis-pool-size", 0, "redis pool size")
	gc.Add("redis-pool-timeout", 0, "redis pool timeout")
	gc.BindFlags()
	gc.ReadConfig()

	logger := gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

	migratorOpts := &redismigrator.Options{
		Address:            gc.GetString("redis-tcp-address"),
		DialTimeout:        gc.GetInt("redis-dial-timeout"),
		IdleCheckFrequency: gc.GetInt("redis-idle-check-frequency"),
		IdleTimeout:        gc.GetInt("redis-idle-timeout"),
		Logger:             logger,
		MaxRetries:         gc.GetInt("redis-max-retries"),
		PoolSize:           gc.GetInt("redis-pool-size"),
		PoolTimeout:        gc.GetInt("redis-pool-timeout"),
		ReadTimeout:        gc.GetInt("redis-read-timeout"),
		WriteTimeout:       gc.GetInt("redis-write-timeout"),
	}
	migrator, err := redismigrator.New(migratorOpts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	proxyOpts := &proxy.Options{
		Logger:       logger,
		Migrator:     migrator,
		NewServerURL: gc.GetString("new-server"),
		OldServerURL: gc.GetString("old-server"),
	}
	proxyHandler, err := proxy.New(proxyOpts)
	if err != nil {
		panic(err)
	}

	router := http.NewServeMux()
	router.Handle("/", proxyHandler)
	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), router)

	s := http.Server{
		Addr:         gc.GetString("tcp-address"),
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("write-timeout")),
		Handler:      loggedRouter,
	}

	logger.Info("server is listening at: " + gc.GetString("tcp-address"))
	err = s.ListenAndServe()
	if err != nil {
		logger.Error("server exited with error", zap.Error(err))
	} else {
		logger.Error("server exited without error")
	}
}
