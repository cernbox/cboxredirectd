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
	gc.Add("http-read-timeout", 300, "the maximum duration for reading the entire request, including the body.")
	gc.Add("http-write-timeout", 300, "the maximum duration before timing out writes of the response.")
	gc.Add("tls-cert", "/etc/grid-security/hostcert.pem", "TLS certificate to encrypt connections.")
	gc.Add("tls-key", "/etc/grid-security/hostkey.pem", "TLS private key to encrypt connections.")
	gc.Add("tls-enable", false, "Enable TLS for encrypting connections.")

	gc.Add("redis-tcp-address", "localhost:6379", "redis tcp address")
	gc.Add("redis-read-timeout", 3, "timeout for socket reads. If reached, commands will fail with a timeout instead of blocking. Zero means default.")
	gc.Add("redis-write-timeout", 0, "timeout for socket writes. If reached, commands will fail with a timeout instead of blocking. Zero means redis-read-timeout.")
	gc.Add("redis-dial-timeout", 5, "dial timeout for establishing new connections. Zero means default.")
	gc.Add("redis-idle-check-frequency", 60, "frequency of idle checks. Zero means default. When minus value is set, then idle check is disabled.")
	gc.Add("redis-idle-timeout", 300, "amount of time after which client closes idle connections. Should be less than server's timeout. Zero means default.")
	gc.Add("redis-max-retries", 0, "maximum number of retries before giving up. Zero means not retry failed commands.")
	gc.Add("redis-pool-size", 0, "maximum number of socket connections. Zermo means 10 connections per every CPU as reported by runtime.NumCPU.")
	gc.Add("redis-pool-timeout", 0, "time a client waits for connection if all connections are busy before returning an error. Zero means redis-read-timeout + 1 second.")
	gc.Add("redis-password", "", "the password to authenticate to a protected Redis instance. Empty means no authentication.")

	gc.Add("proxy-disable-keep-alives", false, "if true, prevents re-use of TCP connections between different HTTP requests.")
	gc.Add("proxy-max-idle-conns", 0, "controls the maximum number of idle (keep-alive) connections across all hosts. Zero means no limit.")
	gc.Add("proxy-max-idle-conns-per-host", 2, "if non-zero, controls the maximum idle (keep-alive) connections to keep per-host. If zero, default is used.")
	gc.Add("proxy-idle-conn-timeout", 0, "the maximum amount of time an idle (keep-alive) connection will remain idle before closing itself. Zero means no limit.")
	gc.Add("proxy-tls-insecure-skip-verify", false, "controls whether a client verifies the server's certificate chain and host name.")

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
		Password:           gc.GetString("redis-password"),
	}
	migrator, err := redismigrator.New(migratorOpts)
	if err != nil {
		logger.Error("", zap.Error(err))
		panic(err)
	}

	proxyOpts := &proxy.Options{
		Logger:              logger,
		Migrator:            migrator,
		NewProxyURL:         gc.GetString("new-proxy"),
		OldProxyURL:         gc.GetString("old-proxy"),
		DisableKeepAlives:   gc.GetBool("proxy-disable-keep-alives"),
		MaxIdleConns:        gc.GetInt("proxy-max-idle-conns"),
		MaxIdleConnsPerHost: gc.GetInt("proxy-max-idle-conns-per-host"),
		IdleConnTimeout:     gc.GetInt("proxy-idle-conn-timeout"),
		InsecureSkipVerify:  gc.GetBool("proxy-tls-insecure-skip-verify"),
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
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("http-read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("http-write-timeout")),
		Handler:      loggedRouter,
	}

	logger.Info("server is listening", zap.String("tcp-address", gc.GetString("tcp-address")), zap.Bool("tls-enabled", gc.GetBool("tls-enable")), zap.String("tls-cert", gc.GetString("tls-cert")), zap.String("tls-key", gc.GetString("tls-key")))
	var listenErr error
	if gc.GetBool("tls-enable") {
		listenErr = s.ListenAndServeTLS(gc.GetString("tls-cert"), gc.GetString("tls-key"))
	} else {
		listenErr = s.ListenAndServe()
	}

	if listenErr != nil {
		logger.Error("server exited with error", zap.Error(listenErr))
	} else {
		logger.Info("server exited without error")
	}
}
