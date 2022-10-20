package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/cboxredirectd/api"
	"github.com/cernbox/cboxredirectd/api/proxy"
	"github.com/cernbox/cboxredirectd/api/redismigrator"
	"github.com/cernbox/gohub/goconfig"
	"github.com/cernbox/gohub/gologger"

	"github.com/facebookgo/grace/gracehttp"
	"go.uber.org/zap"
)

var gc *goconfig.GoConfig
var logger *zap.Logger

func init() {
	gc = goconfig.New()
	gc.SetConfigName("cboxredirectd")
	gc.AddConfigurationPaths("/etc/cboxredirectd")
	gc.Add("tcp-address", "localhost:9998", "tcp addresss to listen for connections and redirect to https on tcp-adress. Only used when tls-enable is true.")
	gc.Add("tcp-address-redirect", "localhost:80", "tcp addresss to listen for connections")
	gc.Add("app-log", "stderr", "file to log application information")
	gc.Add("http-log", "stderr", "file to log http log information")
	gc.Add("log-level", "info", "log level to use (debug, info, warn, error)")
	gc.Add("old-proxy", "", "server to forward requests for non-migrated users")
	gc.Add("new-proxy", "", "server to forward requests for migrated/new users")
	gc.Add("web-proxy", "", "server to forward requests for web UI/API")
	gc.Add("web-canary-proxy", "", "server to forward requests for web canary UI/API")
	gc.Add("web-ocis-regex", "new(qa)?.cernbox.cern.ch", "Regex to identify the an ocis path given a request' hostname")
	gc.Add("web-ocis-redirect", "cernbox.cern.ch", "URL to redirect the ocis requests to")
	gc.Add("old-infra-regex", "old(qa)?.cernbox.cern.ch", "Regex to identify the old infra given a request' hostname")
	gc.Add("web-ocis-proxy", "", "server to forward requests for web OCIS UI/API")
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
	gc.Add("proxy-disable-compression", false, "Disable transport compression (gzip)")

	gc.Add("minimum-sync-client", "0.0.0", "Minimum version of sync client that will be supported")

	gc.BindFlags()
	gc.ReadConfig()

	logger = gologger.New(gc.GetString("log-level"), gc.GetString("app-log"))

}

func main() {

	gracehttp.SetLogger(zap.NewStdLog(logger))
	migrator := newMigrator()

	proxyHandler := newProxyHandler(migrator)
	loggedHandler := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), proxyHandler)

	servers := []*http.Server{}
	servers = append(servers, getMainServer(loggedHandler))
	if s := getRedirectServer(); s != nil {
		servers = append(servers, s)
	}

	if err := gracehttp.Serve(servers...); err != nil {
		logger.Error("", zap.Error(err))
	}
}

func redirect(logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		target := "https://" + req.Host + req.URL.Path
		if len(req.URL.RawQuery) > 0 {
			target += "?" + req.URL.RawQuery
		}
		logger.Info(fmt.Sprintf("redirection: '%s' => '%s'", req.URL.String(), target))
		http.Redirect(w, req, target, http.StatusTemporaryRedirect)
	})
}

func getMainServer(h http.Handler) *http.Server {
	s := &http.Server{
		Addr:         gc.GetString("tcp-address"),
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("http-read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("http-write-timeout")),
		Handler:      h,
	}
	if gc.GetBool("tls-enable") {
		cert, err := tls.LoadX509KeyPair(gc.GetString("tls-cert"), gc.GetString("tls-key"))
		if err != nil {
			logger.Error("", zap.Error(err))
			panic(err.Error())
		}

		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}
		s.TLSConfig = tlsCfg
	}
	logger.Info("server is listening", zap.String("tcp-address", gc.GetString("tcp-address")), zap.Bool("tls-enabled", gc.GetBool("tls-enable")), zap.String("tls-cert", gc.GetString("tls-cert")), zap.String("tls-key", gc.GetString("tls-key")))
	return s
}

func getRedirectServer() *http.Server {
	if !gc.GetBool("tls-enable") {
		return nil
	}

	// redirect port 80 (http) to 443 (https)
	httpOnlyRouter := redirect(logger)
	loggedRouter := gologger.GetLoggedHTTPHandler(gc.GetString("http-log"), httpOnlyRouter)
	logger.Info("server is listening for redirects", zap.String("tcp-address-redirect", gc.GetString("tcp-address-redirect")))
	s := &http.Server{
		Addr:         gc.GetString("tcp-address-redirect"),
		ReadTimeout:  time.Second * time.Duration(gc.GetInt("http-read-timeout")),
		WriteTimeout: time.Second * time.Duration(gc.GetInt("http-write-timeout")),
		Handler:      loggedRouter,
	}
	return s
}

func newMigrator() api.Migrator {
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
	return migrator
}

func newProxyHandler(migrator api.Migrator) http.Handler {

	minimumSyncClientString := strings.Split(gc.GetString("minimum-sync-client"), ".")
	minimumSyncClient := []int{}

	for _, s := range minimumSyncClientString {
		i, err := strconv.Atoi(s)
		if err != nil {
			logger.Error("", zap.Error(err))
			panic(err)
		}
		minimumSyncClient = append(minimumSyncClient, i)
	}

	proxyOpts := &proxy.Options{
		Logger:              logger,
		Migrator:            migrator,
		NewProxyURL:         gc.GetString("new-proxy"),
		OldProxyURL:         gc.GetString("old-proxy"),
		WebProxyURL:         gc.GetString("web-proxy"),
		WebCanaryProxyURL:   gc.GetString("web-canary-proxy"),
		WebOCISProxyURL:     gc.GetString("web-ocis-proxy"),
		OcisRegex:           gc.GetString("web-ocis-regex"),
		OcisRedirect:        gc.GetString("web-ocis-redirect"),
		OldInfraRegex:       gc.GetString("old-infra-regex"),
		DisableKeepAlives:   gc.GetBool("proxy-disable-keep-alives"),
		MaxIdleConns:        gc.GetInt("proxy-max-idle-conns"),
		MaxIdleConnsPerHost: gc.GetInt("proxy-max-idle-conns-per-host"),
		IdleConnTimeout:     gc.GetInt("proxy-idle-conn-timeout"),
		InsecureSkipVerify:  gc.GetBool("proxy-tls-insecure-skip-verify"),
		DisableCompression:  gc.GetBool("proxy-disable-compression"),
		MinimumSyncClient:   minimumSyncClient,
	}
	proxyHandler, err := proxy.New(proxyOpts)
	if err != nil {
		panic(err)
	}
	return proxyHandler
}
