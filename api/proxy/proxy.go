package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/cernbox/cboxredirectd/api"

	"go.uber.org/zap"
)

type Options struct {
	OldProxyURL         string
	NewProxyURL         string
	Logger              *zap.Logger
	Migrator            api.Migrator
	InsecureSkipVerify  bool
	DisableKeepAlives   bool
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     int
}

func (opts *Options) init() {
	if opts.Logger == nil {
		l, _ := zap.NewProduction()
		opts.Logger = l
	}
}

type proxy struct {
	oldProxy           *httputil.ReverseProxy
	newProxy           *httputil.ReverseProxy
	migrator           api.Migrator
	logger             *zap.Logger
	insecureSkipVerify bool
}

func New(opts *Options) (http.Handler, error) {
	opts.init()
	oldURL, err := url.Parse(opts.OldProxyURL)
	if err != nil {
		return nil, err
	}
	newURL, err := url.Parse(opts.NewProxyURL)
	if err != nil {
		return nil, err
	}

	t := &http.Transport{
		DisableKeepAlives:   opts.DisableKeepAlives,
		IdleConnTimeout:     time.Duration(opts.IdleConnTimeout) * time.Second,
		MaxIdleConns:        opts.MaxIdleConns,
		MaxIdleConnsPerHost: opts.MaxIdleConnsPerHost,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
	}

	oldProxy := httputil.NewSingleHostReverseProxy(oldURL)
	newProxy := httputil.NewSingleHostReverseProxy(newURL)

	oldProxy.Transport = t
	newProxy.Transport = t

	return &proxy{
		oldProxy:           oldProxy,
		newProxy:           newProxy,
		migrator:           opts.Migrator,
		logger:             opts.Logger,
		insecureSkipVerify: opts.InsecureSkipVerify,
	}, nil

}

func (p *proxy) getCERNBoxPath(ctx context.Context, u *url.URL) string {
	urlPath := u.Path
	index := strings.Index(urlPath, "remote.php/webdav")
	if index == -1 {
		return ""
	}

	cernboxPath := urlPath[index:]
	cernboxPath = path.Join("/", path.Clean(cernboxPath))
	p.logger.Debug("extract of cernbox path", zap.String("url_path", urlPath), zap.String("cbox_path", cernboxPath))
	return cernboxPath

}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, _, ok := r.BasicAuth()

	p.logger.Info("incoming request", zap.String("username", username))

	// redirect to old server if no basic auth is provided or
	// username is empty.
	if !ok || username == "" {
		p.logger.Info("request without basic auth or empty username", zap.String("forward", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	}

	cernboxPath := p.getCERNBoxPath(r.Context(), r.URL)
	if cernboxPath == "/" { // the path does not point to a valid remote.php/webdav/{path}
		p.logger.Info("cernboxPath is not valid for redirection logic", zap.String("forward", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	}

	// is user is migrated forward request to new server.
	ok, err := p.isPathMigrated(r.Context(), cernboxPath, username)
	if err != nil {
		// abort request as we don't know the state of the user migration
		p.logger.Error("user is in inconsistent migration state: manual action required", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if ok {
		p.logger.Info("username has been migrated or is a new user", zap.String("forward", "new-proxy"))
		p.newProxy.ServeHTTP(w, r)
		return
	}

	// user is not yet migrated, forward to old server.
	p.logger.Info("username is not yet migrated", zap.String("forward", "old-proxy"))
	p.oldProxy.ServeHTTP(w, r)
	return
}

func (p *proxy) isPathMigrated(ctx context.Context, path string, username string) (bool, error) {
	ok, err := p.migrator.IsPathMigrated(ctx, path, username)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		return false, err
	}
	return ok, nil
}
