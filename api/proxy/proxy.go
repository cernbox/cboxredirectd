package proxy

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/cernbox/cboxredirectd/api"

	"go.uber.org/zap"
)

type Options struct {
	OldServerURL string
	NewServerURL string
	Logger       *zap.Logger
	Migrator     api.Migrator
}

func (opts *Options) init() {
	if opts.Logger == nil {
		l, _ := zap.NewProduction()
		opts.Logger = l
	}
}

type proxy struct {
	oldProxy *httputil.ReverseProxy
	newProxy *httputil.ReverseProxy
	migrator api.Migrator
	logger   *zap.Logger
}

func New(opts *Options) (http.Handler, error) {
	opts.init()
	oldURL, err := url.Parse(opts.OldServerURL)
	if err != nil {
		return nil, err
	}
	newURL, err := url.Parse(opts.NewServerURL)
	if err != nil {
		return nil, err
	}

	oldProxy := httputil.NewSingleHostReverseProxy(oldURL)
	newProxy := httputil.NewSingleHostReverseProxy(newURL)

	return &proxy{
		oldProxy: oldProxy,
		newProxy: newProxy,
		migrator: opts.Migrator,
	}, nil

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

	// is user is migrated forward request to new server.
	ok, err := p.isMigrated(r.Context(), username)
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

func (p *proxy) isMigrated(ctx context.Context, username string) (bool, error) {
	ok, err := p.migrator.IsUserMigrated(ctx, username)
	if err != nil {
		p.logger.Error("", zap.Error(err))
		return false, err
	}
	return ok, nil
}
