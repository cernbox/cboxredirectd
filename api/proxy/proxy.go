package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
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
	DisableCompression  bool
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

func singleJoiningSlash(a, b string) string {
  	aslash := strings.HasSuffix(a, "/")
  	bslash := strings.HasPrefix(b, "/")
  	switch {
  	case aslash && bslash:
  		return a + b[1:]
  	case !aslash && !bslash:
  		return a + "/" + b
  	}
  	return a + b
}

func newSingleHostReverseProxy(target *url.URL) *httputil.ReverseProxy {
  	targetQuery := target.RawQuery

  	director := func(req *http.Request) {
  		req.URL.Scheme = target.Scheme
  		req.URL.Host = target.Host
  		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
  		if targetQuery == "" || req.URL.RawQuery == "" {
  			req.URL.RawQuery = targetQuery + req.URL.RawQuery
  		} else {
  			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
  		}
  		if _, ok := req.Header["User-Agent"]; !ok {
  			// explicitly disable User-Agent so it's not set to default value
  			req.Header.Set("User-Agent", "")
  		}

		// See https://github.com/golang/go/issues/26414
		// apply hack only to GET requests, as we have only seen these type of reqs from apt-get.
		if req.Method == "GET" {
			quietReq := req.WithContext(context.Background())
                	*req = *quietReq
        	}
  	}
  	return &httputil.ReverseProxy{Director: director}
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
		DisableCompression:  opts.DisableCompression,
	}

	oldProxy := newSingleHostReverseProxy(oldURL)
	newProxy := newSingleHostReverseProxy(newURL)

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

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username, _, _ := r.BasicAuth()
	normalizedPath := path.Clean(r.URL.Path)

	defaultGenericOrUnauthenticatedDAVRequest := p.migrator.GetDefaultGenericOrUnAuthenticatedDAVRequest(ctx)
	defaultUserNotFound := p.migrator.GetDefaultUserNotFound(ctx)
	defaultProjectNotFound := p.migrator.GetDefaultProjectNotFound(ctx)
	defaultNonDAVRequest := p.migrator.GetDefaultNonDAVRequest(ctx)

	p.logger.Info("migration check", zap.String("non-normalized-path", r.URL.Path), zap.String("normalized-path", normalizedPath), zap.String("username", username), zap.String(api.REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST, string(defaultGenericOrUnauthenticatedDAVRequest)), zap.String(api.REDIS_KEY_DEFAULT_USER_NOT_FOUND, string(defaultUserNotFound)), zap.String(api.REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND, string(defaultProjectNotFound)))

	// prefix is either /cernbox/desktop, /cernbox/mobile or /cernbox/webdav
	if ok, prefix := p.pathInEOSDAVRealm(ctx, username, normalizedPath); ok {
		// remove the prefix from the normalizedPath to have a clean EOS path
		// eosPath is be "", "/", "/home", "/eos", "/home/docs", "/eos/user" or something weird like "mambo jampo
		eosPath := path.Clean(strings.TrimPrefix(normalizedPath, prefix))
		p.logger.Info("obtained eosPath", zap.String("eosPath", eosPath))

		var redisKey string
		var redisKeyType api.RedisKeyType
		if strings.HasPrefix(eosPath, "/home") {
			p.logger.Info("eosPath starts with /home prefix")
			// we need a valid username to know where to send the guy
			if username == "" {
				p.logger.Info("username is empty, we apply default for generic or unauthenticated dav requests", zap.String("default", string(defaultGenericOrUnauthenticatedDAVRequest)))
				// apply default logic for non authenticated users
				p.applyDefaultForGenericOrUnauthenticatedDAVRequest(defaultGenericOrUnauthenticatedDAVRequest, w, r)
				return
			}

			// username is set, we know the user, so we know also his homedirectory
			homeDirectory := fmt.Sprintf("/eos/user/%s/%s", string(username[0]), username)
			p.logger.Info("username is set, we create its home directory key", zap.String("homeDirectory", homeDirectory))
			redisKey = homeDirectory
			redisKeyType = api.RedisKeyUser

		} else {
			p.logger.Info("eosPath does not start with /home prefix")
			// the path is not /home, so we will try to infer the redis key from the path
			key, keyType, found := p.inferRedisKey(ctx, eosPath)
			if !found {
				p.logger.Info("the redis key could not be extracted from the path, we apply the default for generic webdav", zap.String("eosPath", eosPath))
				p.applyDefaultForGenericOrUnauthenticatedDAVRequest(defaultGenericOrUnauthenticatedDAVRequest, w, r)
				return
			}

			// the path is known and the redis key has been extracted
			redisKey = key
			redisKeyType = keyType
		}

		p.logger.Info("redis key extracted", zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)))
		// ask redis for this key
		isMigrated, found := p.migrator.IsKeyMigrated(ctx, redisKey)
		if !found {
			p.logger.Info("redis key not found", zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)))
			// this entry has not been found in the redis database, so we apply the defaults based on the redisKeyType
			if redisKeyType == api.RedisKeyUser {
				p.applyDefaultForUserNotFound(defaultUserNotFound, w, r)
				return
			} else {
				p.applyDefaultForProjectNotFound(defaultProjectNotFound, w, r)
				return
			}
			panic("it should never enter here")
		}

		// the key is found and we redirect accordingly to the value of the key.
		if isMigrated {
			p.logger.Info("key is migrated", zap.String("proxy", "new-proxy"))
			p.newProxy.ServeHTTP(w, r)
			return
		} else {
			p.logger.Info("key is not migrated", zap.String("proxy", "old-proxy"))
			p.oldProxy.ServeHTTP(w, r)
			return
		}

	}

	// check if there are any other webdav paths that we have omited, abort in case we find one
	p.paranoiaDAVcheck(normalizedPath, w, r)

	// the request is a non webdav request so we apply the default for non webdav requests
	p.logger.Info("request is non webdav, apply default logic")
	p.applyDefaultForNonDAVRequest(defaultNonDAVRequest, w, r)
	return
}

// pathInEOSDAVRealm checks for known webdav paths
func (p *proxy) pathInEOSDAVRealm(ctx context.Context, username, path string) (bool, string) {
	cernboxDesktop := "/cernbox/desktop/remote.php/webdav"
	cernboxMobile := "/cernbox/mobile/remote.php/webdav"
	cernboxOther := "/cernbox/webdav"

	if strings.HasPrefix(path, cernboxDesktop) {
		return true, cernboxDesktop
	}

	if strings.HasPrefix(path, cernboxMobile) {
		return true, cernboxMobile
	}

	if strings.HasPrefix(path, cernboxOther) {
		return true, cernboxOther
	}

	return false, ""
}

func (p *proxy) paranoiaDAVcheck(normalizedPath string, w http.ResponseWriter, r *http.Request) {
	// check if the url contains remote.php/webdav in another location of the url
	// the remote.php/webdav endpoint used by the web UI is whitelisted.

	if !strings.HasPrefix(normalizedPath, "/remote.php/webdav") {
		if strings.Contains(normalizedPath, "remote.php/webdav") {
			msg := fmt.Sprintf("CRITICAL: webdav path not controlled in logic rules => %s", normalizedPath)
			p.logger.Error(msg, zap.String("normalizedPath", normalizedPath))
			panic("CRITICAL: " + normalizedPath)
		}
	}
}

const (
	eosUserPrefix    = "/eos/user"
	eosProjectPrefix = "/eos/project"
)

func (p *proxy) inferRedisKey(ctx context.Context, eosPath string) (string, api.RedisKeyType, bool) {
	var redisKey string
	var redisKeyType api.RedisKeyType

	if strings.HasPrefix(eosPath, eosUserPrefix) {
		redisKey = eosUserPrefix
		redisKeyType = api.RedisKeyUser
	} else if strings.HasPrefix(eosPath, eosProjectPrefix) {
		redisKey = eosProjectPrefix
		redisKeyType = api.RedisKeyProject
	}

	if redisKey == "" {
		return "", redisKeyType, false // url does not match /eos/user or /eos/project, like /eos/lhcb

	}

	right := strings.Trim(strings.TrimPrefix(eosPath, redisKey), "/") // l/labrador or l/labradorsvc or l or l/labradorsvc/Docs or csc or c/cbox or csc/Docs or c/cbox/Docs
	tokens := strings.Split(right, "/")
	if len(tokens) > 1 {
		if len(tokens[0]) == 1 { // l/labradorsvc
			redisKey = path.Join(redisKey, path.Join(tokens[0:2]...))
		} else {
			redisKey = path.Join(redisKey, tokens[0]) // csc/Docs
		}
	}

	if len(tokens) == 1 {
		redisKey = path.Join(redisKey, tokens[0])
	}

	return redisKey, redisKeyType, true

}

func (p *proxy) applyDefaultForProjectNotFound(val api.DefaultProjectNotFound, w http.ResponseWriter, r *http.Request) {
	if val == api.DefaultProjectNotFoundOldProxy {
		p.logger.Info("project not found", zap.String("proxy", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	} else {
		p.logger.Info("project not found", zap.String("proxy", "new-proxy"))
		p.newProxy.ServeHTTP(w, r)
		return
	}
}

func (p *proxy) applyDefaultForUserNotFound(val api.DefaultUserNotFound, w http.ResponseWriter, r *http.Request) {
	if val == api.DefaultUserNotFoundOldProxy {
		p.logger.Info("user not found", zap.String("proxy", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	} else {
		p.logger.Info("user not found", zap.String("proxy", "new-proxy"))
		p.newProxy.ServeHTTP(w, r)
		return
	}

}

func (p *proxy) applyDefaultForGenericOrUnauthenticatedDAVRequest(val api.DefaultGenericOrUnAuthenticatedDAVRequest, w http.ResponseWriter, r *http.Request) {
	if val == api.DefaultGenericOrUnAuthenticatedDAVRequestOldProxy {
		p.logger.Info("generic or non authenticated dav request", zap.String("proxy", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	} else {
		p.logger.Info("generic or non authenticated dav request", zap.String("proxy", "new-proxy"))
		p.newProxy.ServeHTTP(w, r)
		return
	}
}

func (p *proxy) applyDefaultForNonDAVRequest(val api.DefaultNonDAVRequest, w http.ResponseWriter, r *http.Request) {
	if val == api.DefaultNonDAVRequestOldProxy {
		p.logger.Info("non-webdav request", zap.String("proxy", "old-proxy"))
		p.oldProxy.ServeHTTP(w, r)
		return
	} else {
		p.logger.Info("non-webdav request", zap.String("proxy", "new-proxy"))
		p.newProxy.ServeHTTP(w, r)
		return
	}
}
