package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cernbox/cboxredirectd/api"

	"go.uber.org/zap"
)

type Options struct {
	OldProxyURL         string
	NewProxyURL         string
	WebProxyURL         string
	WebCanaryProxyURL   string
	Logger              *zap.Logger
	Migrator            api.Migrator
	InsecureSkipVerify  bool
	DisableKeepAlives   bool
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     int
	DisableCompression  bool
	MinimumSyncClient   []int
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
	webProxy           *httputil.ReverseProxy
	webCanaryProxy     *httputil.ReverseProxy
	migrator           api.Migrator
	logger             *zap.Logger
	insecureSkipVerify bool
	MinimumSyncClient  []int
	VersionRegex       *regexp.Regexp
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

// New creates a new proxy handlers.
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
	webURL, err := url.Parse(opts.WebProxyURL)
	if err != nil {
		return nil, err
	}
	webCanaryURL, err := url.Parse(opts.WebCanaryProxyURL)
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
	webProxy := newSingleHostReverseProxy(webURL)
	webCanaryProxy := newSingleHostReverseProxy(webCanaryURL)

	oldProxy.Transport = t
	newProxy.Transport = t
	webProxy.Transport = t
	webCanaryProxy.Transport = t

	versionRegex, err := regexp.Compile(`mirall/(\d+)\.(\d+).?(\d+)?`)
	if err != nil {
		opts.Logger.Error("", zap.Error(err))
		panic(err)
	}

	return &proxy{
		oldProxy:           oldProxy,
		newProxy:           newProxy,
		webProxy:           webProxy,
		webCanaryProxy:     webCanaryProxy,
		migrator:           opts.Migrator,
		logger:             opts.Logger,
		insecureSkipVerify: opts.InsecureSkipVerify,
		MinimumSyncClient:  opts.MinimumSyncClient,
		VersionRegex:       versionRegex,
	}, nil

}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	username, password, okBasicAuth := r.BasicAuth()
	normalizedPath := path.Clean(r.URL.Path)

	defaultGenericOrUnauthenticatedDAVRequest := p.migrator.GetDefaultGenericOrUnAuthenticatedDAVRequest(ctx)
	defaultUserNotFound := p.migrator.GetDefaultUserNotFound(ctx)
	defaultProjectNotFound := p.migrator.GetDefaultProjectNotFound(ctx)
	defaultNonDAVRequest := p.migrator.GetDefaultNonDAVRequest(ctx)

	// Make usernames lowercase to avoid unauthenticated requests from EOS
	username = strings.ToLower(username)
	if okBasicAuth {
		r.SetBasicAuth(username, password)
	}

	p.logger.Info("migration check", zap.String("username", username), zap.String("non-normalized-path", r.URL.Path), zap.String("normalized-path", normalizedPath), zap.String(api.REDIS_KEY_DEFAULT_GENERIC_OR_UNAUTHENTICATED_DAV_REQUEST, string(defaultGenericOrUnauthenticatedDAVRequest)), zap.String(api.REDIS_KEY_DEFAULT_USER_NOT_FOUND, string(defaultUserNotFound)), zap.String(api.REDIS_KEY_DEFAULT_PROJECT_NOT_FOUND, string(defaultProjectNotFound)))

	// prefix is either /cernbox/desktop, /cernbox/mobile or /cernbox/webdav
	if ok, prefix := p.pathInEOSDAVRealm(ctx, username, normalizedPath); ok {

		userAgent := r.Header.Get("User-Agent")

		if !p.validClient(userAgent) {
			w.WriteHeader(http.StatusForbidden)
			p.logger.Info("rejected client", zap.String("username", username), zap.String("userAgent", userAgent))
			return
		}

		// remove the prefix from the normalizedPath to have a clean EOS path
		// eosPath is be "", "/", "/home", "/eos", "/home/docs", "/eos/user" or something weird like "mambo jampo
		eosPath := path.Clean(strings.TrimPrefix(normalizedPath, prefix))
		p.logger.Info("obtained eospath", zap.String("username", username), zap.String("eospath", eosPath), zap.String("webdavprefix", prefix))

		var redisKey string
		var redisKeyType api.RedisKeyType
		// requests coming from the mobile clients treat "home" as "/", that is why we have
		// the magic CBOX_MAPPING headers in the gateways, we treat requests coming from mobile as always
		// from home.
		if strings.HasPrefix(eosPath, "/home") || prefix == "/cernbox/mobile/remote.php/webdav" {
			p.logger.Info("eosPath starts with /home prefix or is a mobile path", zap.String("username", username), zap.String("eospath", eosPath), zap.String("webdavprefix", prefix))
			// we need a valid username to know where to send the guy
			if username == "" {
				p.logger.Info("username is empty, we forward to default for generic or unauthenticated dav requests", zap.String("username", username), zap.String("default", string(defaultGenericOrUnauthenticatedDAVRequest)))
				// apply default logic for non authenticated users
				p.applyDefaultForGenericOrUnauthenticatedDAVRequest(defaultGenericOrUnauthenticatedDAVRequest, w, r)
				return
			}

			// username is set, we know the user, so we know also his homedirectory
			homeDirectory := fmt.Sprintf("/eos/user/%s/%s", string(username[0]), username)
			p.logger.Info("username is set, we create its home directory key", zap.String("username", username), zap.String("homeDirectory", homeDirectory), zap.String("username", username))
			redisKey = homeDirectory
			redisKeyType = api.RedisKeyUser

		} else {
			p.logger.Info("eospath does not start with /home prefix", zap.String("username", username), zap.String("eospath", eosPath), zap.String("webdavprefix", prefix))
			// the path is not /home, so we will try to infer the redis key from the path
			key, keyType, found := p.inferRedisKey(ctx, eosPath)
			if !found {
				p.logger.Info("the redis key could not be extracted from the path, we forward to the default for generic or unauthenticated dav requests", zap.String("username", username), zap.String("eospath", eosPath), zap.String("webdavprefix", prefix), zap.String("username", username))
				p.applyDefaultForGenericOrUnauthenticatedDAVRequest(defaultGenericOrUnauthenticatedDAVRequest, w, r)
				return
			}

			// the path is known and the redis key has been extracted
			redisKey = key
			redisKeyType = keyType
		}

		p.logger.Info("redis key extracted", zap.String("username", username), zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)))
		// ask redis for this key
		isMigrated, found := p.migrator.IsKeyMigrated(ctx, redisKey)
		if !found {
			p.logger.Info("redis key not found, forward for default key not found", zap.String("username", username), zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)))
			// this entry has not been found in the redis database, so we apply the defaults based on the redisKeyType
			if redisKeyType == api.RedisKeyUser {
				p.logger.Info("user not found, forwards to default for user not found", zap.String("username", username), zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)), zap.String("default", string(defaultUserNotFound)))
				p.applyDefaultForUserNotFound(defaultUserNotFound, w, r)
				return
			} else {
				p.logger.Info("project not found, forwards to default for project not found", zap.String("username", username), zap.String("key", redisKey), zap.String("keyType", string(redisKeyType)), zap.String("default", string(defaultProjectNotFound)))
				p.applyDefaultForProjectNotFound(defaultProjectNotFound, w, r)
				return
			}
			panic("it should never enter here")
		}

		// the key is found and we redirect accordingly to the value of the key.
		if isMigrated {
			p.logger.Info("key is migrated, forward to new-proxy", zap.String("username", username), zap.String("key", redisKey), zap.String("proxy", "new-proxy"))
			p.newProxy.ServeHTTP(w, r)
			return
		} else {
			p.logger.Info("key is not migrated, forward to old-proxy", zap.String("username", username), zap.String("key", redisKey), zap.String("proxy", "old-proxy"))
			p.oldProxy.ServeHTTP(w, r)
			return
		}

	}

	// check if there are any other webdav paths that we have omited, abort in case we find one
	p.paranoiaDAVcheck(normalizedPath, w, r)

	// check if request need to be handled by webserver.
	if p.isWebRequest(normalizedPath, r) {
		// check if the user is a tester and we send her to the canary or prod
		// deployments.

		c, err := r.Cookie("web_canary")
		if err != nil { // no cookie
			p.logger.Info("path is a known web path, forward to normal web proxy", zap.String("path", normalizedPath))

			if strings.HasPrefix(normalizedPath, "/cernbox/mobile") {
				p.logger.Info("request is from a new mobile client", zap.String("path", normalizedPath))
				r.Header.Add("CBOXCLIENTMAPPING", "/cernbox/mobile")
			}

			p.webProxy.ServeHTTP(w, r)
			return
		}
		// cookie is set so we send to canary web.
		p.logger.Info("path is a known web path, forward to web canary proxy", zap.String("path", normalizedPath), zap.Int("canary-cookie-max-age", c.MaxAge), zap.String("cookie", fmt.Sprintf("%+v", c)))
		p.webCanaryProxy.ServeHTTP(w, r)
		return
	}

	// the request is a non webdav request so we apply the default for non webdav requests
	p.logger.Info("request is non webdav and non web, forward to the default for non dav requests", zap.String("username", username), zap.String("path", normalizedPath))
	p.applyDefaultForNonDAVRequest(defaultNonDAVRequest, w, r)
	return
}

var knownWebPaths = []string{
	"/cron.php",
	"/settings",
	"/ocs",
	"/version.php",
	"/status.php",
	"/index.php",
	"/remote.php",
	"/public.php",
	"/apps",
	"/core",
	"/favicon.ico",
	"/shibboleth-sp",
	"/Shibboleth.sso",
	"/robots.txt",
	"/swanapi",
	"/byoa",
	"/cernbox/update",
	"/cernbox/mobile/ocs/v1.php/apps/files_sharing/api",
	"/cernbox/mobile/ocs/v2.php/apps/files_sharing/api",
	"/cernbox/desktop/ocs/v1.php/apps/files_sharing/api",
	"/cernbox/desktop/ocs/v2.php/apps/files_sharing/api",
	"/cernbox/mobile/remote.php/dav/files",
	"/cernbox/mobile/remote.php/dav/uploads",
	"/cernbox/mobile/index.php/apps/files/api",
}

func (p *proxy) isWebRequest(path string, r *http.Request) bool {
	// if path is root, is for the web like cernbox.cern.ch
	if path == "/" {
		return true
	}

	for _, prefix := range knownWebPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
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

func (p *proxy) validClient(userAgent string) bool {

	match := p.VersionRegex.FindStringSubmatch(userAgent)
	// match will contain a slice with the full match (if it matches the regex)
	// plus all the sub matches (the integers that correspond to the 'major', 'minor', 'build')

	if len(match) > 0 { // a match was found
		for i, _ := range p.VersionRegex.SubexpNames() {

			if i == 0 { // skip the first entry, as this is the full match
				continue
			}

			var value int
			if match[i] == "" {
				// In case the 'build' version was not specified, we set it at 0
				value = 0
			} else {
				value, _ = strconv.Atoi(match[i])
			}

			if value > p.MinimumSyncClient[i-1] {
				// the current value is higher than what we expected so we can already return true
				break

			} else if value < p.MinimumSyncClient[i-1] {
				// the current value is lower than what we expected so we can already return false
				return false
			}

			// the current value is equal so we need to check the next in the slice...

		}
	} // else, a match was not found but we allow clients that do not specify a version
	return true
}
