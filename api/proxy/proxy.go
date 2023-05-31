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

	"go.uber.org/zap"
)

type Options struct {
	EosProxyURL         string
	WebProxyURL         string
	WebCanaryProxyURL   string
	WebOCISProxyURL     string
	OcisRegex           string
	OcisRedirect        string
	OldInfraRegex       string
	Logger              *zap.Logger
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
	eosProxy           *httputil.ReverseProxy
	webProxy           *httputil.ReverseProxy
	webCanaryProxy     *httputil.ReverseProxy
	webOCISProxy       *httputil.ReverseProxy
	ocisRegex          *regexp.Regexp
	ocisRedirect       string
	oldInfraRegex      *regexp.Regexp
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
	eosURL, err := url.Parse(opts.EosProxyURL)
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
	webOCISURL, err := url.Parse(opts.WebOCISProxyURL)
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

	eosProxy := newSingleHostReverseProxy(eosURL)
	webProxy := newSingleHostReverseProxy(webURL)
	webCanaryProxy := newSingleHostReverseProxy(webCanaryURL)
	webOCISProxy := newSingleHostReverseProxy(webOCISURL)

	eosProxy.Transport = t
	webProxy.Transport = t
	webCanaryProxy.Transport = t
	webOCISProxy.Transport = t

	ocisRegex, err := regexp.Compile(opts.OcisRegex)
	if err != nil {
		opts.Logger.Error("", zap.Error(err))
		panic(err)
	}
	oldInfraRegex, err := regexp.Compile(opts.OldInfraRegex)
	if err != nil {
		opts.Logger.Error("", zap.Error(err))
		panic(err)
	}

	versionRegex, err := regexp.Compile(`mirall/(\d+)\.(\d+).?(\d+)?`)
	if err != nil {
		opts.Logger.Error("", zap.Error(err))
		panic(err)
	}

	return &proxy{
		eosProxy:           eosProxy,
		webProxy:           webProxy,
		webCanaryProxy:     webCanaryProxy,
		webOCISProxy:       webOCISProxy,
		ocisRegex:          ocisRegex,
		ocisRedirect:       opts.OcisRedirect,
		oldInfraRegex:      oldInfraRegex,
		logger:             opts.Logger,
		insecureSkipVerify: opts.InsecureSkipVerify,
		MinimumSyncClient:  opts.MinimumSyncClient,
		VersionRegex:       versionRegex,
	}, nil

}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, okBasicAuth := r.BasicAuth()
	normalizedPath := path.Clean(r.URL.Path)

	// Make usernames lowercase to avoid unauthenticated requests from EOS
	username = strings.ToLower(username)
	if okBasicAuth {
		r.SetBasicAuth(username, password)
	}

	// TEMPORARY REDIRECT
	// People may have bookmarked old URLs, we provide a redirection for those
	// for example, old.cernbox.cern.ch/index.php/s/... -> cernbox.cern.ch/index.php/s/...
	// for example, new.cernbox.cern.ch/index.php/s/... -> cernbox.cern.ch/index.php/s/...
	// The translation of the urls is done by the web frontend
	if p.isTemporaryURL(r) {
		p.logger.Info("request comes from a temporary URL, redirect to default url", zap.String("path", normalizedPath))
		w.Header().Add("Content-Type", "") // To remove html added automatically in the redirect
		http.Redirect(w, r, p.ocisRedirect+r.URL.String(), http.StatusMovedPermanently)
		return
	}

	// old infra contains host-based regex (old.cernbox.cern.ch) and also
	// "/cernbox/desktop", "/cernbox/mobile", "/cernbox/webdav", "/swanapi", "/cernbox/update", "/cernbox/doc",
	/// If request does NOT contain any of these, we forward to OCIS
	if !p.isOldInfra(normalizedPath, r) {
		p.logger.Info("request is not for old infra, sending to ocis", zap.String("path", normalizedPath))
		p.webOCISProxy.ServeHTTP(w, r)
		return

	}

	// WebDAV traffic from sync clients, mobile devices or just generic webdav
	// prefix is either /cernbox/desktop, /cernbox/mobile or /cernbox/webdav
	if ok := p.isEosPath(normalizedPath); ok {

		userAgent := r.Header.Get("User-Agent")

		// validate sync client version
		if !p.validClient(userAgent) {
			w.WriteHeader(http.StatusForbidden)
			p.logger.Info("rejected client", zap.String("username", username), zap.String("userAgent", userAgent))
			return
		}

		p.logger.Info("serving from eos proxy", zap.String("path", normalizedPath))
		p.eosProxy.ServeHTTP(w, r)
		return
	}

	// at this point, the request is not being served by OCIS nor is a WebDAV request handled by EOS
	// We first check if the request is served by the old PHP server (isWebRequest), and if so, we send there.
	// else, we send the traffic to the EOS proxies as fallback.

	// check if request need to be handled by old PHP webserver.
	if p.isWebRequest(normalizedPath, r) {
		p.logger.Info("path is a known web path, forward to normal web proxy", zap.String("path", normalizedPath))
		if strings.HasPrefix(normalizedPath, "/cernbox/mobile") {
			p.logger.Info("request is from a new mobile client", zap.String("path", normalizedPath))
			r.Header.Add("CBOXCLIENTMAPPING", "/cernbox/mobile")
		}
		p.webProxy.ServeHTTP(w, r)
		return
	}

	// check if there are any other webdav paths that we have omited, abort in case we find one
	p.paranoiaDAVcheck(normalizedPath, w, r)

	// fallback request to eos proxy
	p.logger.Info("fallback request to eos proxy", zap.String("username", username), zap.String("path", normalizedPath))
	p.eosProxy.ServeHTTP(w, r)
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
	"/reset",
	"/shibboleth-sp",
	"/Shibboleth.sso",
}

var knownOldPaths = []string{
	"/cernbox/desktop",
	"/cernbox/mobile",
	"/cernbox/webdav",
	"/swanapi",
	"/cernbox/update",
	"/cernbox/doc",
}

var eosDav = []string{
	"/cernbox/desktop/remote.php/dav",
	"/cernbox/desktop/remote.php/webdav",
	"/cernbox/mobile/remote.php/webdav",
	"/cernbox/webdav",
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

func (p *proxy) isTemporaryURL(r *http.Request) bool {
	return p.ocisRegex.MatchString(r.Host)
}

func (p *proxy) isOldInfra(path string, r *http.Request) bool {
	if p.oldInfraRegex.MatchString(r.Host) {
		return true
	}

	for _, prefix := range knownOldPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// isEosPath checks for known webdav paths
func (p *proxy) isEosPath(path string) bool {
	for _, prefix := range eosDav {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (p *proxy) paranoiaDAVcheck(normalizedPath string, w http.ResponseWriter, r *http.Request) {
	// check if the url contains remote.php/webdav in another location of the url
	// the remote.php/webdav endpoint used by the web UI is whitelisted.

	if !strings.HasPrefix(normalizedPath, "/remote.php/webdav") { //whitelist web traffic, remanining traffic must contain cernbox/desktop or cernbox/mobile
		if strings.Contains(normalizedPath, "remote.php/webdav") || strings.Contains(normalizedPath, "remote.php/dav/files") {
			msg := fmt.Sprintf("CRITICAL: webdav path not controlled in logic rules => %s", normalizedPath)
			p.logger.Error(msg, zap.String("normalizedPath", normalizedPath))
			panic("CRITICAL: " + normalizedPath)
		}
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
