// Package server implements powd's entire HTTP surface: the decision
// ladder that gates every request, the challenge page, the verification
// endpoint, and the reverse proxy to the upstream application.
//
// Every request takes exactly one path through the ladder:
//
//  1. /.powd/*                     handled internally, never proxied
//  2. exclude match                proxied
//  3. no protect match             proxied
//  4. valid cookie                 proxied
//  5. GET/HEAD accepting HTML      403 + challenge page
//  6. anything else                403 + one-line text body
package server

import (
	_ "embed"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"path"
	"strings"
	"time"

	"powd/internal/config"
	"powd/internal/replay"
	"powd/internal/token"
)

const (
	// internalPrefix is powd's own path namespace; nothing under it is
	// ever proxied upstream.
	internalPrefix = "/.powd/"
	cookieName     = "powd"
)

//go:embed page.html
var pageHTML string

var pageTemplate = template.Must(template.New("challenge").Parse(pageHTML))

// Server routes requests between the challenge machinery and the
// upstream application. It implements http.Handler.
type Server struct {
	cfg    *config.Config
	signer *token.Signer
	seen   *replay.Cache
	proxy  *httputil.ReverseProxy
	log    *log.Logger
}

// New wires a Server from its parts. The replay cache is created here;
// it is the server's only state.
func New(cfg *config.Config, signer *token.Signer, logger *log.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		signer: signer,
		seen:   replay.New(0),
		log:    logger,
	}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			pr.Out.Host = pr.In.Host // the application sees the original Host
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Printf("proxy error: %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return s
}

// ServeHTTP is the decision ladder. Routing decisions are made on the
// cleaned path so that "/rss/../admin" cannot ride an exclude prefix past
// protection; the upstream still receives the request untouched.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := path.Clean(r.URL.Path)

	switch {
	case strings.HasPrefix(p, internalPrefix):
		s.serveInternal(w, r, p)
	case matchesAny(s.cfg.Exclude, p) || !matchesAny(s.cfg.Protect, p):
		s.proxy.ServeHTTP(w, r)
	case s.cookieValid(r):
		s.proxy.ServeHTTP(w, r)
	default:
		s.serveChallenge(w, r)
	}
}

func (s *Server) serveInternal(w http.ResponseWriter, r *http.Request, p string) {
	if p != verifyPath {
		http.NotFound(w, r)
		return
	}
	s.serveVerify(w, r)
}

// matchesAny reports whether p falls under one of the configured path
// prefixes. Matching is segment-aware: "/blog" covers "/blog" and
// "/blog/…" but not "/blogroll".
func matchesAny(prefixes []string, p string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// serveChallenge answers an unauthenticated request on a protected path.
// Only a navigation-shaped request (GET/HEAD that accepts HTML) receives
// the interstitial; anything else gets a short text 403, since a client
// that cannot render the page cannot solve it either.
func (s *Server) serveChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !acceptsHTML(r) {
		http.Error(w, "proof-of-work required", http.StatusForbidden)
		return
	}

	tok := s.signer.MintChallenge(time.Now(), s.cfg.ChallengeAge, s.cfg.Difficulty)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}
	err := pageTemplate.Execute(w, map[string]any{
		"Challenge":  tok,
		"Difficulty": s.cfg.Difficulty,
	})
	if err != nil {
		s.log.Printf("challenge page: %v", err)
	}
}

func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// cookieValid reports whether the request carries an authentic, unexpired
// cookie whose binding matches this very request.
func (s *Server) cookieValid(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	return s.signer.VerifyCookie(time.Now(), c.Value, s.binding(r)) == nil
}

// binding derives the client-binding value for r from whichever request
// properties the configuration enables.
func (s *Server) binding(r *http.Request) string {
	var ua, ip string
	if s.cfg.BindUA {
		ua = r.Header.Get("User-Agent")
	}
	if s.cfg.BindIP {
		ip = ipPrefix(clientIP(r))
	}
	return token.Binding(ua, ip)
}

// clientIP returns the client address as reported by nginx via X-Real-IP,
// falling back to the peer address. powd is deployed behind a trusted
// proxy by design; there is no header-trust auto-detection.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ipPrefix coarsens an address to /24 (IPv4) or /64 (IPv6), so a cookie
// survives ordinary address churn inside one network but not a move
// across networks. An unparseable value binds as itself.
func ipPrefix(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return ip
	}
	return prefix.String()
}
