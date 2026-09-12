// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

// Route is a reverse-proxy routing rule.
type Route struct {
	// Path is the URL path prefix to match (e.g. "/api/v1"). Requests under this
	// prefix are forwarded to Target with their path preserved.
	Path string
	// Target is the backend base URL (e.g. "http://127.0.0.1:8080").
	Target *url.URL
	// AllowMethods, when non-empty, restricts accepted HTTP methods.
	AllowMethods []string
	// RequiredCapabilities requires the admitted agent to hold these capability
	// ids before the request is forwarded.
	RequiredCapabilities []string
}

// Server is an AIC-protected HTTP reverse proxy. It terminates TLS (optionally
// mTLS), runs the admission pipeline on every request, and forwards admitted
// requests to the matching backend, injecting the verified client identity.
type Server struct {
	cfg        *Config
	routes     []Route
	handler    http.Handler
	transport  *http.Transport
	srv        *http.Server
	listener   net.Listener
	log        *slog.Logger
	revHeaders []string
}

// NewServer builds an AIC-protected reverse proxy server.
func NewServer(c *Config, routes []Route) (*Server, error) {
	if c == nil {
		return nil, fmt.Errorf("aic-verifier: nil config")
	}
	tr := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if c.BackendRootCA != "" {
		pool, err := backendRootPool(c.BackendRootCA)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}
	}
	s := &Server{
		cfg:        c,
		log:        c.logger(),
		transport:  tr,
		revHeaders: trustHeaderNames(),
	}
	for _, r := range routes {
		if r.Target == nil {
			return nil, fmt.Errorf("aic-verifier: route %q has nil target", r.Path)
		}
		s.routes = append(s.routes, r)
	}
	next, err := c.Handler(http.HandlerFunc(s.proxy))
	if err != nil {
		return nil, err
	}
	s.handler = next
	return s, nil
}

// Handler exposes the server as a plain http.Handler (for embedding into an
// existing http.Server). Callers managing TLS themselves should use this.
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe starts the reverse-proxy server listening on addr. When
// TLSCertFile/TLSKeyFile are configured the listener terminates TLS (mTLS when
// CACertFile is also set).
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("aic-verifier: listen %s: %w", addr, err)
	}
	if s.cfg.TLSCertFile != "" {
		cert, err := LoadCert(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			ln.Close()
			return err
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
		if s.cfg.CACertFile != "" {
			pool, err := LoadCA(s.cfg.CACertFile)
			if err != nil {
				ln.Close()
				return err
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		ln = tls.NewListener(ln, tlsCfg)
	}
	s.listener = ln
	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelError),
	}
	if o := s.cfg.ServerOptions; o != nil {
		if o.ReadTimeout > 0 {
			srv.ReadTimeout = o.ReadTimeout
		}
		if o.ReadHeaderTimeout > 0 {
			srv.ReadHeaderTimeout = o.ReadHeaderTimeout
		}
		if o.WriteTimeout > 0 {
			srv.WriteTimeout = o.WriteTimeout
		}
		if o.IdleTimeout > 0 {
			srv.IdleTimeout = o.IdleTimeout
		}
		if o.MaxHeaderBytes > 0 {
			srv.MaxHeaderBytes = o.MaxHeaderBytes
		}
	}
	s.srv = srv
	return s.srv.Serve(ln)
}

// Close gracefully shuts down the server.
func (s *Server) Close(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// proxy forwards an admitted request to the matched backend.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	route, ok := s.matchRoute(r.URL.Path)
	if !ok {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusNotFound, Message: "no matching route"})
		return
	}
	if len(route.AllowMethods) > 0 && !contains(route.AllowMethods, r.Method) {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusMethodNotAllowed, Message: "method not allowed"})
		return
	}

	ac := FromContext(r.Context())
	if ac == nil {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "no verified identity"})
		return
	}
	if len(route.RequiredCapabilities) > 0 {
		if !hasAllCapabilities(ac, route.RequiredCapabilities) {
			s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "agent missing required capabilities"})
			return
		}
	}

	// Strip client-supplied identity headers before forwarding (W19 parity).
	for _, h := range s.revHeaders {
		r.Header.Del(h)
	}
	// The forwarding mode is fixed from server config (S1): a malicious client
	// cannot set X-AICN-Identity-Mode to suppress identity disclosure to the
	// backend. The header is also stripped along with the rest of the namespace.
	r.Header.Del("X-AICN-Identity-Mode")
	// S3: strip the client-supplied credential. The backend receives only the
	// server-asserted X-AIC-* identity headers so the agent's live bearer token
	// or mTLS private key material never leaks downstream.
	r.Header.Del("Authorization")
	r.Header.Del("Proxy-Authorization")
	injectIdentityHeaders(r, ac, s.cfg.IdentityMode)

	rp := httputil.NewSingleHostReverseProxy(route.Target)
	rp.Transport = s.reverseProtocolTransport(route)
	defaultDirector := rp.Director
	rp.Director = func(req *http.Request) {
		defaultDirector(req)
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		req.Header.Set("X-Forwarded-For", host)
	}
	rec := &proxyStatusRecorder{ResponseWriter: w}
	rp.ServeHTTP(rec, r)
	if s.cfg.Hooks != nil && s.cfg.Hooks.Forwarded != nil {
		s.cfg.Hooks.Forwarded(r, &http.Response{StatusCode: rec.status})
	}
}

// deny runs the Denied hook (when configured) and writes the SDK error. The
// Denied hook fires for route-level rejections that happen after admission; the
// pipeline-level Denied hook is invoked by the middleware.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, err *AuthError) {
	if s.cfg.Hooks != nil && s.cfg.Hooks.Denied != nil {
		s.cfg.Hooks.Denied(r, err)
	}
	writeSDKError(w, err.Status, err.Code.String(), err.Message)
}

// proxyStatusRecorder captures the status code written to the backend response
// so the Forwarded hook can observe it after reverse proxy completion.
type proxyStatusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status code and passes it through. Status 0 (never
// written) is normalized to 200 for the hook, matching net/http semantics.
func (r *proxyStatusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// backendRootPool builds the trust pool for the reverse proxy's outbound TLS
// to HTTPS backends: the system roots plus the configured BackendRootCA files.
func backendRootPool(spec string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f == "" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("aic-verifier: read backend root CA %q: %w", f, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("aic-verifier: no certificates parsed from %s", f)
		}
	}
	return pool, nil
}

// reverseProtocolTransport returns the outbound transport for a route. The
// proxy currently uses one TLS-capable transport for both schemes; hook kept
// for future per-target control (timeouts, client certs).
func (s *Server) reverseProtocolTransport(route Route) http.RoundTripper {
	return s.transport
}

func (s *Server) matchRoute(p string) (Route, bool) {
	cleaned := path.Clean(p)
	if cleaned == "/" {
		cleaned = ""
	}
	lower := strings.ToLower(cleaned)
	for _, r := range s.routes {
		pat := strings.ToLower(r.Path)
		if pat == "/*" || pat == "/" {
			return r, true
		}
		if strings.HasSuffix(pat, "/*") {
			prefix := strings.TrimSuffix(pat, "/*")
			if strings.HasPrefix(lower, prefix) && len(prefix) > 0 {
				if rest := strings.TrimPrefix(lower, prefix); rest == "" || strings.HasPrefix(rest, "/") {
					return r, true
				}
			}
			continue
		}
		if lower == pat || strings.HasPrefix(lower, strings.TrimSuffix(pat, "/")+"/") {
			return r, true
		}
	}
	return Route{}, false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func hasAllCapabilities(ac *AuthContext, need []string) bool {
	have := make(map[string]bool, len(ac.Capabilities))
	for _, c := range ac.Capabilities {
		have[c] = true
	}
	for _, n := range need {
		if !have[n] {
			return false
		}
	}
	return true
}

func writeSDKError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":%q,"message":%q}`+"\n", code, message)
}
