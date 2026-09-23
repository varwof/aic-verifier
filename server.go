// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/varwof/register/semantics"
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
//
// Listener state is set once by Listen and read concurrently by Addr and Close,
// so it is guarded by mu. Prefer Listen + Addr + Serve over ListenAndServe when
// the caller needs the bound address (e.g. port 0) without polling.
type Server struct {
	cfg        *Config
	routes     []Route
	handler    http.Handler
	transport  *http.Transport
	log        *slog.Logger
	revHeaders []string

	mu       sync.Mutex
	srv      *http.Server
	listener net.Listener
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
	next, err := c.Handler(outcomeSelfReporting{http.HandlerFunc(s.proxy)})
	if err != nil {
		return nil, err
	}
	s.handler = next
	return s, nil
}

// Handler exposes the server as a plain http.Handler (for embedding into an
// existing http.Server). Callers managing TLS themselves should use this.
func (s *Server) Handler() http.Handler { return s.handler }

// Listen binds the reverse-proxy listener on addr (TLS when
// TLSCertFile/TLSKeyFile are configured, mTLS when CACertFile is also set) and
// returns it. It does not begin serving; pass the listener to Serve. Use this
// instead of ListenAndServe when the bound address is needed before serving
// (a ":0" ephemeral port, for example) — read it with Addr.
func (s *Server) Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("aic-verifier: listen %s: %w", addr, err)
	}
	if s.cfg.TLSCertFile != "" {
		cert, err := LoadCert(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			ln.Close()
			return nil, err
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
		if s.cfg.CACertFile != "" {
			pool, err := LoadCA(s.cfg.CACertFile)
			if err != nil {
				ln.Close()
				return nil, err
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		ln = tls.NewListener(ln, tlsCfg)
	}

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

	s.mu.Lock()
	s.listener = ln
	s.srv = srv
	s.mu.Unlock()
	return ln, nil
}

// Serve serves on a listener returned by Listen until Shutdown or Close. It
// reports http.ErrServerClosed on a graceful shutdown. A listener not obtained
// from Listen (no HTTP server prepared) is a configuration error.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return fmt.Errorf("aic-verifier: Serve requires a listener from Listen")
	}
	return srv.Serve(ln)
}

// Addr returns the address the server is listening on, or nil before Listen.
// It is safe to call concurrently with Listen and Close.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// ListenAndServe binds addr and serves until Close or a fatal serve error. It
// is Listen followed by Serve; callers that need the bound address should call
// those two directly.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := s.Listen(addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close gracefully shuts down the server, releases the listener, and closes the
// Config's owned resources (audit logger, nonce cache, supervision store, log
// file) via Config.Close. It is safe to call before Listen (no-op) and more than
// once. Closing the listener as well as calling Shutdown means a listener
// obtained from Listen but never handed to Serve is still released.
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	ln := s.listener
	s.mu.Unlock()
	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
		if ln != nil {
			_ = ln.Close() // Shutdown may already have closed it; ignore the repeat
		}
	}
	if s.cfg != nil {
		err = errors.Join(err, s.cfg.Close())
	}
	return err
}

// proxy forwards an admitted request to the matched backend.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	route, ok := s.matchRoute(r.URL.Path)
	if !ok {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusNotFound, Stage: "route_denied", Message: "no matching route"})
		return
	}
	if len(route.AllowMethods) > 0 && !contains(route.AllowMethods, r.Method) {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusMethodNotAllowed, Stage: "method_not_allowed", Message: "method not allowed"})
		return
	}

	ac := FromContext(r.Context())
	if ac == nil {
		s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Stage: "identity_denied", Message: "no verified identity"})
		return
	}
	if len(route.RequiredCapabilities) > 0 {
		if !hasAllCapabilities(ac, route.RequiredCapabilities) {
			s.deny(w, r, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Stage: "capability_denied", Message: "agent missing required capabilities"})
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

	// Capture the real client IP before the reverse proxy runs. The proxy's
	// Director runs with req.RemoteAddr already rewritten to the last hop, so
	// recording the peer here is the only way to emit the true client in
	// X-Forwarded-For (M4).
	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	// TODO(H2): NewSingleHostReverseProxy is constructed per admitted request,
	// re-allocating the proxy and its per-route state (Director closure,
	// rewrite machinery) every time. For high-throughput routes this should be
	// built once per Route in NewServer and cached on the Server. The closure
	// below is safe to share: it reads only per-request state (req, clientIP).
	// Deferred because the structural change (per-route proxy table) is a
	// larger refactor.
	rp := httputil.NewSingleHostReverseProxy(route.Target)
	rp.Transport = s.reverseProtocolTransport(route)
	defaultDirector := rp.Director
	rp.Director = func(req *http.Request) {
		defaultDirector(req)
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	// The reverse proxy swallows transport errors into a 502; capture them so
	// the outcome record can say "indeterminate" instead of pretending the
	// backend answered 502.
	backendErr := new(error)
	rp.ErrorHandler = func(rw http.ResponseWriter, rr *http.Request, err error) {
		*backendErr = err
		http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	rec := &proxyStatusRecorder{ResponseWriter: w}
	rp.ServeHTTP(rec, r)
	s.emitProxyOutcome(r, ac, rec.status, *backendErr != nil)
	if s.cfg.Hooks != nil && s.cfg.Hooks.Forwarded != nil {
		s.cfg.Hooks.Forwarded(r, &http.Response{StatusCode: rec.status})
	}
}

// deny runs the Denied hook (when configured), leaves an evidence record for
// this post-admission refusal, and writes the SDK error.  The Denied hook fires
// for route-level rejections that happen after admission; the pipeline-level
// Denied hook is invoked by the middleware.
func (s *Server) deny(w http.ResponseWriter, r *http.Request, err *AuthError) {
	err.Evidence = append(err.Evidence, s.denialEvidence(r, err)...)
	if s.cfg.Hooks != nil && s.cfg.Hooks.Denied != nil {
		s.cfg.Hooks.Denied(r, err)
	}
	writeAuthError(w, err, s.cfg)
}

// denialEvidence records a proxy-layer refusal — the reverse proxy refusing a
// request after admission (no route, disallowed method, missing route
// capability).  These refusals never reached the CLC layer, so like the
// middleware's pre-language refusals they become honest AdmissionRecords, with
// a stage naming the refusing layer (route_denied / method_not_allowed /
// capability_denied).
//
// The single-refusal rule is respected: when the admission already produced
// records for this request (AuthContext.Evidence), nothing is appended — the
// request's outcome is already on record as a decision, and adding another
// record would describe it twice in two payload types.
func (s *Server) denialEvidence(r *http.Request, ae *AuthError) []RecordRef {
	cfg := s.cfg.Evidence
	if cfg == nil || ae == nil || len(ae.Evidence) > 0 {
		return nil
	}
	if ac := FromContext(r.Context()); ac != nil && len(ac.Evidence) > 0 {
		return nil
	}
	ctx := EvidenceContext{
		RecorderID: cfg.RecorderID,
		Outcome:    EvidenceRefused,
		At:         cfg.now(),
	}
	if ac := FromContext(r.Context()); ac != nil {
		ctx.Principal = ac.Principal
		ctx.AgentID = ac.AgentID
		ctx.Serial = ac.Serial
	}
	if r != nil {
		ctx.Method = r.Method
		ctx.Path = r.URL.Path
		ctx.TraceID = r.Header.Get("X-Request-Id")
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			leaf := r.TLS.PeerCertificates[0]
			if ctx.Serial == "" {
				ctx.Serial = leaf.SerialNumber.Text(16)
			}
			sum := sha256.Sum256(leaf.Raw)
			ctx.Facts = append(ctx.Facts, AdmissionFact{
				Type:   "client-cert",
				Digest: semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: sum[:]},
				Note:   "leaf certificate presented on this connection",
			})
		}
	}
	return recordRefusal(cfg, s.log, ctx, ae)
}

// emitProxyOutcome reports the effect the reverse proxy observed for an
// admitted request when the deployment asked for outcome records
// (EvidenceConfig.EmitOutcome).  A response from the backend is reported as
// observed with its status; a transport failure is reported as indeterminate —
// the SDK classifies neither as executed nor failed, that judgement is the
// deployment's.  The decision digest points the outcome back at the admission
// record it followed (empty when the admission produced no record: a gap, not
// consent).
func (s *Server) emitProxyOutcome(r *http.Request, ac *AuthContext, status int, transportErr bool) {
	reportObservedOutcome(s.cfg.Evidence, s.log, r, ac, status, transportErr)
}

// reportObservedOutcome reports the effect the request path observed for an
// admitted request.  Both the reverse proxy (a response → observed + status; a
// transport failure → indeterminate) and the middleware (a downstream handler
// returned → observed + status) share this single emission point, so the
// decision, admission and outcome records of one pipeline always ride the same
// sink and the same recorder.  The outcome is classified as observed — the SDK
// does not claim executed/failed, that judgement stays with the deployment.
func reportObservedOutcome(cfg *EvidenceConfig, log *slog.Logger, r *http.Request, ac *AuthContext, status int, transportErr bool) {
	if cfg == nil || !cfg.EmitOutcome || ac == nil || r == nil {
		return
	}
	outcome := OutcomeObserved
	if transportErr {
		outcome = OutcomeIndeterminate
	}
	decisionDigest := ""
	if len(ac.Evidence) > 0 {
		decisionDigest = ac.Evidence[0].Digest
	}
	at := cfg.now()
	ctx := EvidenceContext{
		RecorderID: cfg.RecorderID,
		Method:     r.Method,
		Path:       r.URL.Path,
		TraceID:    r.Header.Get("X-Request-Id"),
		Principal:  ac.Principal,
		AgentID:    ac.AgentID,
		Serial:     ac.Serial,
		Outcome:    EvidenceAdmitted,
		At:         at,
	}
	rec := OutcomeRecord{
		Outcome:        outcome,
		At:             at,
		DecisionDigest: decisionDigest,
		OperationID:    r.Method + " " + r.URL.Path,
		RecorderID:     cfg.RecorderID,
		StatusCode:     status,
		Identity:       AdmissionIdentity{Principal: ac.Principal, AgentID: ac.AgentID, Serial: ac.Serial},
	}
	sink := cfg.Sink
	if sink == nil {
		sink = SlogSink{Logger: log}
	}
	outSink, ok := sink.(OutcomeSink)
	if !ok {
		// A sink that does not know outcome records is an evidence gap for an
		// EmitOutcome deployment — surfaced, never silent.
		if cfg.OnError != nil {
			cfg.gap()
			cfg.OnError(ctx, fmt.Errorf("evidence: sink does not emit outcome records"))
		}
		return
	}
	if _, err := ReportOutcome(outSink, cfg, ctx, rec); err != nil {
		cfg.gap()
		if cfg.OnError != nil {
			cfg.OnError(ctx, err)
		} else {
			logger := log
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("aic-verifier: outcome record failed", "error", err, "path", ctx.Path)
		}
	}
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

// Unwrap lets http.ResponseController reach the underlying writer so Hijack,
// Push and the rest keep working when the middleware wraps a streaming or
// upgraded downstream handler (EmitOutcome).
func (r *proxyStatusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush forwards flush support (SSE and similar) to the underlying writer.
func (r *proxyStatusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
