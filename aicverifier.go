// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package aic-verifier provides a drop-in Go SDK for HTTP services that need to
// enforce AIC (Authorization Identity Certificate) authorization, derived from
// varwof/gateway-core.
//
// It exposes two integration styles with a shared admission pipeline:
//
//  1. Middleware: wrap any http.Handler with aicverifier.AuthMiddleware, and the
//     SDK authenticates every request (mTLS client certificate or a Bearer
//     AIC-JWT) and runs the full AIC decision chain before your handler runs.
//  2. Reverse proxy: aicverifier.Server listens on one address and forwards
//     verified requests to a real backend API, injecting the verified client
//     identity to the backend via X-AIC-* headers.
//
// Both styles run the identical pipeline (CRL -> OCSP -> RBAC -> AIC ->
// constraints -> plugins) so a request admitted by one is admitted by the
// other.
package aicverifier

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pki "github.com/varwof/types"
	"github.com/varwof/types/aicjwt"
)

// DefaultMaxBodyBytes is the maximum request body the pipeline reads for
// capability plugin evaluation (bounded copy; the full body is restored before
// forwarding or calling the next handler).
const DefaultMaxBodyBytes = 1 << 20 // 1 MiB

// AuthMode selects which credential transports are accepted.
type AuthMode int

const (
	// MTLSOnly accepts requests authenticated by an mTLS client certificate.
	MTLSOnly AuthMode = iota
	// BearerOnly accepts requests authenticated by an Authorization: Bearer AIC-JWT.
	BearerOnly
	// MTLSOrBearer accepts either an mTLS client certificate or a Bearer AIC-JWT,
	// matching gateway-core semantics. mTLS takes precedence when both are present.
	MTLSOrBearer
)

// Config is the full aic-verifier configuration. All fields are optional; the
// zero value disables every check except the raw transport decision pipeline.
type Config struct {
	// TLSCertFile / TLSKeyFile are the server certificate used to terminate TLS
	// (required for the reverse-proxy server in TLS/mTLS mode).
	TLSCertFile string
	TLSKeyFile  string

	// CACertFile is the CA bundle for mTLS client certificate verification.
	// Empty disables mTLS (Bearer-only or plaintext listeners).
	CACertFile string
	// JWTCAFile is a PEM file with the CA certificates used to build the AIC-JWT
	// trust root. Empty disables Bearer authentication.
	JWTCAFile string

	// BackendRootCA, when non-empty, is the root CA bundle (one or more PEM
	// files, comma/space separated) trusted for the reverse proxy's outbound
	// TLS to HTTPS backends. Appended to the system roots when set; empty uses
	// system roots only.
	BackendRootCA string
	// JWTIssuer, when non-empty, requires the AIC-JWT iss claim to match.
	JWTIssuer string
	// JWTAudience, when non-empty, requires the AIC-JWT aud claim to include one.
	JWTAudience []string
	// ReplayProtection enables one-time-use replay protection on bearer tokens
	// (default true).
	ReplayProtection *bool

	// IdentityMode selects how much verified client identity is forwarded to
	// backends (default IdentityForwardClientCert). This is fixed at startup
	// and MUST come from configuration — it is never read from a client-supplied
	// request header, so clients cannot downgrade the identity disclosed to a
	// backend.
	IdentityMode IdentityHeaderMode

	// AuthMode selects accepted credential transports (default MTLSOrBearer).
	AuthMode AuthMode

	// RequireAIC rejects clients whose certificate carries no AIC extension.
	RequireAIC bool
	// RequiredCapabilities requires the agent to hold all listed CapabilityIds.
	RequiredCapabilities []string
	// RequiredOperations are the concrete actions (id + parameters) this
	// service authorizes.  Unlike RequiredCapabilities, parameter bounds are
	// part of the decision (CLC): an operation asking for more than the grant
	// allows is denied.
	RequiredOperations []Operation
	// DisallowRepresentative rejects DelegationRepresentative-mode AIC.
	DisallowRepresentative bool
	// RequireUserAuth requires DelegationAuthorization signature verification.
	RequireUserAuth bool
	// EnforceConstraints enforces authorizationConstraints (CIDR / time window /
	// concurrency).
	EnforceConstraints bool

	// UserCert is the authorized user certificate for DA signature verification.
	// UserCertResolver resolves a user certificate by principal KeyHash when
	// RequireUserAuth needs DA signature verification. If both are nil, only
	// self-issued DA (agent == user) verifies.
	UserCert         *x509.Certificate
	UserCertResolver func(keyHash []byte) (*x509.Certificate, error)

	// CRLCache / OCSPCache plug in revocation checking. Nil disables that check.
	CRLCache  *CRLCache
	OCSPCache *OCSPCache

	// AuditLogger records admission decisions. Nil disables audit logging.
	AuditLogger *AuditLogger
	// NonceCache provides anti-replay protection for DA nonces. Nil disables it.
	NonceCache *NonceCache

	// PluginRegistry registers capability plugins consulted during admission.
	// Nil disables phase-one plugin decisions.
	PluginRegistry *PluginRegistry
	// CapabilityRegistry validates AIC-declared capabilities are registered.
	// Nil falls back to the global registry.
	CapabilityRegistry CapabilityRegistry

	// Logger is the structured logger (default slog.Default()).
	Logger *slog.Logger
	// LogFile, when non-empty, appends the SDK's own log output to this file
	// (created with 0644 if missing) instead of stdout.
	LogFile string
	// StreamBody when false (default) limits the copied evaluation body to
	// DefaultMaxBodyBytes. Services streaming large bodies should set this true.
	StreamBody bool

	// Hooks install lifecycle callbacks (see Hooks). This is the reserved
	// extension point for callers that need to observe or veto decisions.
	Hooks *Hooks

	// Supervision extension points (design draft
	// aic-sdk-监督接口设计-事前事中事后 §3/§4).  Each interface has a
	// fail-closed default when nil; SupervisionPolicy turns the accompanying
	// startup validations on.

	// ApprovalRequester is the mid-operation runtime human approval hook.  A
	// nil requester denies requests flagged by RequireApproval with
	// approval_required.
	ApprovalRequester ApprovalRequester
	// OverrideRecorder records break-glass / override events.  A nil recorder
	// (together with AllowBreakGlass=true) is a startup error: an unlogged
	// break-glass is never available.
	OverrideRecorder OverrideRecorder
	// SupervisionPolicy gates runtime approval, break-glass and evidence
	// export (startup validation rules in newAuthenticator).
	SupervisionPolicy SupervisionPolicy
	// SupervisionStore persists supervision events (append-only JSONL).  Nil
	// skips event persistence; decision outcomes stay fail-closed regardless.
	SupervisionStore *SupervisionStore
	// EvidenceExporter exports evidence bundles for post-operation attribution.
	EvidenceExporter EvidenceExporter
	// RequireApproval, when non-nil, is consulted per request.  Returning true
	// routes the request through ApprovalRequester before it is admitted; nil
	// (or false) admits directly.  The same trigger point is reserved for the
	// LLM semantic gate.
	RequireApproval func(ctx *AuthContext, r *http.Request) bool

	// AuditLogFile / AuditTSAURL / SupervisionLogFile are the file-based
	// supervision inputs read from JSON configuration (see fileConfig).  They
	// are the configuration mirror of the SupervisionStore / audit chain: the
	// built-in EvidenceExporter (FileEvidenceExporter) reads them together
	// with the audit file to build evidence bundles.  Code-injected stores
	// (SupervisionStore, AuditLogger) take precedence when both are set.
	AuditLogFile       string
	AuditTSAURL        string
	SupervisionLogFile string

	// ServerOptions tunes the embedded http.Server used in proxy style
	// (Server.ListenAndServe). Zero values fall back to safe defaults.
	ServerOptions *ServerOptions

	logFile *os.File // lazily opened source for LogFile (owned by this config)
}

// ServerOptions tunes the embedded http.Server of the reverse proxy.
type ServerOptions struct {
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// CloseLogger releases the file opened for LogFile (no-op when none set).
func (c *Config) CloseLogger() error {
	if c == nil || c.logFile == nil {
		return nil
	}
	err := c.logFile.Close()
	c.logFile = nil
	return err
}

func (c *Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	if c.LogFile != "" {
		if c.logFile == nil {
			if f, err := os.OpenFile(c.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
				c.logFile = f
			}
		}
		if c.logFile != nil {
			return slog.New(slog.NewTextHandler(c.logFile, nil))
		}
	}
	return slog.Default()
}

func (c *Config) authMode() AuthMode {
	if c.AuthMode != MTLSOnly && c.AuthMode != BearerOnly && c.AuthMode != MTLSOrBearer {
		return MTLSOrBearer
	}
	return c.AuthMode
}

func (c *Config) replayProtection() bool {
	if c.ReplayProtection == nil {
		return true
	}
	return *c.ReplayProtection
}

// Handler builds a http.Handler that protects next with the AIC admission
// pipeline. On success the verified client identity is attached to the request
// context and pass-through headers are set on req.Header.
func (c *Config) Handler(next http.Handler) (http.Handler, error) {
	if next == nil {
		next = http.NotFoundHandler()
	}
	a, err := newAuthenticator(c)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := a.Authenticate(r)
		if err != nil {
			if a.cfg.Hooks != nil && a.cfg.Hooks.Denied != nil {
				a.cfg.Hooks.Denied(r, asAuthError(err))
			}
			a.writeError(w, err)
			return
		}
		if ctx != nil {
			r = r.WithContext(context.WithValue(r.Context(), authCtxKey{}, ctx))
		}
		if a.cfg.Hooks != nil && a.cfg.Hooks.Authenticated != nil {
			if hErr := a.cfg.Hooks.Authenticated(ctx, r); hErr != nil {
				denied := &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: hErr.Error()}
				if a.cfg.Hooks.Denied != nil {
					a.cfg.Hooks.Denied(r, denied)
				}
				a.writeError(w, denied)
				return
			}
		}
		next.ServeHTTP(w, r)
	}), nil
}

// AuthMiddleware mirrors Handler but panics on an invalid config, so it can be
// used inline in http.Server{Handler: ...}. Use Handler when errors must be
// handled explicitly.
func (c *Config) AuthMiddleware(next http.Handler) http.Handler {
	h, err := c.Handler(next)
	if err != nil {
		panic(fmt.Sprintf("aic-verifier: invalid config: %v", err))
	}
	return h
}

// AuthContext is the verified identity attached to the request context after a
// successful admission.
type AuthContext struct {
	// ClientCert is the admitted client certificate (real mTLS peer or a
	// synthesized carrier for Bearer AIC-JWT).
	ClientCert *x509.Certificate
	// Principal is the AIC PrincipalUid string.
	Principal string
	// AgentID is the AIC AgentId.
	AgentID string
	// SPIFFEID is the SPIFFE ID from the certificate SAN (empty if none).
	SPIFFEID string
	// Roles are the extracted policy roles.
	Roles []string
	// Capabilities lists the admitted AIC capability ids.
	Capabilities []string
	// AIC is the parsed AIC extension (nil for non-AIC certificates).
	AIC *AIC
	// Bearer reports whether the request was authenticated by a JWT bearer.
	Bearer bool
	// Serial is the normalized client certificate serial.
	Serial string
}

type authCtxKey struct{}

// FromContext retrieves the verified AuthContext from a request context.
// Returns nil when the request did not pass through a aic-verifier middleware.
func FromContext(ctx context.Context) *AuthContext {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(authCtxKey{}).(*AuthContext)
	return v
}

// authenticator wires transport credential extraction to the gateway-core
// admission pipeline.
type authenticator struct {
	cfg        *Config
	log        *slog.Logger
	tlsCAs     *x509.CertPool
	verifier   *JWTVerifier
	nonces     aicjwt.NonceStore
	crl        *CRLCache
	ocsp       *OCSPCache
	audit      *AuditLogger
	nonceCache *NonceCache
}

func newAuthenticator(c *Config) (*authenticator, error) {
	a := &authenticator{
		cfg:        c,
		log:        c.logger(),
		crl:        c.CRLCache,
		ocsp:       c.OCSPCache,
		audit:      c.AuditLogger,
		nonceCache: c.NonceCache,
	}

	mode := c.authMode()
	if (mode == MTLSOnly || mode == MTLSOrBearer) && c.CACertFile != "" {
		pool := x509.NewCertPool()
		if err := loadPEMIntoPool(pool, c.CACertFile); err != nil {
			return nil, err
		}
		a.tlsCAs = pool
	}

	if (mode == BearerOnly || mode == MTLSOrBearer) && c.JWTCAFile != "" {
		verifier, err := LoadJWTVerifier(c.JWTCAFile)
		if err != nil {
			return nil, err
		}
		if verifier != nil {
			var nonces aicjwt.NonceStore
			if c.replayProtection() {
				nonces = NewReplayNonceStore(0, 0)
			}
			verifier.SetBearerPolicy(c.JWTIssuer, c.JWTAudience, nonces)
			a.verifier = verifier
			a.nonces = nonces
		}
	}

	if c.RequireUserAuth && c.UserCert == nil && c.UserCertResolver == nil && c.CACertFile == "" {
		return nil, fmt.Errorf("aic-verifier: require_user_auth needs user cert for DA verification")
	}
	if c.SupervisionPolicy.RequireRuntimeApproval && c.ApprovalRequester == nil {
		return nil, fmt.Errorf("aic-verifier: require_runtime_approval needs an ApprovalRequester")
	}
	if c.SupervisionPolicy.AllowBreakGlass && c.OverrideRecorder == nil {
		return nil, fmt.Errorf("aic-verifier: allow_break_glass needs an OverrideRecorder")
	}
	if c.SupervisionPolicy.RequireEvidenceExport && c.EvidenceExporter == nil {
		return nil, fmt.Errorf("aic-verifier: require_evidence_export needs an EvidenceExporter")
	}
	return a, nil
}

func loadPEMIntoPool(pool *x509.CertPool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("aic-verifier: read CA %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("aic-verifier: no CA certs in %q", path)
	}
	return nil
}

// Authenticate runs the admission pipeline for a single request. The returned
// AuthContext is non-nil on success; error is an *AuthError so callers can map
// decision failures to status codes.
func (a *authenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	chain, clientCert, bearer, err := a.extractClient(r)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		chain = []*x509.Certificate{}
	}
	if clientCert == nil {
		return nil, &AuthError{Code: ErrNoCredential, Status: http.StatusUnauthorized, Message: "no client credential presented"}
	}

	// Fail-closed (S2): if a client presented a certificate but no mTLS CA pool
	// was configured, refuse the request rather than accepting an unverified chain.
	if !bearer && a.tlsCAs == nil && len(chain) > 0 {
		return nil, &AuthError{Code: ErrChainInvalid, Status: http.StatusForbidden, Message: "client certificate presented but no mTLS CA configured to verify it"}
	}

	if a.tlsCAs != nil && !bearer {
		if err := buildChain(a.tlsCAs, chain); err != nil {
			return nil, &AuthError{Code: ErrChainInvalid, Status: http.StatusForbidden, Message: err.Error()}
		}
	}

	var opBody []byte
	if !a.cfg.StreamBody && r.Body != nil {
		opBody, _ = io.ReadAll(io.LimitReader(r.Body, DefaultMaxBodyBytes))
		r.Body = io.NopCloser(bytes.NewReader(opBody))
	}

	result := RunAccessPipeline(chain, &PipelineConfig{
		CRLCache:                 a.crl,
		OCSPCache:                a.ocsp,
		CheckScope:               CheckFullChain,
		RequireAIC:               a.cfg.RequireAIC,
		RequiredCapabilities:     a.cfg.RequiredCapabilities,
		Operations:               a.cfg.RequiredOperations,
		DisallowRepresentative:   a.cfg.DisallowRepresentative,
		RequireUserAuth:          a.cfg.RequireUserAuth,
		ClientIP:                 clientIPOf(r),
		EnforceConstraints:       a.cfg.EnforceConstraints,
		StrictConstraints:        true,
		CapabilityPluginRegistry: a.cfg.PluginRegistry,
		CapabilityRegistry:       a.cfg.CapabilityRegistry,
		AuditLogger:              a.audit,
		NonceCache:               a.nonceCache,
		UserCert:                 a.cfg.UserCert,
		UserCertResolver:         a.cfg.UserCertResolver,
		HTTPFacts:                httpFactsFor(r, opBody),
	})
	if !result.Granted {
		a.log.Warn("aic-verifier: admission denied", "reason", result.DenyReason, "path", r.URL.Path)
		return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: result.DenyReason}
	}

	ac := &AuthContext{
		ClientCert: clientCert,
		Principal:  result.Principal,
		AgentID:    result.AgentId,
		SPIFFEID:   result.SPIFFEID,
		Roles:      result.Roles,
		Serial:     result.Serial,
		Bearer:     bearer,
		AIC:        result.AIC,
	}
	if result.AIC != nil {
		for _, cap := range result.AIC.Capabilities {
			ac.Capabilities = append(ac.Capabilities, cap.CapabilityId)
		}
	} else if pa := result.PrincipalAuthorization; pa != nil {
		// A human certificate carries no AIC extension: its authority is the
		// PrincipalAuthorization extension (spec: enterprise privilege
		// autonomy).  Surface those grants so downstream code sees what the
		// caller was actually authorized with, instead of an empty list that
		// reads as "no permissions" for a request that was just admitted.
		for _, g := range pa.Grants {
			ac.Capabilities = append(ac.Capabilities, g.CapabilityId)
		}
	}

	// Mid-operation supervision (design draft §3, decision-path hook before
	// admission): RequireApproval flags requests that need runtime human
	// approval.  The approval path is fail-closed — denied, pending, error or
	// a nil requester all deny with approval_required.
	if err := a.supervise(r, ac, opBody); err != nil {
		return nil, err
	}
	return ac, nil
}

// supervise runs the runtime human approval path for requests flagged by
// RequireApproval.  It returns a nil error when the request is admitted, or an
// *AuthError denying it otherwise.
func (a *authenticator) supervise(r *http.Request, ac *AuthContext, opBody []byte) error {
	if !a.cfg.needRuntimeApproval(ac, r) {
		return nil
	}
	risk := RiskAssessment{
		OperationID:     newOperationID(),
		AgentID:         ac.AgentID,
		PrincipalUid:    ac.Principal,
		DAHash:          DAHash(ac.ClientCert),
		Capabilities:    ac.Capabilities,
		Operation:       r.Method + " " + r.URL.Path,
		RequestedParams: NewSummaryFromBody(opBody),
	}
	sr, err := a.requestApproval(r.Context(), risk)
	if err != nil {
		a.log.Warn("aic-verifier: runtime approval failed", "operation_id", risk.OperationID, "err", err)
		a.noteSupervision(pki.SupervisionDenied, risk, "aic-verifier", "approval_required: "+err.Error())
		return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "approval_required"}
	}
	if !sr.Approved() {
		actor, reason := "aic-verifier", ""
		if sr != nil {
			actor = sr.Approver
			reason = sr.Reason
		}
		a.log.Warn("aic-verifier: runtime approval denied", "operation_id", risk.OperationID, "reason", reason)
		a.noteSupervision(pki.SupervisionDenied, risk, actor, "approval_required: "+reason)
		return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "approval_required"}
	}
	a.log.Info("aic-verifier: runtime approval granted", "operation_id", risk.OperationID, "approver", sr.Approver)
	a.noteSupervision(pki.SupervisionApproval, risk, sr.Approver, sr.Reason)
	return nil
}

// requestApproval calls the configured ApprovalRequester, failing closed with
// a nil result when no requester is configured.
func (a *authenticator) requestApproval(ctx context.Context, risk RiskAssessment) (*SupervisionResult, error) {
	if a.cfg.ApprovalRequester == nil {
		return nil, nil
	}
	return a.cfg.ApprovalRequester.Request(ctx, risk)
}

// noteSupervision persists a supervision event to the configured store.  A nil
// store is skipped; persistence failures never change the admission outcome
// (which stays fail-closed).
func (a *authenticator) noteSupervision(t pki.SupervisionEventType, risk RiskAssessment, actor, reason string) {
	store := a.cfg.SupervisionStore
	if store == nil {
		return
	}
	decision := pki.SupervisionDecisionDenied
	switch t {
	case pki.SupervisionApproval, pki.SupervisionConsent:
		decision = pki.SupervisionDecisionApproved
	}
	ev := &pki.SupervisionEvent{
		Type:        t,
		Source:      "aic-verifier",
		OperationID: risk.OperationID,
		DaHash:      risk.DAHash,
		AgentID:     risk.AgentID,
		Actor:       actor,
		Reason:      reason,
		Decision:    decision,
		Ts:          time.Now().UTC(),
	}
	if err := store.Record(ev); err != nil {
		a.log.Warn("aic-verifier: supervision event record failed", "operation_id", risk.OperationID, "err", err)
	}
}

// extractClient resolves the peer certificate or Bearer token to a certificate
// for the pipeline. Returns the full chain (may be nil for bearer synthesis).
func (a *authenticator) extractClient(r *http.Request) ([]*x509.Certificate, *x509.Certificate, bool, error) {
	mode := a.cfg.authMode()
	var chain []*x509.Certificate
	if r.TLS != nil {
		chain = r.TLS.PeerCertificates
	}
	if len(chain) > 0 && (mode == MTLSOnly || mode == MTLSOrBearer) {
		return chain, chain[0], false, nil
	}
	// Bearer AIC-JWT fallback.
	if mode == BearerOnly || mode == MTLSOrBearer {
		if tok := bearerToken(r); tok != "" {
			if a.verifier == nil {
				return nil, nil, false, &AuthError{Code: ErrNoVerifier, Status: http.StatusUnauthorized, Message: "bearer auth not configured"}
			}
			if r.TLS == nil {
				return nil, nil, false, &AuthError{Code: ErrBearerNeedsTLS, Status: http.StatusUnauthorized, Message: "bearer token requires a TLS transport"}
			}
			cert, _, err := a.verifier.VerifyBearer(tok, time.Now())
			if err != nil {
				return nil, nil, false, &AuthError{Code: ErrInvalidBearer, Status: http.StatusUnauthorized, Message: fmt.Sprintf("invalid bearer token: %v", err)}
			}
			return []*x509.Certificate{cert}, cert, true, nil
		}
	}
	return chain, nil, false, nil
}

func clientIPOf(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return host
}

// buildChain verifies that chain[0] is issued by one of the configured CAs.
func buildChain(pool *x509.CertPool, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}
	if pool == nil {
		return fmt.Errorf("mTLS CA pool not configured; client certificate cannot be verified")
	}
	leaf := chain[0]
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}
	return nil
}

// bearerToken returns the token from an Authorization: Bearer header, or "".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "Bearer ") {
		return ""
	}
	tok := strings.TrimSpace(h[7:])
	if tok == "" || strings.ContainsAny(tok, "\r\n") {
		return ""
	}
	return tok
}

// httpFactsFor builds the HTTP facts used by capability plugins.
func httpFactsFor(r *http.Request, body []byte) *HTTPFacts {
	hdr := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		if len(vs) > 0 {
			hdr[k] = vs[0]
		}
	}
	return &HTTPFacts{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.Query(),
		Headers: hdr,
		Body:    body,
	}
}

// writeError writes a JSON error response.
func (a *authenticator) writeError(w http.ResponseWriter, err error) {
	ae := asAuthError(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(ae.Status)
	io.WriteString(w, fmt.Sprintf(`{"code":%q,"message":%q}`+"\n", ae.Code.String(), ae.Message))
}

// ErrorCode identifies the kind of admission failure.
type ErrorCode int

const (
	ErrNoCredential ErrorCode = iota
	ErrDenied
	ErrNoVerifier
	ErrBearerNeedsTLS
	ErrInvalidBearer
	ErrChainInvalid
	ErrConfig
)

func (c ErrorCode) String() string {
	switch c {
	case ErrNoCredential:
		return "no_credential"
	case ErrDenied:
		return "access_denied"
	case ErrNoVerifier:
		return "bearer_not_configured"
	case ErrBearerNeedsTLS:
		return "bearer_tls_required"
	case ErrInvalidBearer:
		return "invalid_bearer"
	case ErrChainInvalid:
		return "chain_invalid"
	default:
		return "config_error"
	}
}

// AuthError is the typed admission failure.
type AuthError struct {
	Code    ErrorCode
	Status  int
	Message string
}

func (e *AuthError) Error() string { return e.Message }

func asAuthError(err error) *AuthError {
	if e, ok := err.(*AuthError); ok {
		return e
	}
	if err == nil {
		return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "admission failed"}
	}
	return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: err.Error()}
}
