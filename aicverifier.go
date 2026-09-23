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
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/register/semantics"
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
	// (default true).  When enabled every verified token's jti is single-use:
	// a compliant client mints one token per request (aic-agent local Key mode
	// does this); a pre-minted token shared across requests will be rejected as
	// a replay on its second use.  A token not minted per request and no
	// client-side per-request mint → set this to false.
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
	// AdminToken, when non-empty, is the shared secret that must be presented
	// (Authorization: Bearer) to POST /reload on the AdminHandler.  Empty and
	// no AdminTokenFile → /reload is refused (fail-closed): the policy hot
	// reload seam is never left unauthenticated, so a listener that accidentally
	// exposes the admin mux cannot be used to install an arbitrary policy.
	AdminToken string
	// AdminTokenFile, when non-empty, loads AdminToken from a secrets file at
	// startup (trailing newline trimmed).  Precedence: AdminToken wins.
	AdminTokenFile string
	// RequiredOperations are the concrete actions (id + parameters) this
	// service authorizes.  Unlike RequiredCapabilities, parameter bounds are
	// part of the decision (CLC): an operation asking for more than the grant
	// allows is denied.
	RequiredOperations []Operation
	// UnresolvedEvaluator is the §8.4 residual-obligation release hook for
	// allow_unresolved CLC decisions; forwarded to PipelineConfig → AdmissionConfig.
	// Set programmatically — not parsed from JSON.
	UnresolvedEvaluator func(op Operation, unresolved []string) bool
	// DischargeObligations / ObligationsUnderstood enable the strict
	// consumer-side obligation rule (CLC §8.4 + XACML §2.13/§7.2.1); forwarded
	// to PipelineConfig → AdmissionConfig.  Set programmatically — not parsed
	// from JSON.
	DischargeObligations  bool
	ObligationsUnderstood []string
	// RequireFreshDecisionContext / DecisionContext pin the RATS §10 freshness
	// input for allowed operations; forwarded to PipelineConfig →
	// AdmissionConfig.
	RequireFreshDecisionContext bool
	DecisionContext             *semantics.DecisionContext
	// Challenges enables the CLC-CHALLENGE-v1 carrier: a denial caused by
	// unmet §8.4 residual obligations is answered with 403 +
	// application/problem+json carrying the challenge, and its retry lower
	// bound is mapped to Retry-After.  nil (default) keeps the compact JSON
	// error.
	Challenges *ChallengeConfig
	// ChallengeCarrier shapes the HTTP response for a refusal that carries a
	// challenge.  nil (default) uses the built-in RFC 9457
	// application/problem+json carrier.  A custom carrier may change the body
	// shape; the SDK still sets Retry-After from the challenge's retry bound
	// before delegating, so the lower bound survives regardless.
	ChallengeCarrier ChallengeCarrier
	// EvidenceRequirement is the relying party's evidence sufficiency bar
	// (CLC-REQUIREMENT-v1).  The SDK never takes it from the request: it is this
	// deployment's configuration.  When set, every admitted request is also
	// evaluated against it (via EvidenceFacts), a refusal carries the machine
	// readable challenge, and the emitted records bind the requirement digest.
	EvidenceRequirement *semantics.Requirement
	// EvidenceFacts supplies the evidence facts presented with a request.  The
	// SDK does not parse evidence artifacts; the deployment hands over facts its
	// own verifiers established (type, protected subject id, issuance time,
	// whether it reached VERIFIED).  An error is fail-closed.
	EvidenceFacts func(r *http.Request, ac *AuthContext) ([]semantics.EvidenceFact, error)
	// EvidenceProfile names the evidence shape this deployment emits, e.g.
	// "clc-decision+admission+outcome@1".  It is resolved at configuration time
	// (an unknown name is a configuration error) and fills the shape parts of
	// Evidence: which payloads are produced, whether records carry a freshness
	// context and the source chain, and which requirement is bound.  Changing
	// the emitted shape is a value here, not an edit to the decision path.
	EvidenceProfile string
	// Evidence, when set, freezes a CLC decision record for every decided
	// operation and hands it to a sink (structured log by default, or one DSSE
	// envelope per record on disk).  nil (default) emits nothing — a deployment
	// that only decides online pays no bytes.  Records are produced per source
	// (AIC capabilities, principal authorization); the combined verdict stays in
	// AuthContext.
	Evidence *EvidenceConfig
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
	// AuthorizationPolicy, when non-nil, selects the OU→role mapping this
	// gateway uses instead of the package-global policy (per-Config
	// isolation: several gateways in one process can hold distinct policies).
	// Nil falls back to SetAuthorizationPolicy's global.
	AuthorizationPolicy *AuthorizationPolicy
	// Constraints, when non-nil, selects the constraint evaluator registry this
	// gateway uses instead of the package-global registry (per-Config
	// isolation). Nil falls back to the global registry.
	Constraints *ConstraintRegistry
	// ParameterValidators, when non-nil, selects the parameter boundary
	// validator registry (e.g. MaxRowsValidator) this gateway uses.  Nil keeps
	// parameter boundary validation disabled (opt-in at the global default).
	ParameterValidators *ParameterValidatorRegistry

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

	// metrics is the admission counter set shared by every authenticator built
	// from this Config (middleware and DecisionServer alike), so counters
	// recorded on the middleware path are readable via Config.Metrics/Health.
	// Lazily created under metricsInitMu; the pointer keeps Config copyable.
	metrics *DecisionMetrics
}

// metricsInitMu serializes the lazy creation of Config.metrics. It is
// package-level (not a Config field) so Config stays a plain copyable struct.
var metricsInitMu sync.Mutex

// Metrics returns the admission counter set this Config records decisions
// into, creating it on first use. Middleware deployments (Config.Handler /
// Config.AuthMiddleware) that have no DecisionServer handle read their counters
// and readiness through here (see also Config.Health).
func (c *Config) Metrics() *DecisionMetrics {
	if c == nil {
		return nil
	}
	metricsInitMu.Lock()
	defer metricsInitMu.Unlock()
	if c.metrics == nil {
		c.metrics = NewDecisionMetrics()
	}
	return c.metrics
}

// ServerOptions tunes the embedded http.Server of the reverse proxy.
type ServerOptions struct {
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// Validate performs the static configuration checks that otherwise surface only
// at construction time. It is side-effect-free — no CA pools, JWT verifiers or
// material files are loaded — and safe to call from CI. Material loading still
// happens when a handler or server is built (Handler, NewServer).
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("aic-verifier: nil config")
	}
	var errs []error
	if c.EvidenceProfile != "" {
		if _, err := LookupEvidenceProfile(c.EvidenceProfile); err != nil {
			errs = append(errs, err)
		}
	}
	if c.RequireUserAuth && c.UserCert == nil && c.UserCertResolver == nil && c.CACertFile == "" {
		errs = append(errs, fmt.Errorf("aic-verifier: require_user_auth needs user cert for DA verification"))
	}
	if c.SupervisionPolicy.RequireRuntimeApproval && c.ApprovalRequester == nil {
		errs = append(errs, fmt.Errorf("aic-verifier: require_runtime_approval needs an ApprovalRequester"))
	}
	if c.SupervisionPolicy.AllowBreakGlass && c.OverrideRecorder == nil {
		errs = append(errs, fmt.Errorf("aic-verifier: allow_break_glass needs an OverrideRecorder"))
	}
	if c.SupervisionPolicy.RequireEvidenceExport && c.EvidenceExporter == nil {
		errs = append(errs, fmt.Errorf("aic-verifier: require_evidence_export needs an EvidenceExporter"))
	}
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
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

// Close releases every resource the Config owns: the nonce cache's cleanup
// goroutine, the supervision store, the audit logger (draining buffered
// entries), and the SDK log file. It is idempotent — each child close is
// itself idempotent — so Server.Close and DecisionServer.Close can cascade to
// it without the caller tracking which pieces were wired.
//
// Close stops components the caller supplied through Config fields; it owns the
// *lifecycle*, not the memory. CRL and OCSP refresh loops are run by the
// caller's own stop channel (CRLCache.Start, StartOCSPStapling) and are
// therefore not cascaded here.
//
// Config deliberately carries no lock so it stays copyable; the individual
// child closes provide the idempotency. Do not call Close concurrently with
// itself on the same Config.
func (c *Config) Close() error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.NonceCache != nil {
		c.NonceCache.Stop()
	}
	if c.SupervisionStore != nil {
		if err := c.SupervisionStore.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	// Audit last so records emitted while tearing the rest down are drained.
	if c.AuditLogger != nil {
		if err := c.AuditLogger.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := c.CloseLogger(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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

// outcomeSelfReporting marks a downstream handler that already reports outcome
// records itself (the built-in reverse proxy, which alone can tell a backend
// *response* from a *transport failure*).  NewServer passes its proxy wrapped
// in this marker so the middleware probe defers to it instead of double-reporting
// — a transport failure must stay indeterminate, never reclassified as observed
// through a 502 status caught by the outer recorder.
type outcomeSelfReporting struct{ http.Handler }

// Handler builds a http.Handler that protects next with the AIC admission
// pipeline. On success the verified client identity is attached to the request
// context and pass-through headers are set on req.Header.  When
// Evidence.EmitOutcome is set and next does not report outcomes itself (see
// outcomeSelfReporting), the middleware observes the downstream handler and
// reports the outcome (observed + status).
func (c *Config) Handler(next http.Handler) (http.Handler, error) {
	if next == nil {
		next = http.NotFoundHandler()
	}
	a, err := newAuthenticator(c)
	if err != nil {
		return nil, err
	}
	probeOutcome := a.cfg.Evidence != nil && a.cfg.Evidence.EmitOutcome
	if _, selfReporting := next.(outcomeSelfReporting); selfReporting {
		probeOutcome = false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := a.Authenticate(r)
		if err != nil {
			ae := AsAuthError(err)
			ae.Evidence = append(ae.Evidence, a.refusalEvidence(viewFromHTTP(a.cfg, r), ae)...)
			if a.cfg.Hooks != nil && a.cfg.Hooks.Denied != nil {
				a.cfg.Hooks.Denied(r, ae)
			}
			a.writeError(w, ae)
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
		if probeOutcome {
			// The middleware observes the downstream handler the same way the
			// reverse proxy observes its backend: a response → observed +
			// status, wired to the decision that admitted it.  The recorder
			// normalizes a never-written status to 200 (net/http semantics).
			rec := &proxyStatusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			reportObservedOutcome(a.cfg.Evidence, a.log, r, ctx, status, false)
			return
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
	// Verdict is the overall CLC verdict for the requested operations (B3):
	// "allow" when every operation was authorized outright, "allow_unresolved"
	// when one or more carried §8.4 residual obligations (released or pending).
	// Empty when no Operations were configured.
	Verdict string
	// Reason is the aggregated CLC reason for the verdict.
	Reason string
	// Unresolved lists recognized-but-unevaluated constraints carried by an
	// allow_unresolved verdict (§8.4 residual-obligation channel).
	Unresolved []string
	// OperationDecisions is the per-operation CLC verdict detail (B3).
	OperationDecisions []OperationDecision
	// Evidence points at the decision records this admission produced (digest,
	// verdict and, for file-like sinks, where it was written).  Empty when
	// evidence emission is not configured.
	Evidence []RecordRef
	// Satisfaction is the evidence-requirement evaluation for this request
	// (nil when no requirement is configured): satisfied / violated / unknown,
	// with the per-constraint detail and the missing roles.  It answers "was
	// enough evidence presented", not "is this action authorized".
	Satisfaction *semantics.RequirementResult
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
	metrics    *DecisionMetrics
	policy     atomic.Pointer[authPolicyBundle]
}

func newAuthenticator(c *Config) (*authenticator, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	a := &authenticator{
		cfg:        c,
		log:        c.logger(),
		crl:        c.CRLCache,
		ocsp:       c.OCSPCache,
		audit:      c.AuditLogger,
		nonceCache: c.NonceCache,
		metrics:    c.Metrics(),
	}

	if c.EvidenceProfile != "" {
		profile, err := LookupEvidenceProfile(c.EvidenceProfile)
		if err != nil {
			return nil, err
		}
		ev, err := profile.Apply(c.Evidence)
		if err != nil {
			return nil, err
		}
		c.Evidence = ev
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

// Authenticate runs the admission pipeline for a single HTTP request.  It is a
// thin binding: the request is lowered to a transport-neutral RequestView and
// handed to the Decide decision core, so the HTTP middleware, the gRPC binding
// and direct in-process callers all reach the identical decision.  The returned
// AuthContext is non-nil on success; error is an *AuthError so callers can map
// decision failures to status codes.
func (a *authenticator) Authenticate(r *http.Request) (*AuthContext, error) {
	view := viewFromHTTP(a.cfg, r)
	if !a.cfg.StreamBody && r.Body != nil {
		view.Body, _ = io.ReadAll(io.LimitReader(r.Body, DefaultMaxBodyBytes))
		r.Body = io.NopCloser(bytes.NewReader(view.Body))
	}
	return a.Decide(r.Context(), view)
}

// viewFromHTTP lowers a net/http request to the transport-neutral view the
// decision core consumes.  The request itself rides along as the adaptee so
// deployment hooks keyed on *http.Request (EvidenceFacts, RequireApproval)
// keep working unchanged.
func viewFromHTTP(cfg *Config, r *http.Request) *RequestView {
	v := &RequestView{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header,
		ClientIP: clientIPOf(r),
	}
	v.TransportSecure = r.TLS != nil
	if r.TLS != nil {
		v.CertChain = r.TLS.PeerCertificates
		if len(r.TLS.PeerCertificates) > 0 {
			v.PresentedCert = r.TLS.PeerCertificates[0]
		}
	}
	v.BearerToken = bearerToken(r)
	v.HTTPAdapter = r
	return v
}

// supervise runs the runtime human approval path for requests flagged by
// RequireApproval.  It returns a nil error when the request is admitted, or an
// *AuthError denying it otherwise.  The decision core decides on the
// transport-neutral view; carriers that cannot build an *http.Request supply
// RequireApprovalWith on the view.
func (a *authenticator) supervise(ctx context.Context, view *RequestView, ac *AuthContext, opBody []byte) error {
	needs := false
	switch {
	case view != nil && view.RequireApprovalWith != nil:
		needs = view.RequireApprovalWith(ac)
	case view != nil && view.HTTPAdapter != nil:
		needs = a.cfg.needRuntimeApproval(ac, view.HTTPAdapter)
	}
	if !needs {
		return nil
	}
	risk := RiskAssessment{
		OperationID:     newOperationID(),
		AgentID:         ac.AgentID,
		PrincipalUid:    ac.Principal,
		DAHash:          DAHash(ac.ClientCert),
		Capabilities:    ac.Capabilities,
		Operation:       view.Method + " " + view.Path,
		RequestedParams: NewSummaryFromBody(opBody),
	}
	sr, err := a.requestApproval(ctx, risk)
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

// writeError writes the refusal: a problem document when the AuthError carries
// one (the CLC challenge carrier), a compact JSON error otherwise.
func (a *authenticator) writeError(w http.ResponseWriter, err error) {
	writeAuthError(w, AsAuthError(err), a.cfg)
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
	// Stage, when set, overrides the AdmissionRecord stage for this refusal
	// (the default is Code.String()).  The middleware's pre-language refusals
	// keep the default; the reverse proxy names the layer that refused
	// ("route_denied", "method_not_allowed", "capability_denied", ...) so one
	// proxy can tell its refusals apart.
	Stage string
	// Evidence points at the records a refused request still produced, so the
	// caller can log or forward them next to the challenge.
	Evidence []RecordRef
	// Problem, when set, is written as an RFC 9457 problem document instead of
	// the SDK's compact JSON error — the carrier for CLC-CHALLENGE-v1.
	Problem *ProblemDetails
	// Satisfaction, when the refusal is an unsatisfied evidence requirement, is
	// the machine-readable result (violated / unknown with the missing roles),
	// so a caller can act on *why* the evidence bar was not met without parsing
	// the challenge back out.
	Satisfaction *semantics.RequirementResult
}

func (e *AuthError) Error() string { return e.Message }

func AsAuthError(err error) *AuthError {
	if e, ok := err.(*AuthError); ok {
		return e
	}
	if err == nil {
		return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "admission failed"}
	}
	return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: err.Error()}
}

// auditAdmission writes the admission verdict to the audit log, pinning the
// decision's evidence record (record_digest = refs[0].Digest) so the audit
// chain and the record chain cross-reference each other.  No-op when audit
// logging is disabled or the decision produced no record.
func (a *authenticator) auditAdmission(view *RequestView, clientCert *x509.Certificate, refs []RecordRef, denied bool, reason string) {
	if a.audit == nil || len(refs) == 0 || view == nil {
		return
	}
	entry := NewAuditEntryFromConn(view.ClientIP, view.Method, view.Path, clientCert)
	if denied {
		entry.Action = string(ActionDenied)
		entry.DenyReason = reason
	}
	entry.TraceId = view.TraceID()
	entry.RecordDigest = refs[0].Digest
	a.audit.Log(entry)
}

// emitEvidence freezes a decision record for every operation this admission
// decided, per authority source, and hands it to the configured sink.  It
// returns where the records went, so the caller can point at them.  It is a
// no-op when evidence is not configured.
//
// An emission failure is reported through EvidenceConfig.OnError (a deployment
// wants to know about evidence gaps, not only about requests) and returned to
// the caller for the Strict decision.
func (a *authenticator) emitEvidence(view *RequestView, clientCert *x509.Certificate, result *PipelineResult, outcome EvidenceOutcome) ([]RecordRef, error) {
	cfg := a.cfg.Evidence
	if cfg == nil || result == nil || len(result.OperationDecisions) == 0 {
		return nil, nil
	}
	ctx := EvidenceContext{
		RecorderID: cfg.RecorderID,
		Principal:  result.Principal,
		AgentID:    result.AgentId,
		Serial:     result.Serial,
		Outcome:    outcome,
		At:         cfg.now(),
		Facts:      a.admissionFacts(view, result.OperationDecisions),
	}
	if view != nil {
		ctx.Method = view.Method
		ctx.Path = view.Path
		ctx.TraceID = view.TraceID()
	}
	if cfg.Requirement == nil {
		// Never mutate the deployment's shared config: one middleware serves
		// every request, and a lazy backfill here would race with the reads of
		// other concurrent admissions.  Backfill onto a per-emission copy.
		ec := *cfg
		ec.Requirement = a.cfg.EvidenceRequirement
		cfg = &ec
	}
	refs, err := EmitDecisionRecords(cfg, ctx, clientCert, result.AIC, result.PrincipalAuthorization, a.cfg.UserCert, result.OperationDecisions)
	if err != nil {
		cfg.gap()
		if cfg.OnError != nil {
			cfg.OnError(ctx, err)
		} else {
			logger := a.log
			if logger == nil {
				logger = slog.Default()
			}
			logger.Error("aic-verifier: evidence emission failed", "error", err, "path", ctx.Path)
		}
	}
	return refs, err
}

// refusalEvidence records a refusal that did not already produce records.  The
// pipeline's language-layer refusals carry CLC DecisionRecords in
// AuthError.Evidence; everything else (credential, chain, revocation, AIC
// parsing, missing capability) reaches this single point, where it is recorded
// as an AdmissionRecord — an honest payload, because those refusals never
// reached the language layer.
//
// The guard is deliberate: one refusal, one record.  Adding an admission record
// on top of CLC records would describe the same decision twice, in two types.
func (a *authenticator) refusalEvidence(view *RequestView, ae *AuthError) []RecordRef {
	cfg := a.cfg.Evidence
	if cfg == nil || ae == nil || len(ae.Evidence) > 0 {
		return nil
	}
	ctx := EvidenceContext{
		RecorderID: cfg.RecorderID,
		Outcome:    EvidenceRefused,
		At:         cfg.now(),
	}
	if view != nil {
		ctx.Method = view.Method
		ctx.Path = view.Path
		ctx.TraceID = view.TraceID()
		if view.PresentedCert != nil {
			ctx.Serial = view.PresentedCert.SerialNumber.Text(16)
		}
	}
	ctx.Facts = append(ctx.Facts, a.admissionFacts(view, nil)...)

	return recordRefusal(cfg, a.log, ctx, ae)
}

// admissionFacts returns the content-addressed business facts a connection
// already carries — the client leaf certificate and the operations it actually
// asked CLC to decide (falling back to the deployment's RequiredOperations on
// paths that never reached the operation loop) — in the same shape whether the
// path wound up admitted or refused.  Only digests travel here; the material
// stays where it was verified.
func (a *authenticator) admissionFacts(view *RequestView, ods []OperationDecision) []AdmissionFact {
	if view == nil {
		return nil
	}
	var facts []AdmissionFact
	if view.PresentedCert != nil {
		leaf := view.PresentedCert
		sum := sha256.Sum256(leaf.Raw)
		facts = append(facts, AdmissionFact{
			Type:   "client-cert",
			Digest: semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: sum[:]},
			Note:   "leaf certificate presented on this connection",
		})
	}
	ops := make([]semantics.Operation, 0, len(ods))
	for _, od := range ods {
		ops = append(ops, semantics.Operation{ID: od.ID, Params: od.Params})
	}
	if len(ops) == 0 {
		ops = a.cfg.RequiredOperations
	}
	if len(ops) > 0 {
		if digest, err := semantics.DigestOf(ops); err == nil {
			facts = append(facts, AdmissionFact{
				Type:   "requested-operations",
				Digest: digest,
				Note:   "operations this connection asked CLC to decide",
			})
		}
	}
	return facts
}

// checkEvidenceRequirement evaluates the configured CLC-REQUIREMENT-v1 against
// the facts the deployment supplies for this request.  Anything that is not an
// explicit "satisfied" refuses, and the refusal carries a challenge — the
// machine-readable "what is still missing" — built from the requirement result.
func (a *authenticator) checkEvidenceRequirement(view *RequestView, ac *AuthContext, result *PipelineResult) error {
	req := a.cfg.EvidenceRequirement
	if req == nil {
		return nil
	}
	if err := req.Validate(); err != nil {
		return &AuthError{Code: ErrConfig, Status: http.StatusForbidden, Message: "evidence_requirement_invalid: " + err.Error()}
	}
	var facts []semantics.EvidenceFact
	switch {
	case view != nil && view.EvidenceFactsWith != nil:
		var err error
		facts, err = view.EvidenceFactsWith(ac)
		if err != nil {
			return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_facts_unavailable: " + err.Error()}
		}
	case a.cfg.EvidenceFacts != nil:
		var err error
		var r *http.Request
		if view != nil {
			r = view.HTTPAdapter
		}
		facts, err = a.cfg.EvidenceFacts(r, ac)
		if err != nil {
			return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_facts_unavailable: " + err.Error()}
		}
	}
	now := time.Now().UTC()
	if a.cfg.Challenges != nil && a.cfg.Challenges.Now != nil {
		now = a.cfg.Challenges.Now().UTC()
	}
	sat, err := semantics.EvaluateRequirement(*req, facts, semantics.EvidenceContext{Now: now})
	if err != nil {
		return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_requirement_error: " + err.Error()}
	}
	ac.Satisfaction = &sat
	if sat.Satisfied() {
		return nil
	}

	problem, err := evidenceProblem(a.cfg, *req, sat, result, now, view)
	if err != nil {
		logger := a.log
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("aic-verifier: evidence challenge build failed", "error", err, "path", requestPathOf(view))
	}
	detail := fmt.Sprintf("evidence %s for requirement %s (missing roles: %v)", sat.Verdict, req.ID, sat.MissingRoles)
	return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: detail, Problem: problem, Satisfaction: &sat}
}

// requestPathOf returns the path a refused request was for, for logging when
// the view was dropped (nil-safe).
func requestPathOf(view *RequestView) string {
	if view == nil {
		return ""
	}
	return view.Path
}

// evidenceProblem turns an unsatisfied requirement into the RFC 9457 carrier,
// reusing the same challenge shape as the residual-obligation path.
func evidenceProblem(cfg *Config, req semantics.Requirement, sat semantics.RequirementResult, result *PipelineResult, now time.Time, view *RequestView) (*ProblemDetails, error) {
	challengeCfg := cfg.Challenges
	if challengeCfg == nil {
		return nil, nil
	}
	id, err := challengeCfg.newID()
	if err != nil {
		return nil, err
	}
	nonce, err := challengeCfg.newNonce()
	if err != nil {
		return nil, err
	}
	params := semantics.ChallengeParams{
		ID:          id,
		Nonce:       nonce,
		Audience:    challengeCfg.Audience,
		Now:         now,
		TTL:         challengeCfg.TTL,
		ObtainHints: challengeCfg.ObtainHints,
	}
	if params.Nonce == "" || params.ID == "" {
		return nil, fmt.Errorf("challenge randomness unavailable")
	}
	// The retry lower bound must survive into the carrier exactly like the
	// residual-obligation path (buildChallengeForResult): the client is told
	// when a corrected presentation is welcome, which is what guards the
	// enforcement point against retry amplification.
	if challengeCfg.RetryAfter > 0 {
		params.Retry = &semantics.RetryTiming{
			NotBefore: now.Add(challengeCfg.RetryAfter),
			JitterSec: 0,
		}
	}
	if cfg.RequiredOperations != nil && len(cfg.RequiredOperations) > 0 {
		digest, err := semantics.DigestOf(cfg.RequiredOperations)
		if err != nil {
			return nil, err
		}
		params.ActionDigest = digest
	} else {
		// No operation is constrained: bind the challenge to this request
		// (method + path) instead of one constant for every request, so a
		// challenge cannot be presented for a request it was not issued to.
		// A nil request falls back to the neutral constant (test harnesses
		// drive the gate without a request).
		target := []byte("admission")
		if view != nil {
			target = []byte(fmt.Sprintf("%s %s", view.Method, view.Path))
		}
		params.ActionDigest = semantics.DigestOfCanonical(target)
	}
	challenge, err := semantics.BuildChallengeFromRequirement(req, sat, params)
	if err != nil {
		return nil, err
	}
	return &ProblemDetails{
		Type:      ProblemTypeEvidenceRequired,
		Title:     "Authorization evidence required",
		Status:    http.StatusForbidden,
		Detail:    fmt.Sprintf("requirement %s is %s", req.ID, sat.Verdict),
		Challenge: &challenge,
	}, nil
}
