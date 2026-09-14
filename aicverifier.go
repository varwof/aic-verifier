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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
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
			ae := asAuthError(err)
			ae.Evidence = append(ae.Evidence, a.refusalEvidence(r, ae)...)
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
		CRLCache:                    a.crl,
		OCSPCache:                   a.ocsp,
		CheckScope:                  CheckFullChain,
		RequireAIC:                  a.cfg.RequireAIC,
		RequiredCapabilities:        a.cfg.RequiredCapabilities,
		Operations:                  a.cfg.RequiredOperations,
		UnresolvedEvaluator:         a.cfg.UnresolvedEvaluator,
		DischargeObligations:        a.cfg.DischargeObligations,
		ObligationsUnderstood:       a.cfg.ObligationsUnderstood,
		RequireFreshDecisionContext: a.cfg.RequireFreshDecisionContext,
		DecisionContext:             a.cfg.DecisionContext,
		DisallowRepresentative:      a.cfg.DisallowRepresentative,
		RequireUserAuth:             a.cfg.RequireUserAuth,
		ClientIP:                    clientIPOf(r),
		EnforceConstraints:          a.cfg.EnforceConstraints,
		StrictConstraints:           true,
		CapabilityPluginRegistry:    a.cfg.PluginRegistry,
		CapabilityRegistry:          a.cfg.CapabilityRegistry,
		AuditLogger:                 a.audit,
		NonceCache:                  a.nonceCache,
		UserCert:                    a.cfg.UserCert,
		UserCertResolver:            a.cfg.UserCertResolver,
		HTTPFacts:                   httpFactsFor(r, opBody),
	})
	if !result.Granted {
		a.log.Warn("aic-verifier: admission denied", "reason", result.DenyReason, "path", r.URL.Path)
		// A refused operation is evidence too: record the decisions that were
		// made before denying (same per-source shape as the allow path).
		refs, evErr := a.emitEvidence(r, clientCert, result, EvidenceRefused)
		a.auditAdmission(r, clientCert, refs, true, result.DenyReason)
		if evErr != nil && a.cfg.Evidence != nil && a.cfg.Evidence.Strict {
			return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_unavailable: " + evErr.Error(), Evidence: refs}
		}
		// A denial that evidence can fix carries a challenge; anything else
		// keeps the plain error (a challenge must not dress up a hard refusal).
		problem, err := problemForResult(result, a.cfg.Challenges, result.DenyReason)
		if err != nil {
			a.log.Warn("aic-verifier: challenge build failed", "error", err, "path", r.URL.Path)
		}
		return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: result.DenyReason, Problem: problem, Evidence: refs}
	}

	ac := &AuthContext{
		ClientCert:         clientCert,
		Principal:          result.Principal,
		AgentID:            result.AgentId,
		SPIFFEID:           result.SPIFFEID,
		Roles:              result.Roles,
		Serial:             result.Serial,
		Bearer:             bearer,
		AIC:                result.AIC,
		Verdict:            result.CLCVerdict,
		Reason:             result.CLCReason,
		Unresolved:         result.CLCUnresolved,
		OperationDecisions: result.OperationDecisions,
	}
	// The admitted call leaves a replayable record: freeze the per-source
	// decisions before anything downstream can act on them.
	evidenceRefs, evErr := a.emitEvidence(r, clientCert, result, EvidenceAdmitted)
	if evErr != nil && a.cfg.Evidence != nil && a.cfg.Evidence.Strict {
		return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_unavailable: " + evErr.Error(), Evidence: evidenceRefs}
	}
	ac.Evidence = evidenceRefs
	a.auditAdmission(r, clientCert, evidenceRefs, false, "")

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

	// Evidence sufficiency (CLC-E): the deployment's requirement is evaluated
	// against the facts it presented.  Satisfied admits; violated or unknown
	// refuses, and the refusal carries the machine-readable challenge saying
	// what is still needed.  This is not the authorization decision — it is the
	// "is there enough evidence" half, and neither stands in for the other.
	if err := a.checkEvidenceRequirement(r, ac, result); err != nil {
		return nil, err
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

// writeError writes the refusal: a problem document when the AuthError carries
// one (the CLC challenge carrier), a compact JSON error otherwise.
func (a *authenticator) writeError(w http.ResponseWriter, err error) {
	writeAuthError(w, asAuthError(err), a.cfg)
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

func asAuthError(err error) *AuthError {
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
func (a *authenticator) auditAdmission(r *http.Request, clientCert *x509.Certificate, refs []RecordRef, denied bool, reason string) {
	if a.audit == nil || len(refs) == 0 {
		return
	}
	entry := NewAuditEntryFromConn(clientIPOf(r), r.Method, r.URL.Path, clientCert)
	if denied {
		entry.Action = string(ActionDenied)
		entry.DenyReason = reason
	}
	entry.TraceId = r.Header.Get("X-Request-Id")
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
func (a *authenticator) emitEvidence(r *http.Request, clientCert *x509.Certificate, result *PipelineResult, outcome EvidenceOutcome) ([]RecordRef, error) {
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
		Facts:      a.admissionFacts(r, result.OperationDecisions),
	}
	if r != nil {
		ctx.Method = r.Method
		ctx.Path = r.URL.Path
		ctx.TraceID = r.Header.Get("X-Request-Id")
	}
	if cfg.Requirement == nil {
		cfg.Requirement = a.cfg.EvidenceRequirement
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
func (a *authenticator) refusalEvidence(r *http.Request, ae *AuthError) []RecordRef {
	cfg := a.cfg.Evidence
	if cfg == nil || ae == nil || len(ae.Evidence) > 0 {
		return nil
	}
	ctx := EvidenceContext{
		RecorderID: cfg.RecorderID,
		Outcome:    EvidenceRefused,
		At:         cfg.now(),
	}
	if r != nil {
		ctx.Method = r.Method
		ctx.Path = r.URL.Path
		ctx.TraceID = r.Header.Get("X-Request-Id")
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			ctx.Serial = r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		}
	}
	ctx.Facts = append(ctx.Facts, a.admissionFacts(r, nil)...)

	return recordRefusal(cfg, a.log, ctx, ae)
}

// admissionFacts returns the content-addressed business facts a connection
// already carries — the client leaf certificate and the operations it actually
// asked CLC to decide (falling back to the deployment's RequiredOperations on
// paths that never reached the operation loop) — in the same shape whether the
// path wound up admitted or refused.  Only digests travel here; the material
// stays where it was verified.
func (a *authenticator) admissionFacts(r *http.Request, ods []OperationDecision) []AdmissionFact {
	if r == nil {
		return nil
	}
	var facts []AdmissionFact
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf := r.TLS.PeerCertificates[0]
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
func (a *authenticator) checkEvidenceRequirement(r *http.Request, ac *AuthContext, result *PipelineResult) error {
	req := a.cfg.EvidenceRequirement
	if req == nil {
		return nil
	}
	if err := req.Validate(); err != nil {
		return &AuthError{Code: ErrConfig, Status: http.StatusForbidden, Message: "evidence_requirement_invalid: " + err.Error()}
	}
	var facts []semantics.EvidenceFact
	if a.cfg.EvidenceFacts != nil {
		var err error
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

	problem, err := evidenceProblem(a.cfg, *req, sat, result, now)
	if err != nil {
		logger := a.log
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("aic-verifier: evidence challenge build failed", "error", err, "path", r.URL.Path)
	}
	detail := fmt.Sprintf("evidence %s for requirement %s (missing roles: %v)", sat.Verdict, req.ID, sat.MissingRoles)
	return &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: detail, Problem: problem, Satisfaction: &sat}
}

// evidenceProblem turns an unsatisfied requirement into the RFC 9457 carrier,
// reusing the same challenge shape as the residual-obligation path.
func evidenceProblem(cfg *Config, req semantics.Requirement, sat semantics.RequirementResult, result *PipelineResult, now time.Time) (*ProblemDetails, error) {
	challengeCfg := cfg.Challenges
	if challengeCfg == nil {
		return nil, nil
	}
	params := semantics.ChallengeParams{
		ID:          challengeCfg.newID(),
		Nonce:       challengeCfg.newNonce(),
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
		params.ActionDigest = semantics.DigestOfCanonical([]byte("admission"))
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
