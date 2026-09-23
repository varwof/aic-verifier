// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Transport-independent decision core.  The HTTP middleware, the reference
// gRPC binding, message-queue adapters and direct in-process callers all
// describe an admission request the same way — a RequestView — and get the
// same AuthContext decision back.  The net/http binding stays a thin adapter
// (aicverifier.go Authenticate); nothing that decides lives there anymore.

package aicverifier

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// RequestView is the transport-neutral description of an admission request:
// the input of the Decide decision core.  It carries a wire credential — an
// mTLS peer chain or a Bearer AIC-JWT — plus the request facts the admission
// pipeline needs (operations, HTTP facts for capability plugins, client IP,
// bounded body).  Carriers that already verified the credential pass the
// verified leaf in VerifiedCert and leave CertChain empty.
type RequestView struct {
	// Credential — at most one of the three shapes is used:
	// CertChain is the mTLS peer certificate chain as presented on the wire.
	CertChain []*x509.Certificate
	// BearerToken is a Bearer AIC-JWT carried out-of-transport (the verifier
	// parses and verifies it here). Requires TransportSecure.
	BearerToken string
	// VerifiedCert is a pre-verified client leaf supplied by an adapter that
	// already owns credential verification (it bypasses chain verification;
	// only pipeline checks apply).  For Bearer views it is the synthesized
	// cert the binding wants downstream to see.
	VerifiedCert *x509.Certificate

	// TransportSecure reports that the request arrived over a TLS-protected
	// transport.  Bearer credentials are refused when false (mirrors the HTTP
	// rule that a Bearer token never travels in cleartext).
	TransportSecure bool

	// Request facts (HTTP field semantics; harmless when empty for non-HTTP
	// carriers).  RawQuery is the raw query string; Header carries the
	// trace/pass-through headers (X-Request-Id, break-glass).
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	// ClientIP is the transport peer address used by constraint evaluation.
	ClientIP string
	// Body is the request body, already bounded (DefaultMaxBodyBytes).
	Body []byte

	// PresentedCert is the raw leaf presented on the wire by an mTLS peer,
	// kept even when it is later rejected (refusal-evidence recording wants
	// the exact bytes presented).  nil for Bearer views.
	PresentedCert *x509.Certificate

	// Hooks replace the deployment's *http.Request-keyed hooks for carriers
	// that cannot build one (gRPC, queue adapters).  When nil and HTTPAdapter
	// is set, the configured EvidenceFacts / RequireApproval hooks run with the
	// adaptee request instead.
	EvidenceFactsWith   func(ac *AuthContext) ([]semantics.EvidenceFact, error)
	RequireApprovalWith func(ac *AuthContext) bool

	// HTTPAdapter is set by the HTTP middleware to the originating request so
	// existing deployment hooks keep working unchanged.  It is never part of
	// the wire payload.
	HTTPAdapter *http.Request
}

// Decide performs the full admission decision for a transport-neutral request
// view: credential resolution, the access pipeline over the requested
// operations, evidence emission/requirement, supervision and auditing.  It
// returns the verified AuthContext on admission or an *AuthError on refusal —
// the same result the HTTP middleware surfaces, so every carrier behaves
// identically.  This is the instrumented entry point (counters + health); the
// decision itself runs in decide.
func (a *authenticator) Decide(ctx context.Context, view *RequestView) (*AuthContext, error) {
	if a.metrics != nil {
		a.metrics.DecideTotal.Add(1)
	}
	ac, err := a.decide(ctx, view)
	a.metrics.noteResult(err)
	return ac, err
}

// decide is the transport-neutral decision core.
func (a *authenticator) decide(ctx context.Context, view *RequestView) (*AuthContext, error) {
	if view == nil {
		view = &RequestView{}
	}
	chain, clientCert, bearer, err := a.resolveCredential(view)
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
	if !bearer && a.tlsCAs == nil && len(chain) > 0 && view.VerifiedCert == nil {
		return nil, &AuthError{Code: ErrChainInvalid, Status: http.StatusForbidden, Message: "client certificate presented but no mTLS CA configured to verify it"}
	}

	if a.tlsCAs != nil && !bearer {
		if view.VerifiedCert == nil {
			if err := buildChain(a.tlsCAs, chain); err != nil {
				return nil, &AuthError{Code: ErrChainInvalid, Status: http.StatusForbidden, Message: err.Error()}
			}
		}
	}

	result := RunAccessPipeline(chain, a.pipelineConfig(view, view.Body))
	if !result.Granted {
		a.log.Warn("aic-verifier: admission denied", "reason", result.DenyReason, "path", view.Path)
		// A refused operation is evidence too: record the decisions that were
		// made before denying (same per-source shape as the allow path).
		refs, evErr := a.emitEvidence(view, clientCert, result, EvidenceRefused)
		a.auditAdmission(view, clientCert, refs, true, result.DenyReason)
		if evErr != nil && a.cfg.Evidence != nil && a.cfg.Evidence.Strict {
			return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_unavailable: " + evErr.Error(), Evidence: refs}
		}
		// A denial that evidence can fix carries a challenge; anything else
		// keeps the plain error (a challenge must not dress up a hard refusal).
		problem, err := problemForResult(result, a.cfg.Challenges, result.DenyReason)
		if err != nil {
			a.log.Warn("aic-verifier: challenge build failed", "error", err, "path", view.Path)
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
	evidenceRefs, evErr := a.emitEvidence(view, clientCert, result, EvidenceAdmitted)
	if evErr != nil && a.cfg.Evidence != nil && a.cfg.Evidence.Strict {
		return nil, &AuthError{Code: ErrDenied, Status: http.StatusForbidden, Message: "evidence_unavailable: " + evErr.Error(), Evidence: evidenceRefs}
	}
	ac.Evidence = evidenceRefs
	a.auditAdmission(view, clientCert, evidenceRefs, false, "")

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
	if err := a.checkEvidenceRequirement(view, ac, result); err != nil {
		return nil, err
	}

	// Mid-operation supervision (design draft §3, decision-path hook before
	// admission): RequireApproval flags requests that need runtime human
	// approval.  The approval path is fail-closed — denied, pending, error or
	// a nil requester all deny with approval_required.
	if err := a.supervise(ctx, view, ac, view.Body); err != nil {
		return nil, err
	}
	return ac, nil
}

// resolveCredential turns the view's wire credential into a pipeline chain:
// it reproduces the auth-mode selection and bearer verification of the old
// HTTP extractor, but from the view (pure data) alone.
func (a *authenticator) resolveCredential(view *RequestView) ([]*x509.Certificate, *x509.Certificate, bool, error) {
	if view.VerifiedCert != nil {
		chain := view.CertChain
		if len(chain) == 0 {
			chain = []*x509.Certificate{view.VerifiedCert}
		}
		return chain, view.VerifiedCert, false, nil
	}
	mode := a.cfg.authMode()
	if len(view.CertChain) > 0 && (mode == MTLSOnly || mode == MTLSOrBearer) {
		return view.CertChain, view.CertChain[0], false, nil
	}
	// Bearer AIC-JWT fallback.
	if mode == BearerOnly || mode == MTLSOrBearer {
		if view.BearerToken != "" {
			if a.verifier == nil {
				return nil, nil, false, &AuthError{Code: ErrNoVerifier, Status: http.StatusUnauthorized, Message: "bearer auth not configured"}
			}
			if !view.TransportSecure {
				return nil, nil, false, &AuthError{Code: ErrBearerNeedsTLS, Status: http.StatusUnauthorized, Message: "bearer token requires a TLS transport"}
			}
			cert, _, err := a.verifier.VerifyBearer(view.BearerToken, time.Now())
			if err != nil {
				return nil, nil, false, &AuthError{Code: ErrInvalidBearer, Status: http.StatusUnauthorized, Message: fmt.Sprintf("invalid bearer token: %v", err)}
			}
			return []*x509.Certificate{cert}, cert, true, nil
		}
	}
	return nil, nil, false, nil
}

// pipelineConfig assembles the (mostly static) admission pipeline config from
// the authenticator config plus the view's per-request facts.  A reloaded
// policy snapshot (ReloadPolicy) wins over the config-level fields; a nil
// bundle keeps plain config operation, preserving the B isolation exactly.
func (a *authenticator) pipelineConfig(view *RequestView, opBody []byte) *PipelineConfig {
	pol, cons, vals := a.cfg.AuthorizationPolicy, a.cfg.Constraints, a.cfg.ParameterValidators
	if b := a.reloadableBundle(); b != nil {
		if b.Policy != nil {
			pol = b.Policy
		}
		if b.Constraints != nil {
			cons = b.Constraints
		}
		if b.Validators != nil {
			vals = b.Validators
		}
	}
	return &PipelineConfig{
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
		ClientIP:                    view.ClientIP,
		EnforceConstraints:          a.cfg.EnforceConstraints,
		StrictConstraints:           true,
		AuthorizationPolicy:         pol,
		ConstraintRegistry:          cons,
		ParameterValidators:         vals,
		CapabilityPluginRegistry:    a.cfg.PluginRegistry,
		CapabilityRegistry:          a.cfg.CapabilityRegistry,
		AuditLogger:                 a.audit,
		NonceCache:                  a.nonceCache,
		UserCert:                    a.cfg.UserCert,
		UserCertResolver:            a.cfg.UserCertResolver,
		HTTPFacts:                   view.httpFacts(opBody),
	}
}

// httpFacts renders the view's request facts in the shape capability plugins
// read.  A nil view yields nil facts (a pure-TLS admission path).
func (v *RequestView) httpFacts(body []byte) *HTTPFacts {
	if v == nil {
		return nil
	}
	hdr := make(map[string]string, len(v.Header))
	for k, vs := range v.Header {
		if len(vs) > 0 {
			hdr[k] = vs[0]
		}
	}
	return &HTTPFacts{Method: v.Method, Path: v.Path, Query: parseRawQuery(v.RawQuery), Headers: hdr, Body: body}
}

// parseRawQuery parses a raw query string the way http.URL.Query() would.
func parseRawQuery(q string) url.Values {
	values, err := url.ParseQuery(q)
	if err != nil {
		return url.Values{}
	}
	return values
}

// TraceID returns the standard trace header the deployment propagates.
func (v *RequestView) TraceID() string {
	if v == nil || v.Header == nil {
		return ""
	}
	return v.Header.Get("X-Request-Id")
}

// DecisionServer is the transport-independent admission entry point: build one
// per gateway (per Config), share it across HTTP, gRPC, queue and in-process
// carriers to guarantee they all make the identical decision.  It is a thin
// wrapper over the same authenticator the HTTP middleware uses, so a single
// per-Config isolation applies across protocols.
type DecisionServer struct {
	a *authenticator
	// adminToken is the fail-closed reload secret resolved from Config at
	// construction time (Config.AdminToken, else Config.AdminTokenFile).
	// Constant-time compared against the Authorization: Bearer value on admin
	// /reload; empty is never valid at runtime because the constructor refuses
	// to build a server without one (P0-1).
	adminToken string
}

// NewDecisionServer builds a DecisionServer from a Config (equivalent to the
// HTTP middleware's authenticator construction).
func NewDecisionServer(c *Config) (*DecisionServer, error) {
	a, err := newAuthenticator(c)
	if err != nil {
		return nil, err
	}
	tok, err := adminTokenFrom(c)
	if err != nil {
		return nil, err
	}
	return &DecisionServer{a: a, adminToken: tok}, nil
}

// adminTokenFrom resolves the reload-admin secret: Config.AdminToken wins;
// otherwise Config.AdminTokenFile is read at startup.  Empty (neither set) is
// invalid — a /reload admin surface that never shuts the trust-injection door
// is exactly what P0-1 exists to forbid, so the constructor fails closed and
// the operator must configure a secret before an admin listener can run.
func adminTokenFrom(c *Config) (string, error) {
	if c == nil {
		return "", fmt.Errorf("aicverifier: NewDecisionServer: nil Config")
	}
	if c.AdminToken != "" {
		return c.AdminToken, nil
	}
	if c.AdminTokenFile == "" {
		return "", fmt.Errorf("aicverifier: AdminToken: admin /reload is fail-closed; set Config.AdminToken or AdminTokenFile before mounting the admin handler")
	}
	b, err := os.ReadFile(c.AdminTokenFile)
	if err != nil {
		return "", fmt.Errorf("aicverifier: AdminTokenFile: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("aicverifier: AdminTokenFile %s: empty admin secret", c.AdminTokenFile)
	}
	return tok, nil
}

// Decide is the transport-neutral decision entry point.
func (s *DecisionServer) Decide(ctx context.Context, view *RequestView) (*AuthContext, error) {
	return s.a.Decide(ctx, view)
}

// Close releases the config's owned resources (audit logger, nonce cache,
// supervision store, log file) via Config.Close. It is idempotent.
func (s *DecisionServer) Close() error {
	if s == nil || s.a == nil || s.a.cfg == nil {
		return nil
	}
	return s.a.cfg.Close()
}
