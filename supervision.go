// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// Supervision extension points (design draft
// aic-sdk-监督接口设计-事前事中事后 §3/§4).  Every extension point is an
// interface plus a fail-closed default so that not wiring it leaves the system
// safe rather than wide open.

// SemanticVerdict is the output of an optional LLM semantic gate.  The SDK
// does not call an LLM itself; integrations that do (or that enforce semantic
// policies) populate this and attach it to a RiskAssessment for the human
// approver.
type SemanticVerdict struct {
	// Model is the model identifier that produced the verdict.
	Model string `json:"model"`
	// Version is the model/policy version.
	Version string `json:"version"`
	// PromptHash is a hex digest of the evaluation prompt (evidence binding).
	PromptHash string `json:"prompt_hash"`
	// InputDigest is a hex digest of the evaluated input (optional).
	InputDigest string `json:"input_digest,omitempty"`
	// OutputJSON is the raw model output (JSON document, base64 in JSON).
	OutputJSON []byte `json:"output_json,omitempty"`
	// Decision is the semantic decision: allow | deny | refer.
	Decision string `json:"decision"`
	// Confidence is the model-reported confidence (0..1), optional.
	Confidence float64 `json:"confidence,omitempty"`
	// Failed reports that the semantic evaluation itself errored (timeout,
	// transport failure).  A failed gate must never fail-open; it maps to a
	// deny/refer at the caller.
	Failed bool `json:"failed,omitempty"`
	// Err is the evaluation error text when Failed is set.
	Err string `json:"err,omitempty"`
}

// Summary is a redacted summary of the requested operation parameters.  It is
// derived from a digest form and never carries raw parameter values, reusing
// the audit mask concept (see mask.go).  The empty Summary means nothing was
// included.
type Summary string

// NewSummaryFromBody produces a masked digest summary of a request body.  An
// empty body yields an empty Summary.
func NewSummaryFromBody(body []byte) Summary {
	if len(body) == 0 {
		return Summary("")
	}
	sum := sha256.Sum256(body)
	return Summary(fmt.Sprintf("sha256:%s;bytes:%d", hex.EncodeToString(sum[:]), len(body)))
}

// RiskAssessment is the snapshot of a request that needs human supervision.  It
// is passed to ApprovalRequester.Request, OverrideRecorder.Record and attached
// to supervision events.  JSON is snake_case and defaults to omitempty so a
// minimal assessment stays small.
type RiskAssessment struct {
	// OperationID is the server-side per-request tracking id (correlation key).
	OperationID string `json:"operation_id"`
	// AgentID is the AIC agent identifier.
	AgentID string `json:"agent_id,omitempty"`
	// PrincipalUid is the verified principal UID.
	PrincipalUid string `json:"principal_uid,omitempty"`
	// DAHash is the sha256 hex hash of the signed DelegationAuthorization.
	DAHash string `json:"da_hash,omitempty"`
	// Capabilities are the admitted capability ids.
	Capabilities []string `json:"capabilities,omitempty"`
	// Operation is a short human-readable operation label (e.g. "POST /trade").
	Operation string `json:"operation"`
	// RequestedParams is the redacted summary of the request parameters.
	RequestedParams Summary `json:"requested_params,omitempty"`
	// Violations list deterministic-rule risks not yet covered semantically.
	Violations []string `json:"violations,omitempty"`
	// Semantic is the optional LLM semantic verdict for this request.
	Semantic *SemanticVerdict `json:"semantic,omitempty"`
	// PolicyVersion is the policy version effective at decision time.
	PolicyVersion uint64 `json:"policy_version,omitempty"`
}

// SupervisionResult is the outcome of a human (or system) supervision step.
type SupervisionResult struct {
	// Decision is approved | denied | pending.
	Decision string `json:"decision"`
	// Approver identifies the human that decided.
	Approver string `json:"approver,omitempty"`
	// Reason explains the decision.
	Reason string `json:"reason,omitempty"`
	// EvidenceRef references an external approval/review ticket.
	EvidenceRef string `json:"evidence_ref,omitempty"`
	// DecidedAt is when the decision was made.
	DecidedAt time.Time `json:"decided_at"`
}

// Supervision decisions referenced by SupervisionResult.Decision (aliases of
// the shared pki constants).
const (
	SupervisionDecisionApproved = pki.SupervisionDecisionApproved
	SupervisionDecisionDenied   = pki.SupervisionDecisionDenied
	SupervisionDecisionPending  = pki.SupervisionDecisionPending
)

// Approved reports whether the result is an explicit approval.
func (r *SupervisionResult) Approved() bool {
	return r != nil && r.Decision == SupervisionDecisionApproved
}

// ApprovalRequester is the mid-operation (runtime) human approval hook.  It is
// invoked when the admission decision path decides a request needs on-site
// human approval.  The default (nil) fails closed: the request is denied with
// approval_required.
type ApprovalRequester interface {
	// Request asks a human to approve (or deny) the operation described by
	// risk.  A nil result or a denied/pending decision denies the request.
	Request(ctx context.Context, risk RiskAssessment) (*SupervisionResult, error)
}

// OverrideRecorder is the break-glass / override recording point.  The SDK
// only provides the record point: whether break-glass is allowed is the
// operator's policy (SupervisionPolicy.AllowBreakGlass).  When policy allows
// break-glass and the recorder is nil, startup validation fails, so an unlogged
// break-glass is never available.
type OverrideRecorder interface {
	// Record persists a break-glass / override event.  It does not authorize
	// the operation by itself.
	Record(ctx context.Context, risk RiskAssessment, actor, reason string) (*SupervisionResult, error)
}

// EvidenceQuery selects the evidence to export for post-operation attribution.
type EvidenceQuery struct {
	// OperationID is the preferred correlation key (server-side request id).
	OperationID string
	// DaHash correlates by delegation authorization fingerprint.
	DaHash string
	// AgentID correlates by agent identifier.
	AgentID string
	// TimeRange bounds the export window.  Nil means no time bound.
	TimeRange *TimeRange
	// IncludeSupervision merges supervision events into the bundle (default
	// false keeps the bundle audit-only).
	IncludeSupervision bool
	// Record is the CLC decision record this bundle is about.  When set, it is
	// attached to the bundle's decision section as the authority, and the
	// summary fields (Decision, ReasonCodes) are derived from it rather than
	// from the audit text.  Callers obtain it from the evidence sink (see
	// LoadEvidenceRecord).
	Record *semantics.DecisionRecord
}

// EvidenceExporter produces an evidence bundle (evidence-bundle v0.1) for a
// query, merging the audit chain with supervision events.
type EvidenceExporter interface {
	// Export returns a self-contained, canonical-serializable evidence bundle.
	Export(ctx context.Context, q EvidenceQuery) (*EvidenceBundle, error)
}

// SupervisionPolicy gates the supervision features.  Pre-operation (DA)
// supervision is aic-agent side and intentionally absent here.
type SupervisionPolicy struct {
	// RequireRuntimeApproval mandates that requests flagged by RequireApproval
	// go through the ApprovalRequester.  When true and ApprovalRequester is
	// nil, startup validation fails.
	RequireRuntimeApproval bool
	// AllowBreakGlass enables break-glass overrides.  When true and
	// OverrideRecorder is nil, startup validation fails.
	AllowBreakGlass bool
	// RequireEvidenceExport mandates an EvidenceExporter.  When true and
	// EvidenceExporter is nil, startup validation fails.
	RequireEvidenceExport bool
}

// newOperationID generates a per-request tracking id (correlation key for
// supervision and audit linkage).
func newOperationID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("op-%d", time.Now().UnixNano())
	}
	return "op-" + hex.EncodeToString(b)
}

// needRuntimeApproval reports whether the request requires runtime human
// approval under the configured policy.  A nil RequireApproval means no
// runtime approval is needed.
func (c *Config) needRuntimeApproval(ac *AuthContext, r *http.Request) bool {
	return c.RequireApproval != nil && c.RequireApproval(ac, r)
}
