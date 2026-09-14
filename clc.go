// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// CLC-v1 decision core on the service side.
//
// Admission today answers "does this credential carry a capability id that
// matches the route?" by glob matching, which cannot see parameters: a grant of
// max 10 rows and a request for 50 rows are the same declaration.  This file
// adds the CLC-v1 decision (register/semantics) so a concrete operation — id
// plus parameters, plus the constraints attached to the grant — gets a real
// verdict: allow, deny with a normative reason code, or allow_unresolved when a
// recognized constraint still needs to be confirmed.

package aicverifier

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/varwof/register/semantics"
)

// Operation is a concrete action to authorize: a capability id plus the
// parameters the caller wants to use.
type Operation = semantics.Operation

// OperationDecision records the CLC verdict for one requested operation, so
// admission results and the AuthContext can expose verdict / reason /
// unresolved (spec B3) instead of only the final allow/deny.
type OperationDecision struct {
	ID         string         `json:"id"`
	Params     map[string]any `json:"params,omitempty"`
	Verdict    string         `json:"verdict"` // semantics.VerdictAllow / VerdictDeny / VerdictAllowUR
	Reason     string         `json:"reason,omitempty"`
	Unresolved []string       `json:"unresolved,omitempty"`
	// Grants are the effective grant set the operation was decided over: the
	// AIC capability set on the delegated path, the principal's own grants on
	// the direct path, each already carrying the connection's authorization
	// constraints.  Surfacing them here means a downstream consumer can recompute
	// the verdict without parsing an evidence record file.
	Grants []semantics.Grant `json:"grants,omitempty"`
	// Released is true when an allow_unresolved operation was admitted because
	// the deployment's UnresolvedEvaluator confirmed the residual obligations.
	Released bool `json:"released,omitempty"`
}

// CLCRevision is the CLC language revision this SDK decides with.
const CLCRevision = semantics.CLCRevision

// ToGrant converts a declared capability (AIC or PrincipalAuthorization) into
// a CLC-v1 grant.  The identifier grammar and params shape are validated, so a
// declaration that cannot be decided is reported instead of silently ignored.
func ToGrant(c Capability) (semantics.Grant, error) {
	id := c.FullID()
	if err := semantics.ValidateCapabilityID(id); err != nil {
		return semantics.Grant{}, fmt.Errorf("capability %q: %w", id, err)
	}
	params, err := normalizeParams(c.Parameters)
	if err != nil {
		return semantics.Grant{}, fmt.Errorf("capability %q: %w", id, err)
	}
	if err := semantics.ValidateGrantParams(params); err != nil {
		return semantics.Grant{}, fmt.Errorf("capability %q: %w", id, err)
	}
	return semantics.Grant{ID: id, Params: params}, nil
}

// ToGrantSet converts a capability list into a CLC-v1 grant set.
func ToGrantSet(caps []Capability) ([]semantics.Grant, error) {
	grants := make([]semantics.Grant, 0, len(caps))
	for _, c := range caps {
		g, err := ToGrant(c)
		if err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, nil
}

// AuthorizeCapabilities decides a concrete operation against an explicit
// capability list.
func AuthorizeCapabilities(caps []Capability, opID string, params map[string]any) (semantics.Decision, error) {
	return AuthorizeCapabilitiesWithConstraints(caps, nil, opID, params)
}

// AuthorizeCapabilitiesWithConstraints decides an operation against a
// capability list whose grants also carry the connection's authorization
// constraints.
//
// Constraints are what make the three-valued verdict interesting: the CLC core
// evaluates a few of them itself (max_rows), recognises the rest (time:window,
// network:cidr) and reports them as residual obligations rather than silently
// dropping them — so a caller that reads only "allow" fails closed.
func AuthorizeCapabilitiesWithConstraints(caps, constraints []Capability, opID string, params map[string]any) (semantics.Decision, error) {
	grants, err := ToGrantSet(caps)
	if err != nil {
		return semantics.Decision{}, err
	}
	if cs := ConstraintStrings(constraints); len(cs) > 0 {
		for i := range grants {
			grants[i].Constraints = append(grants[i].Constraints, cs...)
		}
	}
	return AuthorizeGrants(grants, opID, params)
}

// ConstraintStrings renders authorization constraints in CLC form:
// <scheme>:<type>[:<params-json>], e.g.
// varwof/constraint-v1:network:cidr:["192.0.2.0/24"].
func ConstraintStrings(constraints []Capability) []string {
	out := make([]string, 0, len(constraints))
	for _, c := range constraints {
		// The AIC extension carries constraints under the bare scheme
		// "constraint" / "constraint-v1"; the CLC core names that namespace
		// varwof/constraint-v1.  Normalise so the language recognises them
		// instead of reporting an unknown constraint.
		scheme := c.SchemeId
		switch scheme {
		case "constraint", "constraint-v1":
			scheme = "varwof/constraint-v1"
		}
		s := scheme
		if c.CapabilityId != "" {
			s += ":" + c.CapabilityId
		}
		if len(c.Parameters) > 0 {
			s += ":" + string(c.Parameters)
		}
		out = append(out, s)
	}
	return out
}

// AuthorizeGrants decides opID/params against an explicit CLC-v1 grant set.
func AuthorizeGrants(grants []semantics.Grant, opID string, params map[string]any) (semantics.Decision, error) {
	normalized, err := normalizeParams(params)
	if err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	// §9.3 pre-check: an absent/empty effective grant set short-circuits to
	// capability_not_authorized before the operation's layer-1 validation, so
	// an empty grant with an empty operation is not reported as
	// missing_capability_id (CLC-1.3 AuthorizeSet).
	if grantsAbsent(grants) {
		return semantics.AuthorizeSet(grants, semantics.Operation{ID: opID, Params: normalized}), nil
	}
	if err := semantics.ValidateCapabilityID(opID); err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	if err := semantics.ValidateOperationParams(normalized); err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	return semantics.AuthorizeSet(grants, semantics.Operation{ID: opID, Params: normalized}), nil
}

// grantsAbsent reports whether every grant is the zero value (no capability
// id), which CLC reads as "no effective grant" regardless of the operation.
func grantsAbsent(grants []semantics.Grant) bool {
	for _, g := range grants {
		if g.ID != "" {
			return false
		}
	}
	return true
}

// AuthorizeOperation decides a concrete operation for an admitted connection.
//
// The effective authority is the AIC capability set intersected with the
// PrincipalAuthorization grants when a PA is present (the P∩C model): the
// operation has to be authorized by both, so each set is decided and the
// results are combined — deny wins, and residual obligations union.
func AuthorizeOperation(aic *AIC, pa *PrincipalAuthorization, opID string, params map[string]any) (semantics.Decision, error) {
	if aic == nil && pa == nil {
		return semantics.Decision{}, fmt.Errorf("no capability source: AIC and PrincipalAuthorization are both absent")
	}
	if aic == nil {
		// Direct authorization (human certificate, no AIC): the principal's own
		// constraints bind here exactly as they do on the delegated path.
		return AuthorizeCapabilitiesWithConstraints(pa.Grants, pa.AuthorizationConstraints, opID, params)
	}
	aisDec, err := AuthorizeCapabilitiesWithConstraints(aic.Capabilities, aic.AuthorizationConstraints, opID, params)
	if err != nil {
		return semantics.Decision{}, err
	}
	if pa == nil {
		return aisDec, nil
	}
	// The principal's constraints bind the human/direct-authorization path the
	// same way the AIC's bind the delegated path: they are declarations the
	// language carries, not a per-connection check to be bypassed.  A constraint
	// the consumer cannot discharge fails closed (§8.4), including the ones the
	// connection-level registry has no evaluator for (e.g. max_rows).
	paDec, err := AuthorizeCapabilitiesWithConstraints(pa.Grants, pa.AuthorizationConstraints, opID, params)
	if err != nil {
		return semantics.Decision{}, err
	}
	return combineDecisions(aisDec, paDec), nil
}

// decisionGrants returns the effective grant set an operation was decided over,
// in the same source priority as AuthorizeOperation: the AIC capability set on
// the delegated path, the principal's grants on the direct path, each already
// carrying the connection's authorization constraints.
func decisionGrants(aic *AIC, pa *PrincipalAuthorization) []semantics.Grant {
	recs := evidenceRecorders(aic, pa)
	if grants, ok := recs["aic"]; ok {
		return grants
	}
	return recs["principal-authorization"]
}

// combineDecisions intersects two decisions — the AIC capability set and the
// principal's authorization — under the language's default combining algorithm:
// deny wins, residual obligations union, allow only when both sides allowed
// outright.  The rule itself lives in register/semantics (P7: define once,
// consume everywhere) so this SDK cannot drift from the specified algorithm.
func combineDecisions(a, b semantics.Decision) semantics.Decision {
	combined, err := semantics.Combine(semantics.DefaultCombiningAlgorithm, a, b)
	if err != nil {
		// A pair that cannot be combined cannot authorize; report the stable
		// reason instead of guessing at a verdict.
		return semantics.Decision{Verdict: semantics.VerdictDeny, Reason: err.Error()}
	}
	return combined
}

// normalizeParams turns capability parameters (raw JSON bytes) or a caller's Go
// map into CLC params.  Absent, empty and "{}" all become nil, which CLC reads
// as "no parameter constraint" (§9.3: {} ≡ absent); everything else is
// parsed as JSON so CLC's type-strict comparison only ever sees JSON values —
// a caller passing a natural Go int must not be denied against the grant's
// JSON-decoded float64.
func normalizeParams(params any) (map[string]any, error) {
	var raw []byte
	switch v := params.(type) {
	case nil:
		return nil, nil
	case []byte:
		if len(v) == 0 {
			return nil, nil
		}
		raw = v
	case json.RawMessage:
		if len(v) == 0 {
			return nil, nil
		}
		raw = []byte(v)
	case map[string]any:
		if len(v) == 0 {
			return nil, nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("params must be a JSON object: %w", err)
		}
		raw = b
	default:
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("params must be a JSON object: %w", err)
		}
		raw = b
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" || trimmed == "null" {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("params must be a JSON object: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
