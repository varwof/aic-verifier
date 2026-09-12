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
	grants, err := ToGrantSet(caps)
	if err != nil {
		return semantics.Decision{}, err
	}
	return AuthorizeGrants(grants, opID, params)
}

// AuthorizeGrants decides opID/params against an explicit CLC-v1 grant set.
func AuthorizeGrants(grants []semantics.Grant, opID string, params map[string]any) (semantics.Decision, error) {
	normalized, err := normalizeParams(params)
	if err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	if err := semantics.ValidateCapabilityID(opID); err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	if err := semantics.ValidateOperationParams(normalized); err != nil {
		return semantics.Decision{}, fmt.Errorf("operation %q: %w", opID, err)
	}
	return semantics.AuthorizeSet(grants, semantics.Operation{ID: opID, Params: normalized}), nil
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
		return AuthorizeCapabilities(pa.Grants, opID, params)
	}
	aisDec, err := AuthorizeCapabilities(aic.Capabilities, opID, params)
	if err != nil {
		return semantics.Decision{}, err
	}
	if pa == nil {
		return aisDec, nil
	}
	paDec, err := AuthorizeCapabilities(pa.Grants, opID, params)
	if err != nil {
		return semantics.Decision{}, err
	}
	return combineDecisions(aisDec, paDec), nil
}

// combineDecisions intersects two decisions: deny wins, residual obligations
// union, and allow only when both sides allowed outright.
func combineDecisions(a, b semantics.Decision) semantics.Decision {
	if a.Verdict == semantics.VerdictDeny {
		return a
	}
	if b.Verdict == semantics.VerdictDeny {
		return b
	}
	if a.Verdict == semantics.VerdictAllowUR || b.Verdict == semantics.VerdictAllowUR {
		unresolved := append(append([]string{}, a.Unresolved...), b.Unresolved...)
		return semantics.Decision{
			Verdict:    semantics.VerdictAllowUR,
			Unresolved: dedupeSorted(unresolved),
		}
	}
	return semantics.Decision{Verdict: semantics.VerdictAllow}
}

func dedupeSorted(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
