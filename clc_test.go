// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

func capWith(scheme, id string, params string) Capability {
	c := Capability{SchemeId: scheme, CapabilityId: id}
	if params != "" {
		c.Parameters = []byte(params)
	}
	return c
}

func TestToGrantUsesFullID(t *testing.T) {
	g, err := ToGrant(capWith("std/database-v1", "query:SELECT", `{"limit":10}`))
	if err != nil {
		t.Fatalf("ToGrant: %v", err)
	}
	if g.ID != "std/database-v1:query:SELECT" {
		t.Errorf("grant id = %q, want the full scheme:capability form", g.ID)
	}
	if g.Params["limit"] != float64(10) {
		t.Errorf("params = %#v, want limit=10 as a JSON number", g.Params)
	}
}

func TestToGrantEmptyParametersMeansUnconstrained(t *testing.T) {
	for _, raw := range []string{"", "{}", "null"} {
		g, err := ToGrant(capWith("std/database-v1", "query:SELECT", raw))
		if err != nil {
			t.Fatalf("params %q: %v", raw, err)
		}
		if g.Params != nil {
			t.Errorf("params %q: got %v, want nil (§9.3: {} ≡ absent)", raw, g.Params)
		}
	}
}

// Admission used to compare only capability ids, so a 50-row request passed a
// 10-row grant.  This is the case CLC exists to decide.
func TestAuthorizeCapabilitiesNarrowsParams(t *testing.T) {
	caps := []Capability{capWith("std/database-v1", "query:SELECT", `{"limit":10}`)}

	dec, err := AuthorizeCapabilities(caps, "std/database-v1:query:SELECT", map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("in-bounds: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllow {
		t.Errorf("in-bounds verdict = %q (%s), want allow", dec.Verdict, dec.Reason)
	}

	dec, err = AuthorizeCapabilities(caps, "std/database-v1:query:SELECT", map[string]any{"limit": 50})
	if err != nil {
		t.Fatalf("out-of-bounds: %v", err)
	}
	if dec.Verdict != semantics.VerdictDeny {
		t.Fatalf("out-of-bounds verdict = %q, want deny", dec.Verdict)
	}
	if dec.Reason != "params_exceed_grant" {
		t.Errorf("out-of-bounds reason = %q, want params_exceed_grant", dec.Reason)
	}
}

// The effective authority is AIC ∩ PrincipalAuthorization: an operation has to
// be authorized by both sides.
func TestAuthorizeOperationIntersectsPrincipalAuthorization(t *testing.T) {
	aic := &AIC{Capabilities: []Capability{
		capWith("std/database-v1", "query:SELECT", `{"limit":10}`),
		capWith("std/database-v1", "cert:issue", ""),
	}}
	pa := &PrincipalAuthorization{Grants: []Capability{
		capWith("std/database-v1", "query:SELECT", `{"limit":10}`),
	}}

	dec, err := AuthorizeOperation(aic, pa, "std/database-v1:query:SELECT", map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("covered operation: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllow {
		t.Errorf("covered verdict = %q (%s), want allow", dec.Verdict, dec.Reason)
	}

	// cert:issue is in the AIC but not in the principal's authorization, so the
	// intersection must not admit it.
	dec, err = AuthorizeOperation(aic, pa, "std/database-v1:cert:issue", nil)
	if err != nil {
		t.Fatalf("uncovered operation: %v", err)
	}
	if dec.Verdict != semantics.VerdictDeny {
		t.Errorf("uncovered verdict = %q, want deny", dec.Verdict)
	}

	// Without a PA the AIC alone decides.
	dec, err = AuthorizeOperation(aic, nil, "std/database-v1:cert:issue", nil)
	if err != nil {
		t.Fatalf("AIC-only operation: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllow {
		t.Errorf("AIC-only verdict = %q (%s), want allow", dec.Verdict, dec.Reason)
	}
}

func TestAuthorizeGrantsCarriesResidualObligations(t *testing.T) {
	const window = `varwof/constraint-v1:time:window:[{"start":"00:00","end":"06:00"}]`
	grants := []semantics.Grant{{
		ID:          "std/database-v1:query:SELECT",
		Constraints: []string{window},
	}}

	dec, err := AuthorizeGrants(grants, "std/database-v1:query:SELECT", nil)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllowUR {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, semantics.VerdictAllowUR)
	}
	if len(dec.Unresolved) != 1 || dec.Unresolved[0] != window {
		t.Errorf("unresolved = %v, want [%s]", dec.Unresolved, window)
	}
}

// CLC-v1 §3 wants <vendor>/<product>-v<major>.  An identifier without the
// version suffix is reported rather than shimmed into looking conformant.
func TestUnversionedIdentifierIsReported(t *testing.T) {
	_, err := ToGrant(capWith("acme/tools", "cert:issue", ""))
	if err == nil {
		t.Fatal("non-conformant identifier must be reported")
	}
	if !strings.Contains(err.Error(), "invalid_capability_id") {
		t.Errorf("error %q should carry the normative reason code", err)
	}
}

func TestAuthorizeOperationRequiresACapabilitySource(t *testing.T) {
	if _, err := AuthorizeOperation(nil, nil, "std/database-v1:query:SELECT", nil); err == nil {
		t.Fatal("deciding without AIC or PrincipalAuthorization must fail")
	}
}
