// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

package smoke

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	aicverifier "github.com/varwof/aic-verifier"
	"github.com/varwof/register/semantics"
)

// outcome is one corpus vector's result.
type outcome struct {
	ID          string
	Kind        string
	Via         string
	WantVerdict string
	GotVerdict  string
	WantReason  string
	GotReason   string
	Note        string
	Pass        bool
}

// TestCLCCorpus drives every CLC-v1 vector through the closest aic-verifier
// entry point and asserts the verdict (and reason, where available) matches the
// normative expectation.  Kinds the SDK does not own (entail / intersect /
// subset) run the CLC core function directly and are labelled `clc-core`, so
// the report distinguishes SDK coverage from language baseline.
func TestCLCCorpus(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) == 0 {
		t.Fatal("corpus contained no vectors")
	}

	results := make([]outcome, 0, len(vectors))
	counts := map[string]int{}
	for _, v := range vectors {
		o := runVector(v)
		results = append(results, o)
		counts[o.Kind]++
		if !o.Pass {
			t.Errorf("%s (%s, via %s): want verdict=%q reason=%q, got verdict=%q reason=%q %s",
				o.ID, o.Kind, o.Via, o.WantVerdict, o.WantReason, o.GotVerdict, o.GotReason, o.Note)
		}
	}

	pass := 0
	for _, o := range results {
		if o.Pass {
			pass++
		}
	}
	for _, o := range results {
		t.Logf("%-14s %-9s %-34s %-18s %-22s %s", o.ID, o.Kind, o.Via, o.GotVerdict, o.GotReason, passMark(o.Pass))
	}
	t.Logf("CLC corpus: %d vectors | pass=%d fail=%d | kinds=%v", len(results), pass, len(results)-pass, counts)
}

func passMark(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

// runVector dispatches one vector to its entry point.
func runVector(v vector) outcome {
	o := outcome{ID: v.ID, Kind: v.Kind, WantVerdict: v.Expect.Verdict, WantReason: canonicalReason(v.Expect.Reason)}

	switch v.Kind {
	case "syntax":
		o.Via = "aic-verifier(ToGrant)"
		if v.Request == nil {
			o.GotVerdict = "error"
			break
		}
		_, err := aicverifier.ToGrant(capFromFullID(v.Request.ID))
		if err != nil {
			o.GotVerdict = "invalid"
			o.GotReason = rootReason(err)
		} else {
			o.GotVerdict = "valid"
		}
		// Parity: aic-verifier and the CLC core must agree on validity.
		coreErr := semantics.ValidateCapabilityID(v.Request.ID)
		if (err == nil) != (coreErr == nil) {
			o.Note = "ToGrant/ValidateCapabilityID validity divergence"
		}
		if coreErr != nil {
			o.GotReason = canonicalReason(coreErr.Error())
		}

	case "decide":
		o.Via = "aic-verifier(AuthorizeGrants)"
		if reason, short := precheck(v); short {
			o.Via = "clc-core(precheck)"
			o.GotVerdict, o.GotReason = "deny", canonicalReason(reason)
			break
		}
		opID, params := operationOf(v)
		grants := []semantics.Grant{}
		if v.Grant != nil {
			grants = append(grants, *v.Grant)
		}
		if v.Multi {
			grants = append(grants, v.Others...)
		} else if len(v.Others) > 0 {
			// Combined vectors are intersected before evaluation; the
			// intersection is CLC-core, the decision is the SDK's.
			o.Via = "clc-core+verifier"
			merged, err := semantics.Intersect(append(grants, v.Others...)...)
			if err != nil {
				o.GotVerdict, o.GotReason = "deny", canonicalReason(err.Error())
				break
			}
			grants = []semantics.Grant{merged}
		}
		dec, err := aicverifier.AuthorizeGrants(grants, opID, params)
		if err != nil {
			o.GotVerdict, o.GotReason = "deny", rootReason(err)
			break
		}
		o.GotVerdict, o.GotReason = dec.Verdict, canonicalReason(dec.Reason)
		if v.Expect.Unresolved != nil && !sameSet(v.Expect.Unresolved, dec.Unresolved) {
			o.Note = fmt.Sprintf("unresolved want=%v got=%v", v.Expect.Unresolved, dec.Unresolved)
		}

	case "entail":
		o.Via = "clc-core(Entails)"
		if reason, short := precheck(v); short {
			o.GotVerdict, o.GotReason = "deny", canonicalReason(reason)
			break
		}
		if v.Grant == nil || v.Request == nil {
			o.GotVerdict = "error"
			break
		}
		res := semantics.Entails(*v.Grant, *v.Request)
		if res.Entails {
			o.GotVerdict = "allow"
		} else {
			o.GotVerdict, o.GotReason = "deny", canonicalReason(res.Reason)
		}

	case "intersect":
		o.Via = "clc-core(Intersect)"
		grants := []semantics.Grant{}
		if v.Grant != nil {
			grants = append(grants, *v.Grant)
		}
		grants = append(grants, v.Others...)
		merged, err := semantics.Intersect(grants...)
		if err != nil {
			o.GotVerdict, o.GotReason = "deny", canonicalReason(err.Error())
			break
		}
		o.GotVerdict = "allow"
		if v.Expect.ResultParams != nil && !jsonEqual(v.Expect.ResultParams, merged.Params) {
			o.Note = fmt.Sprintf("result_params want=%v got=%v", v.Expect.ResultParams, merged.Params)
		}
		if v.Expect.ResultConstraints != nil && !sameSet(v.Expect.ResultConstraints, merged.Constraints) {
			o.Note = fmt.Sprintf("result_constraints want=%v got=%v", v.Expect.ResultConstraints, merged.Constraints)
		}

	case "subset":
		o.Via = "clc-core(SubsetConstraints)"
		ok, err := semantics.SubsetConstraints(v.Principal, v.Requested)
		if err != nil {
			o.GotVerdict, o.GotReason = "error", canonicalReason(err.Error())
		} else if ok {
			o.GotVerdict = "allow"
		} else {
			o.GotVerdict = "deny"
		}

	default:
		o.Via = "n/a"
		o.GotVerdict = "skip"
	}

	o.Pass = o.GotVerdict == o.WantVerdict && o.GotReason == o.WantReason && o.Note == ""
	return o
}

// precheck reproduces the vectors-run input-boundary pre-checks (language
// revision §12.1, raw param normalisation §6.2) that resolve before any §9.3
// layer.  Returns (reason, true) when the vector short-circuits to deny.
func precheck(v vector) (string, bool) {
	if v.Kind != "decide" && v.Kind != "entail" {
		return "", false
	}
	if v.CLCRevision != "" && !semantics.RevisionCompatible(v.CLCRevision) {
		return semantics.ErrUnsupportedLangRev.Error(), true
	}
	if v.RawParams != "" {
		if err := semantics.ValidateRawParams(v.RawParams); err != nil {
			return err.Error(), true
		}
	}
	return "", false
}

func operationOf(v vector) (string, map[string]any) {
	if v.Request == nil {
		return "", nil
	}
	return v.Request.ID, v.Request.Params
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

func jsonEqual(want map[string]any, got map[string]any) bool {
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	return string(wb) == string(gb)
}
