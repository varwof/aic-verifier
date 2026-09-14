// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P3-9：AuthContext 的每个 OperationDecision 带上裁决所用的 grant 集，决策
// 路径的 EvidenceContext.Facts 与拒绝路径共用同一组业务事实——下游复算不再
// 需要去读 evidence 记录文件。

package aicverifier

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

// ---- P3-9 test cases -------------------------------------------------------

type grantsHandlerResult struct {
	ID      string          `json:"id"`
	Verdict string          `json:"verdict"`
	Grants  []semanticsItem `json:"grants,omitempty"`
}

type semanticsItem struct {
	ID     string         `json:"id"`
	Params map[string]any `json:"params,omitempty"`
}

func TestAuthContextCarriesOperationGrants(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-p39",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	cfg := e2eConfig(ca.writePEM(t), t.TempDir(), []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}, false)
	handler, err := cfg.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := FromContext(r.Context())
		if ac == nil {
			http.Error(w, "no auth context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ac.OperationDecisions)
	}))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, body := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var decisions []grantsHandlerResult
	if err := json.Unmarshal([]byte(body), &decisions); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if len(decisions) != 1 {
		t.Fatalf("decisions = %d, want 1", len(decisions))
	}
	first := decisions[0]
	if first.ID != e2eSelectCap {
		t.Errorf("decision id = %q, want %q", first.ID, e2eSelectCap)
	}
	if first.Verdict != string(semantics.VerdictAllow) {
		t.Errorf("decision verdict = %q, want %q", first.Verdict, semantics.VerdictAllow)
	}

	// The grants the connection was decided over travel with it: the AIC
	// capability and its parameters, ready for a downstream recompute.
	got := map[string]grantParams{}
	for _, g := range first.Grants {
		got[g.ID] = g.Params
	}
	params, ok := got["std/database-v1:query:SELECT"]
	if !ok {
		t.Fatalf("grants = %+v, want the AIC query:SELECT grant", first.Grants)
	}
	if limit, ok := params["limit"].(float64); !ok || limit != float64(10) {
		t.Errorf("grant params = %v, want limit 10 (the AIC's declared grant)", params)
	}
}

// captureSink lives in evidence_context_test.go; the fact assertions here reuse
// the EvidenceContexts it records.

func TestDecisionPathCarriesBusinessFacts(t *testing.T) {
	ca := newHTTPTestCA(t)
	allowClient := ca.issueAIC(t, "agent-p39-facts",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}})

	capture := &captureSink{}
	ops := []Operation{{ID: e2eSelectCap, Params: map[string]any{"limit": 5}}}
	cfg := e2eConfig(ca.writePEM(t), "", ops, false)
	cfg.Evidence = &EvidenceConfig{Sink: capture, RecorderID: "pep-p39"}
	handler, err := cfg.Handler(okHandler(t))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSEvidenceTest(t, ca, handler)

	resp, body := doMTLSEvidenceTest(t, url, allowClient)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}

	// The decision path emits records about THIS connection; the facts it
	// carried must show up beside the records, not only in refusal records.
	factTypes := map[string]bool{}
	count := 0
	for _, ctx := range capture.got {
		for _, f := range ctx.Facts {
			factTypes[f.Type] = true
			count++
		}
	}
	for _, want := range []string{"client-cert", "requested-operations"} {
		if !factTypes[want] {
			t.Errorf("decision-path facts = %v, want one of type %q", factTypes, want)
		}
	}
	if count < 2 {
		t.Errorf("captured %d facts, want client-cert + requested-operations", count)
	}
}

type grantParams = map[string]any
