// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 效果侧：只留接口 —— SDK 搬运效果记录并把效果**指回**它依据的裁决，
// 不给"执行/失败/不确定"下判定（那是执行边界/AEB 的词汇）。

package aicverifier

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/varwof/register/semantics"
)

type semanticsEnvelopeAlias = semantics.Envelope

func TestOutcomeRecordRoundTripAndLink(t *testing.T) {
	dir := t.TempDir()
	sink := &FileSink{Dir: dir, RecorderID: "gateway-1"}
	cfg := &EvidenceConfig{Sink: sink, RecorderID: "gateway-1"}

	// A decision digest to point back at.
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil || len(refs) == 0 {
		t.Fatalf("decision emission: %v", err)
	}
	decisionDigest := refs[0].Digest

	ref, err := ReportOutcome(sink, cfg, EvidenceContext{RecorderID: "gateway-1", Path: "/whoami"}, OutcomeRecord{
		Outcome:        OutcomeObserved,
		OperationID:    sqlQueryCap,
		DecisionDigest: decisionDigest,
		StatusCode:     200,
		Note:           "backend returned 200",
	})
	if err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	if ref.Path == "" || ref.Verdict != OutcomeObserved {
		t.Fatalf("ref = %+v", ref)
	}

	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env semanticsEnvelopeAlias
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	kind, err := CheckEvidenceEnvelope(env)
	if err != nil || kind != KindOutcome {
		t.Fatalf("CheckEvidenceEnvelope = %q/%v, want outcome", kind, err)
	}
	rec, err := ParseOutcomeEnvelope(env)
	if err != nil {
		t.Fatalf("ParseOutcomeEnvelope: %v", err)
	}
	if rec.DecisionDigest != decisionDigest {
		t.Errorf("outcome does not point back at the decision: %q vs %q", rec.DecisionDigest, decisionDigest)
	}
	if rec.StatusCode != 200 || rec.Outcome != OutcomeObserved {
		t.Errorf("record = %+v", rec)
	}
	if rec.RecorderID != "gateway-1" || rec.At.IsZero() {
		t.Errorf("recorder/timestamp not filled: %+v", rec)
	}

	// The SDK does not classify effects: whatever the deployment says is what
	// is carried.
	if _, err := ReportOutcome(sink, cfg, EvidenceContext{}, OutcomeRecord{Outcome: OutcomeIndeterminate}); err != nil {
		t.Fatalf("deployment-supplied outcome: %v", err)
	}

	// No sink, no claim.
	if _, err := ReportOutcome(nil, cfg, EvidenceContext{}, OutcomeRecord{Outcome: OutcomeExecuted}); err == nil {
		t.Error("reporting an outcome without a sink must fail")
	}
}
