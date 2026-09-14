// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 证据接口的上下文与回执：sink 必须知道"哪次请求、谁、准入还是拒绝"，
// 并把记录落在哪里回报给调用方。

package aicverifier

import (
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

// captureSink records what it was handed.
type captureSink struct {
	got []EvidenceContext
}

func (c *captureSink) Emit(ctx EvidenceContext, rec semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error) {
	c.got = append(c.got, ctx)
	return RecordRef{Digest: "digest-" + rec.Verdict, Verdict: rec.Verdict, Path: "/somewhere"}, nil
}

func (c *captureSink) EmitAdmission(ctx EvidenceContext, rec AdmissionRecord, env semantics.Envelope) (RecordRef, error) {
	c.got = append(c.got, ctx)
	return RecordRef{Digest: "admission-" + rec.Stage, Verdict: rec.Outcome, Path: "/somewhere"}, nil
}

func TestEvidenceSinkReceivesContextAndReturnsRefs(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}

	sink := &captureSink{}
	cfg := &EvidenceConfig{Sink: sink, RecorderID: "pep-7", TTL: time.Minute}
	refs, err := EmitDecisionRecords(cfg,
		EvidenceContext{RecorderID: "pep-7", Path: "/whoami", Method: "GET", Principal: "people-user01", AgentID: "agent-1", Outcome: EvidenceAdmitted},
		cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(sink.got) == 0 || len(refs) == 0 {
		t.Fatal("sink was not called / no refs returned")
	}
	ctx := sink.got[0]
	if ctx.Outcome != EvidenceAdmitted {
		t.Errorf("outcome = %q, want admitted", ctx.Outcome)
	}
	if ctx.Path != "/whoami" || ctx.Method != "GET" {
		t.Errorf("request context lost: %+v", ctx)
	}
	if ctx.Principal != "people-user01" || ctx.AgentID != "agent-1" {
		t.Errorf("identity context lost: %+v", ctx)
	}
	if ctx.OperationID != sqlQueryCap {
		t.Errorf("operation id = %q, want %q", ctx.OperationID, sqlQueryCap)
	}
	if ctx.At.IsZero() {
		t.Error("timestamp missing")
	}
	if refs[0].Path != "/somewhere" || refs[0].Verdict == "" || refs[0].Digest == "" {
		t.Errorf("refs = %+v", refs)
	}
}

// 默认（不给 Outcome）时按裁决推断：deny 记成拒绝。
func TestEvidenceOutcomeInferredFromVerdict(t *testing.T) {
	sink := &captureSink{}
	cfg := &EvidenceConfig{Sink: sink}
	ops := []OperationDecision{{ID: sqlQueryCap, Verdict: semantics.VerdictDeny, Reason: "capability_not_authorized"}}
	if _, err := EmitDecisionRecords(cfg, EvidenceContext{Path: "/x"}, nil, nil, &PrincipalAuthorization{Grants: []Capability{capWith("std/database-v1", "query:SELECT", "")}}, nil, ops); err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(sink.got) != 1 || sink.got[0].Outcome != EvidenceRefused {
		t.Fatalf("outcome = %+v, want refused", sink.got)
	}
}

// OnError 让"证据缺口"可见（而不是只丢在日志里）。
func TestEvidenceOnErrorReportsGap(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))

	var seen error
	a := &authenticator{cfg: &Config{Evidence: &EvidenceConfig{
		Sink:    failingSink{},
		OnError: func(_ EvidenceContext, err error) { seen = err },
	}}}
	if _, err := a.emitEvidence(nil, cert, &PipelineResult{AIC: res.AIC, OperationDecisions: res.OperationDecisions}, EvidenceAdmitted); err == nil {
		t.Fatal("expected the emission error to surface")
	}
	if seen == nil {
		t.Error("OnError was not called: the gap would be invisible")
	}
}
