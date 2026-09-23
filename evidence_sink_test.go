// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 执行点留证据：每个来源的裁决被冻结成 CLC 记录、包成 DSSE 信封、交给 sink；
// 记录必须能被独立复算（这正是它能当证据的前提）。

package aicverifier

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

// failingSink always fails, to exercise the strict path.
type failingSink struct{}

func (failingSink) Emit(EvidenceContext, semantics.DecisionRecord, semantics.Envelope) (RecordRef, error) {
	return RecordRef{}, errors.New("sink unavailable")
}

func (failingSink) EmitAdmission(EvidenceContext, AdmissionRecord, semantics.Envelope) (RecordRef, error) {
	return RecordRef{}, errors.New("sink unavailable")
}

func TestEvidenceFileSinkWritesVerifiableRecord(t *testing.T) {
	cert := testAICCert(t, true) // carries a time:window constraint → allow_unresolved
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if res.Decision != DecisionDeny {
		// by default an unresolved obligation is fail-closed; the decisions are
		// still recorded, which is the point.
		t.Logf("admission decision = %v (%s)", res.Decision, res.Reason)
	}
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions to record")
	}

	dir := t.TempDir()
	cfg := &EvidenceConfig{
		Sink:       &FileSink{Dir: dir, RecorderID: "pep-1"},
		TTL:        time.Minute,
		Audience:   "https://gateway-a.example",
		RecorderID: "pep-1",
	}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted, Path: "/whoami", Method: "GET"}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("no record references were returned")
	}
	if refs[0].Path == "" || refs[0].Digest == "" || refs[0].Verdict == "" {
		t.Errorf("record reference is incomplete: %+v", refs[0])
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no evidence file was written")
	}

	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env semantics.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("%s is not an envelope: %v", e.Name(), err)
		}
		if err := env.Check(); err != nil {
			t.Fatalf("%s failed structural check: %v", e.Name(), err)
		}
		rec, err := env.DecisionRecord()
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := rec.Verify(); err != nil {
			t.Fatalf("%s does not reproduce: %v", e.Name(), err)
		}
		if rec.Inputs.Context == nil {
			t.Errorf("%s: freshness context was configured but the record carries none", e.Name())
		}
		if rec.Inputs.Sources == nil {
			t.Errorf("%s: the record carries no source chain", e.Name())
		}
		// The recorded verdict must match the decision the pipeline made for
		// this operation (the record recomputes it from the same grants).
		if rec.Verdict != res.OperationDecisions[0].Verdict {
			t.Errorf("%s: recorded verdict %q, pipeline said %q", e.Name(), rec.Verdict, res.OperationDecisions[0].Verdict)
		}
		if len(res.OperationDecisions[0].Unresolved) > 0 && len(rec.Constraints.Unresolved) == 0 {
			t.Errorf("%s: residual obligations were dropped from the record", e.Name())
		}
	}
}

func TestEvidenceDisabledEmitsNothing(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	dir := t.TempDir()
	if refs, err := EmitDecisionRecords(nil, EvidenceContext{}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions); err != nil || refs != nil {
		t.Fatalf("nil config must be a no-op: refs=%v err=%v", refs, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("unexpected files: %v", entries)
	}
}

// TestNoTTLStillBindsUniqueDigest: 决策记录在每个准入里都绑上唯一的 instance 值
// （newEvidenceNonce），TTL 缺省（0）也一样 —— 两次逐字相同的请求产生两个不同的
// input digest，而不是命中同一个通配 digest。这让 outcome 的 decisionDigest 精确指向
// 一次执行，杜绝零 TTL 下把两个相同请求的记录混为一条（P3-gap3）。
func TestNoTTLStillBindsUniqueDigest(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))

	emit := func() []RecordRef {
		dir := t.TempDir()
		cfg := &EvidenceConfig{Sink: &FileSink{Dir: dir}, RecorderID: "pep-ttl0"}
		refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
		if err != nil {
			t.Fatalf("EmitDecisionRecords: %v", err)
		}
		return refs
	}

	first := emit()
	second := emit()
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("no decision records emitted")
	}
	if first[0].Digest == second[0].Digest {
		t.Errorf("two identical admissions share digest %q: per-instance nonce is not bound", first[0].Digest)
	}

	// The nonce rides in the record's DecisionContext and reproduces on Verify:
	// the record stays self-consistent even with TTL zero.
	raw, err := os.ReadFile(first[0].Path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var env semantics.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	rec, err := env.DecisionRecord()
	if err != nil {
		t.Fatalf("decision record: %v", err)
	}
	if rec.Inputs.Context == nil || rec.Inputs.Context.Nonce == "" {
		t.Errorf("record carries no per-instance nonce context")
	}
	if err := rec.Verify(); err != nil {
		t.Errorf("record does not reproduce: %v", err)
	}
}

func TestEvidenceStrictModeSurfacesSinkFailure(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))

	a := &authenticator{cfg: &Config{
		Evidence: &EvidenceConfig{Sink: failingSink{}, Strict: true},
	}}
	_, err := a.emitEvidence(nil, cert, &PipelineResult{
		AIC:                res.AIC,
		OperationDecisions: res.OperationDecisions,
	}, EvidenceAdmitted)
	if err == nil {
		t.Fatal("a failing sink must surface an error for the caller to fail closed on")
	}
}
