// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P2-7 验收：VerifyEvidenceDirReportsGaps 覆盖三场景——好目录（三类载荷各一）、
// 含篡改文件的目录（签名被改但结构完好、未签名、垃圾文件）、空目录。另验
// EvidenceConfig.Gaps 缺口计数：发射失败既走 OnError 报警，又进计数。

package aicverifier

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	semantics "github.com/varwof/register/semantics"
)

func TestVerifyEvidenceDirReportsGaps(t *testing.T) {
	sign, verify := testSigner()

	t.Run("good", func(t *testing.T) {
		dir := t.TempDir()
		writeEnvFile(t, dir, "decision.json", signedDecisionEnvelope(t, sign))
		writeEnvFile(t, dir, "admission.json", signedAdmissionEnvelope(sign))
		writeEnvFile(t, dir, "outcome.json", signedOutcomeEnvelope(sign))

		rep, err := VerifyEvidenceDir(dir, verify)
		if err != nil {
			t.Fatalf("VerifyEvidenceDir: %v", err)
		}
		if rep.Total != 3 || rep.Decision != 1 || rep.Admission != 1 || rep.Outcome != 1 {
			t.Errorf("report = %+v, want 3 records (1 per kind)", rep)
		}
		if len(rep.Failures) != 0 {
			t.Errorf("failures = %+v, want none", rep.Failures)
		}
	})

	t.Run("tampered", func(t *testing.T) {
		dir := t.TempDir()
		writeEnvFile(t, dir, "decision.json", signedDecisionEnvelope(t, sign))

		// Structurally valid but signed with a broken signature: only the
		// verify callback can catch it.
		badSig := signedAdmissionEnvelope(sign)
		badSig.Signatures[0].Sig = append([]byte("tampered"), badSig.Signatures[0].Sig...)
		writeEnvFile(t, dir, "admission-tampered.json", badSig)

		// Unsigned record: fine without a verifier, a gap when one is required.
		unsigned := signedOutcomeEnvelope(sign)
		unsigned.Signatures = nil
		writeEnvFile(t, dir, "outcome-unsigned.json", unsigned)

		// Not an envelope at all.
		if err := os.WriteFile(filepath.Join(dir, "not-a-record.json"), []byte("{oops"), 0o600); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
		// Not a record extension: ignored by the scan.
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600); err != nil {
			t.Fatalf("write notes: %v", err)
		}

		rep, err := VerifyEvidenceDir(dir, verify)
		if err != nil {
			t.Fatalf("VerifyEvidenceDir: %v", err)
		}
		if rep.Total != 1 || rep.Decision != 1 {
			t.Errorf("report = %+v, want only the decision to verify", rep)
		}
		if len(rep.Failures) != 3 {
			t.Errorf("failures = %+v, want the tampered, unsigned and garbage files", rep.Failures)
		}
	})

	t.Run("empty", func(t *testing.T) {
		rep, err := VerifyEvidenceDir(t.TempDir(), nil)
		if err != nil {
			t.Fatalf("VerifyEvidenceDir: %v", err)
		}
		if rep.Total != 0 || len(rep.Failures) != 0 {
			t.Errorf("report = %+v, want an all-zero clean report", rep)
		}
	})
}

func TestVerifyEvidenceDirUnreadable(t *testing.T) {
	if _, err := VerifyEvidenceDir(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("an unreadable directory must return an error")
	}
}

func TestEvidenceGapCounterCountsFailedEmissions(t *testing.T) {
	var onErr []error
	cfg := &EvidenceConfig{
		Sink:    failSink{},
		OnError: func(_ EvidenceContext, err error) { onErr = append(onErr, err) },
		Gaps:    &GapCounter{},
	}
	ctx := EvidenceContext{RecorderID: "pep-7", Path: "/whoami", At: time.Now().UTC()}
	refs := recordRefusal(cfg, nil, ctx, &AuthError{Code: ErrChainInvalid, Status: 403, Message: "chain invalid"})
	if len(refs) != 0 {
		t.Errorf("recordRefusal must return nothing on failure, got %+v", refs)
	}
	if len(onErr) != 1 {
		t.Errorf("OnError calls = %d, want 1", len(onErr))
	}
	if cfg.Gaps.Count() != 1 {
		t.Errorf("gap count = %d, want 1", cfg.Gaps.Count())
	}
}

// failSink is a sink that always fails to store, for gap-counting tests.
type failSink struct{}

func (failSink) Emit(_ EvidenceContext, _ semantics.DecisionRecord, _ semantics.Envelope) (RecordRef, error) {
	return RecordRef{}, errSinkClosed
}

func (failSink) EmitAdmission(_ EvidenceContext, _ AdmissionRecord, _ semantics.Envelope) (RecordRef, error) {
	return RecordRef{}, errSinkClosed
}

var errSinkClosed = errors.New("sink closed")

// ---- envelope builders shared by the P2-7 tests ----------------------------

func writeEnvFile(t *testing.T, dir, name string, env semantics.Envelope) {
	t.Helper()
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func signedDecisionEnvelope(t *testing.T, sign func([]byte) ([]byte, error)) semantics.Envelope {
	t.Helper()
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}
	cfg := &EvidenceConfig{Sink: &FileSink{Dir: t.TempDir()}, Sign: sign, KeyID: "pep-7"}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	var env semantics.Envelope
	raw, err := os.ReadFile(refs[0].Path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return env
}

func signedAdmissionEnvelope(sign func([]byte) ([]byte, error)) semantics.Envelope {
	ctx := EvidenceContext{RecorderID: "pep-7", Path: "/whoami", At: time.Now().UTC()}
	rec := NewAdmissionRecord(ctx, &AuthError{Code: ErrChainInvalid, Status: 403, Message: "chain invalid"},
		[]AdmissionFact{{Type: "client-cert", Digest: dg("cert-der")}})
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		panic(err)
	}
	env, err = signEnvelope(env, &EvidenceConfig{Sign: sign, KeyID: "pep-7"})
	if err != nil {
		panic(err)
	}
	return env
}

func signedOutcomeEnvelope(sign func([]byte) ([]byte, error)) semantics.Envelope {
	rec := OutcomeRecord{Ver: OutcomeRecordVersion, Outcome: OutcomeObserved, At: time.Now().UTC(), StatusCode: 200, DecisionDigest: "ab"}
	env, err := NewOutcomeEnvelope(rec)
	if err != nil {
		panic(err)
	}
	env, err = signEnvelope(env, &EvidenceConfig{Sign: sign, KeyID: "pep-7"})
	if err != nil {
		panic(err)
	}
	return env
}
