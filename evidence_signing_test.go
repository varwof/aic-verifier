// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P0-1：记录签名。三类载荷在构造完信封后统一 env.Sign(cfg.KeyID, cfg.Sign)；
// 验证侧 VerifyEvidenceEnvelope 结构校验为底线，传了 verify 回调则要求至少一条
// 签名通过。签名失败走 OnError，Strict 时拒绝请求。

package aicverifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

// testSigner returns a sign/verify pair over a fixed prefix + PAE digest, as a
// stand-in for a real key without bringing crypto machinery into the test.
func testSigner() (func([]byte) ([]byte, error), func(keyID string, pae, sig []byte) error) {
	sign := func(pae []byte) ([]byte, error) {
		sum := sha256.Sum256(pae)
		return append([]byte("sig:"), sum[:]...), nil
	}
	verify := func(_ string, pae, sig []byte) error {
		sum := sha256.Sum256(pae)
		if !bytes.Equal(sig, append([]byte("sig:"), sum[:]...)) {
			return errors.New("signature mismatch")
		}
		return nil
	}
	return sign, verify
}

func TestEvidenceSignDecisionRoundTrip(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}
	sign, verify := testSigner()
	dir := t.TempDir()
	cfg := &EvidenceConfig{
		Sink:  &FileSink{Dir: dir},
		Sign:  sign,
		KeyID: "pep-7",
	}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("no record references returned")
	}
	raw, err := os.ReadFile(refs[0].Path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var env semantics.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("not an envelope: %v", err)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != "pep-7" {
		t.Fatalf("signatures = %+v, want one entry with keyid pep-7", env.Signatures)
	}
	kind, err := VerifyEvidenceEnvelope(env, verify)
	if err != nil || kind != KindDecision {
		t.Fatalf("VerifyEvidenceEnvelope = %q/%v, want decision", kind, err)
	}

	// Tampering the payload breaks the PAE → the signature no longer verifies.
	flipped := env
	flipped.Payload = append(append([]byte{}, flipped.Payload...), 0x00)
	if _, err := VerifyEvidenceEnvelope(flipped, verify); err == nil {
		t.Fatal("a tampered payload must fail signature verification")
	}

	// Unsigned envelopes fail when a verifier is required.
	unsigned, err := semantics.NewEnvelope(firstDecision(t, refs[0]))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if _, err := VerifyEvidenceEnvelope(unsigned, verify); err == nil {
		t.Fatal("an unsigned envelope must fail when verify is required")
	}
}

func firstDecision(t *testing.T, ref RecordRef) semantics.DecisionRecord {
	t.Helper()
	rec, err := LoadEvidenceRecord(ref.Path)
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	return *rec
}

func TestEvidenceSignAdmissionRoundTrip(t *testing.T) {
	sign, verify := testSigner()
	ctx := EvidenceContext{RecorderID: "pep-7", Path: "/whoami", At: time.Now().UTC()}
	rec := NewAdmissionRecord(ctx, &AuthError{Code: ErrChainInvalid, Status: 403, Message: "chain invalid"},
		[]AdmissionFact{{Type: "client-cert", Digest: dg("cert-der")}})
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	cfg := &EvidenceConfig{Sign: sign, KeyID: "pep-7"}
	env, err = signEnvelope(env, cfg)
	if err != nil {
		t.Fatalf("signEnvelope: %v", err)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("signatures = %+v, want 1", env.Signatures)
	}
	kind, err := VerifyEvidenceEnvelope(env, verify)
	if err != nil || kind != KindAdmission {
		t.Fatalf("VerifyEvidenceEnvelope = %q/%v, want admission", kind, err)
	}

	tampered := env
	tampered.Payload = append(append([]byte{}, tampered.Payload...), 0x01)
	if _, err := VerifyEvidenceEnvelope(tampered, verify); err == nil {
		t.Fatal("a tampered admission payload must fail signature verification")
	}
}

func TestEvidenceSignOutcomeRoundTrip(t *testing.T) {
	sign, verify := testSigner()
	sink := &outcomeCaptureSink{}
	cfg := &EvidenceConfig{Sign: sign, KeyID: "pep-7"}
	_, err := ReportOutcome(sink, cfg, EvidenceContext{RecorderID: "pep-7"}, OutcomeRecord{
		Outcome:    OutcomeObserved,
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	if len(sink.env.Signatures) != 1 || sink.env.Signatures[0].KeyID != "pep-7" {
		t.Fatalf("signatures = %+v, want one entry with keyid pep-7", sink.env.Signatures)
	}
	kind, err := VerifyEvidenceEnvelope(sink.env, verify)
	if err != nil || kind != KindOutcome {
		t.Fatalf("VerifyEvidenceEnvelope = %q/%v, want outcome", kind, err)
	}
}

func TestSignEnvelopeNilConfigIsNoop(t *testing.T) {
	rec := NewAdmissionRecord(EvidenceContext{At: time.Now().UTC()},
		&AuthError{Code: ErrDenied, Status: 403, Message: "denied"}, nil)
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	out, err := signEnvelope(env, nil)
	if err != nil || len(out.Signatures) != 0 {
		t.Fatalf("nil config must leave the envelope unsigned: sigs=%d err=%v", len(out.Signatures), err)
	}
}

func TestVerifyEvidenceEnvelopeStructuralOnlyWhenVerifyNil(t *testing.T) {
	rec := NewAdmissionRecord(EvidenceContext{At: time.Now().UTC()},
		&AuthError{Code: ErrDenied, Status: 403, Message: "denied"}, nil)
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	kind, err := VerifyEvidenceEnvelope(env, nil)
	if err != nil || kind != KindAdmission {
		t.Fatalf("nil verify must keep only the structural check, got %q/%v", kind, err)
	}
}

func TestEvidenceSignFailureTriggersOnError(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	dir := t.TempDir()
	var onError error
	a := &authenticator{cfg: &Config{
		Evidence: &EvidenceConfig{
			Sink:    &FileSink{Dir: dir},
			Sign:    func([]byte) ([]byte, error) { return nil, errors.New("keystore down") },
			KeyID:   "pep-7",
			Strict:  true,
			OnError: func(_ EvidenceContext, err error) { onError = err },
		},
	}}
	_, err := a.emitEvidence(nil, cert, &PipelineResult{
		AIC:                res.AIC,
		OperationDecisions: res.OperationDecisions,
	}, EvidenceAdmitted)
	if err == nil {
		t.Fatal("a signing failure must surface an error")
	}
	if onError == nil {
		t.Fatal("OnError must be called on a signing failure")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a failed signature must not leave a record: %v", entries)
	}
}

// outcomeCaptureSink captures the envelope from ReportOutcome for inspection.
type outcomeCaptureSink struct{ env semantics.Envelope }

func (s *outcomeCaptureSink) Emit(_ EvidenceContext, _ semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error) {
	s.env = env
	return RecordRef{}, nil
}

func (s *outcomeCaptureSink) EmitAdmission(_ EvidenceContext, _ AdmissionRecord, env semantics.Envelope) (RecordRef, error) {
	s.env = env
	return RecordRef{}, nil
}

func (s *outcomeCaptureSink) EmitOutcome(_ EvidenceContext, _ OutcomeRecord, env semantics.Envelope) (RecordRef, error) {
	s.env = env
	return RecordRef{}, nil
}
