// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 发射者标识：记录自己带得出"谁发的"，而且消费方**按摘要**核对，不靠标签。

package aicverifier

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// requestWithCert builds a request whose TLS state carries the given leaf.
func requestWithCert(t *testing.T, cert *x509.Certificate) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "https://gw.example/whoami", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

func TestRecorderDescriptorDigest(t *testing.T) {
	a := RecorderDescriptor{ID: "pep-1", Kind: "aic-verifier"}
	b := RecorderDescriptor{ID: "pep-1", Kind: "aic-verifier"}
	idA, err := a.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	idB, err := b.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !idA.Equal(idB) {
		t.Error("the same descriptor must have the same identity")
	}

	c := a
	c.ID = "pep-2"
	idC, err := c.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if idA.Equal(idC) {
		t.Error("a different recorder is a different identity")
	}

	if _, err := (RecorderDescriptor{}).Digest(); err == nil {
		t.Error("a descriptor without an id must be rejected")
	}
}

// 三类载荷都带 recorder subject；消费方用同一函数读回并核对。
func TestEmittedRecordsCarryRecorderSubject(t *testing.T) {
	desc := &RecorderDescriptor{ID: "pep-7", Kind: "aic-verifier", Note: "gateway-a ingress"}
	want, err := desc.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	dir := t.TempDir()
	sink := &FileSink{Dir: dir}
	cfg := &EvidenceConfig{Sink: sink, RecorderID: "pep-7", Recorder: desc}

	// 1) 语言层裁决记录
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil || len(refs) == 0 {
		t.Fatalf("decision emission: %v", err)
	}
	env := mustEnvelope(t, refs[0].Path)
	got, ok, err := RecorderSubjectDigest(env)
	if err != nil || !ok {
		t.Fatalf("decision record carries no recorder subject: ok=%v err=%v", ok, err)
	}
	if !got.Equal(want) {
		t.Error("the decision record's recorder subject does not match the descriptor")
	}
	if kind, err := CheckEvidenceEnvelope(env); err != nil || kind != KindDecision {
		t.Fatalf("tagged decision envelope: %q/%v", kind, err)
	}

	// 2) 管线级拒绝记录
	a := &authenticator{cfg: &Config{Evidence: cfg}}
	req := requestWithCert(t, cert)
	rrefs := a.refusalEvidence(viewFromHTTP(nil, req), &AuthError{Code: ErrDenied, Status: 403, Message: "denied"})
	if len(rrefs) != 1 {
		t.Fatalf("admission refs = %v", rrefs)
	}
	env2 := mustEnvelope(t, rrefs[0].Path)
	got2, ok2, err := RecorderSubjectDigest(env2)
	if err != nil || !ok2 || !got2.Equal(want) {
		t.Fatalf("admission record recorder subject: ok=%v err=%v", ok2, err)
	}

	// 3) 效果记录
	oref, err := ReportOutcome(sink, cfg, EvidenceContext{RecorderID: "pep-7"}, OutcomeRecord{Outcome: OutcomeObserved})
	if err != nil {
		t.Fatalf("ReportOutcome: %v", err)
	}
	env3 := mustEnvelope(t, oref.Path)
	got3, ok3, err := RecorderSubjectDigest(env3)
	if err != nil || !ok3 || !got3.Equal(want) {
		t.Fatalf("outcome record recorder subject: ok=%v err=%v", ok3, err)
	}
}
