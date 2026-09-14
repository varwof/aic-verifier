// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 管线统一：**语言层之前的拒绝**也留下记录（AdmissionRecord），
// 而且"一次拒绝只留一条记录"——已有 CLC 记录时不重复描述。

package aicverifier

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func TestAdmissionRecordRoundTrip(t *testing.T) {
	ctx := EvidenceContext{RecorderID: "pep-9", Path: "/whoami", Method: "GET", Principal: "people-user01", At: time.Now().UTC()}
	rec := NewAdmissionRecord(ctx, &AuthError{Code: ErrChainInvalid, Status: 403, Message: "client certificate presented but no mTLS CA configured to verify it"},
		[]AdmissionFact{{Type: "client-cert", Digest: dg("cert-der"), Note: "leaf"}})

	if rec.Ver != AdmissionRecordVersion || rec.Outcome != string(EvidenceRefused) || rec.Stage == "" {
		t.Fatalf("record shape = %+v", rec)
	}
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	kind, err := CheckEvidenceEnvelope(env)
	if err != nil || kind != KindAdmission {
		t.Fatalf("CheckEvidenceEnvelope = %q/%v, want admission record", kind, err)
	}
	back, err := ParseAdmissionEnvelope(env)
	if err != nil {
		t.Fatalf("ParseAdmissionEnvelope: %v", err)
	}
	if back.Reason != rec.Reason || back.Identity.Principal != "people-user01" {
		t.Fatalf("round trip changed the record: %+v", back)
	}
	// The refusal reason is present but bounded: no certificate material, no keys.
	if strings.Contains(back.Reason, "BEGIN CERTIFICATE") {
		t.Error("the record must not embed certificate material")
	}
}

// 中间件边界：拒绝 + 证据配置 → 落一条 admission 信封；且语言层已有的记录不会被重复。
func TestRefusalEvidenceEmitsAdmissionRecord(t *testing.T) {
	dir := t.TempDir()
	a := &authenticator{cfg: &Config{
		Evidence: &EvidenceConfig{Sink: &FileSink{Dir: dir, RecorderID: "pep-9"}, RecorderID: "pep-9"},
	}}

	cert := testAICCert(t, false)
	req := httptest.NewRequest("GET", "https://gw.example/whoami", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	ae := &AuthError{Code: ErrChainInvalid, Status: 403, Message: "certificate chain invalid"}
	refs := a.refusalEvidence(req, ae)
	if len(refs) != 1 {
		t.Fatalf("refs = %v, want one admission record", refs)
	}
	if refs[0].Path == "" {
		t.Fatal("ref path missing")
	}
	raw, err := os.ReadFile(refs[0].Path)
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var env struct {
		Payload []byte `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("not an envelope: %v", err)
	}
	rec, err := ParseAdmissionEnvelope(mustEnvelope(t, refs[0].Path))
	if err != nil {
		t.Fatalf("ParseAdmissionEnvelope: %v", err)
	}
	if rec.Stage != ErrChainInvalid.String() {
		t.Errorf("stage = %q, want %q", rec.Stage, ErrChainInvalid.String())
	}
	if len(rec.Facts) == 0 || rec.Facts[0].Type != "client-cert" {
		t.Fatalf("facts = %+v, want the client certificate digest", rec.Facts)
	}
	want := sha256.Sum256(cert.Raw)
	if string(rec.Facts[0].Digest.Value) != string(want[:]) {
		t.Error("the certificate fact is not the certificate digest")
	}

	// One refusal, one record: an error that already carries CLC records is not
	// described a second time.
	withEvidence := &AuthError{Code: ErrDenied, Status: 403, Message: "denied", Evidence: refs}
	if got := a.refusalEvidence(req, withEvidence); got != nil {
		t.Errorf("a refusal with CLC records must not add an admission record: %v", got)
	}

	// Evidence disabled: nothing at all.
	plain := &authenticator{cfg: &Config{}}
	if got := plain.refusalEvidence(req, ae); got != nil {
		t.Errorf("evidence disabled must emit nothing: %v", got)
	}
	_ = filepath.Join // keep the import used on all platforms
}

func dg(s string) semantics.Digest {
	sum := sha256.Sum256([]byte(s))
	return semantics.Digest{Alg: semantics.DigestAlgSHA256, Value: sum[:]}
}

func mustEnvelope(t *testing.T, path string) semantics.Envelope {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env semantics.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return env
}
