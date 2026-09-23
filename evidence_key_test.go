// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P0-1：签名密钥 helper。RecordSigner 把 crypto.Signer 收敛成「配了就签」的证据
// 背书；VerifyFnFromKey 是它的对称验签入口（ECDSA / RSA / Ed25519）。这些测试
// 覆盖三种密钥的签名-验签闭环、PEM 文件加载，以及 RequireSignature 的 fail-closed。

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// signAndVerify builds an admission envelope, signs it through cfg, and checks
// the round trip with the signer's own verification callback.
func signAndVerify(t *testing.T, signer *RecordSigner) {
	t.Helper()
	rec := NewAdmissionRecord(EvidenceContext{At: time.Now().UTC()},
		&AuthError{Code: ErrDenied, Status: 403, Message: "denied"}, nil)
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	cfg := &EvidenceConfig{Signer: signer}
	signed, err := signEnvelope(env, cfg)
	if err != nil {
		t.Fatalf("signEnvelope: %v", err)
	}
	if len(signed.Signatures) != 1 || signed.Signatures[0].KeyID != signer.KeyID() {
		t.Fatalf("signatures = %+v, want one entry with keyid %q", signed.Signatures, signer.KeyID())
	}
	if _, err := VerifyEvidenceEnvelope(signed, signer.VerifyFn()); err != nil {
		t.Fatalf("VerifyEvidenceEnvelope: %v", err)
	}
	// A tampered payload must fail.
	tampered := signed
	tampered.Payload = append(append([]byte{}, tampered.Payload...), 0x01)
	if _, err := VerifyEvidenceEnvelope(tampered, signer.VerifyFn()); err == nil {
		t.Fatal("a tampered payload must fail verification")
	}
}

func TestRecordSignerECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("pep-ec", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	signAndVerify(t, signer)
}

func TestRecordSignerEd25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("pep-ed", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	signAndVerify(t, signer)
}

func TestRecordSignerRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("pep-rsa", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	signAndVerify(t, signer)
}

func TestLoadRecordSignerFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	signer, err := LoadRecordSignerFile(path, "pep-file")
	if err != nil {
		t.Fatalf("LoadRecordSignerFile: %v", err)
	}
	if signer.KeyID() != "pep-file" {
		t.Fatalf("keyID = %q", signer.KeyID())
	}
	signAndVerify(t, signer)
}

// TestEvidenceSignKeyFileResolvedOnBuild checks the SignKeyFile sugar: the file
// is loaded once at handler build (newAuthenticator), and emission then signs
// without per-record I/O.
func TestEvidenceSignKeyFileResolvedOnBuild(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := &Config{Evidence: &EvidenceConfig{Signer: nil, SignKeyFile: path, KeyID: "pep-sugar"}}
	if _, err := newAuthenticator(cfg); err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}
	if cfg.Evidence.Signer == nil {
		t.Fatal("SignKeyFile must be resolved into Signer at build time")
	}
	signAndVerify(t, cfg.Evidence.Signer)
}

func TestEvidenceRequireSignatureValidates(t *testing.T) {
	// No key: fail closed.
	cfg := &Config{Evidence: &EvidenceConfig{RequireSignature: true}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("RequireSignature without a key must fail Validate")
	}
	// Key present: valid.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("pep-1", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	cfg = &Config{Evidence: &EvidenceConfig{RequireSignature: true, Signer: signer}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("RequireSignature with a key must validate: %v", err)
	}
}

// TestEmitDecisionRecordsUsesSigner checks the RecordSigner flows through the
// actual emission path (EmitDecisionRecords), not just signEnvelope.
func TestEmitDecisionRecordsUsesSigner(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("pep-1", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	dir := t.TempDir()
	cfg := &EvidenceConfig{Sink: &FileSink{Dir: dir}, Signer: signer}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("no record references returned")
	}
	rec, err := LoadEvidenceRecord(refs[0].Path)
	if err != nil {
		t.Fatalf("LoadEvidenceRecord: %v", err)
	}
	_ = rec
	reports, err := VerifyEvidenceDir(dir, signer.VerifyFn())
	if err != nil {
		t.Fatalf("VerifyEvidenceDir: %v", err)
	}
	if len(reports.Failures) != 0 || reports.Decision == 0 {
		t.Fatalf("signed records must verify clean: %+v", reports)
	}
}

func TestNewRecordSignerRejectsNil(t *testing.T) {
	if _, err := NewRecordSigner("x", nil); err == nil {
		t.Fatal("nil signer must be rejected")
	}
}
