// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// P1/G2：导出包自身签名。EvidenceBundle 此前 Signatures 只定义、无写入；这里覆盖
// 「包也带密钥背书」：签名覆盖去掉 signatures 后的规范字节（PAE 域分离），验签用同一
// 个 RecordSigner.VerifyFn。

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func testBundle() *EvidenceBundle {
	return &EvidenceBundle{
		Manifest: EvidenceManifest{
			Schema:     evidenceSchema,
			Version:    evidenceVersion,
			BundleID:   "evidence-test",
			ExportedAt: time.Unix(0, 0).UTC(),
			Generator:  "test",
			HashAlg:    evidenceHashAlg,
		},
		Operation: EvidenceOperation{Action: "exec", Outcome: "permit"},
		Decision:  EvidenceDecision{Decision: "allow"},
	}
}

func TestEvidenceBundleSignRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("exporter-1", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	b := testBundle()
	if err := b.Sign(signer.KeyID(), signer.Sign); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(b.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(b.Signatures))
	}
	if err := b.VerifySignature(signer.VerifyFn()); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// A changed decision invalidates the signature: the signing bytes changed.
	tampered := testBundle()
	tampered.Signatures = b.Signatures
	tampered.Decision.Decision = "deny"
	if err := tampered.VerifySignature(signer.VerifyFn()); err == nil {
		t.Fatal("a tampered bundle must fail verification")
	}
}

func TestEvidenceBundleUnsignedFailsWhenVerified(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := NewRecordSigner("exporter-1", key)
	if err != nil {
		t.Fatalf("NewRecordSigner: %v", err)
	}
	if err := testBundle().VerifySignature(signer.VerifyFn()); err == nil {
		t.Fatal("an unsigned bundle must fail when a verifier is required")
	}
}

func TestEvidenceBundleSigningBytesIgnoreSignatures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := NewRecordSigner("exporter-1", key)
	b := testBundle()
	before, err := b.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if err := b.Sign(signer.KeyID(), signer.Sign); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	after, err := b.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("signing bytes must not change when signatures are added")
	}
}

func TestFileEvidenceExporterSignsBundle(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, _ := NewRecordSigner("exporter-1", key)
	auditPath := t.TempDir() + "/audit.jsonl"
	if err := os.WriteFile(auditPath, nil, 0o600); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	exporter := &FileEvidenceExporter{AuditFile: auditPath, Signer: signer}
	exporter.Now = func() time.Time { return time.Unix(0, 0).UTC() }
	b, err := exporter.Export(nil, EvidenceQuery{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(b.Signatures) != 1 {
		t.Fatalf("exported bundle signatures = %d, want 1", len(b.Signatures))
	}
	if err := b.VerifySignature(signer.VerifyFn()); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}
