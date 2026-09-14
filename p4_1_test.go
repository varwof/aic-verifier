// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 4.1：VerifyFnFromPublicKey 把「谁信 key」收敛成一行——部署钉住发射点公钥，
// 签名验证不用每处手写 crypto；目录级校验直接吃这个回调。

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"

	"github.com/varwof/register/semantics"
)

// ecdsaP256Signer signs using the raw r‖s convention (the DSSE / JSON-Sign
// default for ECDSA), the shape VerifyFnFromPublicKey must accept.
func ecdsaP256Signer(key *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
	width := (key.Curve.Params().BitSize + 7) / 8
	return func(pae []byte) ([]byte, error) {
		digest := sha256.Sum256(pae)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 2*width)
		r.FillBytes(sig[:width])
		s.FillBytes(sig[width:])
		return sig, nil
	}
}

func TestVerifyFnFromPublicKeyDirEndToEnd(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if len(res.OperationDecisions) == 0 {
		t.Fatal("no operation decisions")
	}

	dir := t.TempDir()
	cfg := &EvidenceConfig{
		Sink:  &FileSink{Dir: dir, RecorderID: "pep-key"},
		Sign:  ecdsaP256Signer(key),
		KeyID: "pep-key",
	}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert,
		res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil {
		t.Fatalf("EmitDecisionRecords: %v", err)
	}
	if len(refs) == 0 {
		t.Fatal("no record references returned")
	}

	// The deployment pins the emission point's key and gets a directory check
	// without writing any verification code of its own.
	rep, err := VerifyEvidenceDir(dir, VerifyFnFromPublicKey(&key.PublicKey))
	if err != nil {
		t.Fatalf("VerifyEvidenceDir: %v", err)
	}
	if rep.Total != 1 || rep.Decision != 1 {
		t.Errorf("report = %+v, want 1 decision total", rep)
	}
	if len(rep.Failures) != 0 {
		t.Errorf("failures = %v, want clean", rep.Failures)
	}

	// A different key must not verify: the pin is the trust anchor.
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("wrong keygen: %v", err)
	}
	if wrongRep, _ := VerifyEvidenceDir(dir, VerifyFnFromPublicKey(&wrong.PublicKey)); len(wrongRep.Failures) != 1 {
		t.Errorf("wrong-key failures = %v, want 1", wrongRep.Failures)
	}

	// Tampering a payload breaks the PAE behind the signature → the dir check
	// reports it instead of trusting the record.
	raw, err := os.ReadFile(refs[0].Path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env semantics.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	env.Payload = append(append([]byte{}, env.Payload...), 0x00)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if err := os.WriteFile(refs[0].Path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if tamperedRep, _ := VerifyEvidenceDir(dir, VerifyFnFromPublicKey(&key.PublicKey)); len(tamperedRep.Failures) != 1 {
		t.Errorf("tampered failures = %v, want 1", tamperedRep.Failures)
	}
}

func TestVerifyFnFromPublicKeyDERForm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	verify := VerifyFnFromPublicKey(&key.PublicKey)
	pae := semantics.PAE("application/json", []byte(`{"ver":"AIC-DECISION-RECORD-v1"}`))

	digest := sha256.Sum256(pae)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	width := (key.Curve.Params().BitSize + 7) / 8
	rawSig := make([]byte, 2*width)
	r.FillBytes(rawSig[:width])
	s.FillBytes(rawSig[width:])
	if err := verify("", pae, rawSig); err != nil {
		t.Errorf("raw r‖s form must verify: %v", err)
	}

	derSig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign-asn1: %v", err)
	}
	if err := verify("", pae, derSig); err != nil {
		t.Errorf("ASN.1 DER form must verify: %v", err)
	}

	// DER length is data-dependent (70/71/72 bytes for P-256, and 70/72 are
	// even) — run a few dozen so the even-length DER cases are covered, not
	// just whichever length the random k happened to produce.
	for i := 0; i < 40; i++ {
		der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("sign-asn1 loop: %v", err)
		}
		if err := verify("", pae, der); err != nil {
			t.Fatalf("DER iteration %d (len=%d): %v", i, len(der), err)
		}
	}

	// KeyID is an unauthenticated hint: it must not matter which label rides
	// along, and a label must not make a bad signature pass.
	if err := verify("attacker-clamed-key", pae, derSig); err != nil {
		t.Errorf("keyid must be ignored: %v", err)
	}
	if err := verify("", pae, append(append([]byte{}, derSig...), 0x00)); err == nil {
		t.Error("a truncated signature must fail")
	}
}
