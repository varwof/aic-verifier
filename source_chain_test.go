// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 准入结果里的来源链：只声明能证明的（证书 DER 摘要），并且能被记录绑定。

package aicverifier

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

func TestAdmissionResultCarriesSourceChain(t *testing.T) {
	cert := testAICCert(t, false)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionAllow {
		t.Fatalf("decision = %v (%s), want allow", res.Decision, res.Reason)
	}
	if res.Sources == nil {
		t.Fatal("admission result carries no source chain")
	}
	if err := res.Sources.Validate(); err != nil {
		t.Fatalf("chain does not validate: %v", err)
	}
	if len(res.Sources.Sources) != 1 {
		t.Fatalf("sources = %d, want the verified leaf only", len(res.Sources.Sources))
	}
	node := res.Sources.Sources[0]
	if node.Kind != "aic-x509" {
		t.Errorf("kind = %q, want aic-x509", node.Kind)
	}
	if !strings.HasPrefix(node.ID, "serial:") {
		t.Errorf("id = %q, want a certificate serial", node.ID)
	}
	want := sha256.Sum256(cert.Raw)
	if string(node.Digest.Value) != string(want[:]) || node.Digest.Alg != semantics.DigestAlgSHA256 {
		t.Errorf("digest is not the certificate DER digest")
	}

	// The chain is byte-backed by construction: it claims no edges at all, so
	// there is nothing it cannot prove.
	if len(res.Sources.Links) != 0 {
		t.Errorf("links = %d, want none until the DA's raw bytes are retained", len(res.Sources.Links))
	}
}

// 记录能把这条链绑进去，且在信封里照样可复算。
func TestSourceChainBindsIntoRecord(t *testing.T) {
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if res.Sources == nil {
		t.Fatal("no source chain")
	}

	rec, err := semantics.RecordWith(
		[]semantics.Grant{{ID: sqlQueryCap}},
		semantics.Operation{ID: sqlQueryCap},
		semantics.RecordOptions{Sources: res.Sources},
	)
	if err != nil {
		t.Fatalf("RecordWith: %v", err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	env, err := semantics.NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if err := env.Check(); err != nil {
		t.Fatalf("envelope Check: %v", err)
	}
	back, err := env.DecisionRecord()
	if err != nil {
		t.Fatalf("DecisionRecord: %v", err)
	}
	got, err := back.Inputs.Sources.Digest()
	if err != nil {
		t.Fatalf("chain digest: %v", err)
	}
	orig, err := res.Sources.Digest()
	if err != nil {
		t.Fatalf("chain digest: %v", err)
	}
	if !got.Equal(orig) {
		t.Error("the chain changed on the way through the record and envelope")
	}
}

// 没有证书就没有链：不编造来源。
func TestBuildSourceChainRequiresCertificate(t *testing.T) {
	if _, err := BuildSourceChain(nil, nil, nil); err == nil {
		t.Fatal("expected an error for a missing certificate")
	}
}
