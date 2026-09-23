// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// testbedEvaluator is a per-registry constraint evaluator whose Evaluate
// always fails, so isolation is observable by *which* registry ran it.
type testbedEvaluator struct{}

func (testbedEvaluator) CapabilityId() string { return "testbed:tsunami" }

func (testbedEvaluator) Evaluate(cap *Capability, _ *ConstraintContext) error {
	return errors.New("testbed:tsunami refuses underwater queries")
}

// ---- cert builders (local, no reuse of other tests' helpers) -------------

func issueAICWithConstraints(t *testing.T, ca *httpCA, cn string, constraints []Capability) *x509.Certificate {
	t.Helper()
	aic := &pki.AIC{
		Version:                  1,
		AgentId:                  cn,
		PrincipalUid:             pki.PrincipalUid{Version: 1, Realm: "pki", Identifier: cn, KeyHash: make([]byte, sha256.Size), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256}},
		Capabilities:             []pki.Capability{},
		AuthorizationConstraints: constraints,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "isolate", Description: "test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatalf("marshal AIC: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: pki.OIDAIC, Value: aicDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// TestConstraintRegistryIsolationAcrossAdmission proves the per-Config
// ConstraintRegistry is honored by the admission engine: the same certificate
// with the same constraint is denied differently depending on which registry
// the gateway holds (unknown-type fail-closed vs. a running evaluator).
func TestConstraintRegistryIsolationAcrossAdmission(t *testing.T) {
	ca := newHTTPTestCA(t)
	constraint := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "testbed:tsunami", Parameters: []byte(`{}`)}
	leaf := issueAICWithConstraints(t, ca, "isolation-agent", []Capability{constraint})

	regA := NewConstraintRegistry() // empty: the type is unknown
	regB := NewConstraintRegistry() // has the evaluator
	if err := regB.Register(testbedEvaluator{}); err != nil {
		t.Fatalf("register into regB: %v", err)
	}

	// Same admission, registry A: unknown constraint, strict mode → fail-closed.
	r1 := CheckAdmission(leaf, AdmissionConfig{EnforceConstraints: true, StrictConstraints: true, ConstraintRegistry: regA})
	if r1.Decision != DecisionDeny || !strings.Contains(r1.Reason, "unknown constraint type") {
		t.Errorf("registry A: got %v/%q, want deny/unknown constraint type", r1.Decision, r1.Reason)
	}

	// Same admission, registry B: the evaluator actually runs.
	r2 := CheckAdmission(leaf, AdmissionConfig{EnforceConstraints: true, StrictConstraints: true, ConstraintRegistry: regB})
	if r2.Decision != DecisionDeny || !strings.Contains(r2.Reason, "testbed:tsunami refuses") {
		t.Errorf("registry B: got %v/%q, want deny/evaluator text", r2.Decision, r2.Reason)
	}
}

// TestPipelineForwardsPerConfigRegistries proves the wiring
// Config.Constraints → PipelineConfig.ConstraintRegistry → AdmissionConfig.
func TestPipelineForwardsPerConfigRegistries(t *testing.T) {
	ca := newHTTPTestCA(t)
	constraint := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "testbed:tsunami", Parameters: []byte(`{}`)}
	leaf := issueAICWithConstraints(t, ca, "pipeline-isolation", []Capability{constraint})

	regA := NewConstraintRegistry()
	regB := NewConstraintRegistry()
	if err := regB.Register(testbedEvaluator{}); err != nil {
		t.Fatalf("register into regB: %v", err)
	}

	ra := RunAccessPipeline([]*x509.Certificate{leaf}, &PipelineConfig{CheckScope: CheckLeafOnly, EnforceConstraints: true, StrictConstraints: true, ConstraintRegistry: regA})
	if ra.Granted || !strings.Contains(ra.DenyReason, "unknown constraint type") {
		t.Errorf("pipeline regA: granted=%v reason=%q, want deny/unknown", ra.Granted, ra.DenyReason)
	}
	rb := RunAccessPipeline([]*x509.Certificate{leaf}, &PipelineConfig{CheckScope: CheckLeafOnly, EnforceConstraints: true, StrictConstraints: true, ConstraintRegistry: regB})
	if rb.Granted || !strings.Contains(rb.DenyReason, "testbed:tsunami refuses") {
		t.Errorf("pipeline regB: granted=%v reason=%q, want deny/evaluator text", rb.Granted, rb.DenyReason)
	}
}

// TestPolicyIsolationProves a per-Config AuthorizationPolicy wins over the
// package-global one without mutating it.
func TestPolicyIsolation(t *testing.T) {
	ca := newHTTPTestCA(t)
	leaf := issueAICWithConstraints(t, ca, "policy-isolation", nil)
	leaf.Subject.OrganizationalUnit = []string{"data-analyst"}

	global := &AuthorizationPolicy{OUMapping: map[string]string{"data-analyst": "global-analyst"}}
	perCfg := &AuthorizationPolicy{OUMapping: map[string]string{"data-analyst": "config-analyst"}}
	SetAuthorizationPolicy(global)
	t.Cleanup(func() { SetAuthorizationPolicy(nil) })

	fromGlobal := ExtractPolicyRoles(leaf)
	if !containsStr(fromGlobal, "global-analyst") {
		t.Errorf("global policy: roles=%v, want global-analyst", fromGlobal)
	}
	fromCfg := extractPolicyRoles(leaf, perCfg)
	if !containsStr(fromCfg, "config-analyst") {
		t.Errorf("per-config policy: roles=%v, want config-analyst", fromCfg)
	}
	if containsStr(fromCfg, "global-analyst") {
		t.Errorf("per-config policy leaked the global mapping: %v", fromCfg)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
