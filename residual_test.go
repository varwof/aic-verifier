// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// B2/B3: allow_unresolved release hook + CLC verdict surfacing.
//
// An operation that only carries a recognized-but-unevaluated constraint
// (time:window etc.) lands on the §8.4 residual-obligation verdict.  By
// default that is fail-closed deny; a deployment can opt into
// AdmissionConfig.UnresolvedEvaluator to release the operation after
// confirming the obligations.  B3 makes the verdict/reason/unresolved visible
// on the AuthContext instead of only the aggregated allow/deny.

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
	pki "github.com/varwof/types"
)

const sqlQueryCap = "std/database-v1:query:SELECT"

// testAICCert mints a self-signed certificate carrying an AIC with one
// database capability and (optionally) a time-window authorization
// constraint.  The admission pipeline does not cryptographically verify the
// signer, so a self-signed leaf is sufficient for decision tests.
func testAICCert(t testing.TB, withWindow bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var constraints []pki.Capability
	if withWindow {
		constraints = append(constraints, pki.Capability{
			SchemeId:     "varwof/constraint-v1",
			CapabilityId: "time:window",
			Parameters:   []byte(`[{"start":"00:00","end":"06:00"}]`),
		})
	}
	aic := &pki.AIC{
		AgentId: "agent-1",
		PrincipalUid: pki.PrincipalUid{
			Version:    1,
			Realm:      "pki",
			Identifier: "user-1",
			KeyHash:    make([]byte, sha256.Size),
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: []pki.Capability{{
			SchemeId:     "std/database-v1",
			CapabilityId: "query:SELECT",
			Parameters:   []byte(`{"limit":10}`),
		}},
		AuthorizationConstraints: constraints,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "API_ISSUE", Description: "test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatalf("marshal aic: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: aicDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func B2Config(op ...Operation) AdmissionConfig {
	return AdmissionConfig{Operations: op}
}

// An uninstrumented allow_unresolved verdict must stay fail-closed: the
// residual obligation is real and "allow" would over-behave, not under-behave.
func TestUnresolvedOperationDefaultsToDeny(t *testing.T) {
	cert := testAICCert(t, true)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %v, want deny (fail-closed)", res.Decision)
	}
	if !strings.Contains(res.Reason, "allow_unresolved") {
		t.Errorf("reason %q should name the allow_unresolved verdict", res.Reason)
	}
}

// The deployed UnresolvedEvaluator (say, "time-window confirmed for this
// cluster") releases the operation; the per-operation record keeps the verdict
// and the unresolved constraint for runtime honoring.
func TestUnresolvedEvaluatorReleasesOperation(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	var evalOp Operation
	var evalUnresolved []string
	cfg.UnresolvedEvaluator = func(op Operation, unresolved []string) bool {
		evalOp, evalUnresolved = op, unresolved
		return true
	}
	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionAllow {
		t.Fatalf("decision = %v, want allow:", res.Decision)
	}
	if len(res.OperationDecisions) != 1 {
		t.Fatalf("operation decisions = %d, want 1", len(res.OperationDecisions))
	}
	od := res.OperationDecisions[0]
	if od.Verdict != semantics.VerdictAllowUR {
		t.Errorf("verdict = %q, want allow_unresolved", od.Verdict)
	}
	if !od.Released {
		t.Error("released = false, want true")
	}
	if evalOp.ID != sqlQueryCap {
		t.Errorf("evaluator op = %q, want %q", evalOp.ID, sqlQueryCap)
	}
	if len(evalUnresolved) == 0 || !strings.Contains(evalUnresolved[0], "time:window") {
		t.Errorf("evaluator unresolved = %v, want the time:window obligation", evalUnresolved)
	}
}

func TestUnresolvedEvaluatorCanKeepDenying(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	cfg.UnresolvedEvaluator = func(op Operation, unresolved []string) bool { return false }
	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %v, want deny when evaluator refuses", res.Decision)
	}
	if !strings.Contains(res.Reason, "unresolved") {
		t.Errorf("reason %q should surface the unresolved list", res.Reason)
	}
}

// B3: the AuthContext carries the CLC verdict/reason/unresolved for a released
// residual obligation, so downstream peers can honor the time window at
// runtime instead of seeing only "capabilities: [query:SELECT]".
func TestAuthContextCarriesCLCVerdict(t *testing.T) {
	cert := testAICCert(t, true)
	op := Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	cfg := &Config{
		RequiredOperations: []Operation{op},
		UnresolvedEvaluator: func(op Operation, unresolved []string) bool {
			return true
		},
	}
	a := &authenticator{cfg: cfg, tlsCAs: pool, log: testLogger(), nonces: nil}
	r, err := http.NewRequest(http.MethodPost, "https://gw.example/query", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	r.RemoteAddr = "127.0.0.1:54321"

	ac, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if ac.Verdict != "allow_unresolved" {
		t.Errorf("AuthContext.Verdict = %q, want allow_unresolved", ac.Verdict)
	}
	if len(ac.Unresolved) == 0 || !strings.Contains(ac.Unresolved[0], "time:window") {
		t.Errorf("AuthContext.Unresolved = %v, want the time:window obligation", ac.Unresolved)
	}
	if len(ac.OperationDecisions) != 1 {
		t.Fatalf("operation decisions = %d, want 1", len(ac.OperationDecisions))
	}
	if od := ac.OperationDecisions[0]; od.Verdict != semantics.VerdictAllowUR || !od.Released {
		t.Errorf("operation decision = %+v, want allow_unresolved + released", od)
	}
	// Capabilities surfaces as before; verdict fields are additive.
	if len(ac.Capabilities) != 1 || ac.Capabilities[0] != "query:SELECT" {
		t.Errorf("capabilities = %v, want [query:SELECT]", ac.Capabilities)
	}
}

func TestAuthContextCLCVerdictAbsentWithoutOperations(t *testing.T) {
	cert := testAICCert(t, true)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	a := &authenticator{cfg: &Config{}, tlsCAs: pool, log: testLogger()}
	r, err := http.NewRequest(http.MethodGet, "https://gw.example/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	r.RemoteAddr = "127.0.0.1:54321"

	ac, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if ac.Verdict != "" || ac.Reason != "" || len(ac.Unresolved) != 0 {
		t.Errorf("verdict fields should stay empty without operations: %q %q %v", ac.Verdict, ac.Reason, ac.Unresolved)
	}
}
func TestPipelineSurfacesCLCVerdict(t *testing.T) {
	cert := testAICCert(t, true)
	op := Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}
	denied := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
		Operations: []Operation{op},
	})
	if denied.Granted {
		t.Fatal("unreleased allow_unresolved must deny")
	}
	if !strings.Contains(denied.DenyReason, "allow_unresolved") {
		t.Errorf("deny reason %q should name allow_unresolved", denied.DenyReason)
	}

	allowed := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{
		Operations: []Operation{op},
		UnresolvedEvaluator: func(op Operation, unresolved []string) bool {
			return true
		},
	})
	if !allowed.Granted {
		t.Fatalf("released operation must admit: %s", allowed.DenyReason)
	}
	if allowed.CLCVerdict != "allow_unresolved" {
		t.Errorf("CLCVerdict = %q, want allow_unresolved", allowed.CLCVerdict)
	}
	if len(allowed.CLCUnresolved) == 0 || !strings.Contains(allowed.CLCUnresolved[0], "time:window") {
		t.Errorf("CLCUnresolved = %v, want the time:window obligation", allowed.CLCUnresolved)
	}
	if len(allowed.OperationDecisions) != 1 || !allowed.OperationDecisions[0].Released {
		t.Errorf("operation decisions missing released record: %+v", allowed.OperationDecisions)
	}
}
