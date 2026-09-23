// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// RunAccessPipeline branch coverage: empty chain, CheckLeafOnly, full-chain
// iteration, AllowRoles, SPIFFE identity, OfflineMaxCertLifetime, plugin
// deny/error/ignore, capability registry reject, and plugin resolver.

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// ── local mock registries ───────────────────────────────────────────────────

type rejectingRegistry struct{}

func (rejectingRegistry) Enabled() bool                   { return true }
func (rejectingRegistry) ValidateCapability(string) error { return errors.New("not registered") }

// ── local spiffe cert builder ───────────────────────────────────────────────

func testSPIFFECert(t *testing.T, trustDomain, agentID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiFFEURI, _ := url.Parse(fmt.Sprintf("spiffe://%s/%s", trustDomain, agentID))
	aic := &pki.AIC{
		AgentId: agentID,
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "pki", Identifier: agentID,
			KeyHash: make([]byte, 32), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:    pki.Reason{ReasonCode: "test", Description: "spiffe test"},
			Timestamp: time.Now().UTC(), Nonce: make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: aicDER},
		},
		DNSNames: nil,
		URIs:     []*url.URL{spiFFEURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// testAICWithPACert builds an AIC cert that also carries a PA extension so
// EffectiveCaps is populated and the plugin loop is entered.
func testAICWithPACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := &pki.AIC{
		AgentId: "agent-1",
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "pki", Identifier: "user-1",
			KeyHash: make([]byte, 32), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: []pki.Capability{{
			SchemeId:     "std/database-v1",
			CapabilityId: "query:SELECT",
			Parameters:   []byte(`{"limit":10}`),
		}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "test", Description: "pipeline test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatal(err)
	}
	pa := pki.PrincipalAuthorization{
		Version: 1,
		Grants: []pki.Capability{{
			SchemeId:     "std/database-v1",
			CapabilityId: "query:SELECT",
		}},
	}
	paDER, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: aicDER},
			{Id: pki.OIDPrincipalAuthorization, Value: paDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestRunAccessPipelineEmptyChain(t *testing.T) {
	r := RunAccessPipeline(nil, nil)
	if r.Granted {
		t.Error("empty chain must deny")
	}
}

func TestRunAccessPipelineHappyPath(t *testing.T) {
	cert := testAICCert(t, false)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{})
	if !r.Granted {
		t.Fatalf("happy path denied: %s", r.DenyReason)
	}
	if r.Serial == "" {
		t.Error("missing serial in granted result")
	}
}

func TestRunAccessPipelineCheckLeafOnly(t *testing.T) {
	cert := testAICCert(t, false)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CheckScope: CheckLeafOnly})
	if !r.Granted {
		t.Fatalf("CheckLeafOnly happy path denied: %s", r.DenyReason)
	}

	expired := &x509.Certificate{
		Subject: pkix.Name{CommonName: "expired"}, SerialNumber: big.NewInt(2),
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
	}
	r = RunAccessPipeline([]*x509.Certificate{expired}, &PipelineConfig{CheckScope: CheckLeafOnly})
	if r.Granted {
		t.Error("expired cert in CheckLeafOnly must deny")
	}

	cache := &CRLCache{nextUpdate: time.Now().Add(-time.Minute), caCert: &x509.Certificate{}}
	r = RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CheckScope: CheckLeafOnly, CRLCache: cache})
	if r.Granted {
		t.Error("stale CRL must deny")
	}
}

func TestRunAccessPipelineFullChain(t *testing.T) {
	ca := testAICCert(t, false)
	cert := testAICCert(t, false)
	expired := &x509.Certificate{
		Subject: pkix.Name{CommonName: "expired"}, SerialNumber: big.NewInt(99),
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
	}
	r := RunAccessPipeline([]*x509.Certificate{cert, ca}, &PipelineConfig{})
	if !r.Granted {
		t.Fatalf("2-cert chain denied: %s", r.DenyReason)
	}
	r = RunAccessPipeline([]*x509.Certificate{expired, ca}, &PipelineConfig{})
	if r.Granted {
		t.Error("2-cert chain with expired leaf must deny")
	}
}

func TestRunAccessPipelineAllowRolesReject(t *testing.T) {
	cert := testAICCert(t, false)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{AllowRoles: []string{"admin"}})
	if r.Granted {
		t.Error("AllowRoles mismatch must deny")
	}
}

func TestRunAccessPipelineRequireSPIFFE(t *testing.T) {
	cert := testAICCert(t, false)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{RequireSPIFFE: true})
	if r.Granted {
		t.Error("RequireSPIFFE on non-SPIFFE cert must deny")
	}

	spiffe := testSPIFFECert(t, "example.org", "agent-1")
	r = RunAccessPipeline([]*x509.Certificate{spiffe}, &PipelineConfig{
		RequireSPIFFE:     true,
		SPIFFETrustDomain: "example.org",
		AllowedSPIFFEIDs:  []string{"spiffe://example.org/agent-1"},
	})
	if !r.Granted {
		t.Fatalf("valid SPIFFE denied: %s", r.DenyReason)
	}
}

func TestRunAccessPipelineTrustDomainMismatch(t *testing.T) {
	spiffe := testSPIFFECert(t, "example.org", "agent-1")
	r := RunAccessPipeline([]*x509.Certificate{spiffe}, &PipelineConfig{
		RequireSPIFFE:     true,
		SPIFFETrustDomain: "other.org",
	})
	if r.Granted {
		t.Error("trust domain mismatch must deny")
	}
}

func TestRunAccessPipelineAllowedSPIFFEIDReject(t *testing.T) {
	spiffe := testSPIFFECert(t, "example.org", "agent-1")
	r := RunAccessPipeline([]*x509.Certificate{spiffe}, &PipelineConfig{
		RequireSPIFFE:    true,
		AllowedSPIFFEIDs: []string{"spiffe://example.org/other"},
	})
	if r.Granted {
		t.Error("SPIFFE ID not in allow list must deny")
	}
}

func TestRunAccessPipelineOfflineMaxCertLifetime(t *testing.T) {
	longLived := testAICCert(t, false)
	longLived.NotAfter = time.Now().Add(24 * time.Hour)
	r := RunAccessPipeline([]*x509.Certificate{longLived}, &PipelineConfig{OfflineMaxCertLifetime: time.Hour})
	if r.Granted {
		t.Error("offline lifetime exceeded must deny")
	}
}

func TestRunAccessPipelinePluginDeny(t *testing.T) {
	reg := NewPluginRegistry()
	if err := reg.Register(&staticPlugin{scheme: "std/database-v1", result: &PluginResult{Decision: PluginDeny, Reason: "blocked"}}); err != nil {
		t.Fatal(err)
	}
	cert := testAICWithPACert(t)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CapabilityPluginRegistry: reg})
	if r.Granted {
		t.Error("plugin deny must deny connection")
	}
	if !strings.Contains(r.DenyReason, "blocked") {
		t.Errorf("deny reason = %q, want the plugin's block reason", r.DenyReason)
	}
}

func TestRunAccessPipelinePluginError(t *testing.T) {
	reg := NewPluginRegistry()
	if err := reg.Register(&staticPlugin{scheme: "std/database-v1", err: errors.New("boom")}); err != nil {
		t.Fatal(err)
	}
	cert := testAICWithPACert(t)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CapabilityPluginRegistry: reg})
	if r.Granted {
		t.Error("plugin error must deny connection")
	}
	if !strings.Contains(r.DenyReason, "error") {
		t.Errorf("deny reason = %q, want a plugin error mention", r.DenyReason)
	}
}

func TestRunAccessPipelineCapabilityRegistryReject(t *testing.T) {
	cert := testAICCert(t, false)
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CapabilityRegistry: rejectingRegistry{}})
	if r.Granted {
		t.Error("unregistered capability must deny")
	}
}

func TestRunAccessPipelineCapabilityPluginResolver(t *testing.T) {
	spiffeAIC := &pki.AIC{
		AgentId: "special-agent",
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "pki", Identifier: "special-agent",
			KeyHash: make([]byte, 32), HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: []pki.Capability{{SchemeId: "varwof/mcp-v1", CapabilityId: "chat"}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason: pki.Reason{ReasonCode: "test"}, Nonce: make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*spiffeAIC)
	if err != nil {
		t.Fatal(err)
	}
	pa := pki.PrincipalAuthorization{
		Version: 1,
		Grants:  []pki.Capability{{SchemeId: "varwof/mcp-v1", CapabilityId: "chat"}},
	}
	paDER, err := asn1.Marshal(pa)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "special-agent"},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: aicDER},
			{Id: pki.OIDPrincipalAuthorization, Value: paDER},
		},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	customReg := NewPluginRegistry()
	customReg.Register(&staticPlugin{scheme: "varwof/mcp-v1", result: &PluginResult{Decision: PluginDeny, Reason: "resolver block"}})
	resolver := func(agentID string) (uint64, *PluginRegistry) {
		if agentID == "special-agent" {
			return 0, customReg
		}
		return 0, nil
	}
	r := RunAccessPipeline([]*x509.Certificate{cert}, &PipelineConfig{CapabilityPluginResolver: resolver})
	if r.Granted {
		t.Error("resolver-selected plugin deny must deny connection")
	}
}
