// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the SPIFFE identity helpers, the credential bundle, the
// delegation chain capability model and the offline decision pure helpers
// (layer trusted-function surfaces that previously had no coverage).
//
// Reuses the in-package cert/CA builders from security_fixes_test.go,
// audit_integrity_test.go and evidence_http_test.go (captureStdout,
// newPlainCert, newHTTPTestCA).

package aicverifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// ---- shared cert minting helpers ------------------------------------------

// mintCert mints a leaf certificate. When issuerCert is nil the leaf is
// self-signed (sufficient for the pure capability/DA tests, which do not
// build chains through a real CA). Extra AIC/PA extensions are appended so
// both credential-bundle and delegation-chain shapes share one builder.
func mintCert(t *testing.T, issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, cn string, serial *big.Int, aic *AIC, ous []string, extra []pkix.Extension) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("mintCert key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, OrganizationalUnit: ous},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if aic != nil {
		aicDER, err := asn1.Marshal(*aic)
		if err != nil {
			t.Fatalf("mintCert marshal AIC: %v", err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: pki.OIDAIC, Value: aicDER})
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, extra...)
	signerCert, signerKey := tmpl, key
	if issuerCert != nil {
		signerCert, signerKey = issuerCert, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("mintCert create(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("mintCert parse: %v", err)
	}
	return key, cert
}

// baseDelegationAIC builds the AIC shape used by the delegation-chain and
// DA-signature tests. SignatureValue is filled in separately via signDADigest.
func baseDelegationAIC(agentID string, caps []Capability, principal PrincipalUid) AIC {
	return AIC{
		Version:        1,
		AgentId:        agentID,
		PrincipalUid:   principal,
		Capabilities:   caps,
		DelegationMode: DelegationAuthorized,
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "deleg", Description: "trust-model test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
		},
	}
}

// signDADigest reproduces the DelegationAuthTBS construction in
// VerifyDelegationAuth and signs it with signer.
func signDADigest(t *testing.T, signer *ecdsa.PrivateKey, aic *AIC) []byte {
	t.Helper()
	da := aic.DelegationAuthorization
	tbs := DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   da.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	der, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("signDADigest marshal TBS: %v", err)
	}
	digest := sha256.Sum256(der)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatalf("signDADigest sign: %v", err)
	}
	return sig
}

// buildSignedChain mints a two-level delegation chain (chain[0]=scheduler,
// chain[1]=worker) with correctly signed DAs: chain[0].DA is signed by the top
// principal, chain[1].DA by chain[0]'s key. caps1 selects the worker's
// capability for subset/escalation testing.
func buildSignedChain(t *testing.T, caps1 []Capability) (*ecdsa.PrivateKey, *x509.Certificate, []*x509.Certificate) {
	t.Helper()
	topKey, topCert := mintCert(t, nil, nil, "principal.user", big.NewInt(1001), nil, nil, nil)

	caps0 := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}}
	aic0 := baseDelegationAIC("scheduler-a", caps0, PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-a"})
	aic0.DelegationAuthorization.SignatureValue = signDADigest(t, topKey, &aic0)
	schedulerKey, c0 := mintCert(t, nil, nil, "scheduler-a", big.NewInt(2001), &aic0, nil, nil)

	aic1 := baseDelegationAIC("worker-b", caps1, PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-b"})
	aic1.DelegationAuthorization.SignatureValue = signDADigest(t, schedulerKey, &aic1)
	_, c1 := mintCert(t, nil, nil, "worker-b", big.NewInt(2002), &aic1, nil, nil)

	return topKey, topCert, []*x509.Certificate{c0, c1}
}

// spiFFESANCert builds a certificate whose SAN URIs contain the given SPIFFE
// identities (each parsed as a real url.URL, the same ingestion point the
// production ExtractSPIFFEIDFromCert uses).
func spiFFESANCert(t *testing.T, ids ...string) *x509.Certificate {
	t.Helper()
	cert := &x509.Certificate{}
	for _, id := range ids {
		u, err := url.Parse(id)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", id, err)
		}
		cert.URIs = append(cert.URIs, u)
	}
	return cert
}

func caps(scheme, id string) []Capability {
	return []Capability{{SchemeId: scheme, CapabilityId: id}}
}

// ---- 1. SPIFFE -------------------------------------------------------------

func TestSPIFFEParse(t *testing.T) {
	sid, err := ParseSPIFFEID("spiffe://example.org/agent/1")
	if err != nil {
		t.Fatalf("valid SPIFFE ID rejected: %v", err)
	}
	if sid.TrustDomain != "example.org" || sid.Path != "/agent/1" {
		t.Errorf("parsed = %+v, want trust domain example.org path /agent/1", sid)
	}

	// No path defaults to "/".
	sid, err = ParseSPIFFEID("spiffe://example.org")
	if err != nil {
		t.Fatalf("path-less SPIFFE ID rejected: %v", err)
	}
	if sid.Path != "/" {
		t.Errorf("path = %q, want /", sid.Path)
	}

	for _, bad := range []string{
		"http://example.org/agent/1", // wrong scheme
		"spiffe:///agent/1",          // empty trust domain
		"spiffe://nodots/agent/1",    // trust domain without a dot
		"%%%not-a-url",
	} {
		if _, err := ParseSPIFFEID(bad); err == nil {
			t.Errorf("ParseSPIFFEID(%q) succeeded, want error", bad)
		}
	}
}

func TestSPIFFEStringEqual(t *testing.T) {
	a, err := ParseSPIFFEID("spiffe://example.org/agent/1")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.String(); got != "spiffe://example.org/agent/1" {
		t.Errorf("String() = %q", got)
	}
	round, err := ParseSPIFFEID(a.String())
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if !a.Equal(round) {
		t.Errorf("Equal(round-trip) = false")
	}

	b, _ := ParseSPIFFEID("spiffe://example.org/agent/2")
	if a.Equal(b) {
		t.Error("different SPIFFE IDs compare equal")
	}
	var nilSID *SPIFFEID
	if nilSID.String() != "" {
		t.Errorf("nil String() = %q, want empty", nilSID.String())
	}
	if nilSID.Equal(a) {
		t.Error("nil vs non-nil Equal() = true")
	}
	if !nilSID.Equal(nil) {
		t.Error("nil vs nil Equal() = false")
	}
}

func TestSPIFFEExtract(t *testing.T) {
	cert := spiFFESANCert(t, "spiffe://example.org/agent/1", "https://other.example/x")
	if got := ExtractSPIFFEIDFromCert(cert); got != "spiffe://example.org/agent/1" {
		t.Errorf("ExtractSPIFFEIDFromCert = %q", got)
	}
	sid := ExtractSPIFFEID(cert)
	if sid == nil || sid.TrustDomain != "example.org" || sid.Path != "/agent/1" {
		t.Errorf("ExtractSPIFFEID = %+v, want example.org/agent/1", sid)
	}

	if got := ExtractSPIFFEIDFromCert(spiFFESANCert(t, "https://other.example/x")); got != "" {
		t.Errorf("non-SPIFFE URI extracted as %q, want empty", got)
	}
	if sid := ExtractSPIFFEID(spiFFESANCert(t, "https://other.example/x")); sid != nil {
		t.Errorf("non-SPIFFE URI parsed as %+v, want nil", sid)
	}
	// Scheme is right but the trust domain is invalid → parse failure → nil.
	if sid := ExtractSPIFFEID(spiFFESANCert(t, "spiffe://nodots/agent/1")); sid != nil {
		t.Errorf("invalid trust domain parsed as %+v, want nil", sid)
	}
	if sid := ExtractSPIFFEID(nil); sid != nil {
		t.Errorf("nil cert parsed as %+v, want nil", sid)
	}
}

func TestSPIFFEVerifySAN(t *testing.T) {
	cert := spiFFESANCert(t, "spiffe://example.org/agent/1")
	if !VerifySPIFFESAN(cert, "spiffe://example.org/agent/1") {
		t.Error("matching SPIFFE SAN rejected")
	}
	if VerifySPIFFESAN(cert, "spiffe://example.org/agent/2") {
		t.Error("non-matching SPIFFE SAN accepted")
	}
	if VerifySPIFFESAN(spiFFESANCert(t), "spiffe://example.org/agent/1") {
		t.Error("cert without URI SAN accepted as a match")
	}
}

// ---- 2. credential_bundle --------------------------------------------------

func TestCredentialBundleConstruction(t *testing.T) {
	if _, err := NewCredentialBundle(nil, nil, nil); err == nil {
		t.Error("empty agent chain accepted")
	}
	plain := newPlainCert(t)
	if _, err := NewCredentialBundle(nil, []*x509.Certificate{plain}, nil); err == nil {
		t.Error("empty agent chain accepted")
	}
	if _, err := NewCredentialBundle([]*x509.Certificate{plain}, nil, nil); err == nil {
		t.Error("empty principal chain accepted")
	}
	bundle, err := NewCredentialBundle([]*x509.Certificate{plain}, []*x509.Certificate{plain}, []*x509.Certificate{plain})
	if err != nil {
		t.Fatalf("NewCredentialBundle: %v", err)
	}
	if bundle.Agent() != plain || bundle.Principal() != plain {
		t.Error("getters did not return chain[0] certificates")
	}
}

func TestCredentialBundleGetters(t *testing.T) {
	var nilBundle *CredentialBundle
	if nilBundle.Agent() != nil || nilBundle.Principal() != nil {
		t.Error("nil bundle getters must return nil")
	}
	empty := &CredentialBundle{}
	if empty.Agent() != nil || empty.Principal() != nil {
		t.Error("empty bundle getters must return nil")
	}
}

func TestCredentialBundleKeyHash(t *testing.T) {
	ca := newHTTPTestCA(t)
	_, principal := mintCert(t, ca.cert, ca.key, "user-bundle", big.NewInt(3101), nil, nil, nil)

	principalHash := sha256.Sum256(principal.RawSubjectPublicKeyInfo)
	matchAIC := baseDelegationAIC("agent-bundle", caps("std/database-v1", "query:SELECT"),
		PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-bundle", KeyHash: principalHash[:], HashAlgo: AlgorithmIdentifier{Algorithm: pki.OIDSHA256}})
	_, agent := mintCert(t, ca.cert, ca.key, "agent-bundle", big.NewInt(3102), &matchAIC, nil, nil)

	if err := VerifyPrincipalKeyHash(agent, principal); err != nil {
		t.Errorf("matching keyHash rejected: %v", err)
	}

	// Traffic-light mismatch: a different principal key must fail fail-closed.
	_, other := mintCert(t, ca.cert, ca.key, "user-other", big.NewInt(3103), nil, nil, nil)
	if err := VerifyPrincipalKeyHash(agent, other); err == nil || !strings.Contains(err.Error(), "SPKI hash mismatch") {
		t.Errorf("keyHash mismatch = %v, want SPKI hash mismatch error", err)
	}

	// Missing keyHash (empty) must fail closed.
	noHashAIC := baseDelegationAIC("agent-bundle", caps("std/database-v1", "query:SELECT"),
		PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-bundle"})
	_, noHash := mintCert(t, ca.cert, ca.key, "agent-nohash", big.NewInt(3104), &noHashAIC, nil, nil)
	if err := VerifyPrincipalKeyHash(noHash, principal); err == nil || !strings.Contains(err.Error(), "no keyHash") {
		t.Errorf("empty keyHash = %v, want no-keyHash error", err)
	}

	if err := VerifyPrincipalKeyHash(nil, principal); err == nil {
		t.Error("nil agent accepted")
	}
}

func TestCredentialBundleVerify(t *testing.T) {
	ca := newHTTPTestCA(t)
	_, principal := mintCert(t, ca.cert, ca.key, "user-bundle", big.NewInt(3201), nil, nil, nil)
	principalHash := sha256.Sum256(principal.RawSubjectPublicKeyInfo)
	aic := baseDelegationAIC("agent-bundle", caps("std/database-v1", "query:SELECT"),
		PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-bundle", KeyHash: principalHash[:], HashAlgo: AlgorithmIdentifier{Algorithm: pki.OIDSHA256}})
	_, agent := mintCert(t, ca.cert, ca.key, "agent-bundle", big.NewInt(3202), &aic, nil, nil)

	bundle, err := NewCredentialBundle(
		[]*x509.Certificate{agent, ca.cert},
		[]*x509.Certificate{principal, ca.cert},
		[]*x509.Certificate{ca.cert},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyBundle(bundle, ca.pool); err != nil {
		t.Errorf("valid dual-chain bundle rejected: %v", err)
	}
	if err := VerifyBundle(nil, ca.pool); err == nil {
		t.Error("nil bundle accepted")
	}
	if err := VerifyBundle(bundle, nil); err == nil || !strings.Contains(err.Error(), "no trust roots") {
		t.Errorf("nil roots = %v, want no-trust-roots error", err)
	}
	// Non-nil but CA-less roots: the chains cannot anchor → fail closed.
	foreignRoots := x509.NewCertPool()
	if err := VerifyBundle(bundle, foreignRoots); err == nil {
		t.Error("bundle verified against unrelated roots")
	}
}

func TestCredentialBundleIntermediatePool(t *testing.T) {
	if pool := intermediatesPool(nil); pool != nil {
		t.Error("empty intermediate list must yield nil pool")
	}
	ca := newHTTPTestCA(t)
	pool := intermediatesPool([]*x509.Certificate{ca.cert})
	if pool == nil || len(pool.Subjects()) == 0 {
		t.Error("non-empty intermediate list must yield a populated pool")
	}
}

func TestCredentialBundleParsePEM(t *testing.T) {
	if _, err := ParseCredentialBundlePEM([]byte("this is not a PEM block")); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Errorf("bad PEM error = %v, want no-certificates error", err)
	}

	ca := newHTTPTestCA(t)
	agentAIC := baseDelegationAIC("agent-bundle", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-bundle"})
	_, agent := mintCert(t, ca.cert, ca.key, "agent-bundle", big.NewInt(3301), &agentAIC, nil, nil)
	paDER, err := asn1.Marshal(pki.PrincipalAuthorization{Version: 1, Grants: []pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, principal := mintCert(t, ca.cert, ca.key, "user-bundle", big.NewInt(3302), nil, nil, []pkix.Extension{{Id: pki.OIDPrincipalAuthorization, Value: paDER}})

	var pemBuf bytes.Buffer
	for _, c := range []*x509.Certificate{agent, principal, ca.cert} {
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	bundle, err := ParseCredentialBundlePEM(pemBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseCredentialBundlePEM: %v", err)
	}
	if !bytes.Equal(bundle.Agent().Raw, agent.Raw) {
		t.Error("agent cert (AIC) not classified into AgentChain")
	}
	if !bytes.Equal(bundle.Principal().Raw, principal.Raw) {
		t.Error("principal cert (PA) not classified into PrincipalChain")
	}
	if len(bundle.CACerts) != 1 || !bytes.Equal(bundle.CACerts[0].Raw, ca.cert.Raw) {
		t.Errorf("CACerts = %d entries, want the plain CA cert", len(bundle.CACerts))
	}
}

// ---- 3. delegation_chain ---------------------------------------------------

func TestDelegationCapabilityID(t *testing.T) {
	tests := []struct {
		name string
		cap  Capability
		want string
	}{
		{"with-scheme", Capability{SchemeId: "db", CapabilityId: "query:SELECT"}, "db:query:SELECT"},
		{"without-scheme", Capability{CapabilityId: "query:SELECT"}, "query:SELECT"},
	}
	for _, tc := range tests {
		if got := capabilityID(tc.cap); got != tc.want {
			t.Errorf("%s: capabilityID = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDelegationCapabilityCovered(t *testing.T) {
	leaf := Capability{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}
	tests := []struct {
		name     string
		leaf     Capability
		ancestor Capability
		want     bool
	}{
		{"exact-equal", leaf, leaf, true},
		{"ancestor-wildcard-glob", leaf, Capability{SchemeId: "std/database-v1", CapabilityId: "query:*"}, true},
		{"ancestor-path-prefix", leaf, Capability{SchemeId: "std/database-v1", CapabilityId: "query"}, true},
		{"different-scheme", leaf, Capability{SchemeId: "telemetry", CapabilityId: "query"}, false},
		{"disjoint", leaf, Capability{SchemeId: "std/database-v1", CapabilityId: "write"}, false},
	}
	for _, tc := range tests {
		if got := capabilityCovered(tc.leaf, tc.ancestor); got != tc.want {
			t.Errorf("%s: capabilityCovered = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDelegationCapabilitySubset(t *testing.T) {
	db := func(id string) Capability { return Capability{SchemeId: "std/database-v1", CapabilityId: id} }
	single := func(id string) []Capability { return []Capability{db(id)} }
	tests := []struct {
		name     string
		subset   []Capability
		superset []Capability
		want     bool
	}{
		{"empty-subset-any-superset", nil, nil, true},
		{"nonempty-subset-empty-superset", single("query:SELECT"), nil, false},
		{"exact", single("query:SELECT"), single("query:SELECT"), true},
		{"wildcard-superset", single("query:SELECT"), single("query:*"), true},
		{"missing-capability", single("query:UPDATE"), single("query:SELECT"), false},
		{"scheme-mismatch", single("query:SELECT"), []Capability{{SchemeId: "telemetry", CapabilityId: "query:*"}}, false},
	}
	for _, tc := range tests {
		if got := capabilitySubset(tc.subset, tc.superset); got != tc.want {
			t.Errorf("%s: capabilitySubset = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDelegationFilterCovered(t *testing.T) {
	db := func(id string) []Capability {
		return []Capability{{SchemeId: "std/database-v1", CapabilityId: id}}
	}
	// Both entries kept: exact match + wildcard ancestor coverage.
	leaf := append(db("query:SELECT"), db("query:INSERT")...)
	ancestor := db("query:*")
	got := filterCovered(leaf, ancestor)
	if len(got) != 2 {
		t.Fatalf("filterCovered = %d entries, want 2", len(got))
	}
	for i, want := range []string{"std/database-v1:query:SELECT", "std/database-v1:query:INSERT"} {
		if got[i].FullID() != want {
			t.Errorf("filterCovered[%d] = %s, want %s", i, got[i].FullID(), want)
		}
	}
	// Uncovered leaves drop out.
	drop := filterCovered(append(db("query:SELECT"), db("write:DELETE")...), db("query:*"))
	if len(drop) != 1 || drop[0].FullID() != "std/database-v1:query:SELECT" {
		t.Errorf("filterCovered with unrelated leaf = %+v, want only query:SELECT", drop)
	}
	if filterCovered(nil, ancestor) != nil || filterCovered(leaf, nil) != nil {
		t.Error("nil leaf or ancestor must yield nil")
	}
}

func TestDelegationVerifyChainStructure(t *testing.T) {
	_, a := mintCert(t, nil, nil, "a", big.NewInt(1), nil, nil, nil)
	_, b := mintCert(t, nil, nil, "b", big.NewInt(2), nil, nil, nil)
	_, dup := mintCert(t, nil, nil, "a-dup", big.NewInt(1), nil, nil, nil)

	if err := verifyChainStructure(nil, 0); err == nil || !strings.Contains(err.Error(), "empty chain") {
		t.Errorf("empty chain error = %v, want empty-chain", err)
	}
	if err := verifyChainStructure([]*x509.Certificate{a, b}, 1); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("over-length chain error = %v, want length error", err)
	}
	if err := verifyChainStructure([]*x509.Certificate{a, nil}, 0); err == nil || !strings.Contains(err.Error(), "nil certificate") {
		t.Errorf("nil cert error = %v, want nil-certificate", err)
	}
	if err := verifyChainStructure([]*x509.Certificate{a, dup}, 0); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("duplicate serial error = %v, want cycle", err)
	}
	if err := verifyChainStructure([]*x509.Certificate{a, b}, 0); err != nil {
		t.Errorf("valid chain rejected: %v", err)
	}
}

func TestDelegationEffectiveCapabilities(t *testing.T) {
	aic0 := baseDelegationAIC("scheduler-a", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-a"})
	aic0.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, c0 := mintCert(t, nil, nil, "scheduler-a", big.NewInt(4101), &aic0, nil, nil)

	// Level 2 narrows the parameters but keeps the same capability id.
	aic1 := baseDelegationAIC("worker-b", []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":5}`)}}, PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-b"})
	aic1.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, c1 := mintCert(t, nil, nil, "worker-b", big.NewInt(4102), &aic1, nil, nil)

	principalCaps := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}}
	eff, err := EffectiveDelegationCapabilities([]*x509.Certificate{c0, c1}, principalCaps, DefaultMaxChainLength)
	if err != nil {
		t.Fatalf("effective capabilities: %v", err)
	}
	if len(eff) != 1 || eff[0].FullID() != "std/database-v1:query:SELECT" {
		t.Errorf("effective = %+v, want the intersected query:SELECT", eff)
	}

	// Escalation: a level declaring a cap outside the parent effective set is rejected.
	aicEsc := baseDelegationAIC("worker-c", caps("telemetry", "read:metrics"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-c"})
	aicEsc.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, cEsc := mintCert(t, nil, nil, "worker-c", big.NewInt(4103), &aicEsc, nil, nil)
	if _, err := EffectiveDelegationCapabilities([]*x509.Certificate{c0, cEsc}, principalCaps, DefaultMaxChainLength); err == nil || !strings.Contains(err.Error(), "escalation") {
		t.Errorf("escalation error = %v, want permission-escalation", err)
	}

	// Empty intersection at a level ⇒ C_eff empty and the chain is rejected.
	aicEmpty := baseDelegationAIC("worker-d", nil, PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-d"})
	aicEmpty.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, cEmpty := mintCert(t, nil, nil, "worker-d", big.NewInt(4104), &aicEmpty, nil, nil)
	if _, err := EffectiveDelegationCapabilities([]*x509.Certificate{c0, cEmpty}, principalCaps, DefaultMaxChainLength); err == nil || !strings.Contains(err.Error(), "empty effective capabilities") {
		t.Errorf("empty C_eff error = %v, want empty-effective error", err)
	}
}

func TestDelegationFromAIC(t *testing.T) {
	principalAIC := baseDelegationAIC("principal", caps("std/database-v1", "query:*"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "owner"})
	principalAIC.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, top := mintCert(t, nil, nil, "principal", big.NewInt(4201), &principalAIC, nil, nil)

	if _, err := EffectiveDelegationCapabilitiesFromAIC(nil, nil, 0); err == nil {
		t.Error("nil top principal accepted")
	}

	chainAIC := baseDelegationAIC("scheduler-a", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-a"})
	chainAIC.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, c := mintCert(t, nil, nil, "scheduler-a", big.NewInt(4202), &chainAIC, nil, nil)

	eff, err := EffectiveDelegationCapabilitiesFromAIC([]*x509.Certificate{c}, top, DefaultMaxChainLength)
	if err != nil {
		t.Fatalf("from AIC: %v", err)
	}
	if len(eff) != 1 || eff[0].FullID() != "std/database-v1:query:SELECT" {
		t.Errorf("effective from AIC = %+v, want query:SELECT", eff)
	}
}

func TestDelegationChainWithCaps(t *testing.T) {
	workerCaps := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":5}`)}}
	_, topCert, chain := buildSignedChain(t, workerCaps)
	principalCaps := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}}

	eff, err := VerifyDelegationChainWithCaps(chain, topCert, principalCaps, 3, 0)
	if err != nil {
		t.Fatalf("valid signed chain rejected: %v", err)
	}
	if len(eff) != 1 || eff[0].FullID() != "std/database-v1:query:SELECT" {
		t.Errorf("effective = %+v, want query:SELECT", eff)
	}

	// Escalating worker capability must be denied even though every DA signature
	// is valid: permissions only decrease down the chain.
	_, topEsc, chainEsc := buildSignedChain(t, caps("telemetry", "read:metrics"))
	if _, err := VerifyDelegationChainWithCaps(chainEsc, topEsc, principalCaps, 3, 0); err == nil {
		t.Error("escalating chain accepted")
	}
}

// ---- 4. decision.go pure helpers ------------------------------------------

func TestVerifyDelegationAuth(t *testing.T) {
	key, signerCert := mintCert(t, nil, nil, "principal.user", big.NewInt(5000), nil, nil, nil)
	principalHash := make([]byte, sha256.Size)
	copy(principalHash, []byte("principal-spki-hash-0000000000000000000000000"))
	keyHash := sha256.Sum256(signerCert.RawSubjectPublicKeyInfo)

	mkAIC := func(principal PrincipalUid) AIC {
		aic := baseDelegationAIC("scheduler-a", caps("std/database-v1", "query:SELECT"), principal)
		aic.DelegationAuthorization.SignatureValue = signDADigest(t, key, &aic)
		return aic
	}

	valid := mkAIC(PrincipalUid{Version: 1, Realm: "pki", Identifier: "alice", KeyHash: keyHash[:], HashAlgo: AlgorithmIdentifier{Algorithm: pki.OIDSHA256}})
	if err := VerifyDelegationAuth(&valid, signerCert); err != nil {
		t.Errorf("valid DA rejected: %v", err)
	}

	if err := VerifyDelegationAuth(nil, signerCert); err == nil {
		t.Error("nil AIC accepted")
	}
	if err := VerifyDelegationAuth(&valid, nil); err == nil {
		t.Error("nil user cert accepted")
	}
	noSig := baseDelegationAIC("scheduler-a", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "alice"})
	noSig.DelegationAuthorization.SignatureValue = nil
	if err := VerifyDelegationAuth(&noSig, signerCert); err == nil || !strings.Contains(err.Error(), "empty signature") {
		t.Errorf("empty signature error = %v", err)
	}

	// Wrong signer: signature made by a different key must fail.
	_, wrongKey := mintCert(t, nil, nil, "attacker", big.NewInt(5001), nil, nil, nil)
	if err := VerifyDelegationAuth(&valid, wrongKey); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("wrong-signer error = %v, want signature failure", err)
	}

	// keyHash mismatch is fail-closed.
	badKHash := mkAIC(PrincipalUid{Version: 1, Realm: "pki", Identifier: "alice", KeyHash: principalHash, HashAlgo: AlgorithmIdentifier{Algorithm: pki.OIDSHA256}})
	if err := VerifyDelegationAuth(&badKHash, signerCert); err == nil || !strings.Contains(err.Error(), "SPKI hash mismatch") {
		t.Errorf("keyHash mismatch error = %v, want SPKI hash mismatch", err)
	}

	// Unsupported signature algorithm OID (ECDSA key + RSA OID) fails.
	rsaOID := baseDelegationAIC("scheduler-a", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "alice", KeyHash: keyHash[:], HashAlgo: AlgorithmIdentifier{Algorithm: pki.OIDSHA256}})
	rsaOID.DelegationAuthorization.SignatureValue = []byte{0x01}
	rsaOID.DelegationAuthorization.SignatureAlgorithm = AlgorithmIdentifier{Algorithm: pki.OIDSigRSAWithSHA256}
	if err := VerifyDelegationAuth(&rsaOID, signerCert); err == nil {
		t.Error("RSA OID on an ECDSA key accepted")
	}
}

func TestVerifyDelegationChain(t *testing.T) {
	_, topCert, chain := buildSignedChain(t, caps("std/database-v1", "query:SELECT"))

	if err := VerifyDelegationChain(chain, topCert, 3); err != nil {
		t.Errorf("valid signed chain rejected: %v", err)
	}
	if err := VerifyDelegationChain(chain, topCert, 1); err == nil {
		t.Error("chain beyond max depth accepted")
	}
	if err := VerifyDelegationChain(nil, topCert, 3); err == nil || !strings.Contains(err.Error(), "empty chain") {
		t.Errorf("empty chain error = %v", err)
	}
	if err := VerifyDelegationChain(chain, nil, 3); err == nil || !strings.Contains(err.Error(), "nil top principal") {
		t.Errorf("nil principal error = %v", err)
	}

	var nilVerifier *DelegationChainVerifier
	if err := nilVerifier.Verify(chain, topCert); err == nil {
		t.Error("nil verifier accepted")
	}
}

func TestCheckDAFreshness(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	if err := CheckDAFreshness(time.Time{}, now, 0); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("zero timestamp error = %v", err)
	}
	if err := CheckDAFreshness(now.Add(-10*time.Second), now, 30*time.Second); err != nil {
		t.Errorf("fresh DA rejected: %v", err)
	}
	if err := CheckDAFreshness(now.Add(-60*time.Second), now, 30*time.Second); err == nil || !strings.Contains(err.Error(), "outside freshness window") {
		t.Errorf("stale DA error = %v", err)
	}
	// Future timestamps are bounded by the absolute difference too.
	if err := CheckDAFreshness(now.Add(10*time.Second), now, 30*time.Second); err != nil {
		t.Errorf("future-but-fresh DA rejected: %v", err)
	}
	// maxAge <= 0 uses DefaultDAAgeMax.
	if err := CheckDAFreshness(now.Add(-5*time.Second), now, 0); err != nil {
		t.Errorf("fresh DA with default window rejected: %v", err)
	}
	if err := CheckDAFreshness(now.Add(-time.Minute), now, 0); err == nil {
		t.Error("stale DA accepted with default window")
	}
}

func TestHasDelegatedAgentOU(t *testing.T) {
	if HasDelegatedAgentOU(newPlainCert(t)) {
		t.Error("plain certificate flagged as Delegated-Agent")
	}
	if hasDelegatedAgentOU(&x509.Certificate{}) {
		t.Error("empty certificate flagged as Delegated-Agent")
	}
	delegated := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent"}}}
	if !hasDelegatedAgentOU(delegated) {
		t.Error("Delegated-Agent OU not recognized")
	}
	if !HasDelegatedAgentOU(delegated) {
		t.Error("exported HasDelegatedAgentOU disagrees with internal check")
	}
	if hasDelegatedAgentOU(nil) {
		t.Error("nil certificate flagged as Delegated-Agent")
	}
}

func TestCheckDelegatedAgentCert(t *testing.T) {
	if got := CheckDelegatedAgentCert(newPlainCert(t)); got != "" {
		t.Errorf("plain cert rejected: %q", got)
	}
	// OU without core-signed AIC is illegitimate (finding 17).
	ouOnly := &x509.Certificate{
		Subject:   pkix.Name{OrganizationalUnit: []string{"Delegated-Agent"}},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	if got := CheckDelegatedAgentCert(ouOnly); !strings.Contains(got, "lacks a valid core-signed AIC") {
		t.Errorf("OU-only cert rejection = %q", got)
	}
	// OU plus validity window plus AIC is legitimate.
	aic := baseDelegationAIC("agent-x", caps("std/database-v1", "query:SELECT"), PrincipalUid{Version: 1, Realm: "pki", Identifier: "user-x"})
	aic.DelegationAuthorization.SignatureValue = []byte{0x01}
	_, valid := mintCert(t, nil, nil, "agent-x", big.NewInt(6001), &aic, []string{"Delegated-Agent"}, nil)
	if got := CheckDelegatedAgentCert(valid); got != "" {
		t.Errorf("valid delegated-agent cert rejected: %q", got)
	}
	if got := CheckDelegatedAgentCert(nil); got != "nil certificate" {
		t.Errorf("nil cert rejection = %q", got)
	}
}

func TestCheckDelegatedAgentHeaders(t *testing.T) {
	delegated := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"Delegated-Agent"}}}

	if got := CheckDelegatedAgentHeaders(newPlainCert(t), &http.Request{}); got != "" {
		t.Errorf("plain cert rejected: %q", got)
	}
	req := &http.Request{Header: http.Header{}}
	if got := CheckDelegatedAgentHeaders(delegated, req); !strings.Contains(got, "X-Agent-User header required") {
		t.Errorf("missing user header rejection = %q", got)
	}
	req.Header.Set("X-Agent-User", "alice")
	if got := CheckDelegatedAgentHeaders(delegated, req); !strings.Contains(got, "X-Agent-TTL header required") {
		t.Errorf("missing TTL header rejection = %q", got)
	}
	req.Header.Set("X-Agent-TTL", "not-a-time")
	if got := CheckDelegatedAgentHeaders(delegated, req); !strings.Contains(got, "invalid X-Agent-TTL") {
		t.Errorf("invalid TTL rejection = %q", got)
	}
	req.Header.Set("X-Agent-TTL", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if got := CheckDelegatedAgentHeaders(delegated, req); got != "" {
		t.Errorf("valid headers rejected: %q", got)
	}
	req.Header.Set("X-Agent-TTL", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if got := CheckDelegatedAgentHeaders(delegated, req); !strings.Contains(got, "expired") {
		t.Errorf("expired TTL rejection = %q", got)
	}
}

func TestDelegatedAgentServerIdentity(t *testing.T) {
	notAfter := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	delegated := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "delegate", OrganizationalUnit: []string{"Delegated-Agent"}},
		NotAfter: notAfter,
	}

	user, expiry, reason := DelegatedAgentServerIdentity(delegated, "alice")
	if user != "alice" || !expiry.Equal(notAfter) || reason != "" {
		t.Errorf("with principal = (%q, %v, %q)", user, expiry, reason)
	}
	user, expiry, reason = DelegatedAgentServerIdentity(delegated, "")
	if user != "delegate" || !expiry.Equal(notAfter) || reason != "" {
		t.Errorf("fallback principal = (%q, %v, %q)", user, expiry, reason)
	}
	user, expiry, reason = DelegatedAgentServerIdentity(&x509.Certificate{}, "")
	if user != "" || !expiry.IsZero() || reason != "" {
		t.Errorf("plain cert = (%q, %v, %q), want all zero", user, expiry, reason)
	}
}

func TestLogAdmission(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	LogAdmission(AdmissionResult{Decision: DecisionDeny, PrincipalUid: "p:alice", Reason: "missing capability"}, "10.0.0.1", logger)
	out := buf.String()
	for _, needle := range []string{"admission: deny", "client_ip=10.0.0.1", "principal=p:alice", "missing capability"} {
		if !strings.Contains(out, needle) {
			t.Errorf("deny log missing %q:\n%s", needle, out)
		}
	}

	buf.Reset()
	LogAdmission(AdmissionResult{Decision: DecisionAllow, PrincipalUid: "p:bob"}, "10.0.0.2", logger)
	if out := buf.String(); !strings.Contains(out, "admission: allow") {
		t.Errorf("allow log missing admission: allow:\n%s", out)
	}

	// nil logger falls back to slog.Default() (must not panic).
	buf.Reset()
	LogAdmission(AdmissionResult{Decision: DecisionAllow}, "10.0.0.3", nil)
}

func TestValidateCapSizeConstraints(t *testing.T) {
	if err := validateCapSizeConstraints(nil); err != nil {
		t.Errorf("nil caps error: %v", err)
	}
	if err := validateCapSizeConstraints(caps("std/database-v1", "query:SELECT")); err != nil {
		t.Errorf("valid caps error: %v", err)
	}
	if err := validateCapSizeConstraints([]Capability{{SchemeId: "", CapabilityId: "x"}}); err == nil {
		t.Error("empty schemeId accepted")
	}
	if err := validateCapSizeConstraints([]Capability{{SchemeId: strings.Repeat("a", 129), CapabilityId: "x"}}); err == nil {
		t.Error("over-long schemeId accepted")
	}
	if err := validateCapSizeConstraints([]Capability{{SchemeId: "s", CapabilityId: strings.Repeat("b", 257)}}); err == nil {
		t.Error("over-long capabilityId accepted")
	}
	if err := validateCapSizeConstraints([]Capability{{SchemeId: "s", CapabilityId: "x", Parameters: make([]byte, 4097)}}); err == nil {
		t.Error("over-long parameters accepted")
	}
}

func TestNeedRevoke(t *testing.T) {
	if !NeedRevoke(&x509.Certificate{NotAfter: time.Now().Add(time.Hour)}) {
		t.Error("unexpired certificate should be flagged for proactive revocation")
	}
	if NeedRevoke(&x509.Certificate{NotAfter: time.Now().Add(-time.Hour)}) {
		t.Error("expired certificate flagged for proactive revocation")
	}
	if NeedRevoke(nil) {
		t.Error("nil certificate flagged for proactive revocation")
	}
}

func TestEffectiveCapabilities(t *testing.T) {
	declared := []Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT", Parameters: []byte(`{"limit":10}`)}}
	got := effectiveCapabilities(declared, []string{"std/database-v1:query:SELECT"})
	if len(got) != 1 || !bytes.Equal(got[0].Parameters, declared[0].Parameters) {
		t.Errorf("effectiveCapabilities = %+v, want the declared cap preserved with parameters", got)
	}
	if got := effectiveCapabilities(declared, []string{"std/database-v1:query:UPDATE"}); got != nil {
		t.Errorf("disjoint grants = %+v, want nil", got)
	}
	if got := effectiveCapabilities(declared, []string{"telemetry:read"}); got != nil {
		t.Errorf("foreign scheme = %+v, want nil", got)
	}
}

func TestParseTimeParts(t *testing.T) {
	if h, m, ok := parseTimeParts("09:30"); !ok || h != 9 || m != 30 {
		t.Errorf("parseTimeParts(09:30) = %d,%d,%v", h, m, ok)
	}
	if h, m, ok := parseTimeParts("23:59"); !ok || h != 23 || m != 59 {
		t.Errorf("parseTimeParts(23:59) = %d,%d,%v", h, m, ok)
	}
	for _, bad := range []string{"24:00", "23:60", "9:30", "0930", "", "ab:cd"} {
		if _, _, ok := parseTimeParts(bad); ok {
			t.Errorf("parseTimeParts(%q) accepted", bad)
		}
	}
}

func TestIsKnownConstraintType(t *testing.T) {
	if !isKnownConstraintType(ConstraintTimeWindowKey) {
		t.Error("built-in time:window reported unknown")
	}
	if !isKnownConstraintType(ConstraintCIDRKey) {
		t.Error("built-in network:cidr reported unknown")
	}
	if isKnownConstraintType("madeup:does-not-exist") {
		t.Error("unregistered constraint reported known")
	}
}

func TestFirstUnknownConstraint(t *testing.T) {
	allKnown := []Capability{
		{SchemeId: "constraint", CapabilityId: ConstraintTimeWindowKey},
		{SchemeId: "constraint-v1", CapabilityId: ConstraintCIDRKey},
	}
	if u := firstUnknownConstraint(allKnown); u != nil {
		t.Errorf("all-known constraints reported unknown: %+v", u)
	}
	// Business capabilities are not constraint entries and are skipped.
	if u := firstUnknownConstraint([]Capability{{SchemeId: "std/database-v1", CapabilityId: "query:SELECT"}}); u != nil {
		t.Errorf("business capability reported as unknown constraint: %+v", u)
	}
	withUnknown := []Capability{
		{SchemeId: "constraint", CapabilityId: ConstraintTimeWindowKey},
		{SchemeId: "constraint-v1", CapabilityId: "madeup:x"},
	}
	u := firstUnknownConstraint(withUnknown)
	if u == nil || u.CapabilityId != "madeup:x" {
		t.Errorf("unknown constraint = %+v, want madeup:x", u)
	}

	if r := admissionConstraintRegistry(AdmissionConfig{}); r == nil {
		t.Error("admissionConstraintRegistry returned nil for the default (global) config")
	}
	if r := admissionConstraintRegistry(AdmissionConfig{ConstraintRegistry: NewConstraintRegistry()}); r == nil {
		t.Error("admissionConstraintRegistry ignored the per-config registry")
	}
}

func TestAICCapabilityMatchPriority(t *testing.T) {
	tests := []struct {
		name string
		caps []Capability
		req  string
		want int
	}{
		{"exact-no-scheme", []Capability{{CapabilityId: "db:query:SELECT"}}, "db:query:SELECT", pki.MatchPriorityExact},
		{"exact-with-scheme", caps("db", "query:SELECT"), "db:query:SELECT", pki.MatchPriorityExact},
		{"single-segment-wildcard", []Capability{{CapabilityId: "db:query:*"}}, "db:query:SELECT", pki.MatchPrioritySingle},
		{"multi-segment-wildcard", []Capability{{CapabilityId: "db:**"}}, "db:query:SELECT", pki.MatchPriorityMulti},
		{"scheme-wildcard", []Capability{{CapabilityId: "*:query:SELECT"}}, "db:query:SELECT", pki.MatchPriorityScheme},
		{"global-wildcard", []Capability{{CapabilityId: "*"}}, "db:query:SELECT", pki.MatchPriorityGlobal},
		{"no-match", []Capability{{CapabilityId: "other:x"}}, "db:query:SELECT", pki.MatchPriorityNoMatch},
		{"no-match-combined-scheme", caps("db", "query:SELECT"), "telemetry:read", pki.MatchPriorityNoMatch},
	}
	for _, tc := range tests {
		if got := aicCapabilityMatchPriority(tc.caps, tc.req); got != tc.want {
			t.Errorf("%s: priority = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestAICCapabilityDecision(t *testing.T) {
	allow := caps("std/database-v1", "query:SELECT")
	if !aicCapabilityDecision(allow, "std/database-v1:query:SELECT", nil) {
		t.Error("exact allow match denied")
	}
	if aicCapabilityDecision(allow, "std/database-v1:query:UPDATE", nil) {
		t.Error("unmatched request allowed")
	}

	// deny rules override allow (deny overrides allow at equal priority).
	if aicCapabilityDecision(allow, "std/database-v1:query:SELECT", []string{"std/database-v1:query:SELECT"}) {
		t.Error("explicit deny rule overridden by allow")
	}
	// An unrelated deny rule leaves the allow match intact.
	if !aicCapabilityDecision(allow, "std/database-v1:query:SELECT", []string{"telemetry:read"}) {
		t.Error("unrelated deny rule blocked an allowed capability")
	}
	// With deny rules present, a request matching nothing fails closed.
	if aicCapabilityDecision(allow, "std/database-v1:query:UPDATE", []string{"telemetry:read"}) {
		t.Error("unmatched request allowed when deny rules configured")
	}
}

func TestAdmissionConfigValidate(t *testing.T) {
	if err := (AdmissionConfig{}).Validate(); err != nil {
		t.Errorf("default config: %v", err)
	}
	if err := (AdmissionConfig{DisallowRepresentative: true, RequireAIC: true}).Validate(); err != nil {
		t.Errorf("valid representative config: %v", err)
	}
	if err := (AdmissionConfig{RequireUserPermission: true, RequireAIC: true}).Validate(); err != nil {
		t.Errorf("valid user-permission config: %v", err)
	}
	if err := (AdmissionConfig{DisallowRepresentative: true}).Validate(); err == nil {
		t.Error("disallow_representative without require_aic accepted")
	}
	if err := (AdmissionConfig{RequireUserPermission: true}).Validate(); err == nil {
		t.Error("require_user_permission without require_aic accepted")
	}
}

// ---- 5. trust_model.go -----------------------------------------------------

func TestTrustLayerString(t *testing.T) {
	if Layer1Identity.String() != "identity" {
		t.Errorf("Layer1.String() = %q", Layer1Identity.String())
	}
	if Layer2Representation.String() != "representation" {
		t.Errorf("Layer2.String() = %q", Layer2Representation.String())
	}
	if Layer3OnlineAuthorization.String() != "online_authorization" {
		t.Errorf("Layer3.String() = %q", Layer3OnlineAuthorization.String())
	}
	if got := TrustLayer(99).String(); got != "unknown" {
		t.Errorf("unknown layer String() = %q", got)
	}
}

func TestVerifyLayer1(t *testing.T) {
	cfg := &PipelineConfig{}
	if res := VerifyLayer1(nil, cfg); res.Verified || !strings.Contains(res.Reason, "no client certificate") {
		t.Errorf("empty chain result = %+v", res)
	}

	valid := newPlainCert(t)
	if res := VerifyLayer1([]*x509.Certificate{valid}, cfg); !res.Verified {
		t.Errorf("valid chain rejected: %+v", res)
	}

	expired := &x509.Certificate{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}
	if res := VerifyLayer1([]*x509.Certificate{expired}, cfg); res.Verified || !strings.Contains(res.Reason, "expired") {
		t.Errorf("expired chain result = %+v", res)
	}

	roleCfg := &PipelineConfig{AllowRoles: []string{"admin"}}
	res := VerifyLayer1([]*x509.Certificate{valid}, roleCfg)
	if res.Verified || !strings.Contains(res.Reason, "insufficient roles") {
		t.Errorf("role-miss result = %+v", res)
	}
}

func TestVerifyLayer2(t *testing.T) {
	plain := newPlainCert(t)
	if _, res := VerifyLayer2(nil, &PipelineConfig{}, nil); res.Verified || !strings.Contains(res.Reason, "no client certificate") {
		t.Errorf("empty chain L2 = %+v", res)
	}
	if _, res := VerifyLayer2([]*x509.Certificate{plain}, &PipelineConfig{}, nil); !res.Verified {
		t.Errorf("plain cert with require_aic=false rejected at L2: %+v", res)
	}
	admit, res := VerifyLayer2([]*x509.Certificate{plain}, &PipelineConfig{RequireAIC: true}, nil)
	if res.Verified || admit.Decision != DecisionDeny || !strings.Contains(res.Reason, "aic extension required") {
		t.Errorf("require_aic L2 result = %+v / %+v", admit, res)
	}
}

func TestVerifyLayer3(t *testing.T) {
	plain := newPlainCert(t)
	if res := VerifyLayer3(nil, &PipelineConfig{}); res.Verified || !strings.Contains(res.Reason, "no client certificate") {
		t.Errorf("empty chain L3 = %+v", res)
	}
	if res := VerifyLayer3([]*x509.Certificate{plain}, &PipelineConfig{}); !res.Verified {
		t.Errorf("no-cache chain rejected at L3: %+v", res)
	}
	if res := VerifyLayer3([]*x509.Certificate{plain}, &PipelineConfig{CheckScope: CheckLeafOnly}); !res.Verified {
		t.Errorf("leaf-only chain rejected at L3: %+v", res)
	}
}

func TestCheckRevocation(t *testing.T) {
	if err := checkRevocation(newPlainCert(t), nil, &PipelineConfig{}); err != nil {
		t.Errorf("revocation check without caches failed: %v", err)
	}
}

func TestVerifyTrustLayers(t *testing.T) {
	if res := VerifyTrustLayers([]*x509.Certificate{newPlainCert(t)}, nil); res.Granted || !strings.Contains(res.DenyReason, "nil pipeline config") {
		t.Errorf("nil config result = %+v", res)
	}

	plain := newPlainCert(t)
	res := VerifyTrustLayers([]*x509.Certificate{plain}, &PipelineConfig{})
	if !res.Granted {
		t.Errorf("trusted chain denied: %+v", res)
	}
	if res.Serial == "" {
		t.Error("result carries no certificate serial")
	}

	denied := VerifyTrustLayers([]*x509.Certificate{plain}, &PipelineConfig{RequireAIC: true})
	if denied.Granted || !strings.Contains(denied.DenyReason, "aic extension required") {
		t.Errorf("require_aic denial = %+v", denied)
	}
}
