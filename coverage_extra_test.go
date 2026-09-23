// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func TestMatchDoubleStar(t *testing.T) {
	good := []struct{ id, pattern string }{
		{"a/b/c/d", "a/**/d"},
		{"a/b/d", "a/**/d"},
		{"a/d", "a/**/d"},
		{"b/d", "**/d"},
		{"a/b", "a/**"},
		{"a/b/**/c", "a/**/c"},
	}
	for _, tc := range good {
		if !matchDoubleStar(tc.id, tc.pattern) {
			t.Errorf("matchDoubleStar(%q, %q) = false, want true", tc.id, tc.pattern)
		}
	}
	bad := []struct{ id, pattern string }{
		{"x/d", "a/**/d"},
		{"a/b", "a/**/d"},
		{"a/b/../d", "a/**/d"},
		{"a//b/d", "a/**/d"},
		{"a/b/c/d", "a/**/d/x"},
	}
	for _, tc := range bad {
		if matchDoubleStar(tc.id, tc.pattern) {
			t.Errorf("matchDoubleStar(%q, %q) = true, want false", tc.id, tc.pattern)
		}
	}
	// A pattern with != one "**" never matches the batch form.
	if matchDoubleStar("a/b", "a/**/**/b") {
		t.Fatal("double-star pattern with two batches matched")
	}
}

func TestErrorCodeString(t *testing.T) {
	cases := map[ErrorCode]string{
		ErrNoCredential:   "no_credential",
		ErrDenied:         "access_denied",
		ErrNoVerifier:     "bearer_not_configured",
		ErrBearerNeedsTLS: "bearer_tls_required",
		ErrInvalidBearer:  "invalid_bearer",
		ErrChainInvalid:   "chain_invalid",
		ErrorCode(999):    "config_error",
	}
	for code, want := range cases {
		if got := code.String(); got != want {
			t.Errorf("ErrorCode(%d).String() = %q, want %q", int(code), got, want)
		}
	}
}

func TestFromContextNilAndEmpty(t *testing.T) {
	if got := FromContext(nil); got != nil {
		t.Fatalf("FromContext(nil) = %+v, want nil", got)
	}
	if got := FromContext(context.Background()); got != nil {
		t.Fatalf("FromContext(background) = %+v, want nil", got)
	}
}

// caAndLeaf returns a CA and a client-auth leaf signed by it.
func caAndLeaf(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	return caCert, leafCert, leafKey, caKey
}

func TestBuildChain(t *testing.T) {
	caCert, leafCert, _, _ := caAndLeaf(t)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if err := buildChain(pool, []*x509.Certificate{leafCert, caCert}); err != nil {
		t.Fatalf("CA-issued chain should verify: %v", err)
	}
	if err := buildChain(nil, []*x509.Certificate{leafCert}); err == nil {
		t.Fatal("buildChain accepted a nil pool")
	}
	if err := buildChain(pool, nil); err == nil {
		t.Fatal("buildChain accepted an empty chain")
	}
	_, rogue, _, _ := caAndLeaf(t)
	if err := buildChain(pool, []*x509.Certificate{rogue}); err == nil {
		t.Fatal("buildChain verified a leaf from an unrelated CA")
	}
}

func TestLoadPEMIntoPool(t *testing.T) {
	dir := t.TempDir()
	caCert, _, _, _ := caAndLeaf(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	good := dir + "/ca.pem"
	if err := os.WriteFile(good, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if err := loadPEMIntoPool(pool, good); err != nil {
		t.Fatalf("loadPEMIntoPool: %v", err)
	}
	bad := dir + "/bad.pem"
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadPEMIntoPool(x509.NewCertPool(), bad); err == nil {
		t.Fatal("loadPEMIntoPool accepted a PEM without certificates")
	}
	if err := loadPEMIntoPool(x509.NewCertPool(), dir+"/missing.pem"); err == nil {
		t.Fatal("loadPEMIntoPool accepted a missing file")
	}
}

func TestDigestKey(t *testing.T) {
	if _, err := digestKey(semantics.Digest{Alg: "md5", Value: []byte("x")}); err == nil {
		t.Fatal("digestKey accepted md5")
	}
	if alg, err := digestKey(semantics.Digest{Alg: "sha-384"}); err != nil || alg != "sha384" {
		t.Fatalf("sha-384 = %q, %v", alg, err)
	}
	if alg, err := digestKey(dg("x")); err != nil || alg != "sha256" {
		t.Fatalf("sha256 = %q, %v", alg, err)
	}
}

func TestAdmissionRef(t *testing.T) {
	rec := NewAdmissionRecord(EvidenceContext{RecorderID: "pep"}, &AuthError{Code: ErrChainInvalid}, nil)
	ref, err := admissionRef(rec)
	if err != nil {
		t.Fatalf("admissionRef: %v", err)
	}
	if ref.Verdict != string(EvidenceRefused) || len(ref.Digest) != hex.EncodedLen(32) {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestNewAdmissionEnvelopeSkipsUnsupportedDigest(t *testing.T) {
	rec := NewAdmissionRecord(EvidenceContext{RecorderID: "pep"}, &AuthError{Code: ErrChainInvalid}, []AdmissionFact{
		{Type: "client-cert", Digest: semantics.Digest{Alg: "md5", Value: []byte("x")}},
	})
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatalf("NewAdmissionEnvelope: %v", err)
	}
	var st struct {
		Subject []json.RawMessage `json:"subject"`
	}
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Subject) != 0 {
		t.Fatalf("unsupported digest must be dropped from subjects, got %d", len(st.Subject))
	}
	// The predicate still carries the fact itself.
	var full struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(env.Payload, &full); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full.Predicate), "client-cert") {
		t.Fatal("fact must be preserved in the predicate")
	}
}

func TestParseAdmissionEnvelopeRejections(t *testing.T) {
	if _, err := ParseAdmissionEnvelope(semantics.Envelope{PayloadType: "application/bogus"}); err == nil {
		t.Fatal("accepted a wrong payload type")
	}
	badJSON := semantics.Envelope{PayloadType: semantics.PayloadTypeInToto, Payload: []byte("{")}
	if _, err := ParseAdmissionEnvelope(badJSON); err == nil {
		t.Fatal("accepted an unparseable payload")
	}
	wrongStmt := semantics.Envelope{
		PayloadType: semantics.PayloadTypeInToto,
		Payload:     []byte(`{"_type":"wrong","predicateType":"https://varwof.com/aic/v1/admission-record","predicate":{}}`),
	}
	if _, err := ParseAdmissionEnvelope(wrongStmt); err == nil {
		t.Fatal("accepted a statement with a wrong _type")
	}
	incomplete := semantics.Envelope{
		PayloadType: semantics.PayloadTypeInToto,
		Payload:     []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://varwof.com/aic/v1/admission-record","predicate":{"ver":"X","stage":"","outcome":""}}`),
	}
	if _, err := ParseAdmissionEnvelope(incomplete); err == nil {
		t.Fatal("accepted an incomplete record")
	}
}

func TestCheckEvidenceEnvelopeUnknownKind(t *testing.T) {
	env := semantics.Envelope{
		PayloadType: semantics.PayloadTypeInToto,
		Payload:     []byte(`{"_type":"x","predicateType":"nope","predicate":{}}`),
	}
	if _, err := CheckEvidenceEnvelope(env); err == nil {
		t.Fatal("unknown predicate type accepted")
	}
}

func TestEnvelopePredicateRoundTripViaJSON(t *testing.T) {
	rec := NewAdmissionRecord(EvidenceContext{RecorderID: "pep", Principal: "u"}, &AuthError{Code: ErrDenied}, nil)
	env, err := NewAdmissionEnvelope(rec)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	var back semantics.Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, err := ParseAdmissionEnvelope(back)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if got.Identity.Principal != "u" {
		t.Fatalf("principal = %q", got.Identity.Principal)
	}
}
