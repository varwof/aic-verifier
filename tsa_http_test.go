// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// ── tsa.go ───────────────────────────────────────────────────────────────────

func TestSetMaxTSTAge(t *testing.T) {
	tc := NewTSAClient("http://tsa.example")
	if want := time.Hour; tc.maxTSTAge != want {
		t.Fatalf("default maxTSTAge = %v, want %v", tc.maxTSTAge, want)
	}
	tc.SetMaxTSTAge(45 * time.Minute)
	if tc.maxTSTAge != 45*time.Minute {
		t.Fatalf("SetMaxTSTAge not applied: %v", tc.maxTSTAge)
	}
	var nilTC *TSAClient
	nilTC.SetMaxTSTAge(time.Minute) // must not panic
}

func TestSetCACert(t *testing.T) {
	_, cert := newTestTSACert(t)
	p := filepath.Join(t.TempDir(), "tsa-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	tc := NewTSAClient("http://tsa.example")
	if err := tc.SetCACert(p); err != nil {
		t.Fatalf("SetCACert: %v", err)
	}
	if tc.CACert == nil {
		t.Fatal("SetCACert must populate CACert")
	}
	if err := tc.SetCACert("/nonexistent-tsa-ca.pem"); err == nil {
		t.Fatal("SetCACert must error on a bad path")
	}
	if err := tc.SetCACert(""); err != nil {
		t.Fatalf("SetCACert with empty path must be a no-op: %v", err)
	}

	var nilTC *TSAClient
	if err := nilTC.SetCACert(p); err != nil {
		t.Fatalf("nil receiver SetCACert must be a no-op: %v", err)
	}
}

func TestMarshalTSARequest(t *testing.T) {
	hashed := sha256.Sum256([]byte("payload"))
	der, err := MarshalTSARequest(TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: oidSha256},
			HashedMessage: hashed[:],
		},
		CertReq: true,
	})
	if err != nil {
		t.Fatalf("MarshalTSARequest: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("TSA request DER must be non-empty")
	}
	// encoding/asn1 cannot unmarshal into *int (used by Nonce), so round-trip
	// through a mirror struct with the same layout and int nonce.
	var mirror struct {
		Version        int
		MessageImprint MessageImprint
		ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
		Nonce          int                   `asn1:"optional"`
		CertReq        bool                  `asn1:"optional,default:false"`
		Extensions     []asn1.RawValue       `asn1:"optional,set"`
	}
	rest, err := asn1.Unmarshal(der, &mirror)
	if err != nil {
		t.Fatalf("round-trip TimeStampReq unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after TimeStampReq: %d", len(rest))
	}
	if mirror.Version != 1 {
		t.Errorf("Version = %d, want 1", mirror.Version)
	}
	if !bytesEqual(mirror.MessageImprint.HashedMessage, hashed[:]) {
		t.Errorf("round-tripped imprint digest does not match")
	}
	if !mirror.CertReq {
		t.Error("CertReq = false, want true")
	}
}

func TestUnmarshalTimestampToken(t *testing.T) {
	key, cert := newTestTSACert(t)
	payload := []byte("timestamp me")
	token := buildTimeStampTokenRFC3161(t, payload, key, cert)

	tst, err := UnmarshalTimestampToken(token)
	if err != nil {
		t.Fatalf("UnmarshalTimestampToken: %v", err)
	}
	if tst == nil {
		t.Fatal("UnmarshalTimestampToken returned nil TSTInfo")
	}
	if tst.Version != 1 {
		t.Errorf("TSTInfo Version = %d, want 1", tst.Version)
	}
	imprint := sha256.Sum256(payload)
	if !bytesEqual(tst.MessageImprint.HashedMessage, imprint[:]) {
		t.Errorf("TSTInfo message imprint does not match the payload digest")
	}

	if _, err := UnmarshalTimestampToken([]byte("not a cms token")); err == nil {
		t.Fatal("UnmarshalTimestampToken must error on garbage input")
	}
}

// TestTSASignOverHTTP covers Sign + postTSA: the request is POSTed to the TSA
// endpoint and the DER token returned by the responder comes back out of Sign.
func TestTSASignOverHTTP(t *testing.T) {
	key, cert := newTestTSACert(t)
	payload := []byte("audit-entry")
	token := buildTimeStampToken(t, payload, key, cert)

	respDER, err := asn1.Marshal(TimeStampResp{
		Status:         PKIStatusInfo{Status: 0},
		TimeStampToken: asn1.RawValue{FullBytes: token},
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(respDER)
	}))
	defer srv.Close()

	tc := NewTSAClient(srv.URL)
	out, err := tc.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytesEqual(out, token) {
		t.Fatalf("Sign returned %d bytes, want the token (%d bytes)", len(out), len(token))
	}
	if gotCT != "application/timestamp-query" {
		t.Errorf("Content-Type = %q, want application/timestamp-query", gotCT)
	}
}

func TestTSASignStatusRejected(t *testing.T) {
	respDER, err := asn1.Marshal(TimeStampResp{Status: PKIStatusInfo{Status: 2}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(respDER)
	}))
	defer srv.Close()

	tc := NewTSAClient(srv.URL)
	if _, err := tc.Sign([]byte("payload")); err == nil {
		t.Fatal("Sign must reject a non-grant TSA status")
	} else if err.Error() != "TSA status: 2" {
		t.Fatalf("error = %q, want TSA status rejection", err)
	}
}

func TestTSASignUnreachableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()
	tc := NewTSAClient(deadURL)
	if _, err := tc.Sign([]byte("payload")); err == nil {
		t.Fatal("Sign must error when the TSA endpoint is unreachable")
	}
}

func TestTSASignFuncOverrideAndNilReceiver(t *testing.T) {
	tc := NewTSAClient("http://unused.example")
	tc.SignFunc = func(data []byte) ([]byte, error) {
		return append([]byte("custom:"), data...), nil
	}
	out, err := tc.Sign([]byte("x"))
	if err != nil {
		t.Fatalf("SignFunc path: %v", err)
	}
	if string(out) != "custom:x" {
		t.Fatalf("SignFunc output = %q, want custom:x", out)
	}

	var nilTC *TSAClient
	if _, err := nilTC.Sign(nil); err == nil {
		t.Fatal("nil receiver Sign must error")
	}
}

func TestVerifyRSASignatureRaw(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: &rsaKey.PublicKey}

	digest := sha256.Sum256([]byte("signed-data"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRSASignatureRaw(digest[:], sig, cert); err != nil {
		t.Fatalf("valid RSA signature must verify: %v", err)
	}

	wrong := sha256.Sum256([]byte("tampered-data"))
	if err := verifyRSASignatureRaw(wrong[:], sig, cert); err == nil {
		t.Fatal("a signature over a different digest must fail")
	}

	ecKey, _ := newTestTSACert(t)
	ecCert := &x509.Certificate{PublicKey: &ecKey.PublicKey}
	if err := verifyRSASignatureRaw(digest[:], sig, ecCert); err == nil {
		t.Fatal("a non-RSA certificate must be rejected")
	}
}

// bytesEqual avoids importing bytes solely for tiny slices.
func bytesEqual(a, b []byte) bool {
	return reflect.DeepEqual(a, b)
}
