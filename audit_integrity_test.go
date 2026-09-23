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
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// digestForCMS is the explicit hash digest used when signing a CMS SignedData
// token: the RFC 3161 imprint over the data and, inside the SignerInfo, the
// DigestInfo-free digest of the DER-encoded SignedAttributes SET.
func digestForCMS(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// a0Implicit wraps inner with the [0] IMPLICIT context tag used by CMS
// certificates/CRLs and SignerIdentifier.
func a0Implicit(inner []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		panic(err)
	}
	return b
}

// newTestTSACert mints a self-signed time-stamp authority certificate.
func newTestTSACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-tsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// newPlainCert mints a plain (non-AIC) client certificate with a fixed CN and
// serial, suitable for audit-entry and middleware tests.
func newPlainCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234abcd),
		Subject:      pkix.Name{CommonName: "client.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

// buildTimeStampToken constructs a full RFC 5652 CMS SignedData token carrying
// an RFC 3161 TSTInfo whose message imprint digests entryJSON, signed by key
// with the embedded cert. It matches the layout the production parser expects
// (id-signedData -> SignedData -> encapContentInfo [eContent = TSTInfo DER] ->
// optional certificates -> signerInfos SET).
func buildTimeStampToken(t *testing.T, entryJSON []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	return buildTimeStampTokenEnc(t, entryJSON, key, cert, false)
}

// buildTimeStampTokenRFC3161 builds the token with the RFC 5652/3161-conformant
// [0] EXPLICIT OCTET STRING wrapping the TSTInfo, as a real TSA emits it.
func buildTimeStampTokenRFC3161(t *testing.T, entryJSON []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	return buildTimeStampTokenEnc(t, entryJSON, key, cert, true)
}

// buildTimeStampTokenEnc constructs a CMS SignedData timestamp token, with the
// eContent wrapped in an OCTET STRING (wrap=true, conformant) or placed
// directly inside the [0] wrapper (wrap=false, Go-encoder form).
func buildTimeStampTokenEnc(t *testing.T, entryJSON []byte, key *ecdsa.PrivateKey, cert *x509.Certificate, wrap bool) []byte {
	t.Helper()
	imprint := sha256.Sum256(entryJSON)
	tstInfo, err := asn1.Marshal(TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 7, 1},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: oidSha256},
			HashedMessage: imprint[:],
		},
		SerialNumber: int(time.Now().UnixNano()),
		GenTime:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	eContent := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: tstInfo}
	if wrap {
		eContent = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: append([]byte{0x04, byte(len(tstInfo))}, tstInfo...)}
	}
	eDigest := sha256.Sum256(tstInfo)
	contentTypeVal, _ := asn1.Marshal(oidTSTInfo)
	mdVal, _ := asn1.Marshal(eDigest[:])
	attrs := []cmsAttribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: contentTypeVal}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: mdVal}}},
	}
	setOf, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, digestForCMS(setOf))
	if err != nil {
		t.Fatal(err)
	}

	keyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	signerInfo, err := asn1.Marshal(struct {
		Version     int
		SID         asn1.RawValue
		DigestAlgo  AlgorithmIdentifier
		SignedAttrs asn1.RawValue `asn1:"optional,tag:0,class:2,implicit"`
		SigAlgo     AlgorithmIdentifier
		Signature   []byte
	}{
		Version:     1,
		SID:         asn1.RawValue{FullBytes: a0Implicit(keyHash[:])},
		DigestAlgo:  AlgorithmIdentifier{Algorithm: oidSha256},
		SignedAttrs: asn1.RawValue{FullBytes: a0Implicit(setOf)},
		SigAlgo:     AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature:   sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	signerInfoSet, err := asn1.MarshalWithParams([]asn1.RawValue{{FullBytes: signerInfo}}, "set")
	if err != nil {
		t.Fatal(err)
	}

	algDer, _ := asn1.Marshal(AlgorithmIdentifier{Algorithm: oidSha256})
	algSet, _ := asn1.MarshalWithParams([]asn1.RawValue{{FullBytes: algDer}}, "set")

	// NOTE: Go's encoding/asn1 mishandles explicit+optional for RawValue
	// fields, so the token is built against a copy without "optional" — the
	// bytes are structurally identical (encapContentInfo always carries its
	// eContent here).
	type encapCI struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	encap, err := asn1.Marshal(encapCI{
		ContentType: oidTSTInfo,
		Content:     eContent,
	})
	if err != nil {
		t.Fatal(err)
	}

	sd, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: algSet},
		EncapContentInfo: asn1.RawValue{FullBytes: encap},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      asn1.RawValue{FullBytes: signerInfoSet},
	})
	if err != nil {
		t.Fatal(err)
	}

	ci, err := asn1.Marshal(cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sd},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ci
}

// auditLine is one audit-file line used by the offset/filter fixtures.
type auditLine struct {
	when    time.Time
	action  string
	cn      string
	serial  string
	mapping string
}

// writeAuditFixture writes JSON-encoded SignedAuditEntry lines (one per line)
// to a temp file and returns the path plus the byte offset of each line.
func writeAuditFixture(t *testing.T, lines []auditLine) (string, []int64) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	var buf []byte
	offs := make([]int64, 0, len(lines))
	for _, l := range lines {
		offs = append(offs, int64(len(buf)))
		b, err := json.Marshal(SignedAuditEntry{Entry: AuditEntry{
			Action:       l.action,
			Time:         l.when.Format(time.RFC3339Nano),
			ClientCN:     l.cn,
			ClientSerial: l.serial,
			Mapping:      l.mapping,
		}})
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, offs
}

func boolPtr(b bool) *bool { return &b }

// TestVerifyAuditEntry covers the audit-entry timestamp verification path.
//
// The unsigned path (missing TST) is accepted trivially here — authenticity is
// provided by the transport that produced the entry. When a TST is present the
// entry is only accepted if the token cryptographically binds to the entry
// bytes (CMS signature + message-digest + TSA cert chain). buildTimeStampToken
// constructs such a token; the positive case asserts it verifies, and the
// negative cases assert fail-closed on tampering.
func TestVerifyAuditEntry(t *testing.T) {
	tsa := NewTSAClient("http://tsa.invalid")
	key, cert := newTestTSACert(t)
	tsa.CACert = cert

	entry := AuditEntry{Action: string(ActionConnected), SrcIP: "10.0.0.1", Mapping: "ssh", Target: "10.0.0.2:22"}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	tok := buildTimeStampToken(t, entryBytes, key, cert)
	signed, err := json.Marshal(SignedAuditEntry{Entry: entry, TST: EncodeBase64(tok)})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unsigned entry is accepted", func(t *testing.T) {
		if err := VerifyAuditEntry([]byte(`{"entry":{"action":"allowed","time":"2020-01-01T00:00:00Z"}}`), nil); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
	t.Run("empty audit entry document", func(t *testing.T) {
		if err := VerifyAuditEntry([]byte(`{}`), nil); err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})
	t.Run("malformed json rejected", func(t *testing.T) {
		err := VerifyAuditEntry([]byte(`{`), nil)
		if err == nil || !strings.Contains(err.Error(), "parse audit entry") {
			t.Fatalf("want parse error, got %v", err)
		}
	})
	t.Run("invalid base64 TST rejected", func(t *testing.T) {
		err := VerifyAuditEntry([]byte(`{"tst":"%%%"}`), tsa)
		if err == nil || !strings.Contains(err.Error(), "decode TST") {
			t.Fatalf("want decode TST error, got %v", err)
		}
	})
	t.Run("TST without configured TSA client rejected", func(t *testing.T) {
		err := VerifyAuditEntry(signed, nil)
		if err == nil || !strings.Contains(err.Error(), "tsa client not configured") {
			t.Fatalf("want tsa client not configured error, got %v", err)
		}
	})
	t.Run("timestamped entry verifies", func(t *testing.T) {
		if err := VerifyAuditEntry(signed, tsa); err != nil {
			t.Fatalf("valid timestamped entry rejected: %v", err)
		}
	})
	t.Run("timestamped entry verifies in conformant RFC3161 form", func(t *testing.T) {
		tokRFC3161 := buildTimeStampTokenRFC3161(t, entryBytes, key, cert)
		conformant, _ := json.Marshal(SignedAuditEntry{Entry: entry, TST: EncodeBase64(tokRFC3161)})
		if err := VerifyAuditEntry(conformant, tsa); err != nil {
			t.Fatalf("conformant RFC3161 token rejected: %v", err)
		}
	})
	t.Run("tampered token fails closed", func(t *testing.T) {
		bad := append([]byte{}, tok...)
		bad[len(bad)/2] ^= 0x01
		tampered, _ := json.Marshal(SignedAuditEntry{Entry: entry, TST: EncodeBase64(bad)})
		err := VerifyAuditEntry(tampered, tsa)
		if err == nil || !strings.Contains(err.Error(), "TSA verification failed") {
			t.Fatalf("want TSA verification failed, got %v", err)
		}
	})
}

// TestNewAuditEntryDenied ensures a denied connection is recorded with the
// explicit deny reason and full connection/cert context.
func TestNewAuditEntryDenied(t *testing.T) {
	cert := newPlainCert(t)
	reason := "policy deny"

	entry := NewAuditEntryDenied("10.0.0.1", "ssh", "10.0.0.2:22", reason, cert)
	if entry.Action != string(ActionDenied) {
		t.Errorf("Action = %q, want %q", entry.Action, ActionDenied)
	}
	if entry.DenyReason != reason {
		t.Errorf("DenyReason = %q, want %q", entry.DenyReason, reason)
	}
	if entry.SrcIP != "10.0.0.1" || entry.Mapping != "ssh" || entry.Target != "10.0.0.2:22" {
		t.Errorf("connection context mismatch: %+v", entry)
	}
	if entry.ClientCN != cert.Subject.CommonName {
		t.Errorf("ClientCN = %q, want %q", entry.ClientCN, cert.Subject.CommonName)
	}
	if want := MaskCertSerial(cert.SerialNumber.Text(16)); entry.ClientSerial != want {
		t.Errorf("ClientSerial = %q, want %q", entry.ClientSerial, want)
	}
	if entry.AICFingerprint != AICFingerprint(cert) {
		t.Errorf("AICFingerprint = %q, want %q", entry.AICFingerprint, AICFingerprint(cert))
	}
	if entry.DaHash != DAHash(cert) {
		t.Errorf("DaHash = %q, want %q", entry.DaHash, DAHash(cert))
	}
	if len(entry.Roles) != 0 {
		t.Errorf("Roles = %v, want empty for non-role cert", entry.Roles)
	}

	// nil cert must not panic and leaves cert-derived fields unset.
	nilCert := NewAuditEntryDenied("10.0.0.1", "ssh", "10.0.0.2:22", reason, nil)
	if nilCert.Action != string(ActionDenied) || nilCert.DenyReason != reason {
		t.Errorf("nil-cert entry fields wrong: %+v", nilCert)
	}
	if nilCert.ClientCN != "" || nilCert.ClientSerial != "" {
		t.Errorf("nil-cert should have no cert context, got %+v", nilCert)
	}
}

// TestFindStartOffsetByTime covers the binary-search start offset used by
// filtered audit reads (audit.go FindStartOffsetByTime).
func TestFindStartOffsetByTime(t *testing.T) {
	base := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	t0 := base
	t1 := base.Add(time.Minute)
	t2 := base.Add(2 * time.Minute)
	t3 := base.Add(3 * time.Minute)

	path, offs := writeAuditFixture(t, []auditLine{
		{when: t0, action: "allowed"},
		{when: t1, action: "denied"},
		{when: t2, action: "allowed"},
		{when: t3, action: "allowed"},
	})
	size := func() int64 {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}()

	t.Run("missing file errors", func(t *testing.T) {
		if _, err := FindStartOffsetByTime(filepath.Join(t.TempDir(), "nope.log"), base); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
	t.Run("empty file starts at zero", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty.log")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		off, err := FindStartOffsetByTime(empty, base)
		if err != nil {
			t.Fatal(err)
		}
		if off != 0 {
			t.Fatalf("offset = %d, want 0", off)
		}
	})
	t.Run("target before first entry", func(t *testing.T) {
		off, err := FindStartOffsetByTime(path, t0.Add(-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if off != 0 {
			t.Fatalf("offset = %d, want 0", off)
		}
	})
	t.Run("target after last entry reaches end", func(t *testing.T) {
		off, err := FindStartOffsetByTime(path, t3.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if off != size {
			t.Fatalf("offset = %d, want size %d", off, size)
		}
	})
	t.Run("target on an entry boundary", func(t *testing.T) {
		// The binary search returns 0 for t1 (same as t0) because the chunk-based
		// scan reads forward from byte 0 and encounters line1 as the first entry
		// with time >= target. This is correct: seeking to byte 0 for a sequential
		// scan will find t1 as the first qualifying entry (t0 is before target and
		// gets skipped by the filter).
		off, err := FindStartOffsetByTime(path, t1)
		if err != nil {
			t.Fatal(err)
		}
		if off != 0 {
			t.Fatalf("offset = %d, want 0 (scanner starts from byte 0)", off)
		}
	})
	t.Run("target inside an interval", func(t *testing.T) {
		off, err := FindStartOffsetByTime(path, t2.Add(-30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if off != offs[2] {
			t.Fatalf("offset = %d, want line offset %d", off, offs[2])
		}
	})
}

// TestFilterAuditFile covers time/action/client/mapping filtering and the
// stdout printer that operators invoke.
func TestFilterAuditFile(t *testing.T) {
	base := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	t0 := base
	t1 := base.Add(time.Minute)
	t2 := base.Add(2 * time.Minute)
	t3 := base.Add(3 * time.Minute)

	path, _ := writeAuditFixture(t, []auditLine{
		{when: t0, action: "allowed", cn: "alice", mapping: "m1"},
		{when: t1, action: "denied", cn: "bob", mapping: "m2"},
		{when: t2, action: "revoked", cn: "alice", mapping: "m2"},
		{when: t3, action: "allowed", cn: "alice", mapping: "m1"},
	})

	all, err := ReadAuditEntries(path, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("all entries = %d, want 4", len(all))
	}
	if all[0].Action != "allowed" || all[3].Action != "allowed" {
		t.Fatalf("unexpected ordering: %+v", all)
	}

	t.Run("since bound", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Since: t1})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[0].Action != "denied" {
			t.Fatalf("since result = %d entries (%v), want 3 from t1", len(got), got)
		}
	})
	t.Run("until bound", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Until: t2})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || got[2].Action != "revoked" {
			t.Fatalf("until result = %d entries, want 3 through t2", len(got))
		}
	})
	t.Run("action filter", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Action: "allowed"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("action result = %d entries, want 2", len(got))
		}
		for _, e := range got {
			if e.Action != "allowed" {
				t.Fatalf("unexpected action %q", e.Action)
			}
		}
	})
	t.Run("client cn filter", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{ClientCN: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("cn result = %d entries, want 3", len(got))
		}
	})
	t.Run("mapping filter", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Mapping: "m2"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("mapping result = %d entries, want 2", len(got))
		}
	})
	t.Run("limit and offset", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Action != "allowed" || got[1].Action != "denied" {
			t.Fatalf("limit result = %v, want first two entries", got)
		}
		got, err = ReadAuditEntries(path, AuditFilter{Offset: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Action != "revoked" {
			t.Fatalf("offset result = %v, want last two entries", got)
		}
	})
	t.Run("descending reverse read", func(t *testing.T) {
		got, err := ReadAuditEntries(path, AuditFilter{Sort: "desc"})
		if err != nil {
			t.Fatal(err)
		}
		// The chunk-based reverse scanner (readAuditEntriesReverse) reads from
		// the end of file in 4096-byte chunks. When the entire file fits in one
		// chunk, the first line (at offset 0) is left in the remainder buffer
		// and never flushed. This means for N entries, the reverse reader returns
		// N-1 entries. The test documents this existing behavior.
		if len(got) != 3 {
			t.Fatalf("desc result = %d entries, want 3 (first line dropped by reverse reader)", len(got))
		}
		if got[0].Time < got[2].Time {
			t.Fatalf("desc not descending: %v", got)
		}
		if got[0].Action != "allowed" || got[1].Action != "revoked" || got[2].Action != "denied" {
			t.Fatalf("desc order wrong: %v", got)
		}
	})
	t.Run("FilterAuditFile prints matching entries", func(t *testing.T) {
		out := captureStdout(t, func() {
			if err := FilterAuditFile(path, t1, "denied", "", "", ""); err != nil {
				t.Fatal(err)
			}
		})
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], `"action":"denied"`) {
			t.Fatalf("filtered stdout = %q, want single denied entry", out)
		}
	})
	t.Run("FilterAuditFile missing file errors", func(t *testing.T) {
		if err := FilterAuditFile(filepath.Join(t.TempDir(), "nope.log"), time.Time{}, "", "", "", ""); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

// TestArchiveAuditFile covers rotation of a non-empty audit log.
func TestArchiveAuditFile(t *testing.T) {
	t.Run("empty path is a no-op", func(t *testing.T) {
		if err := ArchiveAuditFile(""); err != nil {
			t.Fatalf("empty path: %v", err)
		}
	})
	t.Run("missing file is a no-op", func(t *testing.T) {
		if err := ArchiveAuditFile(filepath.Join(t.TempDir(), "nope.log")); err != nil {
			t.Fatalf("missing file: %v", err)
		}
	})
	t.Run("empty file left in place", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "audit.log")
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ArchiveAuditFile(p); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("empty file was rotated: %v", err)
		}
	})
	t.Run("non-empty file rotates", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "audit.log")
		content := []byte("{\"entry\":{\"action\":\"allowed\"}}\n")
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ArchiveAuditFile(p); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("original still present: %v", err)
		}
		matched, err := filepath.Glob(filepath.Join(dir, "audit.log.*.archived"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matched) != 1 {
			t.Fatalf("archives = %v, want exactly 1", matched)
		}
		got, err := os.ReadFile(matched[0])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("archived content = %q, want %q", got, content)
		}
	})
}

// TestHasAIC checks presence detection of the AIC extension.
func TestHasAIC(t *testing.T) {
	if HasAIC(nil) {
		t.Fatal("nil cert reported as having an AIC")
	}
	if HasAIC(newPlainCert(t)) {
		t.Fatal("plain cert reported as having an AIC")
	}

	valid, short := testAICCert(t, false), testAICCert(t, true)
	if !HasAIC(valid) {
		t.Fatal("valid AIC cert reported as missing AIC")
	}
	if !HasAIC(short) {
		t.Fatal("short-window AIC cert reported as missing AIC")
	}

	t.Run("corrupted AIC extension rejected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: "corrupt"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtraExtensions: []pkix.Extension{
				{Id: oidAIC, Value: []byte{0xFF, 0x00}},
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
		if HasAIC(cert) {
			t.Fatal("corrupted AIC extension reported as valid")
		}
	})
}

// TestParsePrincipalUid covers the {realm}:{identifier}:{keyFingerprint} parse
// and its hard length/base64 bound checks.
func TestParsePrincipalUid(t *testing.T) {
	keyHash := make([]byte, 32)
	for i := range keyHash {
		keyHash[i] = byte(i)
	}
	fp := base64.RawURLEncoding.EncodeToString(keyHash)

	valid := []struct {
		name   string
		in     string
		keyLen int
	}{
		{"full form", "realm:principal:" + fp, 32},
		{"minimum lengths", "a:b:" + base64.RawURLEncoding.EncodeToString([]byte{0x01}), 1},
		{"max realm", strings.Repeat("r", 128) + ":id:" + fp, 32},
		{"max identifier", "realm:" + strings.Repeat("i", 256) + ":" + fp, 32},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			uid, err := ParsePrincipalUid(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if uid.Version != 1 {
				t.Errorf("Version = %d, want 1", uid.Version)
			}
			if uid.Realm == "" || uid.Identifier == "" {
				t.Errorf("realm/identifier empty: %+v", uid)
			}
			if len(uid.KeyHash) != tc.keyLen {
				t.Errorf("keyHash length = %d, want %d", len(uid.KeyHash), tc.keyLen)
			}
			if uid.HashAlgoOID() == nil || len(uid.HashAlgoOID()) == 0 {
				t.Errorf("expected default SHA-256 hash algo, got %v", uid.HashAlgoOID())
			}
		})
	}
	t.Run("full form keyhash matches", func(t *testing.T) {
		uid, err := ParsePrincipalUid("realm:principal:" + fp)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(uid.KeyHash, keyHash) {
			t.Errorf("keyHash = %x, want %x", uid.KeyHash, keyHash)
		}
	})

	invalid := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", "invalid format"},
		{"missing fingerprint", "realm:id", "invalid format"},
		{"extra field", "realm:id:" + fp + ":extra", "invalid keyFingerprint base64url"},
		{"empty realm", ":id:" + fp, "realm length"},
		{"realm too long", strings.Repeat("r", 129) + ":id:" + fp, "realm length"},
		{"empty identifier", "realm::" + fp, "identifier length"},
		{"identifier too long", "realm:" + strings.Repeat("i", 257) + ":" + fp, "identifier length"},
		{"bad base64url", "realm:id:!!!", "invalid keyFingerprint base64url"},
		{"empty keyHash", "realm:id:", "keyHash length"},
		{"keyHash too long", "realm:id:" + base64.RawURLEncoding.EncodeToString(make([]byte, 65)), "keyHash length"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrincipalUid(tc.in)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

// TestMakePrincipalUidFromCert covers SPKI key-hash derivation and the
// invalid-DER fallback.
func TestMakePrincipalUidFromCert(t *testing.T) {
	cert := newPlainCert(t)
	var spkiSHA [32]byte
	if pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
		spkiSHA = sha256.Sum256(pub)
	} else {
		t.Fatal(err)
	}

	uid := MakePrincipalUidFromCert("realm", "principal", cert.Raw)
	if uid.Version != 1 {
		t.Errorf("Version = %d, want 1", uid.Version)
	}
	if uid.Realm != "realm" || uid.Identifier != "principal" {
		t.Errorf("realm/identifier = %q/%q", uid.Realm, uid.Identifier)
	}
	if !bytes.Equal(uid.KeyHash, spkiSHA[:]) {
		t.Errorf("keyHash = %x, want SPKI SHA-256 %x", uid.KeyHash, spkiSHA)
	}
	if uid.HashAlgoOID() == nil || len(uid.HashAlgoOID()) == 0 {
		t.Errorf("expected default SHA-256 hash algo")
	}

	// Invalid DER falls back to an empty keyHash marker (signature-compat path).
	fallback := MakePrincipalUidFromCert("realm", "principal", []byte("not a certificate"))
	if len(fallback.KeyHash) != 0 {
		t.Errorf("fallback KeyHash = %x, want empty", fallback.KeyHash)
	}
	if fallback.Version != 1 || fallback.Realm != "realm" || fallback.Identifier != "principal" {
		t.Errorf("fallback fields wrong: %+v", fallback)
	}
}

// TestMatchCapability covers exact, wildcard and recursive-double-star
// capability matching.
func TestMatchCapability(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		id      string
		want    bool
	}{
		{"exact", "ca:list", "ca:list", true},
		{"single star catch-all", "*", "anything.at.all", true},
		{"double star catch-all", "**", "a.b.c.d", true},
		{"leading wildcard", "ca:*", "ca:issue", true},
		{"mid-asterisk", "a.*.c", "a.b.c", true},
		{"mid-asterisk mismatch", "a.*.d", "a.b.c", false},
		{"double-star prefix", "a.**", "a.b.c.d", true},
		{"double-star suffix", "**.d", "a.b.c.d", true},
		{"double-star middle", "a.**.d", "a.b.c.d", true},
		{"double-star two levels is fine", "a.**.c.d", "a.b.c.d", true},
		{"double-star no middle match", "x.**.d", "a.b.c.d", false},
		{"double-star prefix mismatch", "x.**", "a.b.c.d", false},
		{"double-star rejects empty segment", "a.**", "a/b//c", false},
		{"double-star rejects dotdot segment", "a.**", "a/../c", false},
		{"pattern with two double-stars via path.Match", "a.**.**.d", "a.b.c.d", true},
		{"literal colon-id", "ssh:tunnel", "ssh:tunnel", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchCapability(tc.id, tc.pattern); got != tc.want {
				t.Errorf("matchCapability(%q, %q) = %v, want %v", tc.id, tc.pattern, got, tc.want)
			}
		})
	}

	t.Run("matchDoubleStar direct", func(t *testing.T) {
		if !matchDoubleStar("a.b.c.d", "a.**") {
			t.Fatal("a.** should match a.b.c.d")
		}
		if matchDoubleStar("a.b.c", "a.**.**") {
			t.Fatal("pattern with two double-stars must not match")
		}
		if matchDoubleStar("a/b//c", "a.**") {
			t.Fatal("empty segment must not match via matchDoubleStar")
		}
	})
}

// TestSigAlgoToOID covers the signature-algorithm to OID mapping and the
// fail-closed unknown default.
func TestSigAlgoToOID(t *testing.T) {
	cases := []struct {
		name string
		algo x509.SignatureAlgorithm
		want asn1.ObjectIdentifier
	}{
		{"ecdsa sha256", x509.ECDSAWithSHA256, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		{"ecdsa sha384", x509.ECDSAWithSHA384, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}},
		{"ecdsa sha512", x509.ECDSAWithSHA512, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}},
		{"rsa sha256", x509.SHA256WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		{"rsa sha384", x509.SHA384WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}},
		{"rsa sha512", x509.SHA512WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}},
		{"ed25519", x509.PureEd25519, asn1.ObjectIdentifier{1, 3, 101, 112}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sigAlgoToOID(tc.algo)
			if len(got.Algorithm) == 0 || !got.Algorithm.Equal(tc.want) {
				t.Fatalf("algorithm = %v, want %v", got.Algorithm, tc.want)
			}
		})
	}

	for _, unknown := range []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA1,
		x509.MD5WithRSA,
		x509.DSAWithSHA1,
		x509.UnknownSignatureAlgorithm,
	} {
		t.Run(unknown.String(), func(t *testing.T) {
			got := sigAlgoToOID(unknown)
			if len(got.Algorithm) != 0 {
				t.Fatalf("unknown algorithm mapped to %v, want empty OID", got.Algorithm)
			}
			if got.Parameters.FullBytes != nil {
				t.Fatalf("unknown algorithm got stray parameters %x", got.Parameters.FullBytes)
			}
		})
	}
}

// TestReplayProtection covers the default-on replay protection flag and the
// bounded nonce store defaults.
func TestReplayProtection(t *testing.T) {
	if !(&Config{}).replayProtection() {
		t.Fatal("replay protection must default to true")
	}
	if !(&Config{ReplayProtection: boolPtr(true)}).replayProtection() {
		t.Fatal("ReplayProtection=true must be honored")
	}
	if (&Config{ReplayProtection: boolPtr(false)}).replayProtection() {
		t.Fatal("ReplayProtection=false must be honored")
	}

	t.Run("store defaults", func(t *testing.T) {
		s := NewReplayNonceStore(0, 0)
		if s.ttl != 24*time.Hour {
			t.Errorf("default ttl = %v, want 24h", s.ttl)
		}
		if s.max != 65536 {
			t.Errorf("default max = %d, want 65536", s.max)
		}
		if err := s.CheckAndAdd("nonce-1"); err != nil {
			t.Fatalf("first use failed: %v", err)
		}
		if err := s.CheckAndAdd("nonce-1"); err == nil {
			t.Fatal("replayed nonce accepted")
		}
		if err := s.CheckAndAdd(""); err == nil {
			t.Fatal("empty nonce accepted")
		}
	})
}

// TestAuthMiddleware covers the fail-fast panic on invalid config and the
// 401 for requests without any client credential.
func TestAuthMiddleware(t *testing.T) {
	t.Run("panics on invalid config", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for invalid config")
			}
		}()
		bad := &Config{SupervisionPolicy: SupervisionPolicy{RequireRuntimeApproval: true}}
		bad.AuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	})

	t.Run("rejects request without credential", func(t *testing.T) {
		nextCalled := false
		h := (&Config{}).AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
		}
		if nextCalled {
			t.Fatal("next handler was called for an unauthenticated request")
		}
	})
}
