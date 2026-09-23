// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunGeneratesPairAndPrintsToken(t *testing.T) {
	t.Chdir(t.TempDir())
	var out, errw bytes.Buffer
	if code := run(nil, &out, &errw); code != 0 {
		t.Fatalf("run = %d, stderr=%s", code, errw.String())
	}
	for _, f := range []string{caCert, caKey, tlsCert, tlsKey} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
	token := strings.TrimSpace(out.String())
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("token %q is not a compact JWT (3 segments), got %d", token, len(parts))
	}
}

// Running again reuses the existing artifacts and still signs a fresh token.
func TestRunIdempotent(t *testing.T) {
	t.Chdir(t.TempDir())
	var out, errw bytes.Buffer
	if code := run(nil, &out, &errw); code != 0 {
		t.Fatalf("first run = %d, stderr=%s", code, errw.String())
	}
	out.Reset()
	if code := run(nil, &out, &errw); code != 0 {
		t.Fatalf("second run = %d, stderr=%s", code, errw.String())
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("second run printed no token")
	}
}

func TestRunUnreadableCAPair(t *testing.T) {
	t.Chdir(t.TempDir())
	// ensureCA skips because both files exist; a corrupt key then trips
	// readCAPair and must exit with code 2.
	if err := writePEM(caCert, "CERTIFICATE", []byte{1, 2, 3}); err != nil {
		t.Fatalf("writePEM caCert: %v", err)
	}
	if err := writePEM(caKey, "EC PRIVATE KEY", []byte{0xff, 0xfe}); err != nil {
		t.Fatalf("writePEM caKey: %v", err)
	}
	var out, errw bytes.Buffer
	if code := run(nil, &out, &errw); code != 2 {
		t.Fatalf("run = %d, want 2 (stderr=%s)", code, errw.String())
	}
}

func TestRunCAWriteFailure(t *testing.T) {
	t.Chdir(readOnlyDir(t))
	var out, errw bytes.Buffer
	if code := run(nil, &out, &errw); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, errw.String())
	}
	if !strings.Contains(errw.String(), "gen-bearer:") {
		t.Fatalf("stderr = %q, want gen-bearer prefix", errw.String())
	}
}

func TestReadCAPairMalformed(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := readCAPair("does-not-exist.pem", caKey); err == nil {
		t.Fatal("missing cert file must error")
	}

	// Valid cert + missing key file.
	if err := ensureCA(); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	_ = os.Remove(caKey)
	if _, err := readCAPair(caCert, caKey); err == nil {
		t.Fatal("missing key file must error")
	}

	// garbage (non-PEM) cert content.
	_ = os.WriteFile(caCert, []byte("junk"), 0o600)
	_ = os.WriteFile(caKey, []byte("junk"), 0o600)
	if _, err := readCAPair(caCert, caKey); err == nil {
		t.Fatal("non-PEM cert content must error")
	}

	// PEM wrapper but undecodable DER.
	if err := writePEM(caCert, "CERTIFICATE", []byte{0x30, 0x03}); err != nil {
		t.Fatalf("writePEM: %v", err)
	}
	if _, err := readCAPair(caCert, caKey); err == nil {
		t.Fatal("undecodable cert must error")
	}

	// Valid cert + undecodable key DER.
	_ = os.Remove(caCert)
	_ = os.Remove(caKey)
	if err := ensureCA(); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	if err := writePEM(caKey, "EC PRIVATE KEY", []byte{0x30, 0x00}); err != nil {
		t.Fatalf("writePEM caKey: %v", err)
	}
	if _, err := readCAPair(caCert, caKey); err == nil {
		t.Fatal("undecodable key must error")
	}
}

func TestWritePEMError(t *testing.T) {
	t.Chdir(readOnlyDir(t))
	if err := writePEM("x.pem", "CERTIFICATE", []byte{1}); err == nil {
		t.Fatal("write into read-only dir must error")
	}
}

func TestSignAICJWTOverRealCA(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := ensureCA(); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	ca, err := readCAPair(caCert, caKey)
	if err != nil {
		t.Fatalf("readCAPair: %v", err)
	}
	token, err := signAICJWT(ca)
	if err != nil {
		t.Fatalf("signAICJWT: %v", err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("signAICJWT token %q not compact JWT", token)
	}
}

// readOnlyDir returns a temp directory that cannot be written into.
func readOnlyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	return dir
}
