// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesAllArtifacts(t *testing.T) {
	dir := t.TempDir()
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run([]string{"--out", dir}, out, errw); code != 0 {
		t.Fatalf("run = %d, stderr=%s", code, errw.String())
	}
	for _, f := range []string{
		"ca-cert.pem", "ca-key.pem",
		"server-cert.pem", "server-key.pem",
		"client-cert.pem", "client-key.pem",
	} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s missing: %v", f, err)
		}
	}
	if !strings.Contains(out.String(), "generated in "+dir) {
		t.Fatalf("stdout = %q, want path banner", out.String())
	}
}

func TestRunFlagError(t *testing.T) {
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run([]string{"--nope"}, out, errw); code != 2 {
		t.Fatalf("run = %d, want 2", code)
	}
	if !strings.Contains(errw.String(), "flag provided but not defined") {
		t.Fatalf("stderr = %q", errw.String())
	}
}

func TestRunMkdirError(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run([]string{"--out", blocker + "/sub"}, out, errw); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

func TestRunWriteFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	// --out points at the pre-existing read-only dir; MkdirAll succeeds
	// (exists) and makeCA's writeCert must fail.
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run([]string{"--out", dir}, out, errw); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, errw.String())
	}
}

func TestWriteKeyError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := writeKey(filepath.Join(dir, "k.pem"), testKey(t)); err == nil {
		t.Fatal("write into read-only dir must error")
	}
}

// blockingDir pre-creates a directory at out/<name> so the generated artifact's
// os.Create fails with a non-crypto error at exactly that write.
func blockingDir(t *testing.T, outPath, name string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(outPath, name), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
}

func TestRunServerWriteError(t *testing.T) {
	out := t.TempDir()
	blockingDir(t, out, "server-cert.pem")
	var sw, ew bytes.Buffer
	if code := run([]string{"--out", out}, &sw, &ew); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, ew.String())
	}
}

func TestRunServerKeyWriteError(t *testing.T) {
	out := t.TempDir()
	blockingDir(t, out, "server-key.pem")
	var sw, ew bytes.Buffer
	if code := run([]string{"--out", out}, &sw, &ew); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, ew.String())
	}
}

func TestRunClientWriteError(t *testing.T) {
	out := t.TempDir()
	blockingDir(t, out, "client-cert.pem")
	var sw, ew bytes.Buffer
	if code := run([]string{"--out", out}, &sw, &ew); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, ew.String())
	}
}

func TestRunClientKeyWriteError(t *testing.T) {
	out := t.TempDir()
	blockingDir(t, out, "client-key.pem")
	var sw, ew bytes.Buffer
	if code := run([]string{"--out", out}, &sw, &ew); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr=%s)", code, ew.String())
	}
}

// testKey returns a fresh P-256 key for exercising writeKey's success path
// (also covered indirectly by TestRunGeneratesAllArtifacts).
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}
