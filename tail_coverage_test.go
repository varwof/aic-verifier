// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Coverage for the last low-density paths: Config logger()/CloseLogger,
// newAuthenticator transport-mode branches, audit logSync TSA timeout + write
// failure, and ListenAndServe bind/TLS.

package aicverifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePEMPath(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(p, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCloseLoggerNoop(t *testing.T) {
	if err := (*Config)(nil).CloseLogger(); err != nil {
		t.Errorf("CloseLogger(nil) = %v", err)
	}
	if err := (&Config{}).CloseLogger(); err != nil {
		t.Errorf("CloseLogger(no file) = %v", err)
	}
}

// TestConfigCloseCascades checks that Config.Close tears down every owned
// background/file resource exactly once, and that a second call is a no-op
// (all children are idempotent).
func TestConfigCloseCascades(t *testing.T) {
	if err := (*Config)(nil).Close(); err != nil {
		t.Errorf("Close(nil) = %v", err)
	}
	if err := (&Config{}).Close(); err != nil {
		t.Errorf("Close(empty) = %v", err)
	}

	dir := t.TempDir()
	audit, err := NewAuditLogger(filepath.Join(dir, "audit.log"), nil, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSupervisionStore(filepath.Join(dir, "supervision.log"), nil, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	nc := NewNonceCache()

	cfg := &Config{
		LogFile:          filepath.Join(dir, "sdk.log"),
		AuditLogger:      audit,
		SupervisionStore: store,
		NonceCache:       nc,
	}
	cfg.logger() // open the log file so CloseLogger has something to close

	if err := cfg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if cfg.logFile != nil {
		t.Error("Close did not release the log file")
	}
	select {
	case <-nc.done:
	default:
		t.Error("Close did not stop the nonce cache cleanup goroutine")
	}

	// Every child is idempotent, so a repeat Close must not panic or error.
	if err := cfg.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	nc.Stop() // explicit Stop after Close must also be safe
}

func TestConfigLoggerBranches(t *testing.T) {
	preset := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if got := (&Config{Logger: preset}).logger(); got != preset {
		t.Error("logger() ignored preset Logger")
	}

	dir := t.TempDir()
	cfg := &Config{LogFile: filepath.Join(dir, "audit.log")}
	lg := cfg.logger()
	if cfg.logFile == nil {
		t.Fatal("LogFile open did not populate logFile")
	}
	if lg == preset || lg == slog.Default() {
		t.Error("logger() did not return the file-backed handler")
	}
	handle := cfg.logFile
	cfg.logger()
	if cfg.logFile != handle {
		t.Error("logger() replaced an already-open file handle")
	}
	if err := cfg.CloseLogger(); err != nil {
		t.Errorf("CloseLogger: %v", err)
	}
	if cfg.logFile != nil {
		t.Error("CloseLogger did not nil the file handle")
	}
	if err := cfg.CloseLogger(); err != nil {
		t.Errorf("second CloseLogger: %v", err)
	}

	bad := &Config{LogFile: filepath.Join(dir, "missing", "sub", "x.log")}
	if lg := bad.logger(); lg != slog.Default() {
		t.Error("logger() should fall back to slog.Default on open failure")
	}
	if bad.logFile != nil {
		t.Error("failed open left a handle behind")
	}

	if lg := (&Config{}).logger(); lg != slog.Default() {
		t.Error("empty config logger() != slog.Default()")
	}
}

func TestNewAuthenticatorModes(t *testing.T) {
	dir := t.TempDir()
	ca, _ := testCRLFixture(t, time.Now())
	caPath := writePEMPath(t, dir, "ca.pem", "CERTIFICATE", ca.Raw)

	a1, err := newAuthenticator(&Config{AuthMode: MTLSOnly, CACertFile: caPath})
	if err != nil {
		t.Fatalf("MTLSOnly: %v", err)
	}
	if a1.tlsCAs == nil {
		t.Error("MTLSOnly did not build tlsCAs")
	}

	falsePtr := false
	a2, err := newAuthenticator(&Config{
		AuthMode: BearerOnly, JWTCAFile: caPath,
		JWTIssuer: "iss", JWTAudience: []string{"aud"},
	})
	if err != nil {
		t.Fatalf("BearerOnly: %v", err)
	}
	if a2.verifier == nil {
		t.Error("BearerOnly did not build verifier")
	}
	if a2.nonces == nil {
		t.Error("default replay protection should configure nonces")
	}

	a3, err := newAuthenticator(&Config{
		AuthMode: AuthMode(99), JWTCAFile: caPath, ReplayProtection: &falsePtr,
	})
	if err != nil {
		t.Fatalf("fallback mode: %v", err)
	}
	if a3.verifier == nil {
		t.Error("MTLSOrBearer default should still load the JWT verifier")
	}
	if a3.nonces != nil {
		t.Error("replay protection disabled should leave nonces nil")
	}

	a4, err := newAuthenticator(&Config{})
	if err != nil {
		t.Fatalf("empty config: %v", err)
	}
	if a4.verifier != nil || a4.tlsCAs != nil {
		t.Error("empty config unexpectedly created verifier/tlsCAs")
	}
}

func TestLogSyncTSABranches(t *testing.T) {
	dir := t.TempDir()
	entry := AuditEntry{Action: "admit", Target: "/api"}

	// TSA signer slower than the per-entry bound: entry written unsigned.
	p := filepath.Join(dir, "slow.log")
	slow, err := NewRotatingFile(p, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	blocking := &TSAClient{SignFunc: func([]byte) ([]byte, error) {
		time.Sleep(200 * time.Millisecond)
		return []byte("late"), nil
	}}
	(&AuditLogger{w: slow, tsa: blocking, tsaTimeout: 20 * time.Millisecond}).logSync(entry)
	if err := slow.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "VFNU") {
		t.Error("timed-out TSA entry unexpectedly carried a stamp")
	}

	// Writer error surfaces a diagnostic instead of panicking.
	(&AuditLogger{w: slow, tsaTimeout: time.Second}).logSync(entry)

	// Successful TSA sign embeds the base64 stamp.
	okPath := filepath.Join(dir, "ok.log")
	ok, err := NewRotatingFile(okPath, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	signed := &TSAClient{SignFunc: func([]byte) ([]byte, error) {
		return []byte("TST-BYTES"), nil
	}}
	(&AuditLogger{w: ok, tsa: signed, tsaTimeout: time.Second}).logSync(entry)
	if err := ok.Close(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(okPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "VFNU") {
		t.Error("signed TSA entry missing base64 TST in output")
	}
}

func TestListenAndServeBindError(t *testing.T) {
	s, err := NewServer(&Config{}, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.ListenAndServe("999.999.999.999:0"); err == nil {
		t.Error("expected bind failure for invalid address")
	}
}

func TestListenAndServeTLS(t *testing.T) {
	dir := t.TempDir()
	key, cert := newTestTSACert(t)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := writePEMPath(t, dir, "tls.crt", "CERTIFICATE", cert.Raw)
	keyPath := writePEMPath(t, dir, "tls.key", "EC PRIVATE KEY", keyDER)

	s, err := NewServer(&Config{TLSCertFile: certPath, TLSKeyFile: keyPath}, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ln, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := s.Addr().String()
	if addr == "" {
		t.Fatal("Addr() empty after Listen")
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec -- self-signed fixture cert without SANs; TLS termination path is what is under test
			MinVersion:         tls.VersionTLS12,
		}},
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("uncredentialed request status = %d, want 401/403", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			t.Fatalf("Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS server did not shut down")
	}
}
