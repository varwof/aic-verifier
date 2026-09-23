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
	"encoding/json"

	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// certWithOU mints a self-signed leaf carrying a single OU so the OU→role
// policy mapping has something to bite on.
func certWithOU(t *testing.T, ou string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ou-agent", OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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

func policyWithOUMapping(version, role string) *AuthorizationPolicy {
	return &AuthorizationPolicy{
		Version:   version,
		Roles:     map[string]PolicyRole{role: {Grants: []string{"gateway:read"}}},
		OUMapping: map[string]string{"dev": role},
	}
}

// E: a reliable admin seam — the decision server counts every admission and
// stays healthy, and a ReloadPolicy swap shows up on the very next decision
// (atomic per-request policy snapshot, not a restart seam).
func TestMetricsCountAdmissions(t *testing.T) {
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()

	if _, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert}); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if _, err := s.Decide(context.Background(), &RequestView{}); err == nil {
		t.Fatal("empty view must be refused")
	}
	snap := s.a.metrics.Snapshot()
	if snap.DecideTotal != 2 || snap.Granted != 1 || snap.Denied != 1 {
		t.Fatalf("counters = %+v, want total 2 granted 1 denied 1", snap)
	}
}

func TestHealthReflectsLastDecision(t *testing.T) {
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()

	if h := s.Health(context.Background()); !h.OK || h.Module != "varwof.aic.decision.v1" {
		t.Fatalf("health before traffic = %+v", h)
	}
	if _, err := s.Decide(context.Background(), &RequestView{}); err == nil {
		t.Fatal("empty view must be refused")
	}
	h := s.Health(context.Background())
	if h.OK {
		t.Fatal("a server whose last decision refused must report not-ready when it has never admitted")
	}
	if _, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert}); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if h := s.Health(context.Background()); !h.OK {
		t.Fatal("a healthy admission after the refusal must restore readiness")
	}
}

// The middleware path has no DecisionServer handle, so its counters and
// readiness must be readable from the Config that produced it, and a
// DecisionServer built from the same Config must observe the same set.
func TestMiddlewareMetricsVisibleOnConfig(t *testing.T) {
	cfg := &Config{AdminToken: "test-reload-token"}
	h := cfg.AuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	snap := cfg.Metrics().Snapshot()
	if snap.DecideTotal != 1 || snap.Denied != 1 {
		t.Fatalf("Config counters = %+v, want total 1 denied 1", snap)
	}
	if cfg.Health().OK {
		t.Fatal("Config.Health must be not-ready after a denied decision and no admission")
	}

	s, err := NewDecisionServer(cfg)
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()
	if s.a.metrics != cfg.Metrics() {
		t.Fatal("DecisionServer built from a Config must share its counter set")
	}

	// /readyz is served alongside /healthz.
	mux := s.AdminHandler()
	rrec := httptest.NewRecorder()
	mux.ServeHTTP(rrec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rrec.Code != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200", rrec.Code)
	}
}

// The reload swaps the exact per-config policy the pipeline reads (B seam),
// and an invalid policy never replaces the running one.
func TestReloadPolicySwapsRolesAtomically(t *testing.T) {
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()

	rolesFor := func() []string {
		t.Helper()
		ac, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert})
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		return ac.Roles
	}

	if got := rolesFor(); len(got) != 0 {
		t.Fatalf("roles before any policy = %v, want none", got)
	}
	if err := s.ReloadPolicy(policyWithOUMapping("v1", "dev-role")); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if got := rolesFor(); len(got) != 1 || got[0] != "dev-role" {
		t.Fatalf("roles after reload = %v, want [dev-role]", got)
	}
	if err := s.ReloadPolicy(policyWithOUMapping("v2", "ops-role")); err != nil {
		t.Fatalf("ReloadPolicy v2: %v", err)
	}
	if got := rolesFor(); len(got) != 1 || got[0] != "ops-role" {
		t.Fatalf("roles after second reload = %v, want [ops-role]", got)
	}
	if snap := s.a.metrics.Snapshot(); snap.ConfigReloads != 2 {
		t.Fatalf("config_reloads = %d, want 2", snap.ConfigReloads)
	}

	// An invalid policy is rejected and the running snapshot keeps serving.
	if err := s.ReloadPolicy(&AuthorizationPolicy{Version: ""}); err == nil {
		t.Fatal("a versionless policy must be rejected")
	}
	if got := rolesFor(); len(got) != 1 || got[0] != "ops-role" {
		t.Fatalf("roles after a failed reload = %v, want the running [ops-role]", got)
	}
}

func TestReloadPolicyFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authz.json")
	data, err := json.Marshal(policyWithOUMapping("v-file", "file-role"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()
	if err := s.ReloadPolicyFromFile(path, ".sig", nil); err != nil {
		t.Fatalf("ReloadPolicyFromFile: %v", err)
	}
	ac, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if len(ac.Roles) != 1 || ac.Roles[0] != "file-role" {
		t.Fatalf("roles = %v, want [file-role]", ac.Roles)
	}
}

// Concurrent reload + decision must be race-clean and each decision must see a
// whole, consistent policy snapshot.
func TestReloadConcurrentWithDecide(t *testing.T) {
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ac, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert})
					if err != nil {
						t.Errorf("Decide during reload: %v", err)
						return
					}
					for _, r := range ac.Roles {
						if r != "a-role" && r != "b-role" {
							t.Errorf("roles must be a whole snapshot, got %q", ac.Roles)
							return
						}
					}
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		role := "a-role"
		if i%2 == 0 {
			role = "b-role"
		}
		if err := s.ReloadPolicy(policyWithOUMapping("v"+string(rune('0'+i%10)), role)); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// The admin HTTP surface serves counters, health and the reload endpoint.
func TestAdminHandler(t *testing.T) {
	cert := certWithOU(t, "dev")
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()
	if _, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert}); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	ts := httptest.NewServer(s.AdminHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d", resp.StatusCode)
	}
	var h HealthReport
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if !h.OK || h.Metrics.Granted != 1 {
		t.Fatalf("health = %+v, want ok with one granted", h)
	}

	mp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer mp.Body.Close()
	var snap MetricsSnapshot
	if err := json.NewDecoder(mp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	if snap.DecideTotal != 1 || snap.Granted != 1 {
		t.Fatalf("metrics = %+v", snap)
	}

	body, _ := json.Marshal(map[string]any{"policy": policyWithOUMapping("v-admin", "admin-role")})
	rreq, _ := http.NewRequest(http.MethodPost, ts.URL+"/reload", strings.NewReader(string(body)))
	rreq.Header.Set("Authorization", "Bearer test-reload-token")
	rresp, err := (&http.Client{}).Do(rreq)
	if err != nil {
		t.Fatalf("POST /reload: %v", err)
	}
	rresp.Body.Close()
	if rresp.StatusCode != http.StatusOK {
		t.Fatalf("POST /reload status = %d, want 200", rresp.StatusCode)
	}

	ac, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert})
	if err != nil {
		t.Fatalf("Decide after admin reload: %v", err)
	}
	if len(ac.Roles) != 1 || ac.Roles[0] != "admin-role" {
		t.Fatalf("roles after admin reload = %v, want [admin-role]", ac.Roles)
	}

	// Invalid payloads are 400, and the running policy keeps serving.
	bad, _ := http.NewRequest(http.MethodPost, ts.URL+"/reload", strings.NewReader(`{"policy": {}}`))
	bad.Header.Set("Authorization", "Bearer test-reload-token")
	br, err := (&http.Client{}).Do(bad)
	if err != nil {
		t.Fatalf("POST bad reload: %v", err)
	}
	br.Body.Close()
	if br.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad reload status = %d, want 400", br.StatusCode)
	}

	get, _ := http.NewRequest(http.MethodGet, ts.URL+"/reload", nil)
	gr, err := (&http.Client{}).Do(get)
	if err != nil {
		t.Fatalf("GET /reload: %v", err)
	}
	gr.Body.Close()
	if gr.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /reload status = %d, want 405", gr.StatusCode)
	}
}
