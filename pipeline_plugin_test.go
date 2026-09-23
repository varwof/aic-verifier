// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

// validAIC builds an AIC that ParseAIC accepts (a non-zero
// DelegationAuthorization is required, otherwise parsing fails and callers
// fall back to the certificate CN). OID fields must be populated or
// encoding/asn1 fails to marshal the extension value.
func validAIC(agentID string) *AIC {
	return &AIC{
		Version: 1,
		AgentId: agentID,
		PrincipalUid: PrincipalUid{
			Version:    1,
			Realm:      "pki",
			Identifier: agentID,
			KeyHash:    make([]byte, 32),
			HashAlgo:   AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		DelegationAuthorization: DelegationAuthorization{
			Reason:             Reason{ReasonCode: "test", Description: "aic helper"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, pki.MaxNonceLen),
			SignatureAlgorithm: AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
}

// ── plugin.go ────────────────────────────────────────────────────────────────

// staticPlugin is a minimal CapabilityPlugin for registration/execution tests.
type staticPlugin struct {
	scheme string
	result *PluginResult
	err    error
}

func (p *staticPlugin) Scheme() string { return p.scheme }

func (p *staticPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	return p.result, p.err
}

func TestPluginRegistryEmpty(t *testing.T) {
	reg := NewPluginRegistry()
	if reg == nil {
		t.Fatal("NewPluginRegistry must return a registry")
	}
	if _, err := reg.Find("nope"); err == nil {
		t.Fatal("an empty registry must not find a scheme")
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("registering nil must error")
	}
}

func TestPluginRegisterFindExecuteReset(t *testing.T) {
	ResetPlugins()
	t.Cleanup(ResetPlugins)

	p := &staticPlugin{scheme: "pipeline/test-v1", result: &PluginResult{Decision: PluginAllow, Reason: "allowed"}}
	if err := RegisterPlugin(p); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}

	got, err := findPlugin("pipeline/test-v1")
	if err != nil {
		t.Fatalf("findPlugin: %v", err)
	}
	if got != p {
		t.Fatal("findPlugin returned a different plugin")
	}

	cap := &Capability{SchemeId: "pipeline/test-v1", CapabilityId: "run"}
	ctx := &PluginContext{Target: "run"}
	res, err := ExecutePlugin("pipeline/test-v1", cap, ctx)
	if err != nil {
		t.Fatalf("ExecutePlugin: %v", err)
	}
	if res.Decision != PluginAllow || res.Reason != "allowed" {
		t.Fatalf("ExecutePlugin result = %+v, want allow/allowed", res)
	}

	if err := RegisterPlugin(p); err == nil {
		t.Fatal("re-registering a scheme must error")
	}

	ResetPlugins()
	if _, err := findPlugin("pipeline/test-v1"); err == nil {
		t.Fatal("after ResetPlugins the scheme must be gone")
	}
	if _, err := ExecutePlugin("pipeline/test-v1", cap, ctx); err == nil {
		t.Fatal("after ResetPlugins ExecutePlugin must error")
	}
}

// ── pipeline.go ──────────────────────────────────────────────────────────────

func TestOfflineLifetimeFor(t *testing.T) {
	cases := []struct {
		fallback string
		want     time.Duration
	}{
		{OCSPFallbackAllow, OfflineLifetimeLimit},
		{OCSPFallbackCRL, OfflineLifetimeLimit},
		{OCSPFallbackDeny, 0},
		{"", 0},
		{"garbage", 0},
	}
	for _, tc := range cases {
		if got := OfflineLifetimeFor(tc.fallback); got != tc.want {
			t.Errorf("OfflineLifetimeFor(%q) = %v, want %v", tc.fallback, got, tc.want)
		}
	}
}

func TestAICAgentID(t *testing.T) {
	_, withAIC := mintCert(t, nil, nil, "cn-agent", big.NewInt(5), validAIC("a-42"), nil, nil)
	if got := aicAgentID(withAIC); got != "a-42" {
		t.Errorf("aicAgentID with AIC = %q, want a-42", got)
	}

	if got := aicAgentID(newPlainCert(t)); got != "client.example" {
		t.Errorf("aicAgentID plain cert = %q, want the CN", got)
	}

	if got := aicAgentID(nil); got != "" {
		t.Errorf("aicAgentID(nil) = %q, want empty", got)
	}
}

func TestRecordRiskViolation(t *testing.T) {
	rm := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{Name: "r", Signals: []string{"cap_overflow"}, Threshold: 2, WindowSeconds: 600}},
	})

	plain := newPlainCert(t)
	recordRiskViolation(rm, plain, "cap_overflow", "query:x", "details")
	if rm.Violations("client.example") != 1 {
		t.Errorf("plain-cert violations = %d, want 1 (keyed by CN)", rm.Violations("client.example"))
	}

	_, aicCert := mintCert(t, nil, nil, "cn-agent", big.NewInt(6), validAIC("a-99"), nil, nil)
	recordRiskViolation(rm, aicCert, "cap_overflow", "query:y", "more")
	if rm.Violations("a-99") != 1 {
		t.Errorf("AIC-cert violations = %d, want 1 (keyed by AgentId)", rm.Violations("a-99"))
	}

	recordRiskViolation(nil, plain, "cap_overflow", "query:x", "no-op") // must not panic
	recordRiskViolation(rm, nil, "cap_overflow", "query:x", "nil cert") // must not panic
}

func TestCheckOperationCapability(t *testing.T) {
	reg := NewPluginRegistry()

	allow := &staticPlugin{scheme: "op/db-v1", result: &PluginResult{Decision: PluginAllow, Reason: "ok"}}
	if err := reg.Register(allow); err != nil {
		t.Fatal(err)
	}

	res, err := CheckOperationCapability(reg, &Capability{SchemeId: "op/db-v1", CapabilityId: "query:SELECT"}, &PluginContext{})
	if err != nil {
		t.Fatalf("allowed operation: %v", err)
	}
	if res.Decision != PluginAllow {
		t.Fatalf("Decision = %v, want allow", res.Decision)
	}

	// Scheme with no plugin → fail-closed deny (no error).
	res, err = CheckOperationCapability(reg, &Capability{SchemeId: "op/unknown", CapabilityId: "x"}, &PluginContext{})
	if err != nil {
		t.Fatalf("unserved scheme must deny without an error, got %v", err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("unserved scheme Decision = %v, want deny", res.Decision)
	}

	denyP := &staticPlugin{scheme: "op/deny-v1", result: &PluginResult{Decision: PluginDeny, Reason: "blocked"}}
	if err := reg.Register(denyP); err != nil {
		t.Fatal(err)
	}
	res, err = CheckOperationCapability(reg, &Capability{SchemeId: "op/deny-v1", CapabilityId: "x"}, &PluginContext{})
	if err != nil {
		t.Fatalf("plugin deny: %v", err)
	}
	if res.Decision != PluginDeny {
		t.Fatalf("plugin deny Decision = %v, want deny", res.Decision)
	}

	if _, err := CheckOperationCapability(nil, &Capability{SchemeId: "op/db-v1"}, &PluginContext{}); err == nil {
		t.Fatal("nil registry must error")
	}
	if _, err := CheckOperationCapability(reg, nil, &PluginContext{}); err == nil {
		t.Fatal("nil capability must error")
	}
}

// ── server.go: ListenAndServe/Close ─────────────────────────────────────────

func TestServerListenAndServeClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(&Config{}, []Route{{Path: "/", Target: target}})
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET against running server: %v", err)
	}
	resp.Body.Close()

	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			t.Fatalf("Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down after Close")
	}

	if err := s.Close(ctx); err != nil {
		t.Errorf("second Close must succeed on a shutdown server: %v", err)
	}
}
