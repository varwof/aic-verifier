// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	pki "github.com/varwof/types"
)

func TestAuthContextFromHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/mcp", nil)
	r.Header.Set("X-AIC-Agent-Id", "agent-007")
	r.Header.Set("X-AIC-Principal-Uid", "principal-uid-7")
	r.Header.Set("X-AIC-Capabilities-Full", "mcp:db_query,mcp:trade_exec")

	ac := AuthContextFromHeaders(r)
	if ac == nil {
		t.Fatal("nil AuthContext for present identity headers")
	}
	if ac.AgentID != "agent-007" || ac.Principal != "principal-uid-7" {
		t.Fatalf("identity mismatch: AgentID=%q Principal=%q", ac.AgentID, ac.Principal)
	}
	if len(ac.Capabilities) != 2 || ac.Capabilities[0] != "mcp:db_query" {
		t.Fatalf("Capabilities = %v", ac.Capabilities)
	}
	if ac.AIC == nil {
		t.Fatal("AIC nil")
	}
	if ac.AIC.AgentId != "agent-007" || len(ac.AIC.Capabilities) != 2 {
		t.Fatalf("AIC = %+v", ac.AIC)
	}
	c0 := ac.AIC.Capabilities[0]
	if c0.FullID() != "mcp:db_query" || c0.SchemeId != "mcp" || c0.CapabilityId != "db_query" {
		t.Fatalf("capability round-trip = %+v (FullID %q)", c0, c0.FullID())
	}
}

func TestAuthContextFromHeadersBareCapability(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/mcp", nil)
	r.Header.Set("X-AIC-Agent-Id", "agent-007")
	r.Header.Set("X-AIC-Capabilities-Full", "noscheme")
	ac := AuthContextFromHeaders(r)
	if ac == nil {
		t.Fatal("nil AuthContext")
	}
	if ac.AIC.Capabilities[0].FullID() != "noscheme" {
		t.Fatalf("bare capability round-trip = %+v", ac.AIC.Capabilities[0])
	}
}

func TestAuthContextFromHeadersAgentIDFallback(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/mcp", nil)
	r.Header.Set("X-Agent-ID", "compat-agent")
	ac := AuthContextFromHeaders(r)
	if ac == nil || ac.AgentID != "compat-agent" {
		t.Fatalf("X-Agent-ID fallback failed: %+v", ac)
	}
	if ac.AIC == nil || ac.AIC.AgentId != "compat-agent" {
		t.Fatalf("AIC agent id not set from fallback: %+v", ac.AIC)
	}
}

func TestAuthContextFromHeadersAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/mcp", nil)
	if ac := AuthContextFromHeaders(r); ac != nil {
		t.Fatalf("expected nil without identity headers, got %+v", ac)
	}
	if ac := AuthContextFromHeaders(nil); ac != nil {
		t.Fatalf("nil request must yield nil AuthContext")
	}
}

func TestIdentityHeadersEmitFullCapabilities(t *testing.T) {
	ac := &AuthContext{
		AgentID:    "agent-007",
		Principal:  "principal-uid-7",
		ClientCert: &x509.Certificate{},
		AIC: &AIC{
			AgentId: "agent-007",
			Capabilities: []pki.Capability{
				{SchemeId: "mcp", CapabilityId: "db_query"},
				{SchemeId: "mcp", CapabilityId: "trade_exec"},
			},
		},
	}
	r := httptest.NewRequest(http.MethodGet, "http://backend.test/mcp", nil)
	injectIdentityHeaders(r, ac, IdentityAIC)

	if got := r.Header.Get("X-AIC-Capabilities"); got != "db_query,trade_exec" {
		t.Fatalf("X-AIC-Capabilities = %q", got)
	}
	if got := r.Header.Get("X-AIC-Capabilities-Full"); got != "mcp:db_query,mcp:trade_exec" {
		t.Fatalf("X-AIC-Capabilities-Full = %q", got)
	}
}
