// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build smoke

package smoke

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	aicverifier "github.com/varwof/aic-verifier"
	pki "github.com/varwof/types"
)

// dbCaps returns the standard database capability used by the admission smoke.
func dbCaps(params string) []pki.Capability {
	return []pki.Capability{{
		SchemeId:     "std/database-v1",
		CapabilityId: "query:SELECT",
		Parameters:   []byte(params),
	}}
}

func windowConstraint(windowJSON string) []pki.Capability {
	return []pki.Capability{{
		SchemeId:     "varwof/constraint-v1",
		CapabilityId: "time:window",
		Parameters:   []byte(windowJSON),
	}}
}

// TestCheckAdmissionCuration mirrors the CLC corpus at the admission boundary:
// a parameter-bounded grant, an in-boundary request, an out-of-boundary
// request, and a residual obligation released by the deployment hook.
func TestCheckAdmissionCuration(t *testing.T) {
	ca := newCA(t, "Smoke CA")

	plain, _ := ca.issueAIC(t, "agent-plain", dbCaps(`{"limit":10}`), nil)
	windowed, _ := ca.issueAIC(t, "agent-window",
		dbCaps(`{"limit":10}`),
		windowConstraint(`[{"start":"00:00","end":"06:00"}]`))

	tests := []struct {
		name    string
		cert    *x509.Certificate
		op      aicverifier.Operation
		release bool
		want    aicverifier.DecisionResult
		reason  string
	}{
		{
			name: "in-boundary params allow",
			cert: plain,
			op:   aicverifier.Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
			want: aicverifier.DecisionAllow,
		},
		{
			name: "params exceed grant deny",
			cert: plain,
			op:   aicverifier.Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 50}},
			want: aicverifier.DecisionDeny, reason: "params_exceed_grant",
		},
		{
			name: "unresolved constraint fails closed",
			cert: windowed,
			op:   aicverifier.Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
			want: aicverifier.DecisionDeny, reason: "allow_unresolved",
		},
		{
			name:    "unresolved constraint released",
			cert:    windowed,
			op:      aicverifier.Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
			release: true,
			want:    aicverifier.DecisionAllow,
		},
		{
			name: "capability not authorized deny",
			cert: plain,
			op:   aicverifier.Operation{ID: "std/database-v1:query:INSERT", Params: map[string]any{"rows": 1}},
			want: aicverifier.DecisionDeny, reason: "capability_not_authorized",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := aicverifier.AdmissionConfig{Operations: []aicverifier.Operation{tc.op}}
			if tc.release {
				cfg.UnresolvedEvaluator = func(aicverifier.Operation, []string) bool { return true }
			}
			res := aicverifier.CheckAdmission(tc.cert, cfg)
			if res.Decision != tc.want {
				t.Fatalf("decision = %v (%s), want %v", res.Decision, res.Reason, tc.want)
			}
			if tc.reason != "" && !strings.Contains(res.Reason, tc.reason) {
				t.Errorf("reason %q should contain %q", res.Reason, tc.reason)
			}
		})
	}
}

// TestMTLSAdmissionLive runs the admission pipeline over a real mTLS HTTP
// connection: the client certificate is verified against the CA, the AIC is
// admitted, and the downstream handler sees the freshly surfaced CLC verdict
// via FromContext.  A request whose capability is not granted is refused 403.
func TestMTLSAdmissionLive(t *testing.T) {
	ca := newCA(t, "Smoke Live CA")
	caFile := writeTempPEM(t, "ca.pem", ca.pem)

	_, allowedClient := ca.issueAIC(t, "agent-live", dbCaps(`{"limit":10}`), nil)
	_, deniedClient := ca.issueAIC(t, "agent-live-deny",
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:INSERT"}}, nil)

	cfg := &aicverifier.Config{
		CACertFile:           caFile,
		AuthMode:             aicverifier.MTLSOnly,
		RequireAIC:           true,
		RequiredCapabilities: []string{"query:SELECT"},
		EnforceConstraints:   true,
		RequiredOperations: []aicverifier.Operation{
			{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 5}},
		},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := aicverifier.FromContext(r.Context())
		if ac == nil {
			http.Error(w, "no auth context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent":     ac.AgentID,
			"principal": ac.Principal,
			"verdict":   ac.Verdict,
			"reason":    ac.Reason,
		})
	})
	handler, err := cfg.Handler(next)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	url := startMTLSServer(t, ca, handler)

	// Allowed: real TLS client auth with the AIC leaf.
	resp, body, err := doMTLS(t, url, allowedClient)
	if err != nil {
		t.Fatalf("allowed request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed status = %d, body=%s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if out["agent"] != "agent-live" {
		t.Errorf("agent = %v, want agent-live", out["agent"])
	}
	if out["verdict"] != "allow" {
		t.Errorf("verdict = %v, want allow", out["verdict"])
	}

	// Denied: the AIC lacks query:SELECT, so the required-capability check
	// refuses the connection before the handler runs.
	resp, body, err = doMTLS(t, url, deniedClient)
	if err != nil {
		// A handshake-time refusal is also acceptable, but we expect an
		// application-level 403 since the cert chain is valid.
		t.Fatalf("denied request transport: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "missing capabilities") {
		t.Errorf("denied body %q should name the missing capability", body)
	}
}

// doMTLS performs a GET with the given client certificate.  The client trusts
// no server CA (the httptest server certificate is ephemeral) but still
// presents its client certificate, which the server verifies against the smoke
// CA.
func doMTLS(t *testing.T, url string, client tls.Certificate) (*http.Response, string, error) {
	t.Helper()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{client},
			MinVersion:         tls.VersionTLS12,
		}},
	}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}
	return resp, string(data), nil
}
