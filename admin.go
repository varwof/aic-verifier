// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Administration face of the decision core: admission counters, a readiness
// health view and policy hot reload.  All of it hangs off DecisionServer, so
// HTTP, gRPC and queue carriers share one place to be observed and one policy
// snapshot (task: the per-Config isolation from integration pass B now has a
// live reload seam — ReloadPolicy swaps exactly the per-config policy the
// pipeline reads, atomically).

package aicverifier

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// DecisionMetrics is the light administration counter set of one decision
// server: admission totals plus reload/health bookkeeping, safe for concurrent
// use.  A nil *DecisionMetrics is a no-op (zero-value authenticators do not
// count).
type DecisionMetrics struct {
	StartedAt    time.Time
	DecideTotal  atomic.Uint64
	Granted      atomic.Uint64
	Denied       atomic.Uint64
	ConfigReload atomic.Uint64
	lastErr      atomic.Pointer[timeInst]
	lastOK       atomic.Pointer[timeInst]
}

type timeInst struct{ At time.Time }

// NewDecisionMetrics creates a counter set with its start clock.
func NewDecisionMetrics() *DecisionMetrics {
	return &DecisionMetrics{StartedAt: time.Now().UTC()}
}

// MetricsSnapshot is the serializable counter set (/metrics payload).
type MetricsSnapshot struct {
	UptimeSeconds int64  `json:"uptime_seconds"`
	DecideTotal   uint64 `json:"decide_total"`
	Granted       uint64 `json:"granted"`
	Denied        uint64 `json:"denied"`
	ConfigReloads uint64 `json:"config_reloads"`
}

// Snapshot returns a consistent view of the counters.
func (m *DecisionMetrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		UptimeSeconds: int64(time.Since(m.StartedAt).Seconds()),
		DecideTotal:   m.DecideTotal.Load(),
		Granted:       m.Granted.Load(),
		Denied:        m.Denied.Load(),
		ConfigReloads: m.ConfigReload.Load(),
	}
}

func (m *DecisionMetrics) noteResult(err error) {
	if m == nil {
		return
	}
	now := &timeInst{At: time.Now().UTC()}
	if err != nil {
		m.Denied.Add(1)
		m.lastErr.Store(now)
		return
	}
	m.Granted.Add(1)
	m.lastOK.Store(now)
}

// Healthy reports whether the server is safe to direct new admission traffic
// at: everything served is used as-is; when the most recent decision failed it
// reports false so a load balancer can drain.
func (m *DecisionMetrics) Healthy() bool {
	if m == nil {
		return true
	}
	lastErr, lastOK := m.lastErr.Load(), m.lastOK.Load()
	switch {
	case lastErr == nil:
		return true
	case lastOK == nil:
		return false
	default:
		return lastOK.At.After(lastErr.At)
	}
}

// HealthReport is the /healthz payload: module identity, readiness and the
// counters so one curl shows both liveness and the decision mix.
type HealthReport struct {
	OK            bool            `json:"ok"`
	Module        string          `json:"module"`
	StartTime     string          `json:"start_time"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	LastErrorAt   string          `json:"last_error_at,omitempty"`
	LastOKAt      string          `json:"last_ok_at,omitempty"`
	Metrics       MetricsSnapshot `json:"metrics"`
}

// Health builds the readiness report for one decision server.
func (s *DecisionServer) Health(ctx context.Context) HealthReport {
	if s == nil || s.a == nil {
		return HealthReport{Module: "varwof.aic.decision.v1", OK: false}
	}
	return healthReport(s.a.metrics)
}

// Health builds the readiness report for the middleware path (Config.Handler /
// Config.AuthMiddleware), where no DecisionServer handle exists. It reads the
// same counter set the middleware records into (Config.Metrics), so a service
// embedding the middleware can serve liveness/readiness without constructing a
// DecisionServer.
func (c *Config) Health() HealthReport {
	if c == nil {
		return HealthReport{Module: "varwof.aic.decision.v1", OK: false}
	}
	return healthReport(c.Metrics())
}

// healthReport assembles a HealthReport from a counter set. A nil set is
// treated as a freshly-started, healthy server.
func healthReport(m *DecisionMetrics) HealthReport {
	r := HealthReport{Module: "varwof.aic.decision.v1"}
	if m == nil {
		return r
	}
	r.OK = m.Healthy()
	if ts := m.lastErr.Load(); ts != nil {
		r.LastErrorAt = ts.At.UTC().Format(time.RFC3339Nano)
	}
	if ts := m.lastOK.Load(); ts != nil {
		r.LastOKAt = ts.At.UTC().Format(time.RFC3339Nano)
	}
	snap := m.Snapshot()
	r.Metrics = snap
	r.StartTime = m.StartedAt.UTC().Format(time.RFC3339Nano)
	r.UptimeSeconds = snap.UptimeSeconds
	return r
}

// ── Policy hot reload ──

// authPolicyBundle is one immutable decision-time policy snapshot.  A reload
// swaps the whole bundle through an atomic pointer, so every concurrent
// request reads one consistent policy (an update never sees a half-applied
// half-stale registry).
type authPolicyBundle struct {
	Policy      *AuthorizationPolicy
	Constraints *ConstraintRegistry
	Validators  *ParameterValidatorRegistry
}

// reloadableBundle returns the live bundle, or nil when none was installed
// (plain a.cfg-backed operation).
func (a *authenticator) reloadableBundle() *authPolicyBundle {
	if a == nil {
		return nil
	}
	return a.policy.Load()
}

// ReloadPolicy atomically installs a new authorization policy for the next
// admission.  It validates the policy first; an invalid policy is rejected and
// the running snapshot keeps serving.
func (s *DecisionServer) ReloadPolicy(p *AuthorizationPolicy) error {
	return s.reload(&authPolicyBundle{Policy: p})
}

// ReloadPolicyFromFile loads and verifies a signed gateway policy (authz.json
// + detached PKCS#7 signature) and installs it like ReloadPolicy.  opts nil
// skips signature verification (plain JSON policy), which is fine for the
// admin endpoint but not for production policy rotation.
func (s *DecisionServer) ReloadPolicyFromFile(policyPath, sigSuffix string, opts *PolicyVerifyOptions) error {
	p, err := LoadAuthorizationPolicy(policyPath, sigSuffix, opts)
	if err != nil {
		return err
	}
	return s.ReloadPolicy(p)
}

// reload validates and swaps a policy bundle, counting successful installs.
func (s *DecisionServer) reload(b *authPolicyBundle) error {
	if s == nil || s.a == nil {
		return fmt.Errorf("aic-verifier: reload: decision server not configured")
	}
	if b == nil {
		return fmt.Errorf("aic-verifier: reload: nil bundle")
	}
	if err := validateReloadPolicy(b); err != nil {
		return err
	}
	s.a.policy.Store(b)
	if m := s.a.metrics; m != nil {
		m.ConfigReload.Add(1)
	}
	if l := s.a.log; l != nil {
		l.Info("aic-verifier: policy reloaded", "version", b.Policy.Version, "roles", len(b.Policy.Roles))
	}
	return nil
}

// validateReloadPolicy enforces the same structural bar as
// ParseAuthorizationPolicy: a reload must never install a policy the pipeline
// would reject at parse time.
func validateReloadPolicy(b *authPolicyBundle) error {
	if b.Policy == nil {
		return fmt.Errorf("aic-verifier: reload: policy is nil")
	}
	if b.Policy.Version == "" {
		return fmt.Errorf("aic-verifier: reload: policy missing version")
	}
	if len(b.Policy.Roles) == 0 {
		return fmt.Errorf("aic-verifier: reload: policy has no roles")
	}
	return nil
}

// ── Admin HTTP surface ──

// AdminHandler serves the light administration endpoints on one mux:
//
//	GET  /healthz  readiness + counters (see Health)
//	GET  /readyz   alias of /healthz (Kubernetes convention)
//	GET  /health   alias of /healthz
//	GET  /metrics  counter snapshot
//	POST /reload   install a policy from {"policy": {…}} (validated, atomic)
//
// Mount it yourself (e.g. a management listener); it never multiplexes with
// the admission handler.
func (s *DecisionServer) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleHealth)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/reload", s.handleReload)
	return mux
}

type reloadRequest struct {
	Policy json.RawMessage `json:"policy"`
}

func (s *DecisionServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeAdminJSON(w, http.StatusOK, s.Health(context.Background()))
}

func (s *DecisionServer) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	var snap MetricsSnapshot
	if s != nil && s.a != nil && s.a.metrics != nil {
		snap = s.a.metrics.Snapshot()
	}
	writeAdminJSON(w, http.StatusOK, snap)
}

func (s *DecisionServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed", "use": "POST"})
		return
	}
	// P0-1: /reload is fail-closed.  The constructor refuses to build a
	// DecisionServer without an admin secret, so adminToken is never empty when
	// this handler runs; the operator had to configure AdminToken/AdminTokenFile
	// or the admin listener cannot mount at all.  Compare the Authorization:
	// Bearer secret with the configured token in constant time (no early-exit on
	// length, no plaintext equality) and refuse without chaining into the
	// authenticator when it does not match — the old surface let an unauthenticated
	// POST swap trust material (trust-injection without a credential).
	secret := "reload-admin"
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		sec := []byte(secret)
		_ = subtle.ConstantTimeCompare([]byte(auth), sec)
		writeAdminJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "detail": "Bearer admin secret required"})
		return
	}
	got := strings.TrimPrefix(auth, prefix)
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.adminToken)) != 1 {
		writeAdminJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "detail": "invalid admin bearer token"})
		return
	}
	var req reloadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "detail": err.Error()})
		return
	}
	p, err := ParseAuthorizationPolicy(req.Policy)
	if err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": "policy_invalid", "detail": err.Error()})
		return
	}
	if err := s.ReloadPolicy(p); err != nil {
		writeAdminJSON(w, http.StatusBadRequest, map[string]string{"error": "reload_failed", "detail": err.Error()})
		return
	}
	writeAdminJSON(w, http.StatusOK, s.Health(r.Context()))
}

func writeAdminJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Never fail the response over an encoding error of our own types.
		_, _ = w.Write([]byte("{}"))
	}
}
