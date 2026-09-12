// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// RiskMonitor — automated disconnect + revocation for high-risk agents
//
// Reactive closed loop: behavioral/metric signals → risk rule evaluation →
// disconnect + conditional revocation + audit.
// Positioned as the automated response layer above the monitoring presentation layer
// (2026-08-15 user plan 8.4).

package aicverifier

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// RiskViolation describes a recorded behavioral violation (risk signal).
type RiskViolation struct {
	// AgentId is the violating agent.
	AgentId string `json:"agent_id,omitempty"`
	// Signal is the risk signal type (e.g. cap_overflow / abnormal_rate / out_of_window).
	Signal string `json:"signal"`
	// CapabilityId is the associated capability identifier (optional).
	CapabilityId string `json:"capability_id,omitempty"`
	// Details provides supplementary description.
	Details string `json:"details,omitempty"`
	// At is the violation time (Unix seconds).
	At int64 `json:"at"`
}

// RiskRule is a single risk rule.
type RiskRule struct {
	// Name is the rule name.
	Name string `json:"name"`
	// Signals is the list of behavioral signal types that trigger the rule (any hit counts).
	Signals []string `json:"signals"`
	// Threshold is the violation count threshold within the window; reaching it triggers enforcement.
	Threshold int `json:"threshold"`
	// WindowSeconds is the counting window in seconds, default 60.
	WindowSeconds int `json:"window_seconds,omitempty"`
	// Action is the enforcement action: disconnect (kick) or revoke (kick + revoke).
	Action string `json:"action"`
	// Reason is the risk reason description for audit records.
	Reason string `json:"reason"`
}

// RiskMonitor maintains per-agent violation counts and enforces rules automatically.
// Thread-safe; nil receiver methods are no-ops (safe to call when gateway is not configured).
type RiskMonitor struct {
	mu         sync.Mutex
	rules      []RiskRule
	violations map[string][]RiskViolation // agentId → in-window violations
	onAction   func(agentId, action, reason string)
	logger     *slog.Logger
}

// RiskMonitorConfig is the configuration for RiskMonitor.
type RiskMonitorConfig struct {
	// Rules is the list of risk rules.
	Rules []RiskRule `json:"rules"`
	// OnAction is the enforcement callback (gateway injects: execute disconnect + revoke).
	// When nil, only logging is performed.
	OnAction func(agentId, action, reason string)
	// Logger is the structured logger; uses slog.Default() when nil.
	Logger *slog.Logger
}

// NewRiskMonitor creates a risk monitor.
func NewRiskMonitor(cfg RiskMonitorConfig) *RiskMonitor {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RiskMonitor{
		rules:      cfg.Rules,
		violations: make(map[string][]RiskViolation),
		onAction:   cfg.OnAction,
		logger:     logger,
	}
}

// Rules returns a copy of the current rule list.
func (m *RiskMonitor) Rules() []RiskRule {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RiskRule, len(m.rules))
	copy(out, m.rules)
	return out
}

// SetRules hot-swaps the rule set (called during SIGHUP hot-reload).
func (m *RiskMonitor) SetRules(rules []RiskRule) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = rules
	m.violations = make(map[string][]RiskViolation)
}

// RecordViolation records a behavioral violation and evaluates rules; triggers
// the enforcement callback when the threshold is reached.
// Returns whether enforcement was triggered. Returns false for nil receiver.
func (m *RiskMonitor) RecordViolation(v RiskViolation) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rules) == 0 {
		return false
	}
	now := v.At
	if now == 0 {
		now = time.Now().Unix()
	}
	v.At = now
	m.violations[v.AgentId] = append(m.violations[v.AgentId], v)

	for _, rule := range m.rules {
		window := rule.WindowSeconds
		if window <= 0 {
			window = 60
		}
		if rule.Threshold <= 0 {
			rule.Threshold = 1
		}
		count := 0
		matched := false
		kept := m.violations[v.AgentId][:0]
		for _, viol := range m.violations[v.AgentId] {
			if now-viol.At > int64(window) {
				continue // expired outside window
			}
			kept = append(kept, viol)
			if signalIn(rule.Signals, viol.Signal) {
				matched = true
			}
		}
		m.violations[v.AgentId] = kept
		if matched {
			count = len(kept)
		}
		if matched && count >= rule.Threshold {
			m.logger.Warn("risk monitor: action triggered",
				"agent_id", v.AgentId, "rule", rule.Name,
				"violations", count, "action", rule.Action, "reason", rule.Reason,
			)
			action := rule.Action
			if action == "" {
				action = "disconnect"
			}
			if m.onAction != nil {
				m.onAction(v.AgentId, action, rule.Reason)
			}
			delete(m.violations, v.AgentId)
			return true
		}
	}
	return false
}

// Violations returns the cumulative violation count for an agent within the window
// (used for monitoring display when no enforcement has been triggered).
// Returns 0 for nil receiver.
func (m *RiskMonitor) Violations(agentId string) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.violations[agentId])
}

func signalIn(list []string, sig string) bool {
	if len(list) == 0 {
		return false
	}
	for _, s := range list {
		if s == "*" || strings.EqualFold(s, sig) {
			return true
		}
	}
	return false
}
