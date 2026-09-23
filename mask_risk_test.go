// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"strings"
	"testing"
	"time"
)

// ── mask.go ──────────────────────────────────────────────────────────────────

func TestMaskFilePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/etc/pki/certs/secret.pem", "/etc/pki/certs/s****t.pem"},
		{"/var/run/agent.key", "/var/run/a***t.key"},
		{"/etc/host.conf", "/etc/h**t.conf"},
		{"secret.pem", "s****t.pem"},
		{"ab.txt", "**.txt"},
		{"a.txt", "*.txt"},
		{"noext", "*****"},
		{`c:\secrets\token.txt`, `c:\secrets\t***n.txt`},
		{"", ""},
	}
	for _, tc := range cases {
		if got := MaskFilePath(tc.in); got != tc.want {
			t.Errorf("MaskFilePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMaskFilePathKeepsBasenameShape asserts the directory is preserved and the
// filename keeps its extension and a recognizable first/last char (the
// maskBasename behavior exercised through the public entry point).
func TestMaskFilePathKeepsBasenameShape(t *testing.T) {
	in := "/etc/pki/certs/my-secret-name.pem"
	got := MaskFilePath(in)
	if !strings.HasPrefix(got, "/etc/pki/certs/") {
		t.Errorf("directory must be preserved, got %q", got)
	}
	if !strings.HasSuffix(got, ".pem") {
		t.Errorf("extension must be preserved, got %q", got)
	}
	if strings.Contains(got, "my-secret-name") {
		t.Errorf("filename must be masked, got %q", got)
	}
}

func TestMaskToken(t *testing.T) {
	cases := []struct {
		in   string
		same int // prefix chars kept, suffix chars kept (for len>8)
	}{
		{"", 0},
		{"12345678", 0}, // n<=8 → fully masked
		{"abcdefgh", 0},
		{"abcdefghi", 2}, // n=9 → keep 2 per side
		{"sk-abc123def456ghi789", 4},
	}
	for _, tc := range cases {
		got := MaskToken(tc.in)
		if tc.in == "" {
			if got != "" {
				t.Errorf("MaskToken(%q) = %q, want empty", tc.in, got)
			}
			continue
		}
		if len(got) != len(tc.in) {
			t.Errorf("MaskToken(%q) length = %d, want %d", tc.in, len(got), len(tc.in))
		}
		if tc.same == 0 {
			if got != strings.Repeat(string(DefaultMaskRune), len(tc.in)) {
				t.Errorf("short token must be fully masked, got %q", got)
			}
			continue
		}
		if got[:tc.same] != tc.in[:tc.same] {
			t.Errorf("prefix not preserved: %q vs %q", got[:tc.same], tc.in[:tc.same])
		}
		if got[len(got)-tc.same:] != tc.in[len(tc.in)-tc.same:] {
			t.Errorf("suffix not preserved: %q vs %q", got[len(got)-tc.same:], tc.in[len(tc.in)-tc.same:])
		}
		for _, r := range got[tc.same : len(got)-tc.same] {
			if r != DefaultMaskRune {
				t.Errorf("middle must be fully masked, got %q", got)
			}
		}
	}
}

func TestMaskEmail(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"alice@example.com", "a***e@example.com"},
		{"ab@example.com", "**@example.com"},
		{"a@example.com", "*@example.com"},
		{"verylongmail@x.io", "v**********l@x.io"},
		{"no-at-sign-here", "***********here"}, // no @ → MaskString(_, 4)
	}
	for _, tc := range cases {
		if got := MaskEmail(tc.in); got != tc.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ab\x00\x01cd", "abcd"},
		{"a\rb\x7f", "ab"},
		{"  hello  ", "hello"},
		{"line1\nline2", "line1\nline2"},
		{"a\tb", "a\tb"},
		{"caf\xc3\xa9", "caf"}, // non-ASCII rune stripped
	}
	for _, tc := range cases {
		if got := SanitizeString(tc.in); got != tc.want {
			t.Errorf("SanitizeString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── riskmonitor.go ───────────────────────────────────────────────────────────

func TestRiskMonitorRecordAndEnforce(t *testing.T) {
	var actions []string
	rm := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{
			Name:          "kick-overflow",
			Signals:       []string{"cap_overflow"},
			Threshold:     2,
			WindowSeconds: 600,
			Action:        "revoke",
			Reason:        "repeated overflow",
		}},
		OnAction: func(agentID, action, reason string) {
			actions = append(actions, action+":"+reason)
		},
	})

	rules := rm.Rules()
	if len(rules) != 1 || rules[0].Name != "kick-overflow" {
		t.Fatalf("Rules() = %+v, want the configured rule", rules)
	}

	if rm.Violations("agent-1") != 0 {
		t.Fatalf("fresh monitor must report 0 violations")
	}

	if rm.RecordViolation(RiskViolation{AgentId: "agent-1", Signal: "cap_overflow"}) {
		t.Fatal("1/2 violations must not trigger enforcement")
	}
	if rm.Violations("agent-1") != 1 {
		t.Fatalf("Violations after one record = %d, want 1", rm.Violations("agent-1"))
	}
	if len(actions) != 0 {
		t.Fatalf("no action expected below threshold, got %v", actions)
	}

	if !rm.RecordViolation(RiskViolation{AgentId: "agent-1", Signal: "cap_overflow"}) {
		t.Fatal("2/2 violations must trigger enforcement")
	}
	if rm.Violations("agent-1") != 0 {
		t.Fatalf("violations must be cleared after enforcement, got %d", rm.Violations("agent-1"))
	}
	if len(actions) != 1 || actions[0] != "revoke:repeated overflow" {
		t.Fatalf("actions = %v, want [revoke:repeated overflow]", actions)
	}
}

func TestRiskMonitorNoRulesAndWindowPruning(t *testing.T) {
	rm := NewRiskMonitor(RiskMonitorConfig{}) // no rules
	if rm.RecordViolation(RiskViolation{AgentId: "x", Signal: "s"}) {
		t.Fatal("no rules → must not trigger")
	}
	if rm.Violations("x") != 0 {
		t.Fatal("no rules → violation must not be recorded")
	}

	// Expired violations fall out of the counting window: with two recordings,
	// the first (expired) must be pruned so only the fresh one counts, and a
	// threshold of 2 must NOT trigger.
	rm2 := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{Name: "r", Signals: []string{"*"}, Threshold: 2, WindowSeconds: 60}},
	})
	t0 := time.Now().Unix()
	if rm2.RecordViolation(RiskViolation{AgentId: "w", Signal: "s", At: t0 - 120}) {
		t.Fatal("first violation below threshold must not trigger")
	}
	if rm2.Violations("w") != 1 {
		t.Fatalf("first violation not recorded, got %d", rm2.Violations("w"))
	}
	if rm2.RecordViolation(RiskViolation{AgentId: "w", Signal: "s", At: t0}) {
		t.Fatal("an expired violation must be pruned; only 1 in-window violation < threshold 2")
	}
	if got := rm2.Violations("w"); got != 1 {
		t.Fatalf("windowed violations = %d, want 1 (expired entry pruned)", got)
	}
}

func TestRiskMonitorSetRulesReplacesAndClears(t *testing.T) {
	rm := NewRiskMonitor(RiskMonitorConfig{
		Rules: []RiskRule{{Name: "a", Signals: []string{"a"}, Threshold: 5, WindowSeconds: 60}},
	})
	rm.RecordViolation(RiskViolation{AgentId: "a1", Signal: "a"})
	if rm.Violations("a1") != 1 {
		t.Fatalf("setup: Violations = %d, want 1", rm.Violations("a1"))
	}

	rm.SetRules([]RiskRule{{Name: "b", Signals: []string{"b"}, Threshold: 1, WindowSeconds: 60}})
	if rm.Violations("a1") != 0 {
		t.Fatalf("SetRules must clear recorded violations, got %d", rm.Violations("a1"))
	}
	got := rm.Rules()
	if len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("Rules() after SetRules = %+v, want the new rule", got)
	}
}

func TestRiskMonitorNilReceiver(t *testing.T) {
	var rm *RiskMonitor
	if rm.Rules() != nil {
		t.Fatal("nil receiver Rules must return nil")
	}
	if rm.Violations("a") != 0 {
		t.Fatal("nil receiver Violations must return 0")
	}
	if rm.RecordViolation(RiskViolation{AgentId: "a", Signal: "s"}) {
		t.Fatal("nil receiver RecordViolation must return false")
	}
	rm.SetRules(nil) // must not panic
}

func TestSignalIn(t *testing.T) {
	cases := []struct {
		list []string
		sig  string
		want bool
	}{
		{nil, "x", false},
		{[]string{"a", "b"}, "a", true},
		{[]string{"CAP_OVERFLOW"}, "cap_overflow", true}, // case-insensitive
		{[]string{"*"}, "anything", true},
		{[]string{"a"}, "b", false},
	}
	for _, tc := range cases {
		if got := signalIn(tc.list, tc.sig); got != tc.want {
			t.Errorf("signalIn(%v, %q) = %v, want %v", tc.list, tc.sig, got, tc.want)
		}
	}
}
