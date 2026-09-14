// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 决策上下文（RATS §10）在准入侧的闸门：部署若要求新鲜度，就必须钉定上下文，
// 且放行时它必须仍然新鲜；缺失、过期、未来时间一律 fail-closed。

package aicverifier

import (
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func TestFreshDecisionContextGate(t *testing.T) {
	now := time.Now().UTC()

	cases := []struct {
		name      string
		required  bool
		ctx       *semantics.DecisionContext
		want      DecisionResult
		reasonHas string
	}{
		{"not required, no context", false, nil, DecisionAllow, ""},
		{"required and fresh", true, &semantics.DecisionContext{At: now, MaxAgeSec: 60}, DecisionAllow, ""},
		{"required but missing", true, nil, DecisionDeny, "context_missing"},
		{"required but stale", true, &semantics.DecisionContext{At: now.Add(-10 * time.Minute), MaxAgeSec: 60}, DecisionDeny, "context_stale"},
		{"required but future-dated", true, &semantics.DecisionContext{At: now.Add(5 * time.Minute)}, DecisionDeny, "context_future"},
		{"required, implicit only", true, &semantics.DecisionContext{Nonce: "n-1"}, DecisionDeny, "context_no_clock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := testAICCert(t, false)
			cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
			cfg.RequireFreshDecisionContext = tc.required
			cfg.DecisionContext = tc.ctx

			res := CheckAdmission(cert, cfg)
			if res.Decision != tc.want {
				t.Fatalf("decision = %v (%s), want %v", res.Decision, res.Reason, tc.want)
			}
			if tc.reasonHas != "" && !strings.Contains(res.Reason, tc.reasonHas) {
				t.Errorf("reason %q should carry %q", res.Reason, tc.reasonHas)
			}
		})
	}
}

// 上下文闸门只作用于会放行的路径：拒绝本就拒绝，不被它改写原因。
func TestDecisionContextGateDoesNotMaskDenial(t *testing.T) {
	cert := testAICCert(t, false)
	cfg := B2Config(Operation{ID: "std/database-v1:cert:issue"}) // 证书里没有该能力
	cfg.RequireFreshDecisionContext = true
	cfg.DecisionContext = &semantics.DecisionContext{At: time.Now().UTC().Add(-10 * time.Minute), MaxAgeSec: 60}

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %v, want deny", res.Decision)
	}
	if strings.Contains(res.Reason, "context_stale") {
		t.Errorf("a capability denial must not be reported as a context problem: %q", res.Reason)
	}
}
