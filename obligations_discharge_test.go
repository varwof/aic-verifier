// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 义务语义（CLC §8.4 + XACML 3.0 §2.13/§7.2.1）在准入侧的表现。
//
// 严格模式回答的是「消费方是否理解并有能力履行」这一层：义务的身份必须被
// 部署显式声明过，否则一律 fail-closed —— 即使 UnresolvedEvaluator 愿意放行。
// 值层面的确认（这个时间窗此刻是否成立）仍由 UnresolvedEvaluator 负责。

package aicverifier

import (
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

const timeObligationIdentity = "varwof/constraint-v1:time"

func TestDischargeObligationsReleasesOnlyWithDeclaredSupport(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	cfg.DischargeObligations = true
	cfg.ObligationsUnderstood = []string{timeObligationIdentity}
	cfg.UnresolvedEvaluator = func(Operation, []string) bool { return true }

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionAllow {
		t.Fatalf("decision = %v, want allow (%s)", res.Decision, res.Reason)
	}
	od := res.OperationDecisions[0]
	if od.Verdict != semantics.VerdictAllowUR || !od.Released {
		t.Errorf("operation decision = %+v, want allow_unresolved + released", od)
	}
}

// 声明了别的义务类型（network）而实际带的是 time：消费方**不理解**这条义务，
// 即使 UnresolvedEvaluator 说可以放行，也必须拒绝。
func TestDischargeObligationsUnknownIdentityDenies(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	cfg.DischargeObligations = true
	cfg.ObligationsUnderstood = []string{"varwof/constraint-v1:network"}
	cfg.UnresolvedEvaluator = func(Operation, []string) bool { return true }

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %v, want deny: an unknown obligation must not be released", res.Decision)
	}
	if !strings.Contains(res.Reason, "obligation_unknown") {
		t.Errorf("reason %q should carry the stable obligation_unknown code", res.Reason)
	}
}

// 严格模式下未声明任何可履行义务 == 什么都不懂，必须拒绝（不得默认放行）。
func TestDischargeObligationsWithoutDeclaredSupportDenies(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	cfg.DischargeObligations = true
	cfg.UnresolvedEvaluator = func(Operation, []string) bool { return true }

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %v, want deny when nothing is declared dischargeable", res.Decision)
	}
	if !strings.Contains(res.Reason, "obligation_unknown") {
		t.Errorf("reason %q should carry obligation_unknown", res.Reason)
	}
}

// 严格模式关闭时保持原有行为（向后兼容：只有 UnresolvedEvaluator 说话）。
func TestDischargeObligationsOffKeepsLegacyBehaviour(t *testing.T) {
	cert := testAICCert(t, true)
	cfg := B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}})
	cfg.UnresolvedEvaluator = func(Operation, []string) bool { return true }

	res := CheckAdmission(cert, cfg)
	if res.Decision != DecisionAllow {
		t.Fatalf("decision = %v, want allow (legacy path unchanged)", res.Decision)
	}
}
