// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 来源合并：AIC 能力 ∩ 用户授权（PA）走语义层的具名算法
// （semantics.Combine，默认 deny-overrides），而不是各 SDK 自己写一份。
// 关键负例：一侧的"无条件放行"不得把另一侧的残余义务洗掉。

package aicverifier

import (
	"errors"
	"testing"

	"github.com/varwof/register/semantics"
)

func TestCombineDecisionsFollowsNamedAlgorithm(t *testing.T) {
	allow := semantics.Decision{Verdict: semantics.VerdictAllow}
	deny := semantics.Decision{Verdict: semantics.VerdictDeny, Reason: "capability_not_authorized"}
	obligated := semantics.Decision{
		Verdict:    semantics.VerdictAllowUR,
		Unresolved: []string{`varwof/constraint-v1:time:window:[{"start":"00:00","end":"06:00"}]`},
	}

	if got := combineDecisions(allow, deny); got.Verdict != semantics.VerdictDeny {
		t.Errorf("allow+deny = %+v, want deny (deny-overrides)", got)
	}
	if got := combineDecisions(obligated, allow); got.Verdict != semantics.VerdictAllowUR {
		t.Errorf("obligated+allow = %+v, want allow_unresolved", got)
	}
	if got := combineDecisions(allow, allow); got.Verdict != semantics.VerdictAllow {
		t.Errorf("allow+allow = %+v, want allow", got)
	}
}

// 义务不得被另一侧的 allow 洗掉：这是"冲突"在多来源场景里最危险的一种。
func TestObligationsSurviveSourceCombination(t *testing.T) {
	aic := &AIC{
		Capabilities: []Capability{capWith("std/database-v1", "query:SELECT", "")},
		AuthorizationConstraints: []Capability{{
			SchemeId:     "varwof/constraint-v1",
			CapabilityId: "time:window",
			Parameters:   []byte(`[{"start":"00:00","end":"06:00"}]`),
		}},
	}
	// PA 侧是无条件放行：合并结果仍必须带义务。
	pa := &PrincipalAuthorization{Grants: []Capability{capWith("std/database-v1", "query:SELECT", "")}}

	dec, err := AuthorizeOperation(aic, pa, "std/database-v1:query:SELECT", nil)
	if err != nil {
		t.Fatalf("AuthorizeOperation: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllowUR {
		t.Fatalf("combined verdict = %q (%s), want allow_unresolved", dec.Verdict, dec.Reason)
	}
	if err := semantics.Discharge(dec, nil); !errors.Is(err, semantics.ErrObligationUnknown) {
		t.Errorf("combined obligations must still gate the consumer: got %v", err)
	}
	if err := semantics.Discharge(dec, []string{"varwof/constraint-v1:time"}); err != nil {
		t.Errorf("declared support: %v", err)
	}

	// AIC 侧没有该能力而 PA 有：交集语义必须拒绝（缺源 = 不放行）。
	paOnly := &PrincipalAuthorization{Grants: []Capability{capWith("std/database-v1", "cert:issue", "")}}
	dec, err = AuthorizeOperation(aic, paOnly, "std/database-v1:cert:issue", nil)
	if err != nil {
		t.Fatalf("AuthorizeOperation: %v", err)
	}
	if dec.Verdict != semantics.VerdictDeny {
		t.Fatalf("missing source = %+v, want deny", dec)
	}
}
