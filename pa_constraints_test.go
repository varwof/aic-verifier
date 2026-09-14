// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 步骤②：PA 的约束进语言层（义务出现），**不自动兑现** —— 只有部署显式声明的
// 策略才能释放它；连接级检查变成一个可选的、必须点名的履行器。

package aicverifier

import (
	"errors"
	"testing"

	"github.com/varwof/register/semantics"
)

const paWindow = `varwof/constraint-v1:time:window:[{"start":"00:00","end":"06:00"}]`

func paWithConstraints(t *testing.T, constraints ...Capability) *PrincipalAuthorization {
	t.Helper()
	return &PrincipalAuthorization{
		Grants:                   []Capability{capWith("std/database-v1", "query:SELECT", "")},
		AuthorizationConstraints: constraints,
	}
}

// 之前：PA 侧的约束被丢掉 → allow。现在：它是一条义务 → allow_unresolved。
func TestPAConstraintsReachTheLanguage(t *testing.T) {
	pa := paWithConstraints(t, Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "time:window",
		Parameters: []byte(`[{"start":"00:00","end":"06:00"}]`)})

	dec, err := AuthorizeOperation(nil, pa, "std/database-v1:query:SELECT", nil)
	if err != nil {
		t.Fatalf("AuthorizeOperation: %v", err)
	}
	if dec.Verdict != semantics.VerdictAllowUR {
		t.Fatalf("verdict = %q, want allow_unresolved (the PA constraint is an obligation)", dec.Verdict)
	}
	if len(dec.Unresolved) != 1 || dec.Unresolved[0] != paWindow {
		t.Fatalf("unresolved = %v, want [%s]", dec.Unresolved, paWindow)
	}
	// 默认仍然 fail-closed：消费者没有声明能履行它。
	if err := semantics.Discharge(dec, nil); !errors.Is(err, semantics.ErrObligationUnknown) {
		t.Errorf("discharge without a declared policy: got %v, want ErrObligationUnknown", err)
	}
}

// 之前被**完全忽略**的那一类：max_rows 既不在连接级注册表里，也不在 CLC 里
// （因为约束被丢掉了）。现在它由语言层求值 —— 超界即拒。
func TestPAMaxRowsIsEnforced(t *testing.T) {
	pa := paWithConstraints(t, Capability{SchemeId: "varwof/constraint-v1", CapabilityId: "max_rows",
		Parameters: []byte(`100`)})

	over, err := AuthorizeOperation(nil, pa, "std/database-v1:query:SELECT", map[string]any{"max_rows": float64(150)})
	if err != nil {
		t.Fatalf("AuthorizeOperation: %v", err)
	}
	if over.Verdict != semantics.VerdictDeny || over.Reason != "max_rows:violated" {
		t.Fatalf("over bound = %+v, want deny/max_rows:violated", over)
	}

	within, err := AuthorizeOperation(nil, pa, "std/database-v1:query:SELECT", map[string]any{"max_rows": float64(50)})
	if err != nil {
		t.Fatalf("AuthorizeOperation: %v", err)
	}
	if within.Verdict != semantics.VerdictAllow {
		t.Fatalf("within bound = %+v, want allow", within)
	}
}

// 显式履行：部署点名这个策略，才把连接级检查当作兑现。
func TestConnectionConstraintEvaluator(t *testing.T) {
	// The client IP is inside the granted range → discharged.
	inside := ConnectionConstraintEvaluator("10.1.2.3")
	if !inside(Operation{}, []string{`varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`}) {
		t.Error("a satisfied connection constraint must discharge")
	}
	outside := ConnectionConstraintEvaluator("192.0.2.7")
	if outside(Operation{}, []string{`varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`}) {
		t.Error("a violated connection constraint must not discharge")
	}

	// The registry has no max_rows evaluator → never discharged here (fail-closed).
	if inside(Operation{}, []string{`varwof/constraint-v1:max_rows:100`}) {
		t.Error("a constraint the connection registry cannot evaluate must not be discharged")
	}
	// Unparseable constraint → fail closed.
	if inside(Operation{}, []string{"nonsense"}) {
		t.Error("an unparseable constraint must not be discharged")
	}
	// Mixed set: one undischargeable entry fails the whole release (conjunction).
	if inside(Operation{}, []string{`varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`, "nonsense"}) {
		t.Error("one undischargeable obligation must fail the whole discharge")
	}
}

func TestConstraintToCapabilityRoundTrip(t *testing.T) {
	cases := []string{
		paWindow,
		`varwof/constraint-v1:max_rows:100`,
		`varwof/constraint-v1:network:cidr:["10.0.0.0/8"]`,
	}
	for _, c := range cases {
		cap, ok := ConstraintToCapability(c)
		if !ok {
			t.Fatalf("ConstraintToCapability(%q) failed", c)
		}
		back := ConstraintStrings([]Capability{cap})
		if len(back) != 1 || back[0] != c {
			t.Errorf("round trip %q -> %+v -> %v", c, cap, back)
		}
	}
	if _, ok := ConstraintToCapability("nonsense"); ok {
		t.Error("an unmappable constraint string must be rejected")
	}
}
