// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubConstraintEvaluator is a parameterizable ConstraintEvaluator for wiring/registry tests.
type stubConstraintEvaluator struct {
	capabilityId string
	evaluate     func(cap *Capability, ctx *ConstraintContext) error
}

func (e stubConstraintEvaluator) CapabilityId() string { return e.capabilityId }

func (e stubConstraintEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	if e.evaluate == nil {
		return nil
	}
	return e.evaluate(cap, ctx)
}

func TestParseMaxConcurrentParam(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
		err  bool
	}{
		{"empty", "", 0, false},
		{"valid", `{"max":10}`, 10, false},
		{"min", `{"max":1}`, 1, false},
		{"max", `{"max":1024}`, 1024, false},
		{"below_min", `{"max":0}`, 0, true},
		{"negative", `{"max":-3}`, 0, true},
		{"above_max", `{"max":1025}`, 0, true},
		{"bad_json", `not json`, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseMaxConcurrentParam([]byte(c.raw))
			if c.err {
				if err == nil {
					t.Fatalf("parseMaxConcurrentParam(%q): expected error", c.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMaxConcurrentParam(%q): %v", c.raw, err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestMaxConcurrentEvaluator(t *testing.T) {
	ev := maxConcurrentEvaluator{}
	if ev.CapabilityId() != ConstraintConcurrentKey {
		t.Fatalf("CapabilityId = %q", ev.CapabilityId())
	}
	ctx := &ConstraintContext{ClientIP: "10.0.0.1"}

	withMax := func(max string) *Capability {
		return &Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintConcurrentKey, Parameters: []byte(max)}
	}
	if err := ev.Evaluate(withMax(`{"max":4}`), ctx); err != nil {
		t.Fatalf("in-range limit rejected: %v", err)
	}
	if err := ev.Evaluate(withMax(`{"max":0}`), ctx); err == nil {
		t.Fatal("limit 0 must be rejected")
	}
	if err := ev.Evaluate(withMax(`{"max":1025}`), ctx); err == nil {
		t.Fatal("limit 1025 must be rejected")
	}
	if err := ev.Evaluate(withMax(`garbage`), ctx); err == nil {
		t.Fatal("non-JSON parameters must be rejected")
	}

	// Wire-through: the same limits are enforced by CheckAuthorizationConstraints.
	if err := CheckAuthorizationConstraints([]Capability{*withMax(`{"max":2}`)}, "10.0.0.1"); err != nil {
		t.Fatalf("CheckAuthorizationConstraints valid limit: %v", err)
	}
	if err := CheckAuthorizationConstraints([]Capability{*withMax(`{"max":4096}`)}, "10.0.0.1"); err == nil {
		t.Fatal("CheckAuthorizationConstraints should reject out-of-bounds concurrency limit")
	}
}

func TestConstraintRegistryCRUD(t *testing.T) {
	reg := NewConstraintRegistry()
	a := stubConstraintEvaluator{capabilityId: "custom:a"}
	b := stubConstraintEvaluator{capabilityId: "custom:b"}

	if err := reg.Register(a); err != nil {
		t.Fatalf("Register(a): %v", err)
	}
	if err := reg.Register(a); err == nil {
		t.Fatal("duplicate Register must fail")
	}
	if err := reg.Register(b); err != nil {
		t.Fatalf("Register(b): %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("Len = %d, want 2", reg.Len())
	}
	keys := reg.Keys()
	if len(keys) != 2 || !containsStr(keys, "custom:a") || !containsStr(keys, "custom:b") {
		t.Errorf("Keys = %v", keys)
	}
	ev, err := reg.Find("custom:a")
	if err != nil || ev == nil {
		t.Fatalf("Find(custom:a): ev=%v err=%v", ev, err)
	}
	if _, err := reg.Find("ghost"); err == nil {
		t.Fatal("Find(ghost) should fail")
	}

	// Replace updates in place and registers when absent.
	replaced := stubConstraintEvaluator{capabilityId: "custom:a"}
	if err := reg.Replace(replaced); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := reg.Replace(stubConstraintEvaluator{capabilityId: "custom:new"}); err != nil {
		t.Fatalf("Replace(new): %v", err)
	}
	if reg.Len() != 3 {
		t.Fatalf("Len after replace-new = %d, want 3", reg.Len())
	}

	reg.Remove("custom:a")
	if _, err := reg.Find("custom:a"); err == nil {
		t.Fatal("Find after Remove should fail")
	}
	if reg.Len() != 2 {
		t.Fatalf("Len after Remove = %d, want 2", reg.Len())
	}

	reg.Reset()
	if reg.Len() != 0 || len(reg.Keys()) != 0 {
		t.Fatalf("after Reset: Len=%d Keys=%v, want empty", reg.Len(), reg.Keys())
	}

	if err := reg.Register(nil); err == nil {
		t.Fatal("Register(nil) must fail")
	}
	if err := reg.Register(stubConstraintEvaluator{}); err == nil {
		t.Fatal("Register(empty id) must fail")
	}
	if err := reg.Replace(nil); err == nil {
		t.Fatal("Replace(nil) must fail")
	}
}

func TestHardTimeoutEvaluator(t *testing.T) {
	ev := hardTimeoutEvaluator{}
	if ev.CapabilityId() != ConstraintHardTimeoutKey {
		t.Fatalf("CapabilityId = %q", ev.CapabilityId())
	}
	ctx := &ConstraintContext{}

	cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintHardTimeoutKey, Parameters: []byte(`{"value":120}`)}
	if err := ev.Evaluate(&cap, ctx); err != nil {
		t.Fatalf("in-range value rejected: %v", err)
	}

	cap.Parameters = []byte(`{"value":59}`)
	if err := ev.Evaluate(&cap, ctx); err == nil {
		t.Error("value below HardTimeoutMin must be rejected")
	}
	cap.Parameters = []byte(`{"value":86401}`)
	if err := ev.Evaluate(&cap, ctx); err == nil {
		t.Error("value above HardTimeoutMax must be rejected")
	}
	cap.Parameters = []byte(`not json`)
	if err := ev.Evaluate(&cap, ctx); err == nil {
		t.Error("non-JSON parameters must be rejected")
	}
}

func TestReadOnlyEvaluator(t *testing.T) {
	ev := readOnlyEvaluator{}
	ctx := &ConstraintContext{}
	cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintReadOnlyKey, Parameters: []byte(`{"value":true}`)}
	if err := ev.Evaluate(&cap, ctx); err != nil {
		t.Fatalf("readonly true accepted? %v", err)
	}
	cap.Parameters = []byte(`{"value":"yes"}`)
	if err := ev.Evaluate(&cap, ctx); err == nil {
		t.Error("non-boolean value must be rejected")
	}
}

func TestCIDREvaluator(t *testing.T) {
	ev := cidrEvaluator{}
	cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintCIDRKey, Parameters: []byte(`["10.0.0.0/8","172.16.0.0/12"]`)}

	if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "10.1.2.3"}); err != nil {
		t.Fatalf("IP inside CIDR rejected: %v", err)
	}
	if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "192.168.50.1"}); err == nil {
		t.Fatal("IP outside CIDRs must be rejected")
	}
	if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "not-an-ip"}); err == nil {
		t.Fatal("invalid client IP must be rejected")
	}
	if err := ev.Evaluate(&cap, &ConstraintContext{}); err == nil {
		t.Fatal("missing client IP must fail closed")
	}
	if err := ev.Evaluate(&cap, nil); err == nil {
		t.Fatal("nil context must be rejected")
	}
}

func TestGeoFenceEvaluator(t *testing.T) {
	ev := geoFenceEvaluator{}
	if ev.CapabilityId() != ConstraintGeoFenceKey {
		t.Fatalf("CapabilityId = %q", ev.CapabilityId())
	}

	t.Run("inline_table_allow", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "10.0.0.7"}); err != nil {
			t.Fatalf("inline allow: %v", err)
		}
	})

	t.Run("inline_table_deny", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "192.168.0.5"}); err == nil {
			t.Fatal("IP outside inline regions must be denied")
		}
	})

	t.Run("external_resolver_allow", func(t *testing.T) {
		RegisterGeoResolver("test-resolver-xgeo", func(ip string) (string, error) {
			if ip == "203.0.113.7" {
				return "CN-SHA", nil
			}
			return "CN-OTHER", nil
		})
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"test-resolver-xgeo","regions":["CN-SHA"]}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "203.0.113.7"}); err != nil {
			t.Fatalf("external allow: %v", err)
		}
	})

	t.Run("external_resolver_deny", func(t *testing.T) {
		RegisterGeoResolver("test-resolver-xgeo-deny", func(ip string) (string, error) {
			return "CN-BJS", nil
		})
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"test-resolver-xgeo-deny","regions":["CN-SHA"]}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "203.0.113.9"}); err == nil {
			t.Fatal("resolved region outside allowlist must be denied")
		}
	})

	t.Run("unregistered_resolver_fails_closed", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"test-no-such-resolver","regions":["CN-SHA"]}`)}
		err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "203.0.113.5"})
		if err == nil || !strings.Contains(err.Error(), "not registered") {
			t.Fatalf("unregistered resolver: err=%v", err)
		}
	})

	t.Run("missing_client_ip_fails_closed", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{}); err == nil {
			t.Fatal("geo-fence without client IP must fail closed")
		}
	})

	t.Run("empty_regions_rejected", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`{"resolver":"inline"}`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "10.0.0.1"}); err == nil {
			t.Fatal("missing regions must be rejected")
		}
	})

	t.Run("invalid_parameters_rejected", func(t *testing.T) {
		cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintGeoFenceKey,
			Parameters: []byte(`not json`)}
		if err := ev.Evaluate(&cap, &ConstraintContext{ClientIP: "10.0.0.1"}); err == nil {
			t.Fatal("non-JSON parameters must be rejected")
		}
	})

	t.Run("register_geo_resolver_noop_guards", func(t *testing.T) {
		RegisterGeoResolver("", func(string) (string, error) { return "", nil })
		RegisterGeoResolver("test-nil-fn", nil)
		if _, ok := lookupGeoResolver("test-nil-fn"); ok {
			t.Fatal("nil resolver function must not be registered")
		}
	})
}

// TestGeoResolverConcurrentRegisterLookup drives registration and lookup from
// separate goroutines; run under -race it catches an unguarded geoResolvers map.
func TestGeoResolverConcurrentRegisterLookup(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			RegisterGeoResolver(fmt.Sprintf("race-%d", n), func(string) (string, error) { return "R", nil })
		}(i)
	}
	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			lookupGeoResolver(fmt.Sprintf("race-%d", n))
		}(i)
	}
	wg.Wait()
}

func TestConstraintRecheckLoop(t *testing.T) {
	constraint := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintCIDRKey,
		Parameters: []byte(`["10.0.0.0/8"]`)}

	t.Run("evaluates_once_then_stops_on_violation", func(t *testing.T) {
		var mu sync.Mutex
		var count int
		done := make(chan struct{})
		go ConstraintRecheckLoop([]Capability{constraint}, nil, "192.168.10.10", 2*time.Millisecond, done, func(reason string) {
			mu.Lock()
			count++
			mu.Unlock()
		})
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		got := count
		mu.Unlock()
		if got != 1 {
			t.Errorf("violation callbacks = %d, want exactly 1 (loop must stop after first violation)", got)
		}
	})

	t.Run("stops_when_done_is_closed", func(t *testing.T) {
		done := make(chan struct{})
		close(done)
		var mu sync.Mutex
		var count int
		go ConstraintRecheckLoop([]Capability{constraint}, nil, "192.168.10.10", time.Millisecond, done, func(reason string) {
			mu.Lock()
			count++
			mu.Unlock()
		})
		time.Sleep(25 * time.Millisecond)
		mu.Lock()
		got := count
		mu.Unlock()
		if got != 0 {
			t.Errorf("callbacks after done = %d, want 0", got)
		}
	})
}

func TestGlobalConstraintRegistryWiring(t *testing.T) {
	ResetConstraints()
	defer ResetConstraints()

	pinger := stubConstraintEvaluator{capabilityId: "custom:ping",
		evaluate: func(*Capability, *ConstraintContext) error { return fmt.Errorf("denied-by-custom") }}

	if err := RegisterConstraint(pinger); err != nil {
		t.Fatalf("RegisterConstraint: %v", err)
	}
	if err := RegisterConstraint(pinger); err == nil {
		t.Fatal("duplicate global register must fail")
	}
	if got := globalConstraintRegistry.Len(); got != 9 {
		t.Fatalf("global registry Len = %d, want 9 (8 built-ins + custom)", got)
	}

	err := CheckAuthorizationConstraints([]Capability{{SchemeId: "varwof/constraint-v1", CapabilityId: "custom:ping"}}, "10.0.0.1")
	if err == nil || !strings.Contains(err.Error(), "denied-by-custom") {
		t.Fatalf("custom constraint not wired: %v", err)
	}

	passer := stubConstraintEvaluator{capabilityId: "custom:ping"}
	if err := ReplaceConstraint(passer); err != nil {
		t.Fatalf("ReplaceConstraint: %v", err)
	}
	if err := CheckAuthorizationConstraints([]Capability{{SchemeId: "varwof/constraint-v1", CapabilityId: "custom:ping"}}, "10.0.0.1"); err != nil {
		t.Fatalf("replaced constraint still denies: %v", err)
	}

	ResetConstraints()
	if got := globalConstraintRegistry.Len(); got != 8 {
		t.Fatalf("after ResetConstraints Len = %d, want 8 built-ins", got)
	}
	if _, err := globalConstraintRegistry.Find("custom:ping"); err == nil {
		t.Fatal("custom evaluator survived ResetConstraints")
	}
	for _, id := range []string{
		ConstraintCIDRKey, ConstraintConcurrentKey, ConstraintTimeWindowKey,
		ConstraintHardTimeoutKey, ConstraintIdleTimeoutKey, ConstraintReadOnlyKey,
		ConstraintAuditRequiredKey, ConstraintGeoFenceKey,
	} {
		if _, err := globalConstraintRegistry.Find(id); err != nil {
			t.Errorf("built-in %q missing after ResetConstraints", id)
		}
	}
}
