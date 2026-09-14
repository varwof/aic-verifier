// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// 证据 profile：形状是具名、有版本、可校验的；换形状是换一个值（或加一个 adapter），
// 不改裁决路径；未知名字在配置期就报错。

package aicverifier

import (
	"testing"
	"time"

	"github.com/varwof/register/semantics"
)

func TestLookupEvidenceProfile(t *testing.T) {
	for _, name := range []string{"clc-decision@1", "clc-decision+admission@1", "clc-decision+admission+outcome@1"} {
		p, err := LookupEvidenceProfile(name)
		if err != nil {
			t.Fatalf("LookupEvidenceProfile(%q): %v", name, err)
		}
		if err := p.Validate(); err != nil {
			t.Errorf("%s does not validate: %v", name, err)
		}
		if !p.Decision {
			t.Errorf("%s should emit decision records", name)
		}
	}
	if _, err := LookupEvidenceProfile("clc-decision+telepathy@9"); err == nil {
		t.Error("an unknown profile name must be a configuration error, not best effort")
	}
}

func TestEvidenceProfileValidation(t *testing.T) {
	cases := []struct {
		name string
		p    EvidenceProfile
	}{
		{"no name", EvidenceProfile{Decision: true}},
		{"emits nothing", EvidenceProfile{Name: "empty@1"}},
		{"bad container", EvidenceProfile{Name: "x@1", Decision: true, Container: "carrier-pigeon"}},
		{"negative freshness", EvidenceProfile{Name: "x@1", Decision: true, Freshness: -time.Second}},
		{"bad requirement", EvidenceProfile{Name: "x@1", Decision: true, Requirement: &semantics.Requirement{Version: "nope"}}},
	}
	for _, tc := range cases {
		if err := tc.p.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

// ID 是内容寻址的：形状不同 → ID 不同；形状相同 → ID 相同。
func TestEvidenceProfileIDIsContentAddressed(t *testing.T) {
	a, _ := LookupEvidenceProfile("clc-decision@1")
	b, _ := LookupEvidenceProfile("clc-decision@1")
	idA, err := a.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	idB, err := b.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if !idA.Equal(idB) {
		t.Error("the same shape must have the same identity")
	}

	c := a
	c.Freshness = 5 * time.Minute
	idC, err := c.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if idA.Equal(idC) {
		t.Error("a different freshness bound is a different shape")
	}
}

func TestEvidenceProfileApply(t *testing.T) {
	p, _ := LookupEvidenceProfile("clc-decision+admission+outcome@1")
	req := &semantics.Requirement{Version: semantics.RequirementVersion, ID: "r@1", Expression: "a"}
	custom := p
	custom.Freshness = 90 * time.Second
	custom.Requirement = req

	cfg, err := custom.Apply(&EvidenceConfig{RecorderID: "pep-1"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if cfg.Profile == nil || cfg.Profile.Name != custom.Name {
		t.Error("the profile must be recorded on the config")
	}
	if cfg.TTL != 90*time.Second {
		t.Errorf("TTL = %s, want the profile's freshness", cfg.TTL)
	}
	if cfg.Requirement == nil || cfg.Requirement.ID != "r@1" {
		t.Error("the profile's requirement must reach the config")
	}
	if cfg.RecorderID != "pep-1" {
		t.Error("plumbing (recorder id) must survive Apply")
	}
}

// 配置层：未知 profile 名 → 构造时失败（fail-closed）。
func TestConfigRejectsUnknownEvidenceProfile(t *testing.T) {
	if _, err := (&Config{EvidenceProfile: "clc-decision@99"}).Handler(nil); err == nil {
		t.Error("an unknown evidence profile must fail configuration")
	}
}

// 发出的信封带 profile 的内容寻址 subject，消费方能据此判断形状。
func TestEmittedEnvelopeCarriesProfileSubject(t *testing.T) {
	profile, _ := LookupEvidenceProfile("clc-decision@1")
	cfg := &EvidenceConfig{RecorderID: "pep-1"}
	cfg, err := profile.Apply(cfg)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cert := testAICCert(t, false)
	res := CheckAdmission(cert, B2Config(Operation{ID: sqlQueryCap, Params: map[string]any{"limit": 5}}))

	dir := t.TempDir()
	cfg.Sink = &FileSink{Dir: dir}
	refs, err := EmitDecisionRecords(cfg, EvidenceContext{Outcome: EvidenceAdmitted}, cert, res.AIC, res.PrincipalAuthorization, nil, res.OperationDecisions)
	if err != nil || len(refs) == 0 {
		t.Fatalf("emit: %v", err)
	}
	env := mustEnvelope(t, refs[0].Path)
	digest, ok, err := ProfileSubjectDigest(env)
	if err != nil || !ok {
		t.Fatalf("profile subject missing: ok=%v err=%v", ok, err)
	}
	want, err := profile.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if !digest.Equal(want) {
		t.Error("the tagged profile identity does not match the configured profile")
	}
	// The language-level check still passes: extra subjects are allowed.
	if kind, err := CheckEvidenceEnvelope(env); err != nil || kind != KindDecision {
		t.Fatalf("tagged decision envelope: %q/%v", kind, err)
	}
}
