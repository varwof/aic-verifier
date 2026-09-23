// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

type stubExporter struct{}

func (stubExporter) Export(ctx context.Context, q EvidenceQuery) (*EvidenceBundle, error) {
	return &EvidenceBundle{}, nil
}

func TestConfigValidateZeroValueOK(t *testing.T) {
	if err := (&Config{}).Validate(); err != nil {
		t.Fatalf("zero Config should validate clean: %v", err)
	}
}

func TestConfigValidateNilFails(t *testing.T) {
	var c *Config
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Errorf("nil Config: got %v", err)
	}
}

func TestConfigValidateSupervisionCombos(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"runtime approval nil requester", Config{SupervisionPolicy: SupervisionPolicy{RequireRuntimeApproval: true}}, "needs an ApprovalRequester"},
		{"break glass nil recorder", Config{SupervisionPolicy: SupervisionPolicy{AllowBreakGlass: true}}, "needs an OverrideRecorder"},
		{"evidence export nil exporter", Config{SupervisionPolicy: SupervisionPolicy{RequireEvidenceExport: true}}, "needs an EvidenceExporter"},
		{"user auth no cert", Config{RequireUserAuth: true}, "needs user cert for DA verification"},
		{"all wired ok", Config{
			SupervisionPolicy: SupervisionPolicy{RequireRuntimeApproval: true, AllowBreakGlass: true, RequireEvidenceExport: true},
			ApprovalRequester: &stubRequester{},
			OverrideRecorder:  &stubRecorder{},
			EvidenceExporter:  stubExporter{},
			UserCertResolver:  func([]byte) (*x509.Certificate, error) { return nil, nil },
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tc.want != "" && err == nil:
				t.Errorf("Validate() = nil, want containing %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("Validate() = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestConfigValidateUnknownEvidenceProfile(t *testing.T) {
	c := &Config{EvidenceProfile: "no-such-profile@1"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "evidence profile: unknown") {
		t.Errorf("unknown profile: got %v", err)
	}
}

func TestConfigValidateKnownEvidenceProfileOK(t *testing.T) {
	for name := range builtinProfiles {
		if err := (&Config{EvidenceProfile: name}).Validate(); err != nil {
			t.Errorf("known profile %q should validate: %v", name, err)
		}
	}
}

func TestConfigValidateJoinsMultiple(t *testing.T) {
	c := &Config{
		RequireUserAuth: true,
		SupervisionPolicy: SupervisionPolicy{
			RequireRuntimeApproval: true,
			AllowBreakGlass:        true,
			RequireEvidenceExport:  true,
		},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	var u interface{ Unwrap() []error }
	if !errors.As(err, &u) {
		t.Errorf("expected errors.Join (multi-error), got %T", err)
	}
}
