// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type emptySchemeValidator struct{}

func (emptySchemeValidator) Scheme() string                              { return "" }
func (emptySchemeValidator) Validate(granted, declared Capability) error { return nil }

func TestParameterValidatorRegistry(t *testing.T) {
	reg := NewParameterValidatorRegistry()
	if reg.Len() != 0 {
		t.Fatalf("fresh registry Len = %d, want 0", reg.Len())
	}
	if err := reg.Register(MaxRowsValidator); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(MaxRowsValidator); err == nil {
		t.Fatal("duplicate Register must fail")
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("Register(nil) must fail")
	}
	if err := reg.Register(emptySchemeValidator{}); err == nil {
		t.Fatal("Register(empty scheme) must fail")
	}

	v, err := reg.Find("report")
	if err != nil || v == nil {
		t.Fatalf("Find(report): v=%v err=%v", v, err)
	}
	if _, err := reg.Find("ghost"); err == nil {
		t.Fatal("Find(ghost) must fail")
	}

	if got := reg.Keys(); len(got) != 1 || got[0] != "report" {
		t.Errorf("Keys = %v", got)
	}
	reg.Reset()
	if reg.Len() != 0 {
		t.Fatalf("after Reset Len = %d, want 0", reg.Len())
	}
}

func TestValidateCapability(t *testing.T) {
	reg := NewParameterValidatorRegistry()
	if err := reg.Register(MaxRowsValidator); err != nil {
		t.Fatal(err)
	}
	granted := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":100}`)}
	declared := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(`{"max_rows":50}`)}

	if err := reg.ValidateCapability(granted, declared); err != nil {
		t.Fatalf("in-bound declared rejected: %v", err)
	}

	over := declared
	over.Parameters = []byte(`{"max_rows":500}`)
	if err := reg.ValidateCapability(granted, over); err == nil {
		t.Fatal("declared above grant boundary must fail")
	}

	other := declared
	other.SchemeId = "unregistered-scheme"
	other.Parameters = []byte(`{"max_rows":999999}`)
	if err := reg.ValidateCapability(granted, other); err != nil {
		t.Fatalf("unregistered scheme must be allowed (no boundary rules): %v", err)
	}

	var nilReg *ParameterValidatorRegistry
	if err := nilReg.ValidateCapability(granted, declared); err != nil {
		t.Fatalf("nil registry must no-op: %v", err)
	}
}

func TestParseMaxRows(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		want   int64
		exists bool
		err    bool
	}{
		{"empty", "", 0, false, false},
		{"object_without_key", `{}`, 0, false, false},
		{"valid", `{"max_rows":1000}`, 1000, true, false},
		{"zero", `{"max_rows":0}`, 0, true, false},
		{"negative", `{"max_rows":-1}`, 0, false, true},
		{"bad_json", `not json`, 0, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, exists, err := parseMaxRows([]byte(c.raw))
			if c.err {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMaxRows(%q): %v", c.raw, err)
			}
			if got != c.want || exists != c.exists {
				t.Errorf("got (%d,%v), want (%d,%v)", got, exists, c.want, c.exists)
			}
		})
	}
}

func TestMaxRowsValidatorValidate(t *testing.T) {
	v := maxRowsValidator{}
	cases := []struct {
		name              string
		granted, declared string
		wantErr           bool
	}{
		{"granted_unlimited", "", `{"max_rows":5000}`, false},
		{"declared_absent", `{"max_rows":100}`, "", false},
		{"within_bound", `{"max_rows":100}`, `{"max_rows":50}`, false},
		{"equal_bound", `{"max_rows":100}`, `{"max_rows":100}`, false},
		{"over_bound", `{"max_rows":100}`, `{"max_rows":200}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(c.granted)}
			d := Capability{SchemeId: "report", CapabilityId: "query", Parameters: []byte(c.declared)}
			err := v.Validate(g, d)
			if c.wantErr && err == nil {
				t.Fatal("expected boundary error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	g := Capability{SchemeId: "report", Parameters: []byte(`garbage`)}
	d := Capability{SchemeId: "report", Parameters: []byte(`{"max_rows":1}`)}
	if err := v.Validate(g, d); err == nil {
		t.Fatal("invalid granted parameters must error")
	}
}

func TestGlobalParameterValidators(t *testing.T) {
	reg := BuiltinParameterValidators()
	if reg == nil {
		t.Fatal("BuiltinParameterValidators() = nil")
	}
	if _, err := reg.Find("report"); err != nil {
		t.Fatalf("MaxRowsValidator missing from built-ins: %v", err)
	}
	if err := RegisterParameterValidator(MaxRowsValidator); err == nil {
		t.Fatal("re-registering built-in must fail")
	}

	ResetParameterValidators()
	if reg.Len() != 0 {
		t.Fatalf("after ResetParameterValidators Len = %d, want 0", reg.Len())
	}
	if err := RegisterParameterValidator(MaxRowsValidator); err != nil {
		t.Fatalf("re-register after reset: %v", err)
	}
	if _, err := reg.Find("report"); err != nil {
		t.Fatalf("Find after re-register: %v", err)
	}
}

func TestFormatInt(t *testing.T) {
	if got := formatInt(42); got != "42" {
		t.Errorf("formatInt(42) = %q", got)
	}
	if got := formatInt(-7); got != "-7" {
		t.Errorf("formatInt(-7) = %q", got)
	}
	if got := formatInt(0); got != "0" {
		t.Errorf("formatInt(0) = %q", got)
	}
}

func TestNewOfflineRBAC(t *testing.T) {
	r := NewOfflineRBAC(nil)
	if r == nil {
		t.Fatal("NewOfflineRBAC(nil) = nil")
	}
	if r.CheckRole([]string{RoleAdmin}) {
		t.Error("empty role list must not pass any check")
	}

	r2 := NewOfflineRBAC([]string{RoleOps})
	if !r2.CheckRole([]string{RoleOps}) {
		t.Error("offline RBAC with gateway:ops must allow gateway:ops")
	}
	if r2.CheckRole([]string{RoleAdmin}) {
		t.Error("offline RBAC with gateway:ops must deny gateway:admin")
	}
}

func TestNewOfflineRBACFromCertRoles(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{OrganizationalUnit: []string{"gateway:admin", " gateway:ops ", "ops"}},
	}
	got := ExtractRoles(cert)
	if len(got) != 2 || got[0] != "gateway:admin" || got[1] != "gateway:ops" {
		t.Fatalf("ExtractRoles = %v, want [gateway:admin gateway:ops] (bare `ops` excluded, whitespace trimmed)", got)
	}

	r := NewOfflineRBACFromCert(cert)
	if !r.CheckRole([]string{RoleOps}) {
		t.Error("OU gateway:ops should map into the offline role set")
	}
	if !r.CheckRole([]string{RoleAdmin}) {
		t.Error("OU gateway:admin should map into the offline role set")
	}
	if r.CheckRole([]string{RoleDeploy}) {
		t.Error("unclaimed role must be denied")
	}
}

func TestCheckRole(t *testing.T) {
	cases := []struct {
		name    string
		roles   []string
		allowed []string
		want    bool
	}{
		{"exact", []string{"gateway:ops"}, []string{"gateway:ops"}, true},
		{"mismatch", []string{"gateway:ops"}, []string{"gateway:read"}, false},
		{"role_wildcard_passes_immediately", []string{"gateway:*"}, []string{"gateway:deploy"}, true},
		{"allowed_wildcard_matches_prefix_role", []string{"gateway:ops"}, []string{RoleWild}, true},
		{"empty_roles", nil, []string{"gateway:ops"}, false},
		{"empty_allowed", []string{"gateway:ops"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckRole(c.roles, c.allowed); got != c.want {
				t.Errorf("CheckRole(%v,%v) = %v, want %v", c.roles, c.allowed, got, c.want)
			}
		})
	}
}

func TestPeerCertRoles(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"gateway:read"}}}
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	got := PeerCertRoles(req)
	if len(got) != 1 || got[0] != RoleRead {
		t.Fatalf("PeerCertRoles = %v, want [%s]", got, RoleRead)
	}

	plain := &http.Request{}
	if got := PeerCertRoles(plain); got != nil {
		t.Errorf("plain request PeerCertRoles = %v, want nil", got)
	}
	empty := &http.Request{TLS: &tls.ConnectionState{}}
	if got := PeerCertRoles(empty); got != nil {
		t.Errorf("no peer certs: PeerCertRoles = %v, want nil", got)
	}
}

func TestRequireRoles(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"gateway:read"}}}
	req := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}

	if !RequireRoles(req, []string{RoleRead}) {
		t.Error("RequireRoles should admit gateway:read for [gateway:read]")
	}
	if RequireRoles(req, []string{RoleAdmin}) {
		t.Error("RequireRoles must deny gateway:read request for [gateway:admin]")
	}
	plain := &http.Request{}
	if RequireRoles(plain, []string{RoleRead}) {
		t.Error("RequireRoles must fail closed for a non-mTLS request")
	}
}

func TestLoadConfigFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{
		"log_file": "/tmp/aic-verifier.log",
		"auth_mode": "mtls",
		"jwt_issuer": "aic-verifier",
		"jwt_audience": ["svc"],
		"replay_protection": false,
		"identity_mode": "aic"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := LoadConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if c.LogFile != "/tmp/aic-verifier.log" {
		t.Errorf("LogFile = %q", c.LogFile)
	}
	if c.AuthMode != MTLSOnly {
		t.Errorf("AuthMode = %v, want MTLSOnly", c.AuthMode)
	}
	if c.JWTIssuer != "aic-verifier" {
		t.Errorf("JWTIssuer = %q", c.JWTIssuer)
	}
	if len(c.JWTAudience) != 1 || c.JWTAudience[0] != "svc" {
		t.Errorf("JWTAudience = %v", c.JWTAudience)
	}
	if c.ReplayProtection == nil || *c.ReplayProtection {
		t.Errorf("ReplayProtection = %v, want false", c.ReplayProtection)
	}
	if c.IdentityMode != IdentityAIC {
		t.Errorf("IdentityMode = %v, want IdentityAIC", c.IdentityMode)
	}

	t.Run("malformed_json_errors", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, []byte(`{not json`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfigFile(bad); err == nil {
			t.Fatal("expected error for malformed config")
		}
	})

	t.Run("unknown_field_rejected", func(t *testing.T) {
		unk := filepath.Join(t.TempDir(), "unk.json")
		if err := os.WriteFile(unk, []byte(`{"bogus_field": true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfigFile(unk); err == nil {
			t.Fatal("expected error for unknown config field")
		}
	})

	t.Run("missing_file_errors", func(t *testing.T) {
		if _, err := LoadConfigFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("expected error for missing config file")
		}
	})
}

func TestIsKnownExtension(t *testing.T) {
	if !isKnownExtension(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 2}) {
		t.Error("known extension OID {1 3 6 1 4 1 66257 1 2} reported unknown")
	}
	if !isKnownExtension(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 1}) {
		t.Error("known extension OID {1 3 6 1 4 1 66257 3 1} reported unknown")
	}
	if isKnownExtension(asn1.ObjectIdentifier{1, 2, 3, 4}) {
		t.Error("arbitrary OID reported known")
	}
	if isKnownExtension(nil) {
		t.Error("empty OID reported known")
	}
}

func TestIdleAndAuditConstraintEvaluators(t *testing.T) {
	idle := idleTimeoutEvaluator{}
	if idle.CapabilityId() != ConstraintIdleTimeoutKey {
		t.Fatalf("idle CapabilityId = %q", idle.CapabilityId())
	}
	ctx := &ConstraintContext{}
	cap := Capability{SchemeId: "varwof/constraint-v1", CapabilityId: ConstraintIdleTimeoutKey, Parameters: []byte(`{"value":300}`)}
	if err := idle.Evaluate(&cap, ctx); err != nil {
		t.Fatalf("in-range idle timeout: %v", err)
	}
	cap.Parameters = []byte(`{"value":10}`)
	if err := idle.Evaluate(&cap, ctx); err == nil {
		t.Error("idle timeout below IdleTimeoutMin must be rejected")
	}
	cap.Parameters = []byte(`{"value":3601}`)
	if err := idle.Evaluate(&cap, ctx); err == nil {
		t.Error("idle timeout above IdleTimeoutMax must be rejected")
	}

	audit := auditRequiredEvaluator{}
	if audit.CapabilityId() != ConstraintAuditRequiredKey {
		t.Fatalf("audit CapabilityId = %q", audit.CapabilityId())
	}
	if err := audit.Evaluate(&cap, ctx); err != nil {
		t.Fatalf("audit-required evaluates at check time: %v", err)
	}
}

func TestConstraintToCapability(t *testing.T) {
	c, ok := ConstraintToCapability("varwof/constraint-v1:session:hard-timeout:{\"value\":120}")
	if !ok {
		t.Fatal("expected parse success")
	}
	// Real parse behavior: the crumb immediately following the scheme is the
	// capabilityId; the remainder is carried verbatim as parameters.
	if c.SchemeId != "varwof/constraint-v1" || c.CapabilityId != "session" {
		t.Errorf("parsed = %+v", c)
	}
	if string(c.Parameters) != `hard-timeout:{"value":120}` {
		t.Errorf("parameters = %q, want `hard-timeout:{\"value\":120}`", c.Parameters)
	}
	if _, ok := ConstraintToCapability(":"); ok {
		t.Error("garbage string must not parse")
	}
}
