// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestParseConfigFull(t *testing.T) {
	c, err := ParseConfig([]byte(`{
		"log_file": "/tmp/aicverifier.log",
		"server": {
			"read_timeout": "10s",
			"read_header_timeout": "5s",
			"write_timeout": "15s",
			"idle_timeout": "60s",
			"max_header_bytes": 8192
		},
		"tls_cert_file": "srv.crt",
		"tls_key_file": "srv.key",
		"ca_cert_file": "ca.crt",
		"jwt_ca_file": "jwt-ca.pem",
		"jwt_issuer": "aic-verifier",
		"jwt_audience": ["svc-a","svc-b"],
		"backend_root_ca": "backend-root.pem",
		"replay_protection": false,
		"auth_mode": "bearer",
		"identity_mode": "aic",
		"require_aic": true,
		"required_capabilities": ["ai:infer"],
		"enforce_constraints": true
	}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if c.LogFile != "/tmp/aicverifier.log" {
		t.Errorf("LogFile = %q", c.LogFile)
	}
	if c.TLSCertFile != "srv.crt" || c.TLSKeyFile != "srv.key" {
		t.Errorf("tls files: %q %q", c.TLSCertFile, c.TLSKeyFile)
	}
	if c.CACertFile != "ca.crt" || c.JWTCAFile != "jwt-ca.pem" {
		t.Errorf("verification files: %q %q", c.CACertFile, c.JWTCAFile)
	}
	if c.BackendRootCA != "backend-root.pem" {
		t.Errorf("BackendRootCA = %q", c.BackendRootCA)
	}
	if c.AuthMode != BearerOnly {
		t.Errorf("AuthMode = %v, want BearerOnly", c.AuthMode)
	}
	if c.IdentityMode != IdentityAIC {
		t.Errorf("IdentityMode = %v, want IdentityAIC", c.IdentityMode)
	}
	if c.ReplayProtection == nil || *c.ReplayProtection {
		t.Errorf("ReplayProtection = %v, want false", c.ReplayProtection)
	}
	if len(c.JWTAudience) != 2 || c.JWTAudience[0] != "svc-a" {
		t.Errorf("JWTAudience = %v", c.JWTAudience)
	}
	if c.ServerOptions == nil {
		t.Fatal("ServerOptions = nil")
	}
	if c.ServerOptions.ReadTimeout != 10*time.Second ||
		c.ServerOptions.WriteTimeout != 15*time.Second ||
		c.ServerOptions.MaxHeaderBytes != 8192 {
		t.Errorf("ServerOptions = %+v", c.ServerOptions)
	}
}

func TestParseConfigUnknownFieldRejected(t *testing.T) {
	_, err := ParseConfig([]byte(`{"not_a_field": true}`))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseConfigBadAuthMode(t *testing.T) {
	_, err := ParseConfig([]byte(`{"auth_mode": "gibberish"}`))
	if err == nil {
		t.Fatal("expected error for unknown auth_mode")
	}
}

func TestParseConfigSupervisionPolicy(t *testing.T) {
	// The supervision_log_file is wired into a SupervisionStore at parse time
	// (M3), so the test points it at a writable temp path instead of /var/log.
	supFile := t.TempDir() + "/supervision.jsonl"
	c, err := ParseConfig([]byte(fmt.Sprintf(`{
		"supervision_policy": {
			"require_runtime_approval": true,
			"allow_break_glass": true,
			"require_evidence_export": true
		},
		"audit_log_file": "/var/log/audit.jsonl",
		"audit_tsa_url": "https://tsa.example.com/rfc3161",
		"supervision_log_file": %q
	}`, supFile)))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !c.SupervisionPolicy.RequireRuntimeApproval ||
		!c.SupervisionPolicy.AllowBreakGlass ||
		!c.SupervisionPolicy.RequireEvidenceExport {
		t.Fatalf("SupervisionPolicy = %+v, want all true", c.SupervisionPolicy)
	}
	if c.AuditLogFile != "/var/log/audit.jsonl" {
		t.Errorf("AuditLogFile = %q", c.AuditLogFile)
	}
	if c.AuditTSAURL != "https://tsa.example.com/rfc3161" {
		t.Errorf("AuditTSAURL = %q", c.AuditTSAURL)
	}
	if c.SupervisionLogFile != supFile {
		t.Errorf("SupervisionLogFile = %q", c.SupervisionLogFile)
	}
	// M3: the parsed supervision log file must have produced a working store.
	if c.SupervisionStore == nil {
		t.Fatal("SupervisionStore = nil, want store wired from supervision_log_file")
	}
	if c.SupervisionStore.File() != supFile {
		t.Errorf("SupervisionStore.File() = %q, want %q", c.SupervisionStore.File(), supFile)
	}
}

func TestParseConfigSupervisionPolicyPartialDefaults(t *testing.T) {
	c, err := ParseConfig([]byte(`{"supervision_policy":{"require_runtime_approval":true}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !c.SupervisionPolicy.RequireRuntimeApproval {
		t.Errorf("RequireRuntimeApproval = false, want true")
	}
	if c.SupervisionPolicy.AllowBreakGlass || c.SupervisionPolicy.RequireEvidenceExport {
		t.Errorf("unset policy flags should stay false: %+v", c.SupervisionPolicy)
	}
}

func TestParseConfigCompliancePresetCommentTolerated(t *testing.T) {
	// The compliance preset carries prose metadata via "_comment" so operators
	// can explain code-injected interfaces; it must still parse.
	c, err := ParseConfig([]byte(`{
		"_comment": "code-injected interfaces only",
		"supervision_policy": {"allow_break_glass": true}
	}`))
	if err != nil {
		t.Fatalf("ParseConfig with _comment: %v", err)
	}
	if !c.SupervisionPolicy.AllowBreakGlass {
		t.Errorf("AllowBreakGlass = false, want true")
	}
}

func TestParseConfigUnknownFieldStillRejected(t *testing.T) {
	_, err := ParseConfig([]byte(`{"supervision_policy": {"require_evidence_export": true}, "supervision_interval": 5}`))
	if err == nil {
		t.Fatal("expected error for unknown supervision_interval field")
	}
}

// TestSupervisionPolicyStartupValidation asserts the compliance preset fails
// closed at startup when a required supervision interface is missing: with
// require_runtime_approval / allow_break_glass / require_evidence_export on
// and no ApprovalRequester / OverrideRecorder / EvidenceExporter injected, the
// handler chain must refuse to build.
func TestSupervisionPolicyStartupValidation(t *testing.T) {
	data, err := os.ReadFile("config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("parse compliance preset: %v", err)
	}

	// No interfaces injected → each policy switch must fail startup.
	if _, err := cfg.Handler(http.NotFoundHandler()); err == nil {
		t.Fatal("expected startup error with require_runtime_approval/allow_break_glass/require_evidence_export all true but interfaces nil")
	}
}
