// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pki "github.com/varwof/types"
)

const policyFixture = `{
  "version": "1.1",
  "roles": {
    "admin": {"display_name": "Admin", "profiles": ["gateway-admin"], "grants": ["varwof/gateway-v1:admin:config", "varwof/gateway-v1:*"]},
    "read":  {"display_name": "Read",  "profiles": ["gateway-read"],  "grants": ["varwof/gateway-v1:read:fetch"]}
  },
  "ou_mapping": {"gateway:admin": "admin", "gateway:read": "read"},
  "gateway_namespaces": {"default": {"display_name": "Default", "prefix": "varwof/gateway-v1", "grants": ["*"]}},
  "capability_parameters": {
    "varwof/database-v1:query": {"max_rows": 1000}
  }
}`

func parsePolicyFixture(t *testing.T) *AuthorizationPolicy {
	t.Helper()
	p, err := ParseAuthorizationPolicy([]byte(policyFixture))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return p
}

func writeCertPEMFile(t *testing.T, dir, name string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatalf("write cert PEM %s: %v", path, err)
	}
	return path
}

func writeKeyPEMFile(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write key PEM %s: %v", path, err)
	}
	return path
}

func TestLoadGatewayPolicy(t *testing.T) {
	prev := GetAuthorizationPolicy()
	t.Cleanup(func() { SetAuthorizationPolicy(prev) })

	t.Run("empty_path_is_noop", func(t *testing.T) {
		SetAuthorizationPolicy(nil)
		if err := LoadGatewayPolicy("", ".sig", nil, true); err != nil {
			t.Fatalf("LoadGatewayPolicy(\"\"): %v", err)
		}
		if GetAuthorizationPolicy() != nil {
			t.Fatal("policy set for empty path")
		}
	})

	t.Run("loads_fixture_and_sets_global", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "gatewaypolicy.json")
		if err := os.WriteFile(path, []byte(policyFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := LoadGatewayPolicy(path, ".sig", nil, true); err != nil {
			t.Fatalf("LoadGatewayPolicy: %v", err)
		}
		got := GetAuthorizationPolicy()
		if got == nil {
			t.Fatal("policy not set")
		}
		if !got.HasGrant("admin", "varwof/gateway-v1:admin:config") {
			t.Error("loaded policy does not grant admin:config to admin")
		}
	})

	t.Run("bad_json_require_true_errors", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "gatewaypolicy.json")
		if err := os.WriteFile(path, []byte(`not json`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := LoadGatewayPolicy(path, ".sig", nil, true); err == nil {
			t.Fatal("expected error for bad JSON with require=true")
		}
	})

	t.Run("bad_json_require_false_degrades", func(t *testing.T) {
		SetAuthorizationPolicy(nil)
		dir := t.TempDir()
		path := filepath.Join(dir, "gatewaypolicy.json")
		if err := os.WriteFile(path, []byte(`not json`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := LoadGatewayPolicy(path, ".sig", nil, false); err != nil {
			t.Fatalf("require=false must degrade silently: %v", err)
		}
		if GetAuthorizationPolicy() != nil {
			t.Fatal("degraded load must keep the existing policy (nil)")
		}
	})

	t.Run("missing_file_require_true_errors", func(t *testing.T) {
		if err := LoadGatewayPolicy(filepath.Join(t.TempDir(), "nope.json"), ".sig", nil, true); err == nil {
			t.Fatal("expected error for missing policy file")
		}
	})
}

func TestAuthorizationPolicyGrants(t *testing.T) {
	p := parsePolicyFixture(t)

	t.Run("HasGrant", func(t *testing.T) {
		cases := []struct {
			role, cap string
			want      bool
		}{
			{"admin", "varwof/gateway-v1:admin:config", true},
			{"admin", "varwof/gateway-v1:audit:write", true}, // wildcard grant
			{"read", "varwof/gateway-v1:read:fetch", true},
			{"read", "varwof/gateway-v1:admin:config", false},
			{"ghost", "varwof/gateway-v1:read:fetch", false},
			{"admin", "other:cap", false},
		}
		for _, c := range cases {
			if got := p.HasGrant(c.role, c.cap); got != c.want {
				t.Errorf("HasGrant(%q,%q) = %v, want %v", c.role, c.cap, got, c.want)
			}
		}
	})

	t.Run("RoleGrants", func(t *testing.T) {
		if g := p.RoleGrants("admin"); len(g) != 2 {
			t.Errorf("RoleGrants(admin) = %v, want 2 grants", g)
		}
		if g := p.RoleGrants("ghost"); g != nil {
			t.Errorf("RoleGrants(ghost) = %v, want nil", g)
		}
	})

	t.Run("ParamDefaults", func(t *testing.T) {
		params := p.ParamDefaults("varwof/database-v1", "query")
		if len(params) != 1 {
			t.Fatalf("ParamDefaults = %v, want 1 entry", params)
		}
		if v, ok := params["max_rows"].(float64); !ok || v != 1000 {
			t.Errorf("max_rows = %v (%T), want 1000", params["max_rows"], params["max_rows"])
		}
		if got := p.ParamDefaults("varwof/database-v1", "nope"); got != nil {
			t.Errorf("ParamDefaults(unknown) = %v, want nil", got)
		}
		var nilPolicy *AuthorizationPolicy
		if got := nilPolicy.ParamDefaults("a", "b"); got != nil {
			t.Errorf("nil policy ParamDefaults = %v, want nil", got)
		}
	})

	t.Run("HasParamDefault", func(t *testing.T) {
		v, ok := p.HasParamDefault("varwof/database-v1", "query", "max_rows")
		if !ok {
			t.Fatal("HasParamDefault max_rows: expected present")
		}
		if f, isFloat := v.(float64); !isFloat || f != 1000 {
			t.Errorf("HasParamDefault value = %v (%T), want 1000", v, v)
		}
		if _, ok := p.HasParamDefault("varwof/database-v1", "query", "missing"); ok {
			t.Error("HasParamDefault(missing) = present, want absent")
		}
		if _, ok := p.HasParamDefault("varwof/database-v1", "nope", "max_rows"); ok {
			t.Error("HasParamDefault(unknown cap) = present, want absent")
		}
	})

	t.Run("IntersectGrants", func(t *testing.T) {
		got := p.IntersectGrants([]string{"admin"}, []string{"varwof/gateway-v1:admin:config", "varwof/other:x"})
		if len(got) != 1 || got[0] != "varwof/gateway-v1:admin:config" {
			t.Errorf("IntersectGrants(admin) = %v", got)
		}
		got = p.IntersectGrants([]string{"admin"}, []string{"varwof/gateway-v1:audit:report"})
		if len(got) != 1 || got[0] != "varwof/gateway-v1:audit:report" {
			t.Errorf("IntersectGrants wildcard = %v", got)
		}
		if got := p.IntersectGrants(nil, []string{"a"}); got != nil {
			t.Errorf("IntersectGrants no roles = %v, want nil", got)
		}
		if got := p.IntersectGrants([]string{"admin"}, nil); got != nil {
			t.Errorf("IntersectGrants no caps = %v, want nil", got)
		}
	})
}

func TestMatchCapabilityPriority(t *testing.T) {
	cases := []struct {
		id, pattern string
		want        int
	}{
		{"a:b:c", "a:b:c", pki.MatchPriorityExact},
		{"a:b:c", "a:*:c", pki.MatchPrioritySingle},
		{"database:query", "database:**", pki.MatchPriorityMulti},
		{"a:b:c", "a:b:c", pki.MatchPriorityExact},
		{"anything", "*", pki.MatchPriorityGlobal},
		{"a:b", "*:*", pki.MatchPriorityGlobal},
		{"a:b:c", "x:y:z", pki.MatchPriorityNoMatch},
	}
	for _, c := range cases {
		if got := MatchCapabilityPriority(c.id, c.pattern); got != c.want {
			t.Errorf("MatchCapabilityPriority(%q,%q) = %d, want %d", c.id, c.pattern, got, c.want)
		}
	}
}

func TestMatchCapabilityRules(t *testing.T) {
	t.Run("exact_allow_beats_global_deny", func(t *testing.T) {
		m := MatchCapabilityRules("a:b:c", []pki.CapabilityRule{
			{Pattern: "*", Deny: true},
			{Pattern: "a:b:c", Deny: false},
		})
		if !m.Matched || m.Deny {
			t.Errorf("match = %+v, want matched allow", m)
		}
		if m.Priority != pki.MatchPriorityExact {
			t.Errorf("priority = %d, want exact", m.Priority)
		}
	})

	t.Run("equal_priority_deny_overrides_allow", func(t *testing.T) {
		m := MatchCapabilityRules("a:b:c", []pki.CapabilityRule{
			{Pattern: "a:*:c", Deny: false},
			{Pattern: "a:b:c", Deny: true},
		})
		if !m.Matched || !m.Deny {
			t.Errorf("match = %+v, want deny", m)
		}
	})

	t.Run("no_match", func(t *testing.T) {
		m := MatchCapabilityRules("a:b:c", []pki.CapabilityRule{{Pattern: "x:y:z", Deny: true}})
		if m.Matched {
			t.Errorf("match = %+v, want no match", m)
		}
	})

	t.Run("deny_all_until_more_specific_allow", func(t *testing.T) {
		m := MatchCapabilityRules("a:b:c", []pki.CapabilityRule{
			{Pattern: "*", Deny: true},
			{Pattern: "a:b:*", Deny: false},
		})
		if !m.Matched || m.Deny {
			t.Errorf("match = %+v, want allow (5 beats 1)", m)
		}
	})
}

func TestIsAdminOU(t *testing.T) {
	cases := map[string]bool{
		RoleAdmin:     true,
		"admin":       true,
		"gateway:ops": false,
		"gateway:*":   false,
		"":            false,
	}
	for ou, want := range cases {
		if got := IsAdminOU(ou); got != want {
			t.Errorf("IsAdminOU(%q) = %v, want %v", ou, got, want)
		}
	}
}

func TestSignerHasAdminOU(t *testing.T) {
	adminCert := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"gateway:admin"}}}
	if !SignerHasAdminOU(adminCert) {
		t.Error("admin OU cert: expected true")
	}
	bareAdmin := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"admin"}}}
	if !SignerHasAdminOU(bareAdmin) {
		t.Error("bare admin OU cert: expected true")
	}
	other := &x509.Certificate{Subject: pkix.Name{OrganizationalUnit: []string{"gateway:read"}}}
	if SignerHasAdminOU(other) {
		t.Error("gateway:read cert: expected false")
	}
	empty := &x509.Certificate{}
	if SignerHasAdminOU(empty) {
		t.Error("empty cert: expected false")
	}
}

func TestLoadCAFromFile(t *testing.T) {
	_, caCert := mintCert(t, nil, nil, "test-ca", big.NewInt(1), nil, nil, nil)
	dir := t.TempDir()
	path := writeCertPEMFile(t, dir, "ca.pem", caCert)

	t.Run("parses_ca_pem", func(t *testing.T) {
		pool, err := LoadCAFromFile(path)
		if err != nil {
			t.Fatalf("LoadCAFromFile: %v", err)
		}
		if pool == nil {
			t.Fatal("pool = nil")
		}
		subjects := pool.Subjects()
		if len(subjects) == 0 {
			t.Fatal("pool contains no subjects")
		}
	})

	t.Run("bad_path_errors", func(t *testing.T) {
		if _, err := LoadCAFromFile(filepath.Join(dir, "missing.pem")); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("no_pem_certs_errors", func(t *testing.T) {
		garbage := filepath.Join(dir, "garbage.pem")
		if err := os.WriteFile(garbage, []byte("this is not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCAFromFile(garbage); err == nil {
			t.Fatal("expected error for PEM with no certificates")
		}
	})
}

func TestBuildPolicyVerifyOptions(t *testing.T) {
	t.Run("nil_receiver", func(t *testing.T) {
		var ps *PolicySigningConfig
		opts, err := ps.BuildPolicyVerifyOptions("")
		if err != nil || opts != nil {
			t.Fatalf("nil receiver: opts=%v err=%v, want nil,nil", opts, err)
		}
	})

	t.Run("disabled_returns_nil", func(t *testing.T) {
		opts, err := (&PolicySigningConfig{}).BuildPolicyVerifyOptions("")
		if err != nil || opts != nil {
			t.Fatalf("disabled: opts=%v err=%v, want nil,nil", opts, err)
		}
	})

	t.Run("ca_file_builds_roots", func(t *testing.T) {
		_, caCert := mintCert(t, nil, nil, "ca", big.NewInt(2), nil, nil, nil)
		caPath := writeCertPEMFile(t, t.TempDir(), "ca.pem", caCert)
		opts, err := (&PolicySigningConfig{Enabled: true, CAFile: caPath}).BuildPolicyVerifyOptions("")
		if err != nil {
			t.Fatalf("BuildPolicyVerifyOptions: %v", err)
		}
		if opts == nil {
			t.Fatal("opts = nil")
		}
		if opts.Roots == nil {
			t.Fatal("Roots = nil, want populated pool")
		}
		if !opts.RequireAdminOU {
			t.Error("RequireAdminOU defaults to true")
		}
	})

	t.Run("falls_back_to_tls_client_ca", func(t *testing.T) {
		_, caCert := mintCert(t, nil, nil, "ca", big.NewInt(3), nil, nil, nil)
		caPath := writeCertPEMFile(t, t.TempDir(), "ca.pem", caCert)
		opts, err := (&PolicySigningConfig{Enabled: true}).BuildPolicyVerifyOptions(caPath)
		if err != nil {
			t.Fatalf("BuildPolicyVerifyOptions: %v", err)
		}
		if opts == nil || opts.Roots == nil {
			t.Fatalf("fallback CA not loaded: opts=%v", opts)
		}
	})

	t.Run("require_admin_ou_false_honored", func(t *testing.T) {
		f := false
		opts, err := (&PolicySigningConfig{Enabled: true, RequireAdminOU: &f}).BuildPolicyVerifyOptions("")
		if err != nil {
			t.Fatalf("BuildPolicyVerifyOptions: %v", err)
		}
		if opts == nil || opts.RequireAdminOU {
			t.Fatalf("RequireAdminOU = %+v, want false", opts)
		}
	})

	t.Run("bad_ca_file_errors", func(t *testing.T) {
		opts, err := (&PolicySigningConfig{Enabled: true, CAFile: "/nonexistent/ca.pem"}).BuildPolicyVerifyOptions("")
		if err == nil || opts != nil {
			t.Fatalf("bad CA: opts=%v err=%v, want error", opts, err)
		}
		if !strings.Contains(err.Error(), "policy_signing") {
			t.Errorf("error %q lacks policy_signing context", err)
		}
	})
}

func TestSignAndVerifyPolicyRoundTrip(t *testing.T) {
	policyData := []byte(policyFixture)
	dir := t.TempDir()

	adminKey, adminCert := mintCert(t, nil, nil, "admin-signer", big.NewInt(100), nil, []string{RoleAdmin}, nil)

	t.Run("round_trip_succeeds", func(t *testing.T) {
		sig, err := SignPolicy(policyData, adminCert, adminKey)
		if err != nil {
			t.Fatalf("SignPolicy: %v", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(adminCert)
		got, err := VerifySignedPolicy(sig, policyData, roots, true)
		if err != nil {
			t.Fatalf("VerifySignedPolicy: %v", err)
		}
		if got.Subject.CommonName != "admin-signer" {
			t.Errorf("signer CN = %q", got.Subject.CommonName)
		}
	})

	t.Run("tampered_payload_rejected", func(t *testing.T) {
		sig, err := SignPolicy(policyData, adminCert, adminKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySignedPolicy(sig, []byte(policyFixture+" "), nil, true); err == nil {
			t.Fatal("expected signature failure on tampered payload")
		}
	})

	t.Run("wrong_roots_rejected", func(t *testing.T) {
		sig, err := SignPolicy(policyData, adminCert, adminKey)
		if err != nil {
			t.Fatal(err)
		}
		_, otherCert := mintCert(t, nil, nil, "other-ca", big.NewInt(200), nil, nil, nil)
		roots := x509.NewCertPool()
		roots.AddCert(otherCert)
		_, err = VerifySignedPolicy(sig, policyData, roots, true)
		if err == nil {
			t.Fatal("expected chain-trust failure with unrelated roots")
		}
		if !strings.Contains(err.Error(), "not trusted") {
			t.Errorf("error %q lacks trust context", err)
		}
	})

	t.Run("require_admin_ou_enforced", func(t *testing.T) {
		plainKey, plainCert := mintCert(t, nil, nil, "non-admin", big.NewInt(300), nil, []string{"gateway:read"}, nil)
		sig, err := SignPolicy(policyData, plainCert, plainKey)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(plainCert)
		if _, err := VerifySignedPolicy(sig, policyData, roots, true); err == nil {
			t.Fatal("expected admin-OU rejection")
		}
		if _, err := VerifySignedPolicy(sig, policyData, roots, false); err != nil {
			t.Fatalf("requireAdminOU=false should pass: %v", err)
		}
	})

	t.Run("load_authorization_policy_with_signature", func(t *testing.T) {
		path := filepath.Join(dir, "gatewaypolicy.json")
		if err := os.WriteFile(path, policyData, 0o600); err != nil {
			t.Fatal(err)
		}
		sig, err := SignPolicy(policyData, adminCert, adminKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(adminCert)

		p, err := LoadAuthorizationPolicy(path, ".sig", &PolicyVerifyOptions{Roots: roots, RequireAdminOU: true})
		if err != nil {
			t.Fatalf("LoadAuthorizationPolicy signed: %v", err)
		}
		if p.Version != "1.1" {
			t.Errorf("version = %q", p.Version)
		}

		if err := os.WriteFile(path, []byte(policyFixture+" "), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAuthorizationPolicy(path, ".sig", &PolicyVerifyOptions{Roots: roots, RequireAdminOU: true}); err == nil {
			t.Fatal("expected signature failure for tampered policy file")
		}

		sigPath := filepath.Join(t.TempDir(), "nosig.json")
		if err := os.WriteFile(sigPath, []byte(policyFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAuthorizationPolicy(sigPath, ".sig", &PolicyVerifyOptions{Roots: roots, RequireAdminOU: true}); err == nil {
			t.Fatal("expected error for missing signature file")
		}
	})
}

func TestParseAuthorizationPolicyErrors(t *testing.T) {
	if _, err := ParseAuthorizationPolicy([]byte(`{"version":"1"}`)); err == nil {
		t.Error("expected error for no roles")
	}
	if _, err := ParseAuthorizationPolicy([]byte(`{"roles":{"r":{"grants":[]}}}`)); err == nil {
		t.Error("expected error for missing version")
	}
	if _, err := ParseAuthorizationPolicy([]byte(`not json`)); err == nil {
		t.Error("expected parse error")
	}
}

func TestLoadPolicySigningIdentity(t *testing.T) {
	key, cert := mintCert(t, nil, nil, "signer", big.NewInt(400), nil, []string{RoleAdmin}, nil)
	dir := t.TempDir()
	certPath := writeCertPEMFile(t, dir, "signer.crt", cert)
	keyPath := writeKeyPEMFile(t, dir, "signer.key", key)

	t.Run("loads_both_files", func(t *testing.T) {
		id, err := LoadPolicySigningIdentity(certPath, keyPath)
		if err != nil {
			t.Fatalf("LoadPolicySigningIdentity: %v", err)
		}
		if id == nil || id.Cert == nil || id.Key == nil {
			t.Fatalf("identity = %+v", id)
		}
		if id.Cert.Subject.CommonName != "signer" {
			t.Errorf("cert CN = %q", id.Cert.Subject.CommonName)
		}
	})

	t.Run("missing_cert_errors", func(t *testing.T) {
		if _, err := LoadPolicySigningIdentity(filepath.Join(dir, "nope.crt"), keyPath); err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("missing_key_errors", func(t *testing.T) {
		if _, err := LoadPolicySigningIdentity(certPath, filepath.Join(dir, "nope.key")); err == nil {
			t.Fatal("expected error for missing key file")
		}
	})
}

func TestParseCertPEM(t *testing.T) {
	_, cert := mintCert(t, nil, nil, "leaf", big.NewInt(500), nil, nil, nil)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	t.Run("valid", func(t *testing.T) {
		got, err := ParseCertPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParseCertPEM: %v", err)
		}
		if !got.Equal(cert) {
			t.Error("parsed cert differs")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := ParseCertPEM([]byte("not pem")); err == nil {
			t.Fatal("expected error for garbage")
		}
	})

	t.Run("corrupt_der", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a der")})
		if _, err := ParseCertPEM(bad); err == nil {
			t.Fatal("expected error for corrupt DER")
		}
	})
}

func TestParseCertPEMFile(t *testing.T) {
	_, cert := mintCert(t, nil, nil, "file-leaf", big.NewInt(600), nil, nil, nil)
	path := writeCertPEMFile(t, t.TempDir(), "leaf.crt", cert)

	if _, err := ParseCertPEMFile(path); err != nil {
		t.Fatalf("ParseCertPEMFile: %v", err)
	}
	if _, err := ParseCertPEMFile(filepath.Join(t.TempDir(), "missing.crt")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	t.Run("ec_key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		got, err := ParsePrivateKeyPEM(pemBytes)
		if err != nil {
			t.Fatalf("ParsePrivateKeyPEM EC: %v", err)
		}
		if got == nil {
			t.Fatal("key = nil")
		}
	})

	t.Run("pkcs8_key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, err := ParsePrivateKeyPEM(pemBytes); err != nil {
			t.Fatalf("ParsePrivateKeyPEM PKCS#8: %v", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := ParsePrivateKeyPEM([]byte("junk")); err == nil {
			t.Fatal("expected error for garbage")
		}
	})

	t.Run("unsupported_type", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("x")})
		if _, err := ParsePrivateKeyPEM(pemBytes); err == nil {
			t.Fatal("expected error for unsupported key type")
		}
	})

	t.Run("encrypted_key_rejected", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")})
		if _, err := ParsePrivateKeyPEM(pemBytes); err == nil {
			t.Fatal("expected error for encrypted key")
		}
	})
}

func TestParsePrivateKeyPEMFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeKeyPEMFile(t, t.TempDir(), "key.pem", key)

	if _, err := ParsePrivateKeyPEMFile(path); err != nil {
		t.Fatalf("ParsePrivateKeyPEMFile: %v", err)
	}
	if _, err := ParsePrivateKeyPEMFile(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseSignerKey(t *testing.T) {
	t.Run("ec_private_key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseSignerKey(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err != nil {
			t.Fatalf("parseSignerKey EC: %v", err)
		}
		if got == nil {
			t.Fatal("got nil signer")
		}
	})

	t.Run("rsa_private_key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		if _, err := parseSignerKey(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}); err != nil {
			t.Fatalf("parseSignerKey RSA: %v", err)
		}
	})

	t.Run("unsupported_pem_type", func(t *testing.T) {
		if _, err := parseSignerKey(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("x")}); err == nil {
			t.Fatal("expected error for unsupported type")
		}
	})

	t.Run("encrypted_pem_type", func(t *testing.T) {
		if _, err := parseSignerKey(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}); err == nil {
			t.Fatal("expected error for encrypted type")
		}
	})
}
