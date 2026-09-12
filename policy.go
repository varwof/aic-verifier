// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	pki "github.com/varwof/types"

	"github.com/varwof/pkcs7"
)

// AuthorizationPolicy is the runtime model for the gateway authorization policy (authz.json).
// Structurally identical to varwof-core auth/policy.go, but kept as an independent implementation
// to maintain lib's zero new external dependency policy.
type AuthorizationPolicy struct {
	Version           string                     `json:"version"`
	Roles             map[string]PolicyRole      `json:"roles"`
	OUMapping         map[string]string          `json:"ou_mapping"`
	GatewayNamespaces map[string]PolicyNamespace `json:"gateway_namespaces"`
	// CapabilityParameters is the parameter default values map derived by gen-authz from
	// capability.json. Key is "scheme:capability_id" (e.g., "varwof/gateway:admin:config").
	CapabilityParameters map[string]map[string]any `json:"capability_parameters,omitempty"`
}

// PolicyRole defines a single role's display name, profiles, grants, and scope.
type PolicyRole struct {
	DisplayName string   `json:"display_name"`
	Profiles    []string `json:"profiles"`
	Grants      []string `json:"grants"`
	Scope       []string `json:"scope,omitempty"`
}

// PolicyNamespace defines the grants for a gateway namespace.
type PolicyNamespace struct {
	DisplayName string   `json:"display_name"`
	Prefix      string   `json:"prefix"`
	Grants      []string `json:"grants"`
}

// PolicyVerifyOptions describes the external parameters needed for signature verification.
type PolicyVerifyOptions struct {
	// Roots is the trusted CA chain (Issuing CA + Root CA) for verifying the signer certificate.
	Roots *x509.CertPool
	// RequireAdminOU, when true, requires the signer certificate OU to contain the admin role.
	RequireAdminOU bool
}

// PolicySigningConfig configures PKCS#7 detached signature verification for the gateway
// authz.json policy file. Structurally identical to varwof-core's policy_signing configuration.
type PolicySigningConfig struct {
	// Enabled enables policy signature verification.
	Enabled bool `json:"enabled,omitempty"`
	// CAFile is the trusted CA chain PEM (defaults to tls_client_ca).
	CAFile string `json:"ca_file,omitempty"`
	// RequireAdminOU requires the signer to have admin OU (nil=defaults to true).
	RequireAdminOU *bool `json:"require_admin_ou,omitempty"`
	// Require: true=reject if signature is missing; false=degrade with warning if missing.
	Require bool `json:"require,omitempty"`
	// SigSuffix is the signature file suffix (default ".sig").
	SigSuffix string `json:"sig_suffix,omitempty"`
}

// BuildPolicyVerifyOptions builds signature verification parameters from PolicySigningConfig.
// Returns nil if signature verification is not enabled (signing disabled). tlsClientCA is used
// as the default fallback when CAFile is empty.
func (ps *PolicySigningConfig) BuildPolicyVerifyOptions(tlsClientCA string) (*PolicyVerifyOptions, error) {
	if ps == nil || !ps.Enabled {
		return nil, nil
	}
	suffix := ps.SigSuffix
	if suffix == "" {
		suffix = ".sig"
	}
	caFile := ps.CAFile
	if caFile == "" {
		caFile = tlsClientCA
	}
	var roots *x509.CertPool
	if caFile != "" {
		var err error
		roots, err = LoadCAFromFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("policy_signing: load CA %s: %w", caFile, err)
		}
	}
	requireAdminOU := true
	if ps.RequireAdminOU != nil {
		requireAdminOU = *ps.RequireAdminOU
	}
	return &PolicyVerifyOptions{Roots: roots, RequireAdminOU: requireAdminOU}, nil
}

// LoadGatewayPolicy loads and sets the gateway authorization policy.
// If authorization_file is configured, loads it (with signature verification); opts=nil skips
// signature verification. On successful load, sets the global policy via SetAuthorizationPolicy.
// On failure, if require=true returns an error; otherwise degrades by keeping the existing policy.
func LoadGatewayPolicy(policyPath, sigSuffix string, opts *PolicyVerifyOptions, require bool) error {
	if policyPath == "" {
		return nil
	}
	p, err := LoadAuthorizationPolicy(policyPath, sigSuffix, opts)
	if err != nil {
		if require {
			return fmt.Errorf("policy: load %s (require=true): %w", policyPath, err)
		}
		return nil // Degradation: keep existing policy
	}
	SetAuthorizationPolicy(p)
	return nil
}

var (
	globalGWPolicy *AuthorizationPolicy
	gwPolicyMu     sync.RWMutex
)

// SetAuthorizationPolicy sets the global authorization policy.
func SetAuthorizationPolicy(p *AuthorizationPolicy) {
	gwPolicyMu.Lock()
	defer gwPolicyMu.Unlock()
	globalGWPolicy = p
}

// GetAuthorizationPolicy returns the current global authorization policy (may be nil).
func GetAuthorizationPolicy() *AuthorizationPolicy {
	gwPolicyMu.RLock()
	defer gwPolicyMu.RUnlock()
	return globalGWPolicy
}

// LoadAuthorizationPolicy loads the authorization policy from a file. If opts is non-nil and
// the signature file (policyPath+sigSuffix) exists, signature verification is performed first.
func LoadAuthorizationPolicy(policyPath, sigSuffix string, opts *PolicyVerifyOptions) (*AuthorizationPolicy, error) {
	data, err := os.ReadFile(filepath.Clean(policyPath))
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", policyPath, err)
	}
	if opts != nil {
		sigPath := policyPath + sigSuffix
		sig, err := os.ReadFile(filepath.Clean(sigPath))
		if err != nil {
			return nil, fmt.Errorf("policy: read signature %s: %w", sigPath, err)
		}
		if _, err := VerifySignedPolicy(sig, data, opts.Roots, opts.RequireAdminOU); err != nil {
			return nil, fmt.Errorf("policy: signature check failed: %w", err)
		}
	}
	return ParseAuthorizationPolicy(data)
}

// ParseAuthorizationPolicy parses the policy JSON.
func ParseAuthorizationPolicy(data []byte) (*AuthorizationPolicy, error) {
	var p AuthorizationPolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if p.Version == "" {
		return nil, errors.New("policy: missing version")
	}
	if len(p.Roles) == 0 {
		return nil, errors.New("policy: no roles defined")
	}
	return &p, nil
}

// HasGrant checks whether a role has a given capability (supports wildcards).
func (p *AuthorizationPolicy) HasGrant(role, capability string) bool {
	def, ok := p.Roles[role]
	if !ok {
		return false
	}
	for _, grant := range def.Grants {
		if MatchCapability(capability, grant) {
			return true
		}
	}
	return false
}

// RoleGrants returns the grants list for a role.
func (p *AuthorizationPolicy) RoleGrants(role string) []string {
	def, ok := p.Roles[role]
	if !ok {
		return nil
	}
	return def.Grants
}

// RoleByOU maps a certificate OU to a role name.
func (p *AuthorizationPolicy) RoleByOU(ou string) string {
	role, ok := p.OUMapping[ou]
	if !ok {
		return ""
	}
	return role
}

// ParamDefaults returns the parameter defaults for a given scheme:capability_id (gen-authz derived).
// Returns nil if not found.
func (p *AuthorizationPolicy) ParamDefaults(scheme, capID string) map[string]any {
	if p == nil || p.CapabilityParameters == nil {
		return nil
	}
	return p.CapabilityParameters[scheme+":"+capID]
}

// HasParamDefault checks whether a parameter has a default value (for overflow validation).
func (p *AuthorizationPolicy) HasParamDefault(scheme, capID, param string) (any, bool) {
	params := p.ParamDefaults(scheme, capID)
	if params == nil {
		return nil, false
	}
	v, ok := params[param]
	return v, ok
}

// ExtractPolicyRoles extracts policy roles from the certificate OU.
// Uses the global authorization policy's (if set) OU→role mapping to resolve role names;
// when no policy is set, falls back to the hardcoded ExtractRoles (only identifies
// gateway: prefix OUs).
// Returned role names include both policy role names and original gateway:* OUs (if present),
// for compatibility with both configuration styles.
func ExtractPolicyRoles(cert *x509.Certificate) []string {
	policy := GetAuthorizationPolicy()
	roles := ExtractRoles(cert)
	if policy == nil {
		return roles
	}
	seen := make(map[string]bool)
	var result []string
	for _, ou := range cert.Subject.OrganizationalUnit {
		ou = strings.TrimSpace(ou)
		if role := policy.RoleByOU(ou); role != "" && !seen[role] {
			seen[role] = true
			result = append(result, role)
		}
	}
	// Retain hardcoded gateway:* roles to avoid breaking existing rules during config migration.
	for _, r := range roles {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	return result
}

// IntersectGrants returns the subset of aicCapIds that matches any role grants.
func (p *AuthorizationPolicy) IntersectGrants(roles []string, aicCapIds []string) []string {
	if len(roles) == 0 || len(aicCapIds) == 0 {
		return nil
	}
	grantSet := make(map[string]bool)
	for _, role := range roles {
		if def, ok := p.Roles[role]; ok {
			for _, grant := range def.Grants {
				grantSet[grant] = true
			}
		}
	}
	var result []string
	for _, capID := range aicCapIds {
		for grant := range grantSet {
			if MatchCapability(capID, grant) {
				result = append(result, capID)
				break
			}
		}
	}
	return result
}

// MatchCapability checks whether a capability matches a pattern (supports * and a:b:* prefix).
func MatchCapability(id, pattern string) bool {
	if id == pattern {
		return true
	}
	if pattern == "*" {
		return true
	}
	if ok, _ := filepath.Match(pattern, id); ok {
		return true
	}
	if len(pattern) >= 2 && pattern[len(pattern)-1] == '*' && pattern[len(pattern)-2] == ':' {
		prefix := pattern[:len(pattern)-1]
		return len(id) >= len(prefix) && id[:len(prefix)] == prefix
	}
	return false
}

// MatchCapabilityPriority checks whether id matches pattern and returns a five-level priority
// (pki.MatchPriorityExact .. MatchPriorityGlobal, 0 means no match).
// Semantics: capabilityId is segmented by ':', '*' matches a single segment, '**' crosses segments,
// priority: exact(5) > single-segment(4) > multi-segment(3) > scheme(2) > global(1).
func MatchCapabilityPriority(id, pattern string) int {
	return pki.MatchCapabilityPriority(id, pattern)
}

// MatchCapabilityRules makes a decision within a rule set (allow + deny) by priority:
// takes the highest-priority matching rule; at equal priority, deny takes precedence over allow.
// Returns Matched=false when no rule matches.
func MatchCapabilityRules(id string, rules []pki.CapabilityRule) pki.CapabilityRuleMatch {
	return pki.MatchCapabilityRules(id, rules)
}

// IsAdminOU checks whether the OU is an admin role (compatible with gateway:admin and bare admin).
func IsAdminOU(ou string) bool {
	return ou == RoleAdmin || ou == "admin"
}

// SignerHasAdminOU checks whether the signer certificate carries the admin OU.
func SignerHasAdminOU(cert *x509.Certificate) bool {
	for _, ou := range cert.Subject.OrganizationalUnit {
		if IsAdminOU(ou) {
			return true
		}
	}
	return false
}

// LoadCAFromFile loads a PEM CA chain into a CertPool.
func LoadCAFromFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no PEM certs found in CA file")
	}
	return pool, nil
}

// VerifySignedPolicy verifies a PKCS#7 detached signature (policyData is the raw policy bytes).
// Returns the signer certificate on success, for further OU/status checks by the caller.
func VerifySignedPolicy(sigDER, policyData []byte, roots *x509.CertPool, requireAdminOU bool) (*x509.Certificate, error) {
	cert, err := pkcs7.VerifyDetached(sigDER, policyData)
	if err != nil {
		return nil, err
	}
	if requireAdminOU && !SignerHasAdminOU(cert) {
		return nil, fmt.Errorf("signer cert OU missing admin role (subject=%q)", cert.Subject.String())
	}
	if roots != nil {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("signer cert chain not trusted: %w", err)
		}
	}
	return cert, nil
}

// SignPolicy uses an admin identity to create a PKCS#7 detached signature (SHA-256) for policy
// data, returning .sig DER. signer must be a crypto.Signer (supports RSA/ECDSA/Ed25519).
func SignPolicy(policyData []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	return pkcs7.BuildSignedData(pkcs7.OIDData, policyData, cert, signer, nil)
}

// PolicySigningIdentity describes the admin identity used to sign the policy file.
type PolicySigningIdentity struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// LoadPolicySigningIdentity loads the signer certificate and private key from PEM files.
func LoadPolicySigningIdentity(certPEM, keyPEM string) (*PolicySigningIdentity, error) {
	cert, err := ParseCertPEMFile(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKeyPEMFile(keyPEM)
	if err != nil {
		return nil, err
	}
	return &PolicySigningIdentity{Cert: cert, Key: key}, nil
}

// ParseCertPEMFile reads and parses a PEM certificate file.
func ParseCertPEMFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return ParseCertPEM(data)
}

// ParsePrivateKeyPEMFile reads and parses a PEM private key file.
func ParsePrivateKeyPEMFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}

// ParseCertPEM parses the first certificate from PEM bytes.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in cert data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePrivateKeyPEM parses a PEM private key (PKCS#1/PKCS#8/EC/RSA).
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in key data")
	}
	return parseSignerKey(block)
}

func parseSignerKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("parsed key is not a crypto.Signer")
		}
		return s, nil
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("encrypted private key requires a password (unsupported here)")
	default:
		return nil, fmt.Errorf("unsupported PEM key type %q", block.Type)
	}
}
