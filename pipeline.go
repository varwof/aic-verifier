// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"crypto/x509"
	"fmt"
	"time"
)

// PipelineCheck is the certificate chain check scope type.
type PipelineCheck int

// CheckFullChain/CheckLeafOnly are certificate chain check scope constants.
const (
	CheckFullChain PipelineCheck = iota
	CheckLeafOnly
)

// PipelineConfig is the unified admission pipeline configuration.
type PipelineConfig struct {
	// CRLCache is the CRL cache instance.
	CRLCache *CRLCache
	// OCSPCache is the OCSP cache instance.
	OCSPCache *OCSPCache
	// AllowRoles is the list of allowed RBAC roles.
	AllowRoles []string
	// CheckScope controls the CA scope check mode.
	CheckScope PipelineCheck
	// MaxConnsPerCert is the maximum connections per certificate.
	MaxConnsPerCert int
	// RequireAIC requires the client to hold an AIC certificate.
	RequireAIC bool
	// RequireSPIFFE requires the client certificate to carry a SPIFFE ID
	// SAN URI. When set, connections without a SPIFFE ID are rejected.
	RequireSPIFFE bool
	// AllowedSPIFFEIDs is an optional exact-match allowlist of SPIFFE IDs.
	// Empty means no allowlist restriction.
	AllowedSPIFFEIDs []string
	// SPIFFETrustDomain when non-empty requires the client SPIFFE ID to
	// belong to this trust domain (e.g. "varwof.com").
	SPIFFETrustDomain string
	// RequiredProtocol is the transport protocol required by the client.
	RequiredProtocol string
	// RequiredRuleId is the required matching route rule ID.
	RequiredRuleId string
	// RequiredCapabilities is the list of capabilities the client must possess.
	RequiredCapabilities []string
	// DisallowRepresentative disallows delegated representative mode.
	DisallowRepresentative bool
	// RequireUserPermission requires user authorization signature.
	RequireUserPermission bool
	// RejectOverflow rejects when connection limit is exceeded.
	RejectOverflow bool
	// RequireUserAuth requires user authentication.
	RequireUserAuth bool
	// EnforceCapSizeConstraints enforces capability size constraints.
	EnforceCapSizeConstraints bool
	// EnforceSize32 enforces the 32-byte size constraint.
	EnforceSize32 bool
	// CapabilityPluginRegistry is the capability plugin registry.
	CapabilityPluginRegistry *PluginRegistry
	// CapabilityRegistry is the capability registration validation (single source of truth).
	// When non-nil, phase one performs registration validation on AIC-declared capabilities:
	// unregistered → reject connection.
	// nil means disabled (backward compatible).
	CapabilityRegistry CapabilityRegistry
	// CapabilityPluginResolver selects a capability plugin registry by agent identifier
	// (task 5b: branch control/canary).
	// When non-nil, it takes precedence over CapabilityPluginRegistry: the returned registry
	// is used for phase one plugin evaluation, and the returned version number (if non-zero)
	// overrides PolicyVersion for audit binding. Agents matching a branch use the branch
	// version policy; others fall back to the currently active version.
	CapabilityPluginResolver func(agentID string) (version uint64, reg *PluginRegistry)
	// AuditLogger is the audit log recorder.
	AuditLogger *AuditLogger
	// NonceCache is the anti-replay nonce cache.
	NonceCache *NonceCache
	// ClientIP is the client IP address for authorization constraint checks.
	ClientIP string
	// UserCert is the authorized user's certificate, used for DelegationAuthorization
	// signature verification.
	UserCert *x509.Certificate
	// UserCertResolver resolves a user certificate by PrincipalUid.KeyHash
	// (fetched via varwof-core API). Automatically called when UserCert is nil.
	UserCertResolver func(keyHash []byte) (*x509.Certificate, error)
	// EnforceConstraints, when true, enforces authorizationConstraints.
	EnforceConstraints bool
	// StrictConstraints, when true, fails-closed on unknown constraint types (patent spec P1-B-23).
	StrictConstraints bool
	// ParameterValidators is the parameter boundary validator registry
	// (patent spec P1-B-11/P2-B-05).
	// When non-nil, after the P∩C intersection, parameters of AIC declarations and PA
	// authorizations are compared one by one against the boundary; out-of-bounds → reject.
	ParameterValidators *ParameterValidatorRegistry
	// PolicyServer is the Layer 3 online authorization policy server (patent spec P2-A-02).
	// Called by VerifyLayer3/VerifyTrustLayers; not used by RunAccessPipeline.
	PolicyServer PolicyServer
	// CredentialBundle is the client-submitted credential bundle (P1-B-27/P1-B-29/P2-A-01).
	// When RequireUserAuth is enabled, the Principal certificate is preferentially extracted
	// from the credential bundle for DA signature verification.
	CredentialBundle *CredentialBundle
	// PolicyVersion is the policy version effective at decision time (task 5a: decision
	// records bound to policy version).
	// Filled by the gateway from PolicyManager.CurrentVersion() when constructing PipelineConfig;
	// when 0, the audit entry omits this field.
	PolicyVersion uint64
	// RiskMonitor is the high-risk behavior monitor (2026-08-15). When non-nil, the pipeline
	// automatically records violation signals at behavioral rejection points (parameter overflow /
	// plugin deny / CIDR out-of-bounds); once a rule threshold is reached, the gateway's
	// injected OnAction callback executes kick + revocation.
	RiskMonitor *RiskMonitor
	// OfflineMaxCertLifetime is the maximum remaining certificate validity enforced in offline
	// mode (G2(b)).
	// When >0 (e.g., 1h): revocation checks use fail-open (OCSP fallback=allow / CRL unreachable)
	// in offline scenarios; client certificates with remaining validity exceeding this value are
	// rejected — prevents offline fail-open windows from diluting "short-lived certificate"
	// semantics with long-lived certificates. 0 = not enforced.
	OfflineMaxCertLifetime time.Duration
	// HTTPFacts carries per-request HTTP facts (method/path/query/
	// headers) that are copied into the PluginContext for capability
	// plugins. nil means no HTTP facts (TCP/TLS admission path).
	HTTPFacts *HTTPFacts
}

// PipelineResult is the admission pipeline execution result.
type PipelineResult struct {
	Granted    bool
	DenyReason string
	Roles      []string
	Principal  string
	Serial     string
	AgentId    string
	// SPIFFEID is the SPIFFE ID extracted from the client certificate SAN
	// URI (empty when the certificate carries no SPIFFE URI).
	SPIFFEID string
	// AIC is the AIC extension carried by the admitted connection (parsed result). G3 long-lived
	// connection periodic review requires its AuthorizationConstraints.
	AIC *AIC
	// PrincipalAuthorization is the principal authorization extension carried by the connection
	// (source of the P∩C intersection).
	PrincipalAuthorization *PrincipalAuthorization
}

// OfflineLifetimeLimit is the maximum remaining certificate validity enforced in offline mode (G2(b): ≤1h).
const OfflineLifetimeLimit = time.Hour

// OfflineLifetimeFor returns the enforced offline limit based on the OCSP fallback policy.
// OCSPFallbackAllow (fail-open) and OCSPFallbackCRL (crl data can lag a recent
// revocation) → 1h cap; deny/disabled → 0 (not enforced; deny is fail-closed).
// Called by the gateway when constructing PipelineConfig.OfflineMaxCertLifetime.
func OfflineLifetimeFor(ocspFallback string) time.Duration {
	if ocspFallback == OCSPFallbackAllow || ocspFallback == OCSPFallbackCRL {
		return OfflineLifetimeLimit
	}
	return 0
}

// RunAccessPipeline executes the unified admission pipeline (CRL→OCSP→RBAC→decision engine).
func RunAccessPipeline(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult {
	if len(chain) == 0 {
		return deny("no client certificate presented")
	}

	clientCert := chain[0]

	if cfg.CheckScope == CheckLeafOnly {
		if err := checkCertValidity(clientCert); err != nil {
			return deny(err.Error())
		}
		if cfg.CRLCache != nil {
			if revoked, err := cfg.CRLCache.IsRevokedCert(clientCert); err != nil {
				return deny(fmt.Sprintf("crl check error: %v", err))
			} else if revoked {
				return deny("certificate revoked (CRL)")
			}
		}
		if cfg.OCSPCache != nil {
			if err := cfg.OCSPCache.Check(clientCert, nil); err != nil {
				return deny(fmt.Sprintf("ocsp check error: %v", err))
			}
		}
	} else {
		for i := 0; i < len(chain); i++ {
			c := chain[i]
			if err := checkCertValidity(c); err != nil {
				return deny(err.Error())
			}
			if cfg.CRLCache != nil {
				if revoked, err := cfg.CRLCache.IsRevokedCert(c); err != nil {
					return deny(fmt.Sprintf("crl check error: %v", err))
				} else if revoked {
					return deny("certificate revoked (CRL)")
				}
			}
			if cfg.OCSPCache != nil {
				var issuer *x509.Certificate
				if i+1 < len(chain) {
					issuer = chain[i+1]
				}
				if err := cfg.OCSPCache.Check(c, issuer); err != nil {
					return deny(fmt.Sprintf("ocsp check error: %v", err))
				}
			}
		}
	}

	roles := ExtractPolicyRoles(clientCert)
	if len(cfg.AllowRoles) > 0 {
		if !CheckRole(roles, cfg.AllowRoles) {
			return deny(fmt.Sprintf("insufficient roles: have %v, need %v", roles, cfg.AllowRoles))
		}
	}

	// SPIFFE identity integration: extract the SPIFFE ID from the client
	// certificate SAN URI and enforce admission-time constraints when
	// configured (RequireSPIFFE / trust domain / allowlist).
	spiffeID := ExtractSPIFFEIDFromCert(clientCert)
	if cfg.RequireSPIFFE || len(cfg.AllowedSPIFFEIDs) > 0 || cfg.SPIFFETrustDomain != "" {
		if spiffeID == "" {
			return deny("spiffe id required but not present in client certificate")
		}
		sid, err := ParseSPIFFEID(spiffeID)
		if err != nil {
			return deny(fmt.Sprintf("invalid spiffe id: %v", err))
		}
		if cfg.SPIFFETrustDomain != "" && sid.TrustDomain != cfg.SPIFFETrustDomain {
			return deny(fmt.Sprintf("spiffe trust domain mismatch: have %s, want %s",
				sid.TrustDomain, cfg.SPIFFETrustDomain))
		}
		if len(cfg.AllowedSPIFFEIDs) > 0 {
			allowed := false
			for _, id := range cfg.AllowedSPIFFEIDs {
				if id == spiffeID {
					allowed = true
					break
				}
			}
			if !allowed {
				return deny(fmt.Sprintf("spiffe id not in allowed list: %s", spiffeID))
			}
		}
	}

	// G2(b): enforce maximum remaining certificate validity in offline mode.
	// When revocation checks use fail-open (OCSP fallback=allow / CRL unreachable),
	// long-lived certificates dilute "short-lived certificate strict enforcement" semantics;
	// when the gateway injects OfflineMaxCertLifetime (e.g., 1h), reject here.
	if cfg.OfflineMaxCertLifetime > 0 {
		remaining := time.Until(clientCert.NotAfter)
		if remaining > cfg.OfflineMaxCertLifetime {
			return deny(fmt.Sprintf("offline mode: certificate remaining validity %s exceeds offline limit %s",
				remaining.Round(time.Second), cfg.OfflineMaxCertLifetime))
		}
	}

	admit := CheckAdmission(clientCert, AdmissionConfig{
		RequireAIC:                cfg.RequireAIC,
		RequiredProtocol:          cfg.RequiredProtocol,
		RequiredRuleId:            cfg.RequiredRuleId,
		RequiredCapabilities:      cfg.RequiredCapabilities,
		DisallowRepresentative:    cfg.DisallowRepresentative,
		RequireUserPermission:     cfg.RequireUserPermission,
		RejectOverflow:            cfg.RejectOverflow,
		RequireUserAuth:           cfg.RequireUserAuth,
		EnforceCapSizeConstraints: cfg.EnforceCapSizeConstraints,
		EnforceSize32:             cfg.EnforceSize32,
		NonceCache:                cfg.NonceCache,
		UserCert:                  cfg.UserCert,
		UserCertResolver:          cfg.UserCertResolver,
		ClientIP:                  cfg.ClientIP,
		EnforceConstraints:        cfg.EnforceConstraints,
		StrictConstraints:         cfg.StrictConstraints,
		AuditLogger:               cfg.AuditLogger,
		CredentialBundle:          cfg.CredentialBundle,
	})
	if admit.Decision != DecisionAllow {
		return deny(admit.Reason)
	}

	// Parameter-level boundary validation (P1-B-11/P2-B-05): AIC-declared parameters must not
	// exceed PA authorization boundaries.
	// After the P∩C intersection (inside CheckAdmission), parameters are compared one by one;
	// the iteration target is EffectiveCaps (intersection); declarations outside the intersection
	// do not participate in parameter validation.
	if cfg.ParameterValidators != nil && admit.AIC != nil && admit.PrincipalAuthorization != nil {
		for _, declared := range admit.EffectiveCaps {
			for _, granted := range admit.PrincipalAuthorization.Grants {
				// Only compare parameters for declarations within the authorized boundary (intersection hit).
				if aicCapabilityMatches([]Capability{declared}, granted.CapabilityId) {
					if err := cfg.ParameterValidators.ValidateCapability(granted, declared); err != nil {
						LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
							Scheme:        declared.SchemeId,
							CapabilityID:  declared.CapabilityId,
							Decision:      "deny",
							Reason:        err.Error(),
							ClientCN:      clientCert.Subject.CommonName,
							Principal:     admit.PrincipalUid,
							Level:         "WARN",
							PolicyVersion: cfg.PolicyVersion,
						})
						recordRiskViolation(cfg.RiskMonitor, clientCert, "parameter_overflow",
							declared.CapabilityId, err.Error())
						return deny(fmt.Sprintf("parameter boundary: %v", err))
					}
				}
			}
		}
	}

	// Phase one (connection/declaration layer): P∩C intersection + scheme-aligned plugin
	// evaluation (P2-A-06/P2-A-07).
	// Plugin decisions are only made for schemes this gateway declares to serve: plugin deny →
	// reject connection; plugin allow → allow.
	// Schemes not served by this gateway (no plugin) → ignore, do not block connection
	// (multi-protocol agents are not dragged down by unrelated schemes).
	// Decision for specific operations is phase two's responsibility (see CheckOperationCapability,
	// operation-level fail-closed).
	// Task 4: authorization evidence binding action records — plugin decision entries carry DA hash
	// (reused within the same session).
	daHash := DAHashFromAIC(admit.AIC)
	policyVersion := cfg.PolicyVersion
	agentId := ""
	if admit.AIC != nil {
		agentId = admit.AIC.AgentId
	}
	// Task 5b: branch control — select policy version registry by agent identifier (canary).
	// Human certificates without AIC (direct authorization) also participate in branch routing;
	// when agentId is empty, the global branch is matched.
	pluginReg := cfg.CapabilityPluginRegistry
	if cfg.CapabilityPluginResolver != nil {
		if v, reg := cfg.CapabilityPluginResolver(agentId); reg != nil {
			pluginReg = reg
			if v != 0 {
				policyVersion = v
			}
		}
	}
	// Capability registration validation (single source of truth): AIC-declared capabilities
	// must be registered. Unregistered scheme/capability = illegal declaration → reject
	// connection (fail-closed).
	// Prefers the explicitly injected registry from PipelineConfig; falls back to the
	// package-level default registry when nil.
	capReg := cfg.CapabilityRegistry
	if capReg == nil {
		capReg = GetGlobalCapabilityRegistry()
	}
	if capReg != nil && capReg.Enabled() && len(admit.EffectiveCaps) > 0 {
		for _, cap := range admit.EffectiveCaps {
			full := cap.FullID()
			if err := capReg.ValidateCapability(full); err != nil {
				LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
					Scheme:        cap.SchemeId,
					CapabilityID:  cap.CapabilityId,
					Decision:      "deny",
					Reason:        fmt.Sprintf("capability %q not registered: %v", full, err),
					ClientCN:      clientCert.Subject.CommonName,
					Principal:     admit.PrincipalUid,
					Level:         "WARN",
					DaHash:        daHash,
					PolicyVersion: policyVersion,
				})
				recordRiskViolation(cfg.RiskMonitor, clientCert, "unregistered_capability",
					cap.CapabilityId, err.Error())
				return deny(fmt.Sprintf("capability %q not registered: %v", full, err))
			}
		}
	}

	if pluginReg != nil && len(admit.EffectiveCaps) > 0 {
		for _, cap := range admit.EffectiveCaps {
			p, err := pluginReg.Find(cap.SchemeId)
			if err != nil {
				// Scheme has no plugin = gateway does not serve this declaration → ignore
				// (spec: Ignore, not Deny)
				LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
					Scheme:        cap.SchemeId,
					CapabilityID:  cap.CapabilityId,
					Decision:      "ignore",
					Reason:        fmt.Sprintf("scheme %q not served by this gateway", cap.SchemeId),
					ClientCN:      clientCert.Subject.CommonName,
					Principal:     admit.PrincipalUid,
					Level:         "INFO",
					DaHash:        daHash,
					PolicyVersion: policyVersion,
				})
				continue
			}
			pc := &PluginContext{
				AgentId:  agentId,
				ClientCN: clientCert.Subject.CommonName,
				Roles:    roles,
				Target:   cap.CapabilityId,
			}
			if cfg.HTTPFacts != nil {
				pc.Method = cfg.HTTPFacts.Method
				pc.Path = cfg.HTTPFacts.Path
				pc.Query = cfg.HTTPFacts.Query
				pc.Headers = cfg.HTTPFacts.Headers
				pc.Body = cfg.HTTPFacts.Body
			}
			res, err := p.Execute(&cap, pc)
			if err != nil {
				LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
					Scheme:        cap.SchemeId,
					CapabilityID:  cap.CapabilityId,
					Decision:      "error",
					Reason:        err.Error(),
					ClientCN:      clientCert.Subject.CommonName,
					Principal:     admit.PrincipalUid,
					Level:         "WARN",
					DaHash:        daHash,
					PolicyVersion: policyVersion,
				})
				return deny(fmt.Sprintf("plugin %q error: %v", cap.SchemeId, err))
			}
			if res.Decision == PluginDeny {
				LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
					Scheme:        cap.SchemeId,
					CapabilityID:  cap.CapabilityId,
					Decision:      "deny",
					Reason:        res.Reason,
					ClientCN:      clientCert.Subject.CommonName,
					Principal:     admit.PrincipalUid,
					Level:         "WARN",
					DaHash:        daHash,
					PolicyVersion: policyVersion,
				})
				recordRiskViolation(cfg.RiskMonitor, clientCert, "plugin_deny",
					cap.CapabilityId, res.Reason)
				return deny(fmt.Sprintf("plugin %q denied: %s", cap.SchemeId, res.Reason))
			}
			LogPluginDecision(cfg.AuditLogger, PluginAuditEntry{
				Scheme:        cap.SchemeId,
				CapabilityID:  cap.CapabilityId,
				Decision:      "allow",
				Reason:        res.Reason,
				ClientCN:      clientCert.Subject.CommonName,
				Principal:     admit.PrincipalUid,
				Level:         "INFO",
				DaHash:        daHash,
				PolicyVersion: policyVersion,
			})
		}
	}

	serial := clientCert.SerialNumber.Text(16)
	return &PipelineResult{
		Granted:                true,
		Roles:                  roles,
		Principal:              admit.PrincipalUid,
		Serial:                 serial,
		AgentId:                agentId,
		SPIFFEID:               spiffeID,
		AIC:                    admit.AIC,
		PrincipalAuthorization: admit.PrincipalAuthorization,
	}
}

func checkCertValidity(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate %q not yet valid", cert.Subject.String())
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate %q expired", cert.Subject.String())
	}
	return nil
}

func deny(reason string) *PipelineResult {
	return &PipelineResult{
		Granted:    false,
		DenyReason: reason,
	}
}

// recordRiskViolation records a risk signal at a behavioral rejection point (no-op if RiskMonitor is not configured).
func recordRiskViolation(m *RiskMonitor, cert *x509.Certificate, signal, capabilityID, details string) {
	if m == nil {
		return
	}
	agentID := ""
	if cert != nil {
		agentID = aicAgentID(cert)
	}
	m.RecordViolation(RiskViolation{
		AgentId:      agentID,
		Signal:       signal,
		CapabilityId: capabilityID,
		Details:      details,
	})
}

// aicAgentID best-effort extracts the AIC AgentId from the client certificate; falls back to CN on failure.
func aicAgentID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if aic, err := ParseAIC(cert); err == nil && aic != nil && aic.AgentId != "" {
		return aic.AgentId
	}
	return cert.Subject.CommonName
}

// CheckOperationCapability executes phase two (operation layer) plugin decisions (P2-A-06/P2-A-07).
// Called by the gateway before processing a specific operation (e.g., HTTP route, TCP tunnel,
// UDP target), making decisions only for the capability corresponding to that operation:
//
//   - Operation scheme has no plugin → fail-closed reject (gateway declares service but no
//     decision rule configured; cannot allow uncontrolled operations);
//   - Plugin deny → reject;
//   - Plugin allow/bypass → allow.
//
// Complementary to phase one (P∩C intersection + scheme alignment inside RunAccessPipeline):
// phase one ignores unrelated schemes to allow connections; phase two is fail-closed for
// operations that will actually be executed.
//
// Returns (PluginResult, error): error indicates only internal execution errors (e.g., webhook
// call failure); Decision==PluginDeny means the operation is rejected, and the caller should
// block the operation and record an audit entry accordingly.
func CheckOperationCapability(reg *PluginRegistry, cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	if reg == nil || cap == nil {
		return nil, fmt.Errorf("check_operation: nil registry or capability")
	}
	p, err := reg.Find(cap.SchemeId)
	if err != nil {
		// Operation scheme has no plugin = cannot determine → fail-closed
		return &PluginResult{Decision: PluginDeny, Reason: fmt.Sprintf("scheme %q has no registered plugin: fail-closed", cap.SchemeId)}, nil
	}
	return p.Execute(cap, ctx)
}
