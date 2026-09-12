// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Three-layer trust model — spec P2-A-02
//
//	Layer 1 Identity verification (Agent Cert + CA Chain)
//	Layer 2 Representation verification (+ Principal Cert + PA)
//	Layer 3 Online authorization verification (+ OCSP/CRL/Policy Server, freshness check)
//
// RunAccessPipeline maintains single-entry-point compatibility; this file provides
// explicit three-layer functions and VerifyTrustLayers composite entry point
// (layers can be independently orchestrated/reused).

package aicverifier

import (
	"crypto/x509"
	"fmt"
)

// TrustLayer represents a layer in the three-layer trust model.
type TrustLayer int

// Layer1/2/3 three-layer trust model layer constants.
const (
	Layer1Identity TrustLayer = iota
	Layer2Representation
	Layer3OnlineAuthorization
)

// String returns the layer name.
func (l TrustLayer) String() string {
	switch l {
	case Layer1Identity:
		return "identity"
	case Layer2Representation:
		return "representation"
	case Layer3OnlineAuthorization:
		return "online_authorization"
	default:
		return "unknown"
	}
}

// Layer1Result is the Layer 1 identity verification result (Agent Cert + CA Chain + RBAC).
type Layer1Result struct {
	Verified bool
	Reason   string
	Roles    []string
}

// Layer2Result is the Layer 2 representation verification result (+ Principal Cert + PA).
type Layer2Result struct {
	Verified               bool
	Reason                 string
	AIC                    *AIC
	PrincipalAuthorization *PrincipalAuthorization
	PrincipalUid           string
}

// Layer3Result is the Layer 3 online authorization verification result (OCSP/CRL/Policy Server).
type Layer3Result struct {
	Verified bool
	Reason   string
}

// PolicyServer is the Layer 3 online authorization policy server interface (spec P2-A-02 Layer 3).
// Online authorization verification includes revocation freshness (OCSP/CRL, handled by
// PipelineConfig's cache instances) and policy server policy checks (if configured).
type PolicyServer interface {
	// Name returns the policy server name (for auditing).
	Name() string
	// CheckOnline checks online authorization (leaf certificate + parsed AIC).
	// Returns nil for authorization granted; non-nil for denial (with reason).
	CheckOnline(leaf *x509.Certificate, aic *AIC) error
}

// VerifyLayer1 performs Layer 1 identity verification:
// certificate chain validity (validity period) + RBAC roles (AllowRoles matching).
// Cryptographic certificate chain verification is done by the TLS layer
// (VerifyPeerCertificate); this layer performs application-level identity checks
// (validity period + roles). Returns roles for use by subsequent layers.
func VerifyLayer1(chain []*x509.Certificate, cfg *PipelineConfig) *Layer1Result {
	if len(chain) == 0 {
		return &Layer1Result{Reason: "no client certificate presented"}
	}
	for _, c := range chain {
		if err := checkCertValidity(c); err != nil {
			return &Layer1Result{Reason: err.Error()}
		}
	}
	roles := ExtractPolicyRoles(chain[0])
	if len(cfg.AllowRoles) > 0 {
		if !CheckRole(roles, cfg.AllowRoles) {
			return &Layer1Result{
				Reason: fmt.Sprintf("insufficient roles: have %v, need %v", roles, cfg.AllowRoles),
				Roles:  roles,
			}
		}
	}
	return &Layer1Result{Verified: true, Roles: roles}
}

// VerifyLayer2 performs Layer 2 representation verification:
// AIC parsing + PA parsing + delegation representation check (completed within CheckAdmission).
// Returns AdmissionResult and Layer2Result.
func VerifyLayer2(chain []*x509.Certificate, cfg *PipelineConfig, roles []string) (AdmissionResult, *Layer2Result) {
	if len(chain) == 0 {
		return AdmissionResult{}, &Layer2Result{Reason: "no client certificate presented"}
	}
	clientCert := chain[0]
	admit := CheckAdmission(clientCert, AdmissionConfig{
		RequireAIC:                cfg.RequireAIC,
		RequiredProtocol:          cfg.RequiredProtocol,
		RequiredRuleId:            cfg.RequiredRuleId,
		RequiredCapabilities:      cfg.RequiredCapabilities,
		Operations:                cfg.Operations,
		UnresolvedEvaluator:       cfg.UnresolvedEvaluator,
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
	})
	res := &Layer2Result{
		AIC:                    admit.AIC,
		PrincipalAuthorization: admit.PrincipalAuthorization,
		PrincipalUid:           admit.PrincipalUid,
	}
	if admit.Decision != DecisionAllow {
		res.Reason = admit.Reason
		return admit, res
	}
	res.Verified = true
	return admit, res
}

// VerifyLayer3 performs Layer 3 online authorization verification:
// CRL/OCSP revocation freshness check + optional PolicyServer online policy check.
func VerifyLayer3(chain []*x509.Certificate, cfg *PipelineConfig) *Layer3Result {
	if len(chain) == 0 {
		return &Layer3Result{Reason: "no client certificate presented"}
	}
	if cfg.CheckScope == CheckLeafOnly {
		leaf := chain[0]
		if err := checkRevocation(leaf, nil, cfg); err != nil {
			return &Layer3Result{Reason: err.Error()}
		}
		if cfg.PolicyServer != nil {
			if err := cfg.PolicyServer.CheckOnline(leaf, nil); err != nil {
				return &Layer3Result{Reason: fmt.Sprintf("policy server %q: %v", cfg.PolicyServer.Name(), err)}
			}
		}
	} else {
		for i, c := range chain {
			var issuer *x509.Certificate
			if i+1 < len(chain) {
				issuer = chain[i+1]
			}
			if err := checkRevocation(c, issuer, cfg); err != nil {
				return &Layer3Result{Reason: err.Error()}
			}
		}
		if cfg.PolicyServer != nil {
			if err := cfg.PolicyServer.CheckOnline(chain[0], nil); err != nil {
				return &Layer3Result{Reason: fmt.Sprintf("policy server %q: %v", cfg.PolicyServer.Name(), err)}
			}
		}
	}
	return &Layer3Result{Verified: true}
}

// checkRevocation performs CRL/OCSP revocation check on a single certificate.
func checkRevocation(cert, issuer *x509.Certificate, cfg *PipelineConfig) error {
	if cfg.CRLCache != nil {
		if revoked, err := cfg.CRLCache.IsRevokedCert(cert); err != nil {
			return fmt.Errorf("crl check error: %v", err)
		} else if revoked {
			return fmt.Errorf("certificate revoked (CRL)")
		}
	}
	if cfg.OCSPCache != nil {
		if err := cfg.OCSPCache.Check(cert, issuer); err != nil {
			return fmt.Errorf("ocsp check error: %v", err)
		}
	}
	return nil
}

// VerifyTrustLayers executes three-layer trust verification in combination (L1 → L2 → L3),
// equivalent to the explicit layered entry point of RunAccessPipeline.
// Returns denial on any layer failure.
func VerifyTrustLayers(chain []*x509.Certificate, cfg *PipelineConfig) *PipelineResult {
	if cfg == nil {
		return deny("nil pipeline config")
	}
	// L1 identity verification
	l1 := VerifyLayer1(chain, cfg)
	if !l1.Verified {
		return deny(l1.Reason)
	}
	// L2 representation verification
	admit, l2 := VerifyLayer2(chain, cfg, l1.Roles)
	if !l2.Verified {
		return deny(l2.Reason)
	}
	// L3 online authorization verification
	l3 := VerifyLayer3(chain, cfg)
	if !l3.Verified {
		return deny(l3.Reason)
	}

	serial := chain[0].SerialNumber.Text(16)
	agentId := ""
	if admit.AIC != nil {
		agentId = admit.AIC.AgentId
	}
	return &PipelineResult{
		Granted:   true,
		Roles:     l1.Roles,
		Principal: admit.PrincipalUid,
		Serial:    serial,
		AgentId:   agentId,
	}
}
