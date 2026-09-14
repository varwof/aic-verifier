// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Delegation chain hardening
//
//   - Anti-cycle: certificate serial number deduplication within chain, reject on duplicate (cycle/reuse detection);
//   - Anti-certificate-bomb: reject when chain length exceeds MaxChainLength;
//   - Per-level capability subset: each level's AIC.capabilities must be a subset of the parent's effective capabilities (permissions only decrease);
//   - Recursive intersection along chain: C_eff = P ∩ C_1 ∩ … ∩ C_n, computed level by level; any failure rejects the entire chain.

package aicverifier

import (
	"crypto/x509"
	"fmt"
	"strings"

	pki "github.com/varwof/types"
)

// DefaultMaxChainLength is the default upper bound for maximum delegation chain length
// (anti-certificate-bomb). Chains exceeding this are rejected (specification
// maxDepth is set by the top Principal; this serves as the gateway-side hard limit).
// Real-world Agent delegation depths are typically 2–3 levels; default 8 provides ample margin.
const DefaultMaxChainLength = 8

// capabilityID returns the canonical identifier for a single capability (schemeId:capabilityId).
// Reuses pki-types Capability.FullID() as the single authoritative join point, avoiding duplicate implementations across modules.
func capabilityID(c pki.Capability) string {
	return c.FullID()
}

// capabilityCovered reports whether leaf capability is covered by ancestor capability.
// Coverage relationship (capability subset semantics):
//   - Exact equality, or ancestor is a wildcard (glob, MatchCapability semantics, e.g. database:*);
//   - Or ancestor is a specific path prefix of leaf (permission narrowing: database:query covers
//     database:query:SELECT).
func capabilityCovered(leaf, ancestor pki.Capability) bool {
	leafID := capabilityID(leaf)
	ancID := capabilityID(ancestor)
	if MatchCapability(leafID, ancID) {
		return true
	}
	// ancestor is a specific path prefix (no wildcards) → leaf is its sub-path.
	if !strings.ContainsAny(ancID, "*") {
		if strings.HasPrefix(leafID, ancID+":") {
			return true
		}
	}
	return false
}

// capabilitySubset reports whether every capability in subset is covered by
// some capability in superset (this level ⊆ parent effective capabilities).
func capabilitySubset(subset, superset []pki.Capability) bool {
	if len(subset) == 0 {
		return true
	}
	if len(superset) == 0 {
		return false
	}
	for _, s := range subset {
		covered := false
		for _, sup := range superset {
			if capabilityCovered(s, sup) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// filterCovered returns capabilities from leaf that are covered by ancestor (core filter for C_eff computation).
func filterCovered(leaf, ancestor []pki.Capability) []pki.Capability {
	if len(leaf) == 0 || len(ancestor) == 0 {
		return nil
	}
	var out []pki.Capability
	for _, l := range leaf {
		for _, a := range ancestor {
			if capabilityCovered(l, a) {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// verifyChainStructure validates chain structure constraints:
//   - Non-empty, does not exceed MaxChainLength (anti-certificate-bomb);
//   - No duplicate certificate serial numbers within the chain (anti-cycle).
func verifyChainStructure(chain []*x509.Certificate, maxChainLen int) error {
	if len(chain) == 0 {
		return fmt.Errorf("delegation_chain: empty chain")
	}
	if maxChainLen > 0 && len(chain) > maxChainLen {
		return fmt.Errorf("delegation_chain: chain length %d exceeds limit %d", len(chain), maxChainLen)
	}
	seen := make(map[string]struct{}, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("delegation_chain: nil certificate at index %d", i)
		}
		serial := NormalizeSerial(cert.SerialNumber)
		if _, dup := seen[serial]; dup {
			return fmt.Errorf("delegation_chain: duplicate node serial %s at index %d (cycle)", serial, i)
		}
		seen[serial] = struct{}{}
	}
	return nil
}

// EffectiveDelegationCapabilities validates per-level capability subsets and computes
// the intersection along the delegation chain.
//
// chain goes top-down: chain[0]=topmost delegated Agent, chain[len-1]=bottom Agent.
// principalCaps is the effective capabilities P of the original principal (top Principal).
// Returns C_eff = P ∩ C_1 ∩ … ∩ C_n.
//
// Process: eff = P; for each level C_i, first verify C_i ⊆ eff (permissions only decrease,
// escalation is rejected), then eff = filterCovered(C_i, eff) (retain this level's
// capabilities that are authorized by eff).
//
// Note: This function only performs capability semantic validation; signature verification
// is handled separately by Verify.
func EffectiveDelegationCapabilities(chain []*x509.Certificate, principalCaps []pki.Capability, maxChainLen int) ([]pki.Capability, error) {
	if err := verifyChainStructure(chain, maxChainLen); err != nil {
		return nil, err
	}

	eff := principalCaps
	for i, cert := range chain {
		aic, err := ParseAIC(cert)
		if err != nil {
			return nil, fmt.Errorf("delegation_chain level %d (%s): parse AIC: %w", i, cert.Subject.CommonName, err)
		}
		if aic == nil {
			return nil, fmt.Errorf("delegation_chain level %d (%s): no AIC extension", i, cert.Subject.CommonName)
		}
		// Per-level subset validation: this level's declared capabilities must be a subset of the parent's effective capabilities (permissions only decrease).
		if !capabilitySubset(aic.Capabilities, eff) {
			return nil, fmt.Errorf("delegation_chain level %d (%s): capabilities not subset of parent effective capabilities (permission escalation)", i, cert.Subject.CommonName)
		}
		eff = filterCovered(aic.Capabilities, eff)
		if len(eff) == 0 {
			return nil, fmt.Errorf("delegation_chain level %d (%s): empty effective capabilities (C_eff = empty)", i, cert.Subject.CommonName)
		}
	}
	return eff, nil
}

// VerifyDelegationChainWithCaps verifies a multi-level delegation chain and computes
// the effective capability intersection:
//   - Basic signature verification (bottom-up per level) and depth limits;
//   - Anti-cycle (serial number deduplication within chain);
//   - Anti-certificate-bomb (chain length upper bound);
//   - Per-level capability subset validation + C_eff recursive intersection.
//
// maxDepth is set by the top Principal (≤0 means no limit); maxChainLen is the
// gateway-side hard upper bound (≤0 uses DefaultMaxChainLength).
// Returns C_eff = P ∩ C_1 ∩ … ∩ C_n.
func VerifyDelegationChainWithCaps(chain []*x509.Certificate, topPrincipal *x509.Certificate, principalCaps []pki.Capability, maxDepth, maxChainLen int) ([]pki.Capability, error) {
	if maxChainLen <= 0 {
		maxChainLen = DefaultMaxChainLength
	}
	v := &DelegationChainVerifier{MaxDepth: maxDepth, MaxChainLength: maxChainLen}
	if err := v.Verify(chain, topPrincipal); err != nil {
		return nil, err
	}
	return EffectiveDelegationCapabilities(chain, principalCaps, maxChainLen)
}

// EffectiveDelegationCapabilitiesFromAIC is a convenience entry point: extracts
// AIC.capabilities from the top Principal certificate as P, then recursively computes
// the intersection. Chain signature verification is performed separately by the caller.
func EffectiveDelegationCapabilitiesFromAIC(chain []*x509.Certificate, topPrincipal *x509.Certificate, maxChainLen int) ([]pki.Capability, error) {
	if topPrincipal == nil {
		return nil, fmt.Errorf("delegation_chain: nil top principal")
	}
	aic, err := ParseAIC(topPrincipal)
	if err != nil {
		return nil, fmt.Errorf("delegation_chain: parse top principal AIC: %w", err)
	}
	if aic == nil {
		return nil, fmt.Errorf("delegation_chain: top principal has no AIC")
	}
	return EffectiveDelegationCapabilities(chain, aic.Capabilities, maxChainLen)
}
