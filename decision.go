// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"github.com/varwof/register/semantics"
	"log/slog"
	"net/http"
	"time"

	pki "github.com/varwof/types"
)

// DecisionResult is the result of a connection admission decision.
type DecisionResult int

const (
	// DecisionAllow means admission is allowed.
	DecisionAllow DecisionResult = iota
	// DecisionDeny means admission is denied.
	DecisionDeny DecisionResult = iota
	// DecisionNeedAuth means additional authentication is required.
	DecisionNeedAuth
)

// AdmissionResult contains the complete admission check result.
type AdmissionResult struct {
	Decision               DecisionResult
	Reason                 string
	AIC                    *AIC
	PrincipalAuthorization *PrincipalAuthorization
	PrincipalUid           string
	// EffectiveCaps is the P∩C (AIC declarations ∩ PA grants) intersection result,
	// preserving full Capability (including SchemeId/Parameters). When no PA is present,
	// equals the full AIC declarations. Phase two plugin evaluation only acts on this set
	// — declarations outside the intersection (including unrelated schemes) do not participate
	// in decisions or block connections (P2-A-06/P2-A-07 operation-level mapping).
	EffectiveCaps []Capability
	// OperationDecisions records the per-operation CLC verdicts when
	// cfg.Operations was set.  Populated on the allow path (and kept on the
	// deny path for the operation that caused it) so upstream can surface
	// verdict / reason / unresolved to downstream.
	OperationDecisions []OperationDecision
}

// AdmissionConfig is the configuration for the admission engine.
type AdmissionConfig struct {
	// RequireAIC when set to true rejects connections without AIC extension.
	RequireAIC bool
	// RequiredProtocol requires the Agent to have the specified protocol capability (empty = no check).
	RequiredProtocol string
	// RequiredRuleId requires the Agent to have the specified CapabilityId permission (empty = no check).
	RequiredRuleId string
	// RequiredCapabilities requires the Agent to have all specified CapabilityIds (empty = no check).
	RequiredCapabilities []string
	// Operations are the concrete actions (capability id + parameters) this
	// request wants to perform.  When set, each is decided with the CLC core
	// against the effective authority — the AIC capabilities intersected with
	// the PrincipalAuthorization grants — so parameter bounds take part in the
	// decision instead of matching capability ids alone.
	// Operation decisions are recorded in AdmissionResult.OperationDecisions so
	// upstream can surface verdict / reason / unresolved to downstream.
	Operations []Operation
	// UnresolvedEvaluator is the §8.4 residual-obligation release hook.  When
	// an operation's CLC decision lands on allow_unresolved (recognized but
	// not-evaluated constraint, e.g. time:window), the default is fail-closed
	// deny.  This evaluator can confirm those obligations out-of-band: returning
	// true releases the operation — the call site must still honor the residual
	// obligations (semantics.Decision.Unresolved) at runtime.  nil (default)
	// keeps fail-closed deny.
	UnresolvedEvaluator func(op Operation, unresolved []string) bool
	// DisallowRepresentative when set to true rejects DelegationRepresentative mode connections.
	DisallowRepresentative bool
	// RequireUserPermission when set to true rejects connections without UserPermission extension.
	RequireUserPermission bool
	// RejectOverflow when set to true rejects AIC containing CapabilityIds not authorized by UserPermission.
	RejectOverflow bool
	// RequireUserAuth when set to true requires DelegationAuthorization signature verification in the AIC.
	RequireUserAuth bool
	// EnforceCapSizeConstraints when set to true validates Capability field lengths (schemeId 1-128, capabilityId 1-256, parameters 0-4096).
	EnforceCapSizeConstraints bool
	// NonceCache is used for DelegationAuthorization nonce replay protection.
	// nil means skip nonce replay check (not recommended).
	NonceCache *NonceCache
	// EnforceSize32 when set to true validates Nonce is exactly 32 bytes.
	EnforceSize32 bool
	// UserCert is the authorized user's certificate for verifying DelegationAuthorization signatures.
	// When nil, if UserCertResolver is not nil, resolves via KeyHash from varwof-core;
	// otherwise falls back to the connection peer certificate (only agent == user can verify).
	UserCert *x509.Certificate
	// UserCertResolver resolves user certificates based on PrincipalUid.KeyHash (via varwof-core API).
	// Automatically called when UserCert is nil and RequireUserAuth is true.
	UserCertResolver func(keyHash []byte) (*x509.Certificate, error)
	// EnforceConstraints when set to true enforces authorizationConstraints (CIDR/time window/concurrency).
	EnforceConstraints bool
	// StrictConstraints when set to true directly rejects connections with unregistered constraint types
	// in authorizationConstraints (unknown capabilityId under constraint/constraint-v1 scheme),
	// fail-closed. Default false only logs audit warnings for unknown constraints and ignores them
	// (forward compatible, specification P1-B-23 strict mode).
	StrictConstraints bool
	// ClientIP is used for authorizationConstraints allowed-cidr checks.
	ClientIP string
	// AuditLogger is used for authorization decision audit logging. When non-nil, logs warnings
	// for unknown constraint types, etc.
	AuditLogger *AuditLogger
	// CheckDAAge when set to true validates DelegationAuthorization.timestamp freshness
	// (|now - timestamp| ≤ DAAgeMax). Default off — specification delegates lifecycle validation
	// to X.509 NotAfter (dev-docs/aic/06-delegation-auth.md §validation flow (gateway runtime));
	// deployments requiring stricter time window defense (specification P1-B-13) can enable this.
	CheckDAAge bool
	// DAAgeMax is the DA timestamp freshness window (|now - timestamp| ≤ DAAgeMax).
	// Only effective when CheckDAAge=true; <=0 uses DefaultDAAgeMax (30 seconds).
	DAAgeMax time.Duration
	// CredentialBundle is the client-submitted credential bundle (P1-B-27/P1-B-29/P2-A-01).
	// When RequireUserAuth is true and UserCert is nil, prioritizes the Principal certificate
	// from the credential bundle for DA signature verification (including keyHash cross-validation);
	// falls back to UserCertResolver when missing.
	CredentialBundle *CredentialBundle
}

// DefaultDAAgeMax is the default value for the DelegationAuthorization.timestamp freshness window
// (specification P1-B-13 / dev-docs/aic/06-delegation-auth.md §validation flow ①: |now - timestamp| ≤ 30s).
const DefaultDAAgeMax = 30 * time.Second

// CheckDAFreshness validates that DelegationAuthorization.timestamp is within the freshness window.
// When now is nil, uses time.Now(); when maxAge <= 0, uses DefaultDAAgeMax.
// Zero-value timestamp (never set) is treated as expired.
func CheckDAFreshness(ts time.Time, now time.Time, maxAge time.Duration) error {
	if ts.IsZero() {
		return fmt.Errorf("delegation auth timestamp: missing")
	}
	if maxAge <= 0 {
		maxAge = DefaultDAAgeMax
	}
	age := now.Sub(ts)
	if age < 0 {
		age = -age
	}
	if age > maxAge {
		return fmt.Errorf("delegation auth timestamp %v: outside freshness window (|now-ts|=%s > %s)", ts.UTC(), age, maxAge)
	}
	return nil
}

// Validate checks the configuration for conflicting options.
func (c AdmissionConfig) Validate() error {
	if c.DisallowRepresentative && !c.RequireAIC {
		return fmt.Errorf("disallow_representative requires require_aic")
	}
	if c.RequireUserPermission && !c.RequireAIC {
		return fmt.Errorf("require_user_permission requires require_aic")
	}
	return nil
}

// ConstraintCIDRKey is the capabilityId for IP network range constraint.
const ConstraintCIDRKey = "network:cidr"

// ConstraintConcurrentKey is the capabilityId for max concurrent connections constraint.
const ConstraintConcurrentKey = "session:max-concurrent"

// ConstraintTimeWindowKey is the capabilityId for time window constraint.
const ConstraintTimeWindowKey = "time:window"

// ConstraintHardTimeoutKey is the capabilityId for session hard timeout constraint.
const ConstraintHardTimeoutKey = "session:hard-timeout"

// ConstraintIdleTimeoutKey is the capabilityId for session idle timeout constraint.
const ConstraintIdleTimeoutKey = "session:idle-timeout"

// ConstraintReadOnlyKey is the capabilityId for read-only operation constraint.
const ConstraintReadOnlyKey = "op:readonly"

// ConstraintAuditRequiredKey is the capabilityId for audit-required operation constraint.
const ConstraintAuditRequiredKey = "op:audit:required"

// ConstraintGeoFenceKey is the capabilityId for geo fence constraint.
const ConstraintGeoFenceKey = "geo-fence"

// CheckAuthorizationConstraints performs offline validation of authorizationConstraints.
// Supports: network:cidr (requires ClientIP), time:window, geo-fence (requires ClientIP),
// session:max-concurrent, session:hard-timeout, session:idle-timeout, op:readonly, op:audit:required.
// Unknown constraint types are ignored by default (forward compatible); the caller logs audit warnings;
// after registering a custom constraint executor (RegisterConstraint), it will be recognized and executed.
func CheckAuthorizationConstraints(constraints []Capability, clientIP string) error {
	return checkConstraintsAt(constraints, clientIP, time.Now().In(time.UTC))
}

// CheckAuthorizationConstraintsAt is the same as CheckAuthorizationConstraints, but evaluates
// time-window constraints at a specified UTC time (HH:MM), useful for testing and offline
// decision demonstrations. When timeHHMM is empty, uses the current time. The tz field
// in time-window is converted to the corresponding timezone during evaluation.
func CheckAuthorizationConstraintsAt(constraints []Capability, clientIP, timeHHMM string) error {
	now := time.Now().In(time.UTC)
	if timeHHMM != "" {
		h, m, ok := parseTimeParts(timeHHMM)
		if !ok {
			return fmt.Errorf("time-window: invalid --time %q (want HH:MM UTC)", timeHHMM)
		}
		now = time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, time.UTC)
	}
	return checkConstraintsAt(constraints, clientIP, now)
}

// checkConstraintsAt evaluates authorizationConstraints one by one through the constraint registry.
// Only processes constraint / constraint-v1 scheme entries; other schemes are skipped as business capabilities.
func checkConstraintsAt(constraints []Capability, clientIP string, now time.Time) error {
	ctx := &ConstraintContext{ClientIP: clientIP, Now: now}
	for _, c := range constraints {
		if !isConstraintScheme(c.SchemeId) {
			continue
		}
		ev, err := globalConstraintRegistry.Find(c.CapabilityId)
		if err != nil {
			// Unknown constraint type: ignored (forward compatible), caller logs audit warning.
			// Will be recognized and executed after registering the corresponding executor.
			continue
		}
		if err := ev.Evaluate(&c, ctx); err != nil {
			return err
		}
	}
	return nil
}

// isKnownConstraintType determines whether a capabilityId is a registered constraint type.
func isKnownConstraintType(capabilityId string) bool {
	_, err := globalConstraintRegistry.Find(capabilityId)
	return err == nil
}

// firstUnknownConstraint returns the first unregistered constraint entry from constraints
// (scheme ∈ {constraint, constraint-v1} with unregistered capabilityId). Returns nil if none found.
func firstUnknownConstraint(constraints []Capability) *Capability {
	for i := range constraints {
		c := &constraints[i]
		if !isConstraintScheme(c.SchemeId) {
			continue
		}
		if !isKnownConstraintType(c.CapabilityId) {
			return c
		}
	}
	return nil
}

// aicCapabilityMatches determines whether the request capability req is authorized by any
// capability declared in the AIC. Declarations (with full schemeId:capabilityId names) serve
// as patterns, req as the id; supports declaration-side wildcards (SELECT:* can authorize
// SELECT:/api/tables-type requests). Matching semantics are consistent with MatchCapability
// (supports * and a:b:* prefixes).
func aicCapabilityMatches(caps []Capability, req string) bool {
	for _, cap := range caps {
		if MatchCapability(req, cap.CapabilityId) {
			return true
		}
		if cap.SchemeId != "" && MatchCapability(req, cap.SchemeId+":"+cap.CapabilityId) {
			return true
		}
	}
	return false
}

// aicCapabilityMatchPriority determines whether the request capability req is authorized by
// AIC-declared capabilities, returning the highest match priority level (MatchPriorityNoMatch
// means not authorized). Compared to aicCapabilityMatches, provides five-level wildcard
// semantics (exact > single-segment > multi-segment > scheme > global).
func aicCapabilityMatchPriority(caps []Capability, req string) int {
	best := pki.MatchPriorityNoMatch
	for _, cap := range caps {
		if p := pki.MatchCapabilityPriority(req, cap.CapabilityId); p > best {
			best = p
		}
		if cap.SchemeId != "" {
			if p := pki.MatchCapabilityPriority(req, cap.SchemeId+":"+cap.CapabilityId); p > best {
				best = p
			}
		}
	}
	return best
}

// aicCapabilityDecision makes a decision on AIC-declared capabilities + explicit allow/deny
// rule sets: deny overrides allow. Rule priority follows MatchCapabilityRules.
// When denyRules is empty, degrades to pure allow semantics (any match outside all-must-pass
// is authorized).
func aicCapabilityDecision(caps []Capability, req string, denyRules []string) bool {
	if len(denyRules) > 0 {
		var rules []pki.CapabilityRule
		for _, d := range denyRules {
			rules = append(rules, pki.CapabilityRule{Pattern: d, Deny: true})
		}
		for _, cap := range caps {
			rules = append(rules, pki.CapabilityRule{Pattern: cap.CapabilityId})
			if cap.SchemeId != "" {
				rules = append(rules, pki.CapabilityRule{Pattern: cap.SchemeId + ":" + cap.CapabilityId})
			}
		}
		m := pki.MatchCapabilityRules(req, rules)
		if !m.Matched {
			return false
		}
		return !m.Deny
	}
	return aicCapabilityMatches(caps, req)
}

// parseTimeParts parses an HH:MM format string into hour, minute, ok.
func parseTimeParts(s string) (int, int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// CheckAdmission performs the complete connection admission check:

//  2. Parse GatewaySession extension
//  3. Verify AgentType is in the allowed list
//  4. Check protocol capability match
//  5. Check RuleId permission
//  6. Check required capability subset
//  7. Check delegation mode
//  8. Parse UserPermission extension
//  9. Check merge with UserPermission
//
// Returns AdmissionResult; caller decides whether to allow based on the Decision field.
func CheckAdmission(cert *x509.Certificate, cfg AdmissionConfig) AdmissionResult {
	if cert == nil {
		return AdmissionResult{Decision: DecisionDeny, Reason: "nil certificate"}
	}

	result := AdmissionResult{Decision: DecisionAllow}

	// Parse AIC
	aic, err := ParseAIC(cert)
	if err != nil {
		return AdmissionResult{Decision: DecisionDeny, Reason: fmt.Sprintf("aic parse: %v", err)}
	}
	if aic == nil {
		if cfg.RequireAIC {
			return AdmissionResult{Decision: DecisionDeny, Reason: "aic extension required"}
		}
		result.PrincipalUid = ouFallbackPrincipal(cert)
	} else {
		result.AIC = aic
		result.PrincipalUid = aic.PrincipalUid.String()
	}

	// GAP-08/09/10/11/12: AIC field constraint unified validation
	if aic != nil {
		if err := ValidateAIC(aic); err != nil {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("aic validation: %v", err),
			}
		}
	}

	// v1.4: Capability size constraints
	if aic != nil && cfg.EnforceCapSizeConstraints {
		if err := validateCapSizeConstraints(aic.Capabilities); err != nil {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("capability size constraint: %v", err),
			}
		}
	}

	// v1.5: SIZE(32) enforcement (Nonce in DelegationAuthorization)
	if aic != nil && cfg.EnforceSize32 {
		da := aic.DelegationAuthorization
		if len(da.Nonce) != 32 {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("delegation auth nonce length %d: must be exactly 32 bytes", len(da.Nonce)),
			}
		}
	}

	// Parse PrincipalAuthorization (must be done before constraint checks, for parameter boundary validation).
	// Independent of AIC: human certificates without AIC can also carry PA directly (direct authorization scenario),
	// performing grants authorization determination and RequiredCapabilities checks.
	pa, parseErr := ParseUserPermissionExtension(cert)
	if parseErr != nil {
		return AdmissionResult{Decision: DecisionDeny, Reason: fmt.Sprintf("principal_authorization parse: %v", parseErr)}
	}
	result.PrincipalAuthorization = pa
	// Runtime principal PA refresh (patent: P_grants uses the latest
	// principal certificate). When a current principal certificate is
	// available (UserCert or credential bundle) and its keyHash matches
	// the AIC's principalUid, its PrincipalAuthorization becomes the
	// authoritative P_grants -- permission downgrades take effect
	// without reissuing the agent's AIC.
	if pc := currentPrincipalCert(cfg); pc != nil {
		if pa2, err := ParseUserPermissionExtension(pc); err == nil && pa2 != nil {
			if err := VerifyPrincipalKeyHash(cert, pc); err == nil {
				result.PrincipalAuthorization = pa2
			}
		}
	}
	if pa == nil && cfg.RequireUserPermission {
		return AdmissionResult{Decision: DecisionDeny, Reason: "principal_authorization extension required"}
	}

	// PA-level constraint checks (independent of AIC constraints; PA and AIC are checked separately at different layers)
	// Direct authorization (no AIC): PA constraints are the only constraints; in delegation, PA and AIC constraints are checked independently
	if cfg.EnforceConstraints && result.PrincipalAuthorization != nil && len(result.PrincipalAuthorization.AuthorizationConstraints) > 0 {
		if err := CheckAuthorizationConstraints(result.PrincipalAuthorization.AuthorizationConstraints, cfg.ClientIP); err != nil {
			return AdmissionResult{Decision: DecisionDeny, Reason: fmt.Sprintf("pa constraint: %v", err)}
		}
		// Strict mode: unknown PA constraint type fail-closed (specification P1-B-23).
		if cfg.StrictConstraints {
			if u := firstUnknownConstraint(result.PrincipalAuthorization.AuthorizationConstraints); u != nil {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   fmt.Sprintf("pa constraint: unknown constraint type %q (strict mode)", u.CapabilityId),
				}
			}
		}
	}

	// v1.6: authorizationConstraints execute first (low-cost fast rejection)
	if aic != nil && cfg.EnforceConstraints && len(aic.AuthorizationConstraints) > 0 {
		// Strict mode priority: unknown constraint type fail-closed (specification P1-B-23).
		if cfg.StrictConstraints {
			if u := firstUnknownConstraint(aic.AuthorizationConstraints); u != nil {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   fmt.Sprintf("aic constraint: unknown constraint type %q (strict mode)", u.CapabilityId),
				}
			}
		}
		if err := CheckAuthorizationConstraints(aic.AuthorizationConstraints, cfg.ClientIP); err != nil {
			return AdmissionResult{Decision: DecisionDeny, Reason: err.Error()}
		}
		// Log unknown constraint type audit warning (forward compatible: does not block business)
		if cfg.AuditLogger != nil {
			for _, c := range aic.AuthorizationConstraints {
				if !isKnownConstraintType(c.CapabilityId) {
					cfg.AuditLogger.Log(AuditEntry{
						Action:   string(ActionUnknownConstraint),
						TargetID: c.CapabilityId,
						Level:    "WARN",
					})
				}
			}
		}
	}

	// Check protocol capability
	if aic != nil && cfg.RequiredProtocol != "" {
		if !aic.HasProtocol(cfg.RequiredProtocol) {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("protocol %s not in capabilities", cfg.RequiredProtocol),
			}
		}
	}

	// Check CapabilityId permission
	if aic != nil && cfg.RequiredRuleId != "" {
		if !aic.CheckPermission(cfg.RequiredRuleId) {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("rule %s not in capabilities", cfg.RequiredRuleId),
			}
		}
	}

	// Check required capability subset (glob matching: a single declaration can match multiple request types,
	// supports * and a:b:* prefixes).
	// Capability source: uses AIC declarations when available; uses PA grants for human certificates without AIC (direct authorization semantics).
	if len(cfg.RequiredCapabilities) > 0 {
		var effective []Capability
		if aic != nil {
			effective = aic.Capabilities
		} else if result.PrincipalAuthorization != nil {
			effective = result.PrincipalAuthorization.Grants
		}
		var missing []string
		for _, req := range cfg.RequiredCapabilities {
			if !aicCapabilityMatches(effective, req) {
				missing = append(missing, req)
			}
		}
		if len(missing) > 0 {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("missing capabilities: %v", missing),
			}
		}
	}

	// Concrete-operation authorization (CLC).  The id-only check above cannot
	// see parameters, so a grant of {"tables":["a"]} and a request for
	// {"tables":["a","b"]} look identical to it.  Each declared operation is
	// decided by the CLC core instead, over the effective authority.
	for _, op := range cfg.Operations {
		dec, err := AuthorizeOperation(aic, result.PrincipalAuthorization, op.ID, op.Params)
		if err != nil {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("operation %s: %v", op.ID, err),
			}
		}
		od := OperationDecision{
			ID:         op.ID,
			Params:     op.Params,
			Verdict:    dec.Verdict,
			Reason:     dec.Reason,
			Unresolved: dec.Unresolved,
		}
		result.OperationDecisions = append(result.OperationDecisions, od)
		switch dec.Verdict {
		case semantics.VerdictAllow:
			// authorized outright
		case semantics.VerdictDeny:
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("operation %s denied: %s", op.ID, dec.Reason),
			}
		default:
			// allow_unresolved is an independent verdict carrying §8.4 residual
			// obligations; reading it as "allow" would fail open.
			if cfg.UnresolvedEvaluator != nil && cfg.UnresolvedEvaluator(op, dec.Unresolved) {
				// The deployment confirmed the residual obligations; the operation
				// is released but must still be honored at runtime. Only opt-in
				// paths reach here — nil (default) keeps fail-closed deny.
				result.OperationDecisions[len(result.OperationDecisions)-1].Released = true
				continue
			}
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("operation %s: %s (unresolved %v)", op.ID, dec.Verdict, dec.Unresolved),
			}
		}
	}

	// Check delegation mode (v1.4: check if AIC.DelegationMode is representative)
	// If DisallowRepresentative=true and AIC uses representative mode, reject.
	if aic != nil && cfg.DisallowRepresentative && aic.DelegationMode == DelegationRepresentative {
		return AdmissionResult{
			Decision: DecisionDeny,
			Reason:   "representative delegation mode not allowed by gateway policy",
		}
	}
	// If AIC uses representative mode, verify PrincipalAuthorization is allowed.
	if aic != nil && aic.DelegationMode == DelegationRepresentative {
		if result.PrincipalAuthorization == nil {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   "representative mode requires principal_authorization extension",
			}
		}
		allowedMode := result.PrincipalAuthorization.DelegationPolicy.AllowedMode
		if allowedMode != 1 {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   "user_permission does not allow representative delegation",
			}
		}
	}

	// Verify DelegationAuthorization signature
	if aic != nil && cfg.RequireUserAuth {
		if len(aic.DelegationAuthorization.SignatureValue) == 0 {
			return AdmissionResult{Decision: DecisionDeny, Reason: "user_auth: signature required but empty"}
		}
		userCert := cfg.UserCert
		// P1-B-27/P1-B-29: credential bundle takes priority — principal certificate is submitted
		// together with the credential bundle; dual-chain verification includes keyHash cross-validation.
		// Falls back to UserCertResolver (fetches by keyHash from local store) when missing.
		if userCert == nil && cfg.CredentialBundle != nil {
			userCert = cfg.CredentialBundle.Principal()
			if userCert != nil {
				if err := VerifyPrincipalKeyHash(cert, userCert); err != nil {
					return AdmissionResult{
						Decision: DecisionDeny,
						Reason:   fmt.Sprintf("user_auth: credential bundle: %v", err),
					}
				}
			}
		}
		if userCert == nil && cfg.UserCertResolver != nil && len(aic.PrincipalUid.KeyHash) > 0 {
			var err error
			userCert, err = cfg.UserCertResolver(aic.PrincipalUid.KeyHash)
			if err != nil {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   fmt.Sprintf("user_auth: resolve user cert: %v", err),
				}
			}
		}
		if userCert == nil {
			// G5: Missing authorization certificate must explicitly fail-close (strict control semantics),
			// no silent degradation allowed. Only when the connection peer certificate is itself the
			// authorized principal (agent==user self-authorization scenario, cert SPKI == AIC.KeyHash)
			// is the peer certificate allowed to verify the DA signature;
			// otherwise, reject directly — no path for "missing authorization cert = degraded pass".
			if len(aic.PrincipalUid.KeyHash) > 0 {
				if ha := aic.PrincipalUid.HashAlgoOID(); len(ha) > 0 && !ha.Equal(OIDSHA256) {
					return AdmissionResult{
						Decision: DecisionDeny,
						Reason:   "user_auth: unsupported keyHash algorithm",
					}
				}
				spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if !bytes.Equal(spkiHash[:], aic.PrincipalUid.KeyHash) {
					return AdmissionResult{
						Decision: DecisionDeny,
						Reason:   "user_auth: authorization certificate required but not provided",
					}
				}
				userCert = cert
			} else {
				// Finding 16: without a KeyHash there is no way to establish that the
				// peer certificate is the authorized principal, so a self-authorization
				// fallback would let an agent fill its own RequireUserAuth. Fail closed.
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   "user_auth: no authorization certificate and no keyHash to bind the peer certificate",
				}
			}
		}
		if err := VerifyDelegationAuth(aic, userCert); err != nil {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   fmt.Sprintf("user_auth: %v", err),
			}
		}
		// Optional time window defense (P1-B-13): validate DA.timestamp freshness. Default off,
		// lifecycle validation is handled by X.509 NotAfter; when enabled, additionally requires
		// |now - timestamp| ≤ DAAgeMax (the "short time window second defense" in the specification).
		if cfg.CheckDAAge {
			if err := CheckDAFreshness(aic.DelegationAuthorization.Timestamp, time.Now(), cfg.DAAgeMax); err != nil {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   fmt.Sprintf("user_auth: %v", err),
				}
			}
		}
	}

	// v1.4: DelegationAuthorization nonce replay protection
	// Scoped by certificate identity (issuer/serial): same certificate presenting the same nonce
	// again passes normally; different certificate reusing the same nonce is judged as a DA replay
	// attack (prevents "copying DA evidence to issue a new AIC").
	if aic != nil && len(aic.DelegationAuthorization.Nonce) > 0 && cfg.NonceCache != nil {
		scope := cert.Issuer.String() + "/" + cert.SerialNumber.String()
		if !cfg.NonceCache.CheckAndAdd(scope, aic.DelegationAuthorization.Nonce) {
			return AdmissionResult{
				Decision: DecisionDeny,
				Reason:   "delegation auth nonce replay detected",
			}
		}
	}

	// v1.5: AIC and PrincipalAuthorization capability intersection (P1-B-07/P2-A-04/P1-17):
	//   - Representative mode (DelegationMode=1): P_effective = P_grants ∩ C_agent,
	//     validates capabilities ⊆ principal permissions, performs intersection + overflow rejection;
	//   - Authorized mode (DelegationMode=0/default): uses AIC.capabilities directly as the permission basis,
	//     no P_grants runtime upper-bound validation (EffectiveCaps = full AIC declarations).
	// EffectiveCaps preserves full Capability (SchemeId/Parameters), used for phase two plugin routing.
	isRepresentative := aic != nil && aic.DelegationMode == DelegationRepresentative
	if isRepresentative && result.PrincipalAuthorization != nil {
		if len(aic.Capabilities) > 0 && len(result.PrincipalAuthorization.GrantIds()) > 0 {
			intersection := aic.IntersectPermissions(result.PrincipalAuthorization)
			if len(intersection) == 0 {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   "aic and principal_authorization capabilities have no intersection",
				}
			}
			// v1.5: capability_overflow — reject AIC with excess capabilities
			if cfg.RejectOverflow && len(intersection) < len(aic.Capabilities) {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   "aic has capabilities not authorized by principal_authorization",
				}
			}
			result.EffectiveCaps = effectiveCapabilities(aic.Capabilities, result.PrincipalAuthorization.GrantIds())
		} else {
			// Representative declared capabilities but PA has no authorization → empty intersection (fail-closed)
			if len(aic.Capabilities) > 0 {
				return AdmissionResult{
					Decision: DecisionDeny,
					Reason:   "aic and principal_authorization capabilities have no intersection",
				}
			}
			result.EffectiveCaps = nil
		}
	} else if aic != nil {
		// Authorized mode (or no PA): effective caps = full AIC declarations (P2-A-04, no upper-bound check).
		result.EffectiveCaps = append([]Capability(nil), aic.Capabilities...)
	} else if result.PrincipalAuthorization != nil {
		// Direct authorization (no AIC human cert): effective caps = full PA grants.
		// PA is the authority source; no P∩C intersection needed; stage-2 plugin evaluation aligns by scheme.
		result.EffectiveCaps = append([]Capability(nil), result.PrincipalAuthorization.Grants...)
	}

	return result
}

// effectiveCapabilities computes the full capability intersection (P∩C) between AIC
// declared capabilities and PA grants. Unlike IntersectPermissions which returns only
// CapabilityId strings, this preserves the full structure (SchemeId/Parameters) for each
// matched declaration, used by stage-2 plugin evaluation to align by scheme (P2-A-06: unrelated schemes ignored).
func effectiveCapabilities(declared []Capability, grants []string) []Capability {
	var out []Capability
	for _, c := range declared {
		for _, g := range grants {
			if aicCapabilityMatches([]Capability{c}, g) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// VerifyDelegationAuth verifies the validity of a DelegationAuthorization signature.
// aic must contain a non-empty DelegationAuthorization; userCert is the authorizing user's certificate.
// The signed content is the DelegationAuthTBS DER encoding (a specific subset, not the entire AIC).
func VerifyDelegationAuth(aic *AIC, userCert *x509.Certificate) error {
	if aic == nil {
		return fmt.Errorf("verify_user_auth: nil aic")
	}
	if userCert == nil {
		return fmt.Errorf("verify_user_auth: nil user cert")
	}
	ua := aic.DelegationAuthorization
	if len(ua.SignatureValue) == 0 {
		return fmt.Errorf("verify_user_auth: empty signature")
	}

	// Construct DelegationAuthTBS for signature verification (spec §6 DelegationAuthTBS)
	tbs := DelegationAuthTBS{
		Version:                  aic.Version,
		AgentId:                  aic.AgentId,
		PrincipalUid:             aic.PrincipalUid,
		Reason:                   ua.Reason,
		Capabilities:             aic.Capabilities,
		DelegationMode:           aic.DelegationMode,
		AuthorizationConstraints: aic.AuthorizationConstraints,
		RequestedLifetime:        ua.RequestedLifetime,
		Timestamp:                ua.Timestamp,
		Nonce:                    ua.Nonce,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return fmt.Errorf("verify_user_auth: marshal tbs: %w", err)
	}
	digest := sha256.Sum256(tbsDER)

	switch pub := userCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ua.SignatureAlgorithm.Algorithm.Equal(OIDSigECDSAWithSHA256) {
			return fmt.Errorf("verify_user_auth: unsupported ECDSA algorithm OID %s", ua.SignatureAlgorithm.Algorithm)
		}
		if !ecdsa.VerifyASN1(pub, digest[:], ua.SignatureValue) {
			return fmt.Errorf("verify_user_auth: ecdsa signature verification failed")
		}
	case *rsa.PublicKey:
		switch {
		case ua.SignatureAlgorithm.Algorithm.Equal(OIDSigRSAWithSHA256):
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], ua.SignatureValue); err != nil {
				return fmt.Errorf("verify_user_auth: rsa-sha256 verification: %w", err)
			}
		case ua.SignatureAlgorithm.Algorithm.Equal(OIDSigRSAPSSWithSHA256):
			if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], ua.SignatureValue, nil); err != nil {
				return fmt.Errorf("verify_user_auth: rsa-pss-sha256 verification: %w", err)
			}
		default:
			return fmt.Errorf("verify_user_auth: unsupported RSA algorithm OID %s", ua.SignatureAlgorithm.Algorithm)
		}
	default:
		return fmt.Errorf("verify_user_auth: unsupported key type %T", userCert.PublicKey)
	}

	// Cross-validation: the provided user cert's SPKI hash must match the KeyHash in AIC PrincipalUid
	// (hash algorithm determined by PrincipalUid.hashAlgo; v1.7.1 only supports SHA-256)
	if len(aic.PrincipalUid.KeyHash) > 0 {
		if ha := aic.PrincipalUid.HashAlgoOID(); len(ha) > 0 && !ha.Equal(OIDSHA256) {
			return fmt.Errorf("verify_user_auth: unsupported keyHash algorithm %s", ha)
		}
		spkiHash := sha256.Sum256(userCert.RawSubjectPublicKeyInfo)
		if !bytes.Equal(spkiHash[:], aic.PrincipalUid.KeyHash) {
			return fmt.Errorf("verify_user_auth: user cert SPKI hash mismatch")
		}
	}

	return nil
}

// DelegationChainVerifier verifies multi-level delegation chains (Zhang→Scheduler-A→Worker-B→…).
//
// Multi-level delegation reuses the same DelegationAuthorization structure (spec dev-docs/aic/06-delegation-auth.md
// §Multi-level delegation chain, FUTURE reserved): each Agent's AIC contains a DelegationAuthorization
// signed by the previous level (delegator) certificate's private key. Verification proceeds bottom-up:
//
//	chain[i].AIC.DA signed by chain[i-1].cert → chain[i-1].AIC.DA signed by chain[i-2].cert
//	→ … → chain[0].AIC.DA signed by topPrincipal certificate
//
// chainDepth is the number of delegation certificates in the chain (excluding the top Principal);
// maxDepth is set by the top Principal; exceeding it results in rejection. No new ASN.1 types needed;
// the entire chain is verifiable offline.
type DelegationChainVerifier struct {
	// MaxDepth is the maximum delegation depth allowed by the top Principal (including intermediate Agent B etc.).
	MaxDepth int
	// MaxChainLength is the hard upper limit to prevent certificate bomb attacks (P1-B-15):
	// ≤0 means no extra limit (only constrained by MaxDepth).
	MaxChainLength int
}

// Verify verifies the delegation chain bottom-up starting from workerCert.
// chain is the certificate list from top to bottom: chain[0]=Scheduler-A (top-level delegating Agent),
// chain[len-1]=Worker-B (bottom-level Agent). Each level's AIC.DA is signed by the previous level's certificate.
//
// Verification steps:
//  1. Each certificate must contain an AIC with non-empty DA;
//  2. Each level's AIC.DA signer = previous certificate (SPKI hash cross-validation);
//  3. Top-level chain[0].AIC.DA signer = topPrincipal certificate;
//  4. Chain depth (len(chain)) must ≤ MaxDepth;
//  5. Entire chain verified offline, no external service dependency.
func (v *DelegationChainVerifier) Verify(chain []*x509.Certificate, topPrincipal *x509.Certificate) error {
	if v == nil {
		return fmt.Errorf("delegation_chain: nil verifier")
	}
	if len(chain) == 0 {
		return fmt.Errorf("delegation_chain: empty chain")
	}
	if topPrincipal == nil {
		return fmt.Errorf("delegation_chain: nil top principal")
	}
	if len(chain) > v.MaxDepth {
		return fmt.Errorf("delegation_chain: chain depth %d exceeds maxDepth %d", len(chain), v.MaxDepth)
	}
	// Anti-loop + anti-certificate-bomb (P1-B-14/15).
	if err := verifyChainStructure(chain, v.MaxChainLength); err != nil {
		return err
	}

	// Bottom-up signature verification: chain[i].AIC.DA signed by chain[i-1] or topPrincipal
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		aic, err := ParseAIC(cert)
		if err != nil {
			return fmt.Errorf("delegation_chain level %d: parse AIC: %w", i, err)
		}
		if aic == nil {
			return fmt.Errorf("delegation_chain level %d: no AIC extension", i)
		}
		if !aic.DelegationAuthorization.IsPresent() {
			return fmt.Errorf("delegation_chain level %d: empty delegation authorization", i)
		}

		// Determine the signer certificate for this level's DA
		var signer *x509.Certificate
		if i == 0 {
			signer = topPrincipal
		} else {
			signer = chain[i-1]
		}

		// This level's AIC.DA signer should be signer (SPKI hash cross-validation + signature verification)
		if err := VerifyDelegationAuth(aic, signer); err != nil {
			return fmt.Errorf("delegation_chain level %d (%s): %w", i, cert.Subject.CommonName, err)
		}
	}

	return nil
}

// VerifyDelegationChain is a convenience entry point: creates a default verifier and verifies the chain.
// chain goes from top to bottom: chain[0]=top-level delegating Agent, chain[len-1]=bottom-level Agent.
// maxDepth is set by the top Principal.
func VerifyDelegationChain(chain []*x509.Certificate, topPrincipal *x509.Certificate, maxDepth int) error {
	v := &DelegationChainVerifier{MaxDepth: maxDepth}
	return v.Verify(chain, topPrincipal)
}

// NeedRevoke checks whether a certificate needs proactive revocation.
func NeedRevoke(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	now := time.Now()
	return now.Before(cert.NotAfter)
}

// ouFallbackPrincipal extracts the principal identifier from the certificate OU (fallback when no AIC).
func ouFallbackPrincipal(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	return ""
}

// hasDelegatedAgentOU checks whether the certificate contains a Delegated-Agent OU.
func hasDelegatedAgentOU(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "Delegated-Agent" {
			return true
		}
	}
	return false
}

// HasDelegatedAgentOU is the exported wrapper of hasDelegatedAgentOU, for gateways to check delegation identity before forwarding.
func HasDelegatedAgentOU(cert *x509.Certificate) bool {
	return hasDelegatedAgentOU(cert)
}

// CheckDelegatedAgentCert validates the legitimacy of a Delegated-Agent certificate (for non-HTTP protocols like TCP).
// Returns empty string on success, non-empty rejection reason on failure.
//
// A certificate that merely carries the "Delegated-Agent" OU is not legitimate
// on its own (finding 17): the OU is a plaintext subject attribute anyone can
// mint, so a Delegated-Agent cert must additionally be core-signed (carry a
// valid AIC extension) and be within its validity window. Certificates without
// the OU are not delegated-agent certs and pass through.
func CheckDelegatedAgentCert(cert *x509.Certificate) string {
	if cert == nil {
		return "nil certificate"
	}
	if !hasDelegatedAgentOU(cert) {
		return ""
	}
	if now := time.Now(); now.Before(cert.NotBefore) {
		return "Delegated-Agent certificate not yet valid"
	}
	if now := time.Now(); now.After(cert.NotAfter) {
		return "Delegated-Agent certificate expired"
	}
	aic, err := ParseAIC(cert)
	if err != nil || aic == nil {
		return "Delegated-Agent certificate lacks a valid core-signed AIC"
	}
	return ""
}

// Deprecated: CheckDelegatedAgentHeaders validates the X-Agent-User/X-Agent-TTL headers
// of a Delegated-Agent certificate (B1 username delegation path). The username cannot be
// cryptographically bound to the certificate; identity propagation has been changed to B2
// (X-Client-Cert-DER certificate passthrough). This function is kept for legacy client
// compatibility only. Certificates without Delegated-Agent OU pass through directly.
// Returns empty string on success, non-empty rejection reason on failure.
//
// Security note (G4): The client's X-Agent-User / X-Agent-TTL headers are entirely
// controlled by the requestor and must never be trusted as the true identity of the
// proxied user. This function only performs "declarative" validation (prompting ops to
// configure the delegation channel). The real delegation identity is derived by
// DelegatedAgentServerIdentity from the core-signed AIC/GatewaySession, and the gateway
// overwrites X-Agent-User / X-Agent-TTL headers before forwarding.
func CheckDelegatedAgentHeaders(cert *x509.Certificate, r *http.Request) string {
	if !hasDelegatedAgentOU(cert) {
		return ""
	}
	if user := r.Header.Get("X-Agent-User"); user == "" {
		return "X-Agent-User header required for Delegated-Agent"
	}
	ttlStr := r.Header.Get("X-Agent-TTL")
	if ttlStr == "" {
		return "X-Agent-TTL header required for Delegated-Agent"
	}
	ttl, err := time.Parse(time.RFC3339, ttlStr)
	if err != nil {
		return fmt.Sprintf("invalid X-Agent-TTL: %s", err.Error())
	}
	if time.Now().After(ttl) {
		return "X-Agent-TTL expired"
	}
	return ""
}

// DelegatedAgentServerIdentity derives the server-asserted delegation identity from the
// core-signed certificate extension (AIC), preventing G4 identity spoofing:
// never trust client-supplied plaintext headers.
// Returns:
//   - user: the server-asserted proxied subject (from AIC.PrincipalUid or cert CN/OU fallback)
//   - expiry: delegation validity deadline (zero time.Time{} when no hard-timeout constraint)
//   - reason: non-empty rejection reason (illegal conditions other than missing Delegated-Agent OU)
func DelegatedAgentServerIdentity(cert *x509.Certificate, principal string) (user string, expiry time.Time, reason string) {
	if !hasDelegatedAgentOU(cert) {
		return "", time.Time{}, ""
	}
	// Finding 17: the delegation cannot outlive its certificate — bind the
	// validity deadline to the cert's NotAfter instead of returning zero.
	expiry = cert.NotAfter
	if principal != "" {
		user = principal
	} else {
		user = ouFallbackPrincipal(cert)
	}
	return user, expiry, ""
}

// LogAdmission records the admission decision log.
func LogAdmission(result AdmissionResult, clientIP string, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	level := slog.LevelInfo
	msg := "admission: allow"
	if result.Decision != DecisionAllow {
		level = slog.LevelWarn
		msg = "admission: deny"
	}

	logger.LogAttrs(nil, level, msg,
		slog.String("client_ip", clientIP),
		slog.String("principal", result.PrincipalUid),
		slog.String("reason", result.Reason),
	)
}

// validateCapSizeConstraints validates Capability field length constraints (I-D §6 Capability SEQUENCE).
// schemeId: 1..128, capabilityId: 1..256, parameters: 0..4096
func validateCapSizeConstraints(caps []Capability) error {
	for i, cap := range caps {
		if len(cap.SchemeId) < 1 || len(cap.SchemeId) > 128 {
			return fmt.Errorf("capability[%d] schemeId length %d: must be 1-128", i, len(cap.SchemeId))
		}
		if len(cap.CapabilityId) < 1 || len(cap.CapabilityId) > 256 {
			return fmt.Errorf("capability[%d] capabilityId length %d: must be 1-256", i, len(cap.CapabilityId))
		}
		if len(cap.Parameters) > 4096 {
			return fmt.Errorf("capability[%d] parameters length %d: must be 0-4096", i, len(cap.Parameters))
		}
	}
	return nil
}

// currentPrincipalCert returns the most current principal certificate
// available for PA refresh: an explicitly provided UserCert first, then
// the credential bundle's principal certificate.
func currentPrincipalCert(cfg AdmissionConfig) *x509.Certificate {
	if cfg.UserCert != nil {
		return cfg.UserCert
	}
	if cfg.CredentialBundle != nil {
		return cfg.CredentialBundle.Principal()
	}
	return nil
}

// isConstraintScheme reports whether a capability belongs to the
// constraint namespace. The canonical scheme is varwof/constraint-v1
// (03-validation C2); legacy values constraint / constraint-v1 are
// accepted for backward compatibility.
func isConstraintScheme(scheme string) bool {
	return scheme == "varwof/constraint-v1" || scheme == "constraint" || scheme == "constraint-v1"
}
