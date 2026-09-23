// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ConstraintContext is the runtime context provided during constraint evaluation.
type ConstraintContext struct {
	// ClientIP is used for source-address-based constraints such as allowed-cidr / geo-fence.
	ClientIP string
	// Now is the evaluation time; defaults to current UTC time. Can be injected for testing and offline decisions.
	Now time.Time
}

// ConstraintEvaluator evaluates a single constraint from authorizationConstraints.
// Returns a non-nil error if the constraint is not satisfied; the gateway denies the connection.
type ConstraintEvaluator interface {
	// CapabilityId returns the constraint type identifier handled by this evaluator.
	CapabilityId() string
	// Evaluate evaluates a single constraint. The cap's SchemeId has already been filtered
	// to constraint / constraint-v1 by the caller.
	Evaluate(cap *Capability, ctx *ConstraintContext) error
}

// ConstraintRegistry registers/looks up constraint evaluators by capabilityId.
// It provides an extensible constraint type registration mechanism: when adding
// a new constraint type, only the corresponding evaluator needs to be registered
// without modifying the certificate ASN.1 structure or gateway core routing code.
type ConstraintRegistry struct {
	mu         sync.RWMutex
	evaluators map[string]ConstraintEvaluator
}

// NewConstraintRegistry creates an empty registry.
func NewConstraintRegistry() *ConstraintRegistry {
	return &ConstraintRegistry{evaluators: make(map[string]ConstraintEvaluator)}
}

// Register registers a constraint evaluator. Returns an error if the same
// capabilityId is registered twice.
func (r *ConstraintRegistry) Register(ev ConstraintEvaluator) error {
	if ev == nil {
		return fmt.Errorf("constraint: nil evaluator")
	}
	id := ev.CapabilityId()
	if id == "" {
		return fmt.Errorf("constraint: empty capabilityId")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.evaluators[id]; exists {
		return fmt.Errorf("constraint: %q already registered", id)
	}
	r.evaluators[id] = ev
	return nil
}

// Replace atomically replaces a registered evaluator (for hot updates).
// Registers the evaluator if not already registered.
func (r *ConstraintRegistry) Replace(ev ConstraintEvaluator) error {
	if ev == nil {
		return fmt.Errorf("constraint: nil evaluator")
	}
	id := ev.CapabilityId()
	if id == "" {
		return fmt.Errorf("constraint: empty capabilityId")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evaluators[id] = ev
	return nil
}

// Find looks up an evaluator by capabilityId.
func (r *ConstraintRegistry) Find(capabilityId string) (ConstraintEvaluator, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ev, ok := r.evaluators[capabilityId]
	if !ok {
		return nil, fmt.Errorf("constraint: no evaluator for %q", capabilityId)
	}
	return ev, nil
}

// Remove removes an evaluator. After removal, unknown types revert to the
// "unknown constraint" semantics (ignored by default).
func (r *ConstraintRegistry) Remove(capabilityId string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.evaluators, capabilityId)
}

// Reset clears the registry (for testing only).
func (r *ConstraintRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evaluators = make(map[string]ConstraintEvaluator)
}

// Len returns the number of registered constraint evaluators.
func (r *ConstraintRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.evaluators)
}

// Keys returns the list of registered capabilityIds (for metrics/audit).
func (r *ConstraintRegistry) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.evaluators))
	for k := range r.evaluators {
		keys = append(keys, k)
	}
	return keys
}

// globalConstraintRegistry is the default constraint registry with four built-in
// constraint types. Custom types can be added via Replace/Register.
var globalConstraintRegistry = NewConstraintRegistry()

func init() {
	for _, ev := range []ConstraintEvaluator{
		cidrEvaluator{},
		timeWindowEvaluator{},
		maxConcurrentEvaluator{},
		hardTimeoutEvaluator{},
		idleTimeoutEvaluator{},
		readOnlyEvaluator{},
		auditRequiredEvaluator{},
		geoFenceEvaluator{},
	} {
		_ = globalConstraintRegistry.Register(ev)
	}
}

// RegisterConstraint registers a constraint evaluator in the global registry (extension point).
func RegisterConstraint(ev ConstraintEvaluator) error {
	return globalConstraintRegistry.Register(ev)
}

// ReplaceConstraint replaces an evaluator in the global registry (hot update extension point).
func ReplaceConstraint(ev ConstraintEvaluator) error {
	return globalConstraintRegistry.Replace(ev)
}

// ResetConstraints clears the global registry and re-registers built-in types (for testing only).
func ResetConstraints() {
	globalConstraintRegistry.Reset()
	for _, ev := range []ConstraintEvaluator{
		cidrEvaluator{},
		timeWindowEvaluator{},
		maxConcurrentEvaluator{},
		hardTimeoutEvaluator{},
		idleTimeoutEvaluator{},
		readOnlyEvaluator{},
		auditRequiredEvaluator{},
		geoFenceEvaluator{},
	} {
		_ = globalConstraintRegistry.Register(ev)
	}
}

// cidrEvaluator implements the allowed-cidr constraint: client IP must fall
// within the allowed CIDR ranges.
// parameters supports two JSON forms:
//
//	Bare array: ["10.0.0.0/8", "172.16.0.0/12"]
//	Object:     {"cidrs": ["10.0.0.0/8", "172.16.0.0/12"]}
//
// The constraint is skipped when clientIP is empty (unable to evaluate source address).
type cidrEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (cidrEvaluator) CapabilityId() string { return ConstraintCIDRKey }

// Evaluate checks whether the client IP falls within the allowed CIDR ranges.
func (cidrEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	if ctx == nil {
		return fmt.Errorf("constraint allowed-cidr: nil context")
	}
	cidrs, err := parseCIDRParam(cap.Parameters)
	if err != nil {
		return fmt.Errorf("constraint allowed-cidr: invalid JSON: %w", err)
	}
	if len(cidrs) == 0 {
		return nil
	}
	// Finding 18: a configured CIDR restriction with no client IP must fail
	// closed — otherwise a gateway not populating ClientIP silently bypasses
	// source-address restrictions.
	if ctx.ClientIP == "" {
		return fmt.Errorf("constraint allowed-cidr: client IP unavailable")
	}
	parsedIP := net.ParseIP(ctx.ClientIP)
	if parsedIP == nil {
		return fmt.Errorf("constraint allowed-cidr: invalid client IP %q", ctx.ClientIP)
	}
	for _, cidr := range cidrs {
		_, cidrNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("constraint allowed-cidr: invalid CIDR %q in allowed list", cidr)
		}
		if cidrNet.Contains(parsedIP) {
			return nil
		}
	}
	return fmt.Errorf("constraint allowed-cidr: client IP %q not in allowed CIDRs", ctx.ClientIP)
}

// parseCIDRParam parses allowed-cidr parameters, supporting both bare arrays
// and {"cidrs": [...]} objects.
func parseCIDRParam(raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj struct {
			CIDRs []string `json:"cidrs"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, err
		}
		return obj.CIDRs, nil
	}
	var cidrs []string
	if err := json.Unmarshal(trimmed, &cidrs); err != nil {
		return nil, err
	}
	return cidrs, nil
}

// MaxConcurrentMin is the minimum value for the max parameter of the max-concurrent
// constraint.
const MaxConcurrentMin = 1

// MaxConcurrentMax is the maximum value for the max parameter of the max-concurrent
// constraint.
const MaxConcurrentMax = 1024

// parseMaxConcurrentParam parses the max-concurrent parameters (JSON {"max": N})
// and validates that N is in the range 1..1024. Returns a zero value when parameters
// are missing or empty (caller decides default policy).
func parseMaxConcurrentParam(raw []byte) (int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, nil
	}
	var obj struct {
		Max int `json:"max"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return 0, fmt.Errorf("constraint max-concurrent: invalid JSON: %w", err)
	}
	if obj.Max < MaxConcurrentMin || obj.Max > MaxConcurrentMax {
		return 0, fmt.Errorf("constraint max-concurrent: max %d: must be %d-%d", obj.Max, MaxConcurrentMin, MaxConcurrentMax)
	}
	return obj.Max, nil
}

// maxConcurrentEvaluator implements the max-concurrent constraint: concurrent connection limit.
// parameters is JSON {"max": N}, N in range 1..1024. Actual concurrent counting is performed
// by gateway runtime components (connection tracker); this stage validates parameter legality
// and bounds, returning reject on overflow.
type maxConcurrentEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (maxConcurrentEvaluator) CapabilityId() string { return ConstraintConcurrentKey }

// Evaluate validates max-concurrent parameters and passes evaluation context to the runtime
// counting component. Returns reject for invalid parameters (non-JSON or out of bounds);
// missing parameters are treated as unconfigured.
func (maxConcurrentEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	if _, err := parseMaxConcurrentParam(cap.Parameters); err != nil {
		return err
	}
	return nil
}

// skipEvaluator implements a placeholder constraint type: checked separately by gateway
// runtime components (e.g. connection tracker); this stage passes directly.
type skipEvaluator struct {
	capabilityId string
}

// CapabilityId returns the capability scheme ID for this constraint.
func (e skipEvaluator) CapabilityId() string { return e.capabilityId }

// Evaluate directly allows placeholder constraint types (evaluation is delegated to gateway runtime components).
func (skipEvaluator) Evaluate(_ *Capability, _ *ConstraintContext) error { return nil }

// timeWindowParams is the parameters structure for time-window constraints.
// tz is an IANA timezone name (e.g. "Asia/Shanghai"); empty values are evaluated as UTC (backward compatible).
type timeWindowParams struct {
	Start string `json:"start"`
	End   string `json:"end"`
	TZ    string `json:"tz"`
}

// timeWindowEvaluator implements the time-window constraint: the evaluation time must fall
// within the [start, end) window. The window is interpreted in the timezone specified by tz,
// supporting cross-midnight windows (start > end treated as spanning days).
type timeWindowEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (timeWindowEvaluator) CapabilityId() string { return ConstraintTimeWindowKey }

// Evaluate checks whether the current time falls within the allowed [start, end) window.
func (timeWindowEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	var params timeWindowParams
	if err := json.Unmarshal(cap.Parameters, &params); err != nil {
		return fmt.Errorf("constraint time-window: invalid JSON: %w", err)
	}
	if params.Start == "" || params.End == "" {
		return fmt.Errorf("constraint time-window: start and end are required")
	}
	startH, startM, startOK := parseTimeParts(params.Start)
	endH, endM, endOK := parseTimeParts(params.End)
	if !startOK || !endOK {
		return fmt.Errorf("constraint time-window: invalid time format %q / %q", params.Start, params.End)
	}
	loc := time.UTC
	if params.TZ != "" {
		l, err := time.LoadLocation(params.TZ)
		if err != nil {
			return fmt.Errorf("constraint time-window: invalid tz %q: %w", params.TZ, err)
		}
		loc = l
	}
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().In(time.UTC)
	}
	t := now.In(loc)
	startTime := time.Date(t.Year(), t.Month(), t.Day(), startH, startM, 0, 0, loc)
	endTime := time.Date(t.Year(), t.Month(), t.Day(), endH, endM, 0, 0, loc)
	inWindow := false
	if startTime.Before(endTime) || startTime.Equal(endTime) {
		inWindow = !t.Before(startTime) && t.Before(endTime)
	} else {
		inWindow = !t.Before(startTime) || t.Before(endTime)
	}
	if !inWindow {
		return fmt.Errorf("constraint time-window: current time %s outside window %s-%s (%s)",
			t.Format("15:04"), params.Start, params.End, loc)
	}
	return nil
}

// GeoResolver resolves a geographic region identifier (e.g. "CN-SHA") from a source IP.
// Registered with the geo-fence evaluator to make region resolution pluggable
// (built-in inline table; third-party databases like ip2region can self-register).
type GeoResolver func(ip string) (string, error)

// geoFenceEvaluator implements the geo-fence constraint: the client IP's resolved region
// must match the allowed set.
// parameters supports two forms:
//
//	Inline table: {"resolver":"inline","regions":{"CN-SHA":["10.0.0.0/8"]}}
//	External resolver: {"resolver":"ip2region","regions":["CN-SHA","CN-BJS"]}
//
// Inline table mode has zero external dependencies and can evaluate directly; external
// resolvers must call RegisterGeoResolver to register the corresponding resolver first;
// unregistered resolvers cause constraint evaluation failure (reject connection, not silent pass).
type geoFenceEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (geoFenceEvaluator) CapabilityId() string { return ConstraintGeoFenceKey }

// Evaluate checks whether the client IP's resolved region identifier hits the allowed set.
func (geoFenceEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	if ctx == nil {
		return fmt.Errorf("constraint geo-fence: nil context")
	}
	var params struct {
		Resolver string            `json:"resolver"`
		Regions  json.RawMessage   `json:"regions"`
		Table    map[string]string `json:"-"`
	}
	if err := json.Unmarshal(cap.Parameters, &params); err != nil {
		return fmt.Errorf("constraint geo-fence: invalid JSON: %w", err)
	}
	if len(params.Regions) == 0 {
		return fmt.Errorf("constraint geo-fence: regions are required")
	}
	resolver := params.Resolver
	if resolver == "" {
		resolver = "inline"
	}
	// Finding 18: a configured geo-fence with no client IP must fail closed.
	if ctx.ClientIP == "" {
		return fmt.Errorf("constraint geo-fence: client IP unavailable")
	}
	parsedIP := net.ParseIP(ctx.ClientIP)
	if parsedIP == nil {
		return fmt.Errorf("constraint geo-fence: invalid client IP %q", ctx.ClientIP)
	}
	if _, err := geoResolve(resolver, parsedIP, params.Regions); err != nil {
		return err
	}
	return nil
}

// geoResolve resolves the client IP's region identifier and checks against the allowed set.
func geoResolve(resolver string, ip net.IP, regions json.RawMessage) (string, error) {
	switch resolver {
	case "inline":
		var table map[string][]string
		if err := json.Unmarshal(regions, &table); err != nil {
			return "", fmt.Errorf("constraint geo-fence: inline regions must be {\"region\":[\"cidr\"]}: %w", err)
		}
		for region, cidrs := range table {
			for _, cidr := range cidrs {
				_, cidrNet, err := net.ParseCIDR(cidr)
				if err != nil {
					return "", fmt.Errorf("constraint geo-fence: invalid CIDR %q for region %q", cidr, region)
				}
				if cidrNet.Contains(ip) {
					return region, nil
				}
			}
		}
		return "", fmt.Errorf("constraint geo-fence: client IP %q not in any allowed region", ip.String())
	default:
		fn, ok := lookupGeoResolver(resolver)
		if !ok {
			return "", fmt.Errorf("constraint geo-fence: resolver %q not registered", resolver)
		}
		var allowed []string
		if err := json.Unmarshal(regions, &allowed); err != nil {
			return "", fmt.Errorf("constraint geo-fence: resolver %q expects regions array: %w", resolver, err)
		}
		region, err := fn(ip.String())
		if err != nil {
			return "", fmt.Errorf("constraint geo-fence: resolver %q: %w", resolver, err)
		}
		for _, a := range allowed {
			if a == region {
				return region, nil
			}
		}
		return "", fmt.Errorf("constraint geo-fence: client IP %q resolved to %q not in allowed regions", ip.String(), region)
	}
}

// geoResolvers stores registered geographic resolvers (resolver name → resolution function).
// Registration and lookup run on different goroutines (register at startup, look
// up per request), so the map is guarded.
var (
	geoMu        sync.RWMutex
	geoResolvers = map[string]GeoResolver{}
)

func lookupGeoResolver(name string) (GeoResolver, bool) {
	geoMu.RLock()
	defer geoMu.RUnlock()
	fn, ok := geoResolvers[name]
	return fn, ok
}

// RegisterGeoResolver registers a custom geographic resolver (extension point) for use
// in the geo-fence resolver mode (e.g. third-party geographic databases like ip2region).
// It is safe to call concurrently with evaluation.
func RegisterGeoResolver(name string, fn GeoResolver) {
	if name == "" || fn == nil {
		return
	}
	geoMu.Lock()
	geoResolvers[name] = fn
	geoMu.Unlock()
}

// HardTimeoutMin is the minimum value for session:hard-timeout (seconds).
const HardTimeoutMin = 60

// HardTimeoutMax is the maximum value for session:hard-timeout (seconds).
const HardTimeoutMax = 86400

// hardTimeoutEvaluator implements the session:hard-timeout constraint.
// Parameters: {"value": N} where N is in range 60..86400 seconds.
type hardTimeoutEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (hardTimeoutEvaluator) CapabilityId() string { return ConstraintHardTimeoutKey }

// Evaluate validates hard-timeout parameters. Actual timeout enforcement is performed
// by the gateway runtime (goroutine timer); this stage validates parameter legality.
func (hardTimeoutEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	var params struct {
		Value int `json:"value"`
	}
	if err := json.Unmarshal(cap.Parameters, &params); err != nil {
		return fmt.Errorf("constraint session:hard-timeout: invalid JSON: %w", err)
	}
	if params.Value < HardTimeoutMin || params.Value > HardTimeoutMax {
		return fmt.Errorf("constraint session:hard-timeout: value %d: must be %d-%d", params.Value, HardTimeoutMin, HardTimeoutMax)
	}
	return nil
}

// IdleTimeoutMin is the minimum value for session:idle-timeout (seconds).
const IdleTimeoutMin = 30

// IdleTimeoutMax is the maximum value for session:idle-timeout (seconds).
const IdleTimeoutMax = 3600

// idleTimeoutEvaluator implements the session:idle-timeout constraint.
// Parameters: {"value": N} where N is in range 30..3600 seconds.
type idleTimeoutEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (idleTimeoutEvaluator) CapabilityId() string { return ConstraintIdleTimeoutKey }

// Evaluate validates idle-timeout parameters. Actual timeout enforcement is performed
// by the gateway runtime; this stage validates parameter legality.
func (idleTimeoutEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	var params struct {
		Value int `json:"value"`
	}
	if err := json.Unmarshal(cap.Parameters, &params); err != nil {
		return fmt.Errorf("constraint session:idle-timeout: invalid JSON: %w", err)
	}
	if params.Value < IdleTimeoutMin || params.Value > IdleTimeoutMax {
		return fmt.Errorf("constraint session:idle-timeout: value %d: must be %d-%d", params.Value, IdleTimeoutMin, IdleTimeoutMax)
	}
	return nil
}

// readOnlyEvaluator implements the op:readonly constraint.
// Parameters: {"value": true} restricts to read-only operations.
type readOnlyEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (readOnlyEvaluator) CapabilityId() string { return ConstraintReadOnlyKey }

// Evaluate validates op:readonly parameters. Actual enforcement is performed
// by the gateway runtime (request method filtering); this stage validates parameter legality.
func (readOnlyEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	var params struct {
		Value bool `json:"value"`
	}
	if err := json.Unmarshal(cap.Parameters, &params); err != nil {
		return fmt.Errorf("constraint op:readonly: invalid JSON: %w", err)
	}
	return nil
}

// auditRequiredEvaluator implements the op:audit:required constraint.
// No parameters; asserts that operations must write an audit log.
type auditRequiredEvaluator struct{}

// CapabilityId returns the capability scheme ID for this constraint.
func (auditRequiredEvaluator) CapabilityId() string { return ConstraintAuditRequiredKey }

// Evaluate always passes at check time. Actual enforcement is performed
// by the gateway runtime (audit logger integration); this stage only
// validates that the constraint is present.
func (auditRequiredEvaluator) Evaluate(cap *Capability, ctx *ConstraintContext) error {
	return nil
}

// ConstraintRecheckLoop periodically re-evaluates authorizationConstraints (G3: constraint timing consistency).
//
// Constraints on long-lived data plane connections like TCP are only checked once at handshake;
// time-window / revocation constraints that expire over time cease to be effective after crossing
// the window — for example, a "weekdays 9-18 only" connection established during the night window
// remains active during the day. This function re-evaluates the authorizationConstraints of both
// AIC and PrincipalAuthorization at the given interval (using the current time), calling
// onViolation when a constraint is no longer met (gateway disconnects and audits accordingly).
// Stops when done is closed (idempotent).
//
// Any single constraint evaluation failure is treated as a violation; a and pa may both be
// nil/empty (skipping the corresponding set). Callers should ensure onViolation is non-nil
// (nil internally only logs, no actual action).
func ConstraintRecheckLoop(aicConstraints, paConstraints []Capability, clientIP string, interval time.Duration, done <-chan struct{}, onViolation func(reason string)) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		// Time-dependent constraint recheck: allowed-cidr/geo pass unchanged when source is static;
		// time-window is re-evaluated at current time (CheckAuthorizationConstraints internally uses time.Now).
		if err := CheckAuthorizationConstraints(aicConstraints, clientIP); err != nil {
			if onViolation != nil {
				onViolation(err.Error())
			}
			return
		}
		if err := CheckAuthorizationConstraints(paConstraints, clientIP); err != nil {
			if onViolation != nil {
				onViolation(err.Error())
			}
			return
		}
	}
}

// ConstraintToCapability is the inverse of ConstraintStrings: it maps a CLC
// constraint string back to the (scheme, capability, parameters) triple the
// connection-level registry evaluates.  A string this SDK cannot map is
// reported as false so callers fail closed.
func ConstraintToCapability(c string) (Capability, bool) {
	parts := strings.Split(c, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Capability{}, false
	}
	cap := Capability{SchemeId: parts[0]}
	switch parts[1] {
	case "time", "network":
		// `<scheme>:<type>:<crumb>:<json>` — the crumb ("window"/"cidr") is part
		// of the capability id in the extension encoding.
		if len(parts) < 4 {
			return Capability{}, false
		}
		cap.CapabilityId = parts[1] + ":" + parts[2]
		cap.Parameters = []byte(strings.Join(parts[3:], ":"))
	default:
		if len(parts) == 2 {
			cap.CapabilityId = parts[1]
			return cap, true
		}
		cap.CapabilityId = parts[1]
		cap.Parameters = []byte(strings.Join(parts[2:], ":"))
	}
	return cap, true
}

// ConnectionConstraintEvaluator returns an UnresolvedEvaluator that discharges
// the obligations the connection-level constraint registry can evaluate for the
// given client IP (source CIDRs, time windows, and whatever else is registered).
//
// It exists because the connection-level check and the language-level obligation
// are two halves of one rule: the language *declares* the constraint, and this
// evaluator *discharges* it.  Passing it is an explicit act — a deployment that
// does not pass it keeps the §8.4 default, which is fail-closed — so the release
// is a declared policy rather than an implicit bypass.  Anything the registry
// cannot evaluate (for example `max_rows`) is not discharged here: return false
// and let the caller decide.
func ConnectionConstraintEvaluator(clientIP string) func(op Operation, unresolved []string) bool {
	return func(_ Operation, unresolved []string) bool {
		for _, c := range unresolved {
			cap, ok := ConstraintToCapability(c)
			if !ok {
				return false
			}
			// The registry must actually have an evaluator for this type: a
			// successful check for an unknown type only means the non-strict
			// path ignored it, and ignoring is not discharging.
			if _, err := globalConstraintRegistry.Find(cap.CapabilityId); err != nil {
				return false
			}
			if err := CheckAuthorizationConstraints([]Capability{cap}, clientIP); err != nil {
				return false
			}
		}
		return true
	}
}
