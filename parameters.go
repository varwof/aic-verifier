// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Parameter-level boundary validation — patent spec P1-B-11 / P2-B-05
//
// Each schemeId defines its own parameter boundary comparison logic (e.g., max_rows).
// Scenario: principal grants max_rows=1000, agent declares 100 → pass (takes 100);
// declares 5000 → reject (out of bounds).
//
// The gateway runtime only performs capability-level intersection (no per-parameter
// comparison); parameter-level boundaries are checked by registered validators at
// CA signing time (P2-B-05) or when explicitly enabled (P1-B-11).

package aicverifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
)

// ParameterValidator validates whether a capability declaration's parameters fall
// within the authorized boundary. Implemented per schemeId (one Scheme → one validator).
type ParameterValidator interface {
	// Scheme returns the schemeId associated with this validator.
	Scheme() string
	// Validate checks whether declared (agent/certificate declaration) falls within
	// granted (principal authorization boundary). Returns a non-nil error if out of bounds
	// (includes the specific parameter name and boundary).
	Validate(granted, declared Capability) error
}

// ParameterValidatorRegistry manages registration and lookup of parameter boundary validators.
type ParameterValidatorRegistry struct {
	mu sync.RWMutex
	m  map[string]ParameterValidator
}

// NewParameterValidatorRegistry creates an empty parameter boundary validator registry.
func NewParameterValidatorRegistry() *ParameterValidatorRegistry {
	return &ParameterValidatorRegistry{m: make(map[string]ParameterValidator)}
}

// Register registers a parameter boundary validator.
func (r *ParameterValidatorRegistry) Register(v ParameterValidator) error {
	if r == nil {
		return fmt.Errorf("parameter_validator: nil registry")
	}
	if v == nil {
		return fmt.Errorf("parameter_validator: nil validator")
	}
	s := v.Scheme()
	if s == "" {
		return fmt.Errorf("parameter_validator: empty scheme")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.m[s]; exists {
		return fmt.Errorf("parameter_validator: scheme %q already registered", s)
	}
	r.m[s] = v
	return nil
}

// Find looks up the parameter boundary validator for the given schemeId.
func (r *ParameterValidatorRegistry) Find(schemeID string) (ParameterValidator, error) {
	if r == nil {
		return nil, fmt.Errorf("parameter_validator: nil registry")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.m[schemeID]
	if !ok {
		return nil, fmt.Errorf("parameter_validator: no validator for scheme %q", schemeID)
	}
	return v, nil
}

// Reset clears the registry.
func (r *ParameterValidatorRegistry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m = make(map[string]ParameterValidator)
}

// Len returns the number of registered validators.
func (r *ParameterValidatorRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}

// Keys returns all registered scheme IDs.
func (r *ParameterValidatorRegistry) Keys() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	return out
}

// ValidateCapability validates a capability declaration against the authorized boundary
// using the given registry. Unregistered schemes are allowed (no parameter boundary rules;
// capability-level intersection was already performed upstream).
func (r *ParameterValidatorRegistry) ValidateCapability(granted, declared Capability) error {
	if r == nil {
		return nil
	}
	v, err := r.Find(declared.SchemeId)
	if err != nil {
		return nil
	}
	return v.Validate(granted, declared)
}

// maxRowsParams parses the max_rows parameter.
// Parameters is a JSON object {"max_rows": N}.
type maxRowsParams struct {
	MaxRows *int64 `json:"max_rows"`
}

// parseMaxRows parses max_rows from parameters (compatible with {"max_rows": N} and empty).
// Returns (value, exists, error).
func parseMaxRows(raw []byte) (int64, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, false, nil
	}
	var p maxRowsParams
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return 0, false, fmt.Errorf("max_rows: invalid parameters JSON: %w", err)
	}
	if p.MaxRows == nil {
		return 0, false, nil
	}
	if *p.MaxRows < 0 {
		return 0, false, fmt.Errorf("max_rows: negative value %d", *p.MaxRows)
	}
	return *p.MaxRows, true, nil
}

// maxRowsValidator is an example parameter boundary validator (patent spec P1-B-11/P2-B-05 example semantics).
// schemeId is "report"; declared max_rows must not exceed the authorized boundary.
type maxRowsValidator struct{}

// Scheme returns the schemeId for this validator.
func (maxRowsValidator) Scheme() string { return "report" }

// Validate checks that declared max_rows ≤ granted max_rows.
// If granted does not specify max_rows → treated as unlimited; if declared is not specified → allowed.
func (maxRowsValidator) Validate(granted, declared Capability) error {
	g, gOK, err := parseMaxRows(granted.Parameters)
	if err != nil {
		return err
	}
	d, dOK, err := parseMaxRows(declared.Parameters)
	if err != nil {
		return err
	}
	if !dOK {
		return nil
	}
	if gOK && d > g {
		return fmt.Errorf("report: declared max_rows %d exceeds granted boundary %d", d, g)
	}
	return nil
}

// MaxRowsValidator is an exported instance of the max_rows parameter boundary validator
// (for registration: NewParameterValidatorRegistry().Register(MaxRowsValidator)).
var MaxRowsValidator ParameterValidator = maxRowsValidator{}

// builtinParameterValidators is the built-in parameter boundary validator registry (global convenience entry).
var builtinParameterValidators = NewParameterValidatorRegistry()

func init() {
	_ = builtinParameterValidators.Register(MaxRowsValidator)
}

// RegisterParameterValidator registers a validator in the built-in parameter boundary validator registry.
func RegisterParameterValidator(v ParameterValidator) error {
	return builtinParameterValidators.Register(v)
}

// ResetParameterValidators clears the built-in parameter boundary validator registry (testing only).
func ResetParameterValidators() {
	builtinParameterValidators.Reset()
}

// BuiltinParameterValidators returns the built-in parameter boundary validator registry.
func BuiltinParameterValidators() *ParameterValidatorRegistry {
	return builtinParameterValidators
}

// formatInt is a utility (keeps strconv import used; formats error messages for validators).
func formatInt(v int64) string {
	return strconv.FormatInt(v, 10)
}
