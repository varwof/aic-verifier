// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Constraint is one deterministic parameter barrier from the manifest.
// Supported barrier kinds (the deterministic subset, no generic code blocks):
//
//	min / max              — numeric bounds on the property value
//	min_length / max_length — string length or array element count
//	enum                    — the string value must be one of these
//	pattern                 — the string value must match (Go regexp, unanchored
//	                          search; anchor with ^...$ in the manifest for exact match)
type Constraint struct {
	Name      string   `json:"name"`
	Min       *float64 `json:"min,omitempty"`
	Max       *float64 `json:"max,omitempty"`
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	Enum      []string `json:"enum,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	patternRe *regexp.Regexp
}

// ToolSpec is a single tool binding: the tools/list surface (name,
// description, inputSchema) plus the tools/call gate (required_capability +
// parameter_constraints).
type ToolSpec struct {
	Name               string          `json:"name"`
	Description        string          `json:"description,omitempty"`
	InputSchema        json.RawMessage `json:"input_schema"`
	RequiredCapability string          `json:"required_capability"`
	// ParameterConstraints holds the deterministic barriers. Property kinds are
	// resolved at validate time from the argument JSON, not from the schema,
	// so a barrier either applies or is skipped without an unchecked side.
	ParameterConstraints []Constraint `json:"parameter_constraints,omitempty"`
}

// Registry is the loaded tool manifest (tools.json).
type Registry struct {
	Version int        `json:"version"`
	Tools   []ToolSpec `json:"tools"`
	byName  map[string]*ToolSpec
}

// LoadJSON parses manifest JSON bytes into a Registry. Uses
// DisallowUnknownFields at every nesting level.
func LoadJSON(data []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var reg Registry
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("mcp: parse manifest: %w", err)
	}
	if err := reg.rebuild(); err != nil {
		return nil, err
	}
	return &reg, nil
}

// rebuild indexes the tools and compiles constraint patterns. It is separate
// from Decode so the contract "unknown fields reject" stays on the JSON path
// while programmatic construction can call it explicitly.
func (r *Registry) rebuild() error {
	if r.Version < 1 {
		return fmt.Errorf("mcp: manifest version must be >= 1, got %d", r.Version)
	}
	if len(r.Tools) == 0 {
		return fmt.Errorf("mcp: manifest declares no tools")
	}
	r.byName = make(map[string]*ToolSpec, len(r.Tools))
	for i := range r.Tools {
		spec := &r.Tools[i]
		if spec.Name == "" {
			return fmt.Errorf("mcp: tool %d has empty name", i)
		}
		if len(bytes.TrimSpace(spec.InputSchema)) == 0 || string(bytes.TrimSpace(spec.InputSchema)) == "null" {
			return fmt.Errorf("mcp: tool %q missing input_schema", spec.Name)
		}
		if !json.Valid(spec.InputSchema) {
			return fmt.Errorf("mcp: tool %q has invalid input_schema JSON", spec.Name)
		}
		if spec.RequiredCapability == "" {
			return fmt.Errorf("mcp: tool %q missing required_capability", spec.Name)
		}
		if _, dup := r.byName[spec.Name]; dup {
			return fmt.Errorf("mcp: duplicate tool name %q", spec.Name)
		}
		for ci := range spec.ParameterConstraints {
			c := &spec.ParameterConstraints[ci]
			if c.Name == "" {
				return fmt.Errorf("mcp: tool %q: constraint %d has empty name", spec.Name, ci)
			}
			if c.Pattern != "" {
				re, err := regexp.Compile(c.Pattern)
				if err != nil {
					return fmt.Errorf("mcp: tool %q pattern %q: %w", spec.Name, c.Pattern, err)
				}
				c.patternRe = re
			}
		}
		r.byName[spec.Name] = spec
	}
	return nil
}

// Find returns the tool spec by name, or nil.
func (r *Registry) Find(name string) *ToolSpec {
	if r == nil || r.byName == nil {
		return nil
	}
	return r.byName[name]
}

// names returns the registered tool names sorted (stable tool listing).
func (r *Registry) names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// validateArgs checks the tools/call arguments against the manifest barriers.
// Every present argument is compared; a failing barrier produces an error that
// denies the call (JSON-RPC -32602) before the tool handler runs.
//
// Argument kinds are inferred from the JSON value so barriers never silently
// pass an incompatible value: strings run length/enum/pattern, numbers run
// min/max, arrays run length. A value whose kind no barrier fits is accepted
// (it is still bounded by the input_schema the client sees).
func validateArgs(spec *ToolSpec, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return fmt.Errorf("missing arguments object")
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(raw, &args); err != nil {
		return fmt.Errorf("arguments must be a JSON object")
	}

	// required set from input_schema (declarative, same source the client
	// sees through tools/list).
	required, err := requiredFields(spec.InputSchema)
	if err != nil {
		return fmt.Errorf("input_schema.required: %w", err)
	}
	for _, name := range required {
		if _, ok := args[name]; !ok {
			return fmt.Errorf("missing required argument %q", name)
		}
	}

	for _, c := range spec.ParameterConstraints {
		v, ok := args[c.Name]
		if !ok {
			continue
		}
		if err := checkConstraint(c, v); err != nil {
			return err
		}
	}
	return nil
}

// requiredFields extracts the required array from a JSON Schema object.
func requiredFields(schema json.RawMessage) ([]string, error) {
	var s struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, err
	}
	return s.Required, nil
}

func checkConstraint(c Constraint, v json.RawMessage) error {
	if err := checkNumeric(c, v); err != nil {
		return err
	}
	if err := checkString(c, v); err != nil {
		return err
	}
	if err := checkArray(c, v); err != nil {
		return err
	}
	return nil
}

func checkNumeric(c Constraint, v json.RawMessage) error {
	if c.Min == nil && c.Max == nil {
		return nil
	}
	num, ok := jsonNumber(v)
	if !ok {
		return nil // not a number; numeric barriers don't bind other kinds
	}
	if c.Min != nil && num < *c.Min {
		return fmt.Errorf("param %q %v < min %v", c.Name, num, *c.Min)
	}
	if c.Max != nil && num > *c.Max {
		return fmt.Errorf("param %q %v > max %v", c.Name, num, *c.Max)
	}
	return nil
}

func checkString(c Constraint, v json.RawMessage) error {
	if c.MinLength == nil && c.MaxLength == nil && len(c.Enum) == 0 && c.Pattern == "" {
		return nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil // not a string
	}
	n := utf8.RuneCountInString(s)
	if c.MinLength != nil && n < *c.MinLength {
		return fmt.Errorf("param %q length %d < min_length %d", c.Name, n, *c.MinLength)
	}
	if c.MaxLength != nil && n > *c.MaxLength {
		return fmt.Errorf("param %q length %d > max_length %d", c.Name, n, *c.MaxLength)
	}
	if len(c.Enum) > 0 {
		ok := false
		for _, e := range c.Enum {
			if s == e {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("param %q value %q not in enum %v", c.Name, s, c.Enum)
		}
	}
	if c.Pattern != "" && c.patternRe != nil && !c.patternRe.MatchString(s) {
		return fmt.Errorf("param %q value does not match pattern %q", c.Name, c.Pattern)
	}
	return nil
}

func checkArray(c Constraint, v json.RawMessage) error {
	if c.MinLength == nil && c.MaxLength == nil {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(v, &items); err != nil {
		return nil // not an array
	}
	n := len(items)
	if c.MinLength != nil && n < *c.MinLength {
		return fmt.Errorf("param %q length %d < min_length %d", c.Name, n, *c.MinLength)
	}
	if c.MaxLength != nil && n > *c.MaxLength {
		return fmt.Errorf("param %q length %d > max_length %d", c.Name, n, *c.MaxLength)
	}
	return nil
}

// jsonNumber parses a JSON number (integer or float) into a float64. JSON
// numbers are the only values numeric barriers bind; booleans/strings are left
// untouched (validators are deterministic, never type-coerce).
func jsonNumber(raw json.RawMessage) (float64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "null" || strings.HasPrefix(s, `"`) || strings.HasPrefix(s, "[") || strings.HasPrefix(s, "{") {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}
