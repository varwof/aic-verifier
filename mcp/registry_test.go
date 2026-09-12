// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

const testManifest = `{
  "version": 2,
  "tools": [
    {
      "name": "db_query",
      "description": "Read-only SQL query with a bounded row count.",
      "input_schema": {
        "type": "object",
        "properties": {
          "sql": {"type": "string", "minLength": 1, "maxLength": 200},
          "max_rows": {"type": "integer", "minimum": 1, "maximum": 1000},
          "mode": {"type": "string", "enum": ["read", "sync"]}
        },
        "required": ["sql"]
      },
      "required_capability": "mcp:db_query",
      "parameter_constraints": [
        {"name": "sql", "min_length": 1, "max_length": 200},
        {"name": "max_rows", "min": 1, "max": 1000},
        {"name": "mode", "enum": ["read", "sync"], "pattern": "^(read|sync)$"}
      ]
    },
    {
      "name": "bulk_load",
      "description": "Load up to 3 rows in one call.",
      "input_schema": {
        "type": "object",
        "properties": {
          "ids": {"type": "array", "items": {"type": "string"}}
        }
      },
      "required_capability": "mcp:db_write",
      "parameter_constraints": [
        {"name": "ids", "max_length": 3}
      ]
    }
  ]
}`

func loadTestRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := LoadJSON([]byte(testManifest))
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	return reg
}

func TestLoadJSONBasic(t *testing.T) {
	reg := loadTestRegistry(t)
	if reg.Version != 2 {
		t.Fatalf("Version = %d, want 2", reg.Version)
	}
	if got := reg.Find("db_query"); got == nil {
		t.Fatalf("Find(db_query) = nil")
	} else if got.RequiredCapability != "mcp:db_query" {
		t.Fatalf("RequiredCapability = %q", got.RequiredCapability)
	}
	if reg.Find("nope") != nil {
		t.Fatalf("Find(nope) should be nil")
	}
	names := reg.names()
	want := []string{"bulk_load", "db_query"}
	if len(names) != 2 || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("names = %v, want %v", names, want)
	}
}

func TestLoadJSONRejectsUnknownFields(t *testing.T) {
	cases := []string{
		`{"version":1,"tools":[],"bogus":true}`,
		`{"version":1,"tools":[{"name":"a","input_schema":{"type":"object"},"required_capability":"x","bogus":1}]}`,
		`{"version":1,"tools":[{"name":"a","input_schema":{"type":"object"},"required_capability":"x","parameter_constraints":[{"name":"p","max":1,"nope":2}]}]}`,
	}
	for i, doc := range cases {
		if _, err := LoadJSON([]byte(doc)); err == nil {
			t.Errorf("case %d: expected unknown-field error", i)
		}
	}
}

func TestLoadJSONStructuralErrors(t *testing.T) {
	cases := map[string]string{
		"version zero":     `{"version":0,"tools":[{"name":"a","input_schema":{"type":"object"},"required_capability":"x"}]}`,
		"no tools":         `{"version":1,"tools":[]}`,
		"empty name":       `{"version":1,"tools":[{"name":"","input_schema":{},"required_capability":"x"}]}`,
		"no schema":        `{"version":1,"tools":[{"name":"a","required_capability":"x"}]}`,
		"no capability":    `{"version":1,"tools":[{"name":"a","input_schema":{}}]}`,
		"duplicate name":   `{"version":1,"tools":[{"name":"a","input_schema":{},"required_capability":"x"},{"name":"a","input_schema":{},"required_capability":"y"}]}`,
		"bad pattern":      `{"version":1,"tools":[{"name":"a","input_schema":{},"required_capability":"x","parameter_constraints":[{"name":"p","pattern":"["}]}`,
		"null schema":      `{"version":1,"tools":[{"name":"a","input_schema":null,"required_capability":"x"}]}`,
		"bad json":         `{`,
		"empty constraint": `{"version":1,"tools":[{"name":"a","input_schema":{},"required_capability":"x","parameter_constraints":[{"max":1}]}]}`,
	}
	for name, doc := range cases {
		if _, err := LoadJSON([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidateArgs(t *testing.T) {
	reg := loadTestRegistry(t)
	db := reg.Find("db_query")
	bl := reg.Find("bulk_load")

	ok := map[string]json.RawMessage{
		"sql":      json.RawMessage(`"select 1"`),
		"max_rows": json.RawMessage(`100`),
		"mode":     json.RawMessage(`"read"`),
	}
	if err := validateArgs(db, mustMarshal(ok)); err != nil {
		t.Fatalf("valid args rejected: %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`{"max_rows":100}`)); err == nil || !strings.Contains(err.Error(), `missing required argument "sql"`) {
		t.Fatalf("missing required arg: got %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`{"sql":"select 1","max_rows":5000}`)); err == nil || !strings.Contains(err.Error(), "> max 1000") {
		t.Fatalf("max_rows out of range: got %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`{"sql":"select 1","max_rows":0}`)); err == nil || !strings.Contains(err.Error(), "< min 1") {
		t.Fatalf("max_rows below min: got %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`{"sql":"select 1","mode":"write"}`)); err == nil || !strings.Contains(err.Error(), "not in enum") {
		t.Fatalf("enum rejected valid? got %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`{"sql":"select 1","mode":"evasive"}`)); err == nil || !strings.Contains(err.Error(), "enum") {
		t.Fatalf("enum fallback: got %v", err)
	}

	longSQL := `"` + strings.Repeat("x", 201) + `"`
	if err := validateArgs(db, mustMarshal(map[string]json.RawMessage{"sql": json.RawMessage(longSQL)})); err == nil || !strings.Contains(err.Error(), "max_length") {
		t.Fatalf("max_length: got %v", err)
	}

	if err := validateArgs(db, json.RawMessage(`null`)); err == nil {
		t.Fatalf("null arguments accepted")
	}
	if err := validateArgs(db, json.RawMessage(`[1,2]`)); err == nil {
		t.Fatalf("array arguments accepted")
	}

	// Numeric constraints must not bind non-numeric values.
	if err := validateArgs(db, json.RawMessage(`{"sql":"null","max_rows":"5000"}`)); err != nil {
		t.Fatalf("string value with numeric constraint should pass: %v", err)
	}

	// Array max_length on bulk_load.
	if err := validateArgs(bl, json.RawMessage(`{"ids":["a","b","c","d"]}`)); err == nil || !strings.Contains(err.Error(), "max_length") {
		t.Fatalf("array max_length: got %v", err)
	}
	if err := validateArgs(bl, json.RawMessage(`{"ids":["a","b"]}`)); err != nil {
		t.Fatalf("small array rejected: %v", err)
	}
}

func TestCheckConstraintPattern(t *testing.T) {
	c := Constraint{Name: "code", Pattern: `^[a-z][0-9]{2}$`}
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	c.patternRe = re
	if err := checkConstraint(c, json.RawMessage(`"a12"`)); err != nil {
		t.Fatalf("valid pattern rejected: %v", err)
	}
	if err := checkConstraint(c, json.RawMessage(`"A12"`)); err == nil {
		t.Fatalf("invalid pattern accepted")
	}
	// Non-string values are untouched by pattern barriers.
	if err := checkConstraint(c, json.RawMessage(`123`)); err != nil {
		t.Fatalf("non-string should bypass pattern: %v", err)
	}
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
