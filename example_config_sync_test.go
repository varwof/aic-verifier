// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// config.example.json is the operator-facing reference for this SDK: the full
// JSON surface a gateway can configure from a file. These tests keep it in
// sync with fileConfig both ways:
//
//  1. the example must still parse (every key it uses is a recognized field —
//     ParseConfig rejects unknown fields, so a renamed/tagged field breaks at
//     the first run of this test);
//  2. the example must document every configurable field, so adding a JSON
//     option without updating the reference fails here instead of going out
//     quietly.
package aicverifier

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const exampleConfigPath = "config.example.json"

func readExampleConfig(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(exampleConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v (is this running from the repo root?)", exampleConfigPath, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", exampleConfigPath, err)
	}
	return doc
}

// The reference must stay loadable: ParseConfig is strict about unknown keys,
// and the example's switches must wire into the expected Config values.
func TestExampleConfigParses(t *testing.T) {
	data, err := os.ReadFile(exampleConfigPath)
	if err != nil {
		t.Fatalf("read %s: %v", exampleConfigPath, err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig(config.example.json): %v", err)
	}
	if c.AuthMode != MTLSOrBearer {
		t.Errorf("auth_mode %q parsed as %v, want mtls_or_bearer", "mtls_or_bearer", c.AuthMode)
	}
	if c.IdentityMode != IdentityForwardClientCert {
		t.Errorf("identity_mode parsed as %v, want forward_client_cert", c.IdentityMode)
	}
	if !c.RequireAIC || !c.DisallowRepresentative {
		t.Errorf("require_aic/disallow_representative not honored: %+v", c)
	}
	if !c.SupervisionPolicy.RequireRuntimeApproval ||
		!c.SupervisionPolicy.AllowBreakGlass ||
		!c.SupervisionPolicy.RequireEvidenceExport {
		t.Errorf("supervision_policy not honored: %+v", c.SupervisionPolicy)
	}
	if c.SupervisionStore == nil {
		t.Error("supervision_log_file should wire a SupervisionStore")
	}
	c.Close() // example wires a temp-free store; close regardless of path
}

// jsonField returns the json tag name of a struct field ("" when tagless or "-").
func jsonField(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	name := tag
	if idx := indexOfByte(name, ','); idx >= 0 {
		name = name[:idx]
	}
	return name
}

// fileConfigChildTags maps each json tag of fileConfig to its leaf json tags
// (empty for scalar fields). Containers (struct fields) return their nested
// fields, which live under the container key in the example document.
func fileConfigChildTags(typ reflect.Type) map[string][]string {
	out := map[string][]string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := jsonField(f)
		if name == "" {
			continue
		}
		var leaves []string
		if f.Type.Kind() == reflect.Struct {
			for j := 0; j < f.Type.NumField(); j++ {
				if leaf := jsonField(f.Type.Field(j)); leaf != "" {
					leaves = append(leaves, leaf)
				}
			}
		}
		out[name] = leaves
	}
	return out
}

// jsonChildren of a decoded example document are the keys of the value object
// under the given container (nil for scalar/absent values).
func jsonChildren(raw json.RawMessage) map[string]bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func indexOfByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// Every configurable JSON field must appear in the example — the reference is
// the place humans learn the surface, so it cannot drift behind the code.
func TestExampleConfigDocumentsEveryField(t *testing.T) {
	doc := readExampleConfig(t)

	for tag, leaves := range fileConfigChildTags(reflect.TypeOf(fileConfig{})) {
		raw, ok := doc[tag]
		if !ok {
			t.Errorf("example missing field %q", tag)
			continue
		}
		if len(leaves) == 0 {
			continue
		}
		children := jsonChildren(raw)
		for _, leaf := range leaves {
			if !children[leaf] {
				t.Errorf("example missing %q.%s", tag, leaf)
			}
		}
	}
}

// The example must not invent keys the code does not know (typo guard); only
// _comment is tolerated metadata. This mirrors ParseConfig's strictness but
// without needing a parse (keeps the reference check runnable alongside the
// strict-parse assertion above).
func TestExampleConfigNoUnknownFields(t *testing.T) {
	doc := readExampleConfig(t)
	children := fileConfigChildTags(reflect.TypeOf(fileConfig{}))

	for key, raw := range doc {
		if key == "_comment" {
			continue
		}
		leaves, known := children[key]
		if !known {
			t.Errorf("example uses unknown field %q", key)
			continue
		}
		if len(leaves) == 0 {
			continue
		}
		for child := range jsonChildren(raw) {
			found := false
			for _, leaf := range leaves {
				if leaf == child {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("example uses unknown nested field %q.%s", key, child)
			}
		}
	}
}
