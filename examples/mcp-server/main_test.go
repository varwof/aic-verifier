package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const testManifest = `{
  "version": 1,
  "tools": [
    {
      "name": "db_query",
      "description": "Run a read-only SQL statement against the demo catalog. The result row count is bounded by max_rows regardless of what the catalog contains.",
      "input_schema": {
        "type": "object",
        "properties": {
          "sql": { "type": "string", "minLength": 1, "maxLength": 200, "description": "read-only SELECT statement" },
          "max_rows": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "hard cap on returned rows" }
        },
        "required": ["sql"]
      },
      "required_capability": "mcp:db_query",
      "parameter_constraints": [
        { "name": "sql", "pattern": "^SELECT ", "max_length": 200 },
        { "name": "max_rows", "min": 1, "max": 1000 }
      ]
    },
    {
      "name": "trade_exec",
      "description": "Place a market order. A single order amount is capped at 50000; the capability mcp:trade_exec is required.",
      "input_schema": {
        "type": "object",
        "properties": {
          "symbol": { "type": "string", "minLength": 1, "maxLength": 16 },
          "side": { "type": "string", "enum": ["buy", "sell"] },
          "amount": { "type": "number", "minimum": 1, "maximum": 50000 }
        },
        "required": ["symbol", "side", "amount"]
      },
      "required_capability": "mcp:trade_exec",
      "parameter_constraints": [
        { "name": "symbol", "pattern": "^[A-Z]{1,6}$", "max_length": 16 },
        { "name": "side", "enum": ["buy", "sell"] },
        { "name": "amount", "min": 1, "max": 50000 }
      ]
    }
  ]
}`

func TestJSONNumber(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want int
		ok   bool
	}{
		{"missing", "max_rows", 0, false},
		{"empty", "sql", 0, false},
		{"invalid", "amount", 0, false},
		{"string", "max_rows", 0, false},
		{"valid", "max_rows", 7, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]json.RawMessage{
				"max_rows": json.RawMessage("7"),
				"sql":      json.RawMessage(`"SELECT 1"`),
				"amount":   json.RawMessage(`"not a number"`),
			}
			switch tc.name {
			case "missing", "empty":
				delete(args, tc.key)
			case "string":
				args[tc.key] = json.RawMessage(`"7"`)
			}
			got, ok := jsonNumber(args, tc.key)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("jsonNumber(%s) = %d,%v want %d,%v", tc.key, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{"1.2.3.4:555", "1.2.3.4"},
		{"[::1]:88", "::1"},
		{"1.2.3.4", "1.2.3.4"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		r := &http.Request{RemoteAddr: tc.remote}
		if got := clientIP(r); got != tc.want {
			t.Errorf("clientIP(%q) = %q want %q", tc.remote, got, tc.want)
		}
	}
}

func TestBoolPtrAndClose(t *testing.T) {
	p := boolPtr(true)
	if p == nil || !*p {
		t.Fatal("boolPtr(true) must be &true")
	}
	var nilStack *mcpStack
	if err := nilStack.close(); err != nil {
		t.Fatalf("nil stack close: %v", err)
	}
	if err := (&mcpStack{}).close(); err != nil {
		t.Fatalf("empty stack close: %v", err)
	}
}

func TestPEMHelpers(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := writePEM("missing-dir/a.pem", "CERTIFICATE", []byte("x")); err == nil {
		t.Fatal("writePEM into a missing dir must fail")
	}
	if _, err := readCAPair("nope.pem", "nope-key.pem"); err == nil {
		t.Fatal("missing cert must fail")
	}
	if err := os.WriteFile("cert.pem", []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("key.pem", []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPair("cert.pem", "key.pem"); err == nil || !strings.Contains(err.Error(), "no cert") {
		t.Fatalf("non-PEM cert err = %v", err)
	}
	if err := os.WriteFile("cert.pem", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPair("cert.pem", "key.pem"); err == nil {
		t.Fatal("bad cert must fail")
	}
	// A valid CA pair reaches the key decode path.
	if err := ensureCA(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caKey, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPair(caCert, caKey); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("non-PEM key err = %v", err)
	}
}

func TestEnsureCAAndMint(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := ensureCA(); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	if err := ensureCA(); err != nil {
		t.Fatalf("ensureCA again must be idempotent: %v", err)
	}
	ca, err := readCAPair(caCert, caKey)
	if err != nil {
		t.Fatalf("readCAPair: %v", err)
	}
	if !ca.cert.IsCA {
		t.Fatal("minted CA cert must be a CA")
	}
	op, aud, err := mintLocalTokens(defaultIssuer, defaultAudience)
	if err != nil {
		t.Fatalf("mintLocalTokens: %v", err)
	}
	if op == "" || aud == "" || op == aud {
		t.Fatal("expected two distinct tokens")
	}
}

func TestEnsureServerTLS(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := ensureServerTLS("srv.pem", "srv-key.pem"); err != nil {
		t.Fatalf("ensureServerTLS: %v", err)
	}
	for _, f := range []string{"srv.pem", "srv-key.pem"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
	}
	if err := ensureServerTLS("srv.pem", "srv-key.pem"); err != nil {
		t.Fatalf("ensureServerTLS again: %v", err)
	}
}

func TestBuildStackErrors(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if _, err := buildStack("missing.json", defaultCA, defaultIssuer, defaultAudience, "audit.jsonl", true); err == nil {
		t.Fatal("missing manifest must fail")
	}
	if err := os.WriteFile("tools.json", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildStack("tools.json", defaultCA, defaultIssuer, defaultAudience, "audit.jsonl", true); err == nil || !strings.Contains(err.Error(), "tools.json") {
		t.Fatalf("bad manifest err = %v", err)
	}
	if err := os.WriteFile("tools.json", []byte(testManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildStack("tools.json", "no-such-ca.pem", defaultIssuer, defaultAudience, "audit.jsonl", true); err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("missing jwt-ca err = %v", err)
	}
}

func TestRun(t *testing.T) {
	t.Run("parse error", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var out, errb bytes.Buffer
		if code := run([]string{"--bogus"}, &out, &errb); code != 2 {
			t.Fatalf("run(--bogus) = %d, want 2", code)
		}
	})
	t.Run("default mode reaches serve", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("tools.json", []byte(testManifest), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "OPERATOR TOKEN") || !strings.Contains(errb.String(), "AUDITOR TOKEN") {
			t.Fatalf("missing minted-token banner in stderr: %s", errb.String())
		}
		if !strings.Contains(errb.String(), "AIC-gated MCP server listening") {
			t.Fatalf("missing listen banner in stderr: %s", errb.String())
		}
	})
	t.Run("missing manifest", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var out, errb bytes.Buffer
		if code := run([]string{"--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(missing tools) = %d, want 1", code)
		}
	})
	t.Run("full-chain mode", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("tools.json", []byte(testManifest), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := ensureCA(); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"--no-mint", "--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(--no-mint, bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "Full-chain mode") {
			t.Fatalf("missing full-chain banner in stderr: %s", errb.String())
		}
	})
}

func TestStackEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("tools.json", []byte(testManifest), 0o600); err != nil {
		t.Fatal(err)
	}

	stack, err := buildStack("tools.json", defaultCA, defaultIssuer, defaultAudience, "audit-mcp.jsonl", false)
	if err != nil {
		t.Fatalf("buildStack: %v", err)
	}
	defer stack.close()

	if stack.opToken == "" || stack.audToken == "" {
		t.Fatal("minting must produce both tokens")
	}

	ts := httptest.NewTLSServer(stack.handler)
	defer ts.Close()
	client := ts.Client()

	// initialize (audited pass-through); collect the minted session ID so the
	// transport routes subsequent messaging.
	body, status, hdr := rpc(t, client, ts.URL, stack.opToken, "", 1, "initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "opencode-example-test", "version": "0.0.test"},
	})
	if status != http.StatusOK {
		t.Fatalf("initialize status = %d, body=%s", status, body)
	}
	if !strings.Contains(string(body), "aic-verifier-mcp-demo") {
		t.Fatalf("initialize did not report server name: %s", body)
	}
	session := hdr.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatalf("initialize did not mint a session: %v", hdr)
	}

	// tools/call db_query with the operator token: allowed, row cap applied.
	body, status, _ = rpc(t, client, ts.URL, stack.opToken, session, 2, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT * FROM t", "max_rows": 2}})
	if status != http.StatusOK {
		t.Fatalf("db_query status = %d, body=%s", status, body)
	}
	if !strings.Contains(string(body), "returned") || !strings.Contains(string(body), "alice") {
		t.Fatalf("db_query result missing rows: %s", body)
	}

	// trade_exec is operator-only: auditor token is denied by the capability gate.
	body, status, _ = rpc(t, client, ts.URL, stack.audToken, session, 3, "tools/call", map[string]any{"name": "trade_exec", "arguments": map[string]any{"symbol": "AAPL", "side": "buy", "amount": 10}})
	if status != http.StatusOK {
		t.Fatalf("trade_exec(deny) status = %d, body=%s", status, body)
	}
	if !strings.Contains(string(body), "trade_exec") || !strings.Contains(string(body), "-32602") {
		t.Fatalf("trade_exec(deny) did not answer -32602: %s", body)
	}

	// Argument barriers: out-of-range max_rows is denied even with the right token.
	body, _, _ = rpc(t, client, ts.URL, stack.opToken, session, 4, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT * FROM t", "max_rows": 5000}})
	if !strings.Contains(string(body), "-32602") || !strings.Contains(string(body), "max_rows") {
		t.Fatalf("db_query(max_rows=5000) was not refused: %s", body)
	}

	// Non-SELECT statements are refused by the constraints.
	body, _, _ = rpc(t, client, ts.URL, stack.opToken, session, 5, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "DROP TABLE t"}})
	if !strings.Contains(string(body), "-32602") {
		t.Fatalf("db_query(DROP) was not refused: %s", body)
	}

	// Unknown tools are refused by the surface gate.
	body, _, _ = rpc(t, client, ts.URL, stack.opToken, session, 6, "tools/call", map[string]any{"name": "no_such_tool", "arguments": map[string]any{}})
	if !strings.Contains(string(body), "-32602") || !strings.Contains(string(body), "unknown tool") {
		t.Fatalf("unknown tool was not refused: %s", body)
	}

	// No credential: admission itself rejects before the MCP layer (401).
	body, status, _ = rpc(t, client, ts.URL, "", session, 7, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT 1"}})
	if status != http.StatusUnauthorized {
		t.Fatalf("no-credential status = %d, want 401 (body=%s)", status, body)
	}

	// tools/list passes through (audited).
	body, status, _ = rpc(t, client, ts.URL, stack.opToken, session, 8, "tools/list", map[string]any{})
	if status != http.StatusOK || !strings.Contains(string(body), "db_query") || !strings.Contains(string(body), "trade_exec") {
		t.Fatalf("tools/list = %d %s", status, body)
	}

	// The audit file received the decisions.
	audit, err := os.ReadFile("audit-mcp.jsonl")
	if err != nil {
		t.Fatalf("audit file: %v", err)
	}
	if !strings.Contains(string(audit), `"agent_id":"agent-001"`) {
		t.Fatalf("audit missing operator allow entries: %s", audit)
	}
	if !strings.Contains(string(audit), `"decision":"deny"`) {
		t.Fatalf("audit missing deny entries: %s", audit)
	}
}

// rpc performs one JSON-RPC POST and returns the raw response body (SSE frames
// collapsed to the last JSON payload), the HTTP status, and the response
// headers (for the minted Mcp-Session-Id).
func rpc(t *testing.T, c *http.Client, url, token, session string, id int, method string, params map[string]any) ([]byte, int, http.Header) {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	hreq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		hreq.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		hreq.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := c.Do(hreq)
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return collapseSSE(body), resp.StatusCode, resp.Header
}

// collapseSSE extracts the trailing JSON-RPC payload from a text/event-stream
// response, so both response shapes are parsed the same way.
func collapseSSE(body []byte) []byte {
	if len(body) == 0 || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return bytes.TrimSpace(body)
	}
	var last []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			last = []byte(strings.TrimSpace(rest))
		}
	}
	return last
}
