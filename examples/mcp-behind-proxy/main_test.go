package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestDirPath(t *testing.T) {
	if got := dirPath(".", "ca.pem"); got != "ca.pem" {
		t.Fatalf("dirPath(.) = %q", got)
	}
	if got := dirPath("", "ca.pem"); got != "ca.pem" {
		t.Fatalf("dirPath(\"\") = %q", got)
	}
	if got := dirPath("/tmp/x", "ca.pem"); got != "/tmp/x/ca.pem" {
		t.Fatalf("dirPath(/tmp/x) = %q", got)
	}
}

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

func TestEnsureServerTLS(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "srv.pem"), filepath.Join(dir, "srv-key.pem")
	if err := ensureServerTLS(cert, key); err != nil {
		t.Fatalf("ensureServerTLS: %v", err)
	}
	for _, f := range []string{cert, key} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
	}
	if err := ensureServerTLS(cert, key); err != nil {
		t.Fatalf("ensureServerTLS again: %v", err)
	}
}

func TestHelpersAndPEMErrors(t *testing.T) {
	dir := t.TempDir()
	if p := boolPtr(false); p == nil || *p {
		t.Fatal("boolPtr(false) must be &false")
	}
	if err := writePEM(filepath.Join(dir, "missing", "a.pem"), "CERTIFICATE", []byte("x")); err == nil {
		t.Fatal("writePEM into a missing dir must fail")
	}
	if _, err := readCAPair(filepath.Join(dir, "nope.pem"), filepath.Join(dir, "nope-key.pem")); err == nil {
		t.Fatal("missing cert must fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); err == nil || !strings.Contains(err.Error(), "no cert") {
		t.Fatalf("non-PEM cert err = %v", err)
	}
	// A valid CA reaches the key decode path.
	if err := ensureCA(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAPair(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "key.pem")); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("non-PEM key err = %v", err)
	}
}

func TestMintInCertsDir(t *testing.T) {
	dir := t.TempDir()

	if err := ensureCA(dir); err != nil {
		t.Fatalf("ensureCA: %v", err)
	}
	if err := ensureCA(dir); err != nil {
		t.Fatalf("ensureCA again must be idempotent: %v", err)
	}
	ca, err := readCAPair(dirPath(dir, caCert), dirPath(dir, caKey))
	if err != nil {
		t.Fatalf("readCAPair: %v", err)
	}
	if !ca.cert.IsCA {
		t.Fatal("minted CA must be a CA")
	}
	op, aud, err := mintLocalTokens(defaultIssuer, defaultAudience, dir)
	if err != nil {
		t.Fatalf("mintLocalTokens: %v", err)
	}
	if op == "" || aud == "" || op == aud {
		t.Fatal("expected two distinct tokens")
	}
	if err := mintAICClientCert(dir); err != nil {
		t.Fatalf("mintAICClientCert: %v", err)
	}
	for _, f := range []string{"client-cert.pem", "client-key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
	}
	client, err := readCAPair(filepath.Join(dir, "client-cert.pem"), filepath.Join(dir, "client-key.pem"))
	if err != nil {
		t.Fatalf("readCAPair(client keys): %v", err)
	}
	if client.cert.IsCA {
		t.Fatal("client cert must NOT be a CA")
	}
	if got := client.cert.Subject.CommonName; got != "agent-001" {
		t.Fatalf("client cert CN = %q, want agent-001", got)
	}
}

func TestBuildStackErrors(t *testing.T) {
	opts := stackOptions{
		toolsFile:      "missing.json",
		certsDir:       t.TempDir(),
		proxyAuditFile: "proxy-audit.jsonl",
		mcpAuditFile:   "audit-mcp.jsonl",
	}
	if _, err := buildStack(opts); err == nil {
		t.Fatal("missing manifest must fail")
	}
	opts.toolsFile = filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(opts.toolsFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildStack(opts); err == nil || !strings.Contains(err.Error(), "tools.json") {
		t.Fatalf("bad manifest err = %v", err)
	}
	if err := os.WriteFile(opts.toolsFile, []byte(testManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.backendPort = "not-a-port"
	if _, err := buildStack(opts); err == nil || !strings.Contains(err.Error(), "backend listen") {
		t.Fatalf("bad backend port err = %v", err)
	}
}

func TestRun(t *testing.T) {
	writeTools := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile("tools.json", []byte(testManifest), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("parse error", func(t *testing.T) {
		t.Chdir(t.TempDir())
		var out, errb bytes.Buffer
		if code := run([]string{"--bogus"}, &out, &errb); code != 2 {
			t.Fatalf("run(--bogus) = %d, want 2", code)
		}
	})
	t.Run("default bearer mode", func(t *testing.T) {
		writeTools(t)
		var out, errb bytes.Buffer
		if code := run([]string{"--tools", "tools.json", "--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "OPERATOR TOKEN") || !strings.Contains(errb.String(), "AUDITOR TOKEN") {
			t.Fatalf("missing bearer banner in stderr: %s", errb.String())
		}
		if !strings.Contains(errb.String(), "AIC-gated MCP proxy listening") {
			t.Fatalf("missing listen banner in stderr: %s", errb.String())
		}
	})
	t.Run("mtls authed mode", func(t *testing.T) {
		writeTools(t)
		var out, errb bytes.Buffer
		if code := run([]string{"--tools", "tools.json", "--mtls", "--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(--mtls, bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "mTLS OPERATOR AIC CERT") {
			t.Fatalf("missing mtls banner in stderr: %s", errb.String())
		}
	})
	t.Run("bearer full-chain", func(t *testing.T) {
		writeTools(t)
		if err := ensureCA("."); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"--tools", "tools.json", "--no-mint", "--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(--no-mint, bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "Full-chain mode") {
			t.Fatalf("missing full-chain banner in stderr: %s", errb.String())
		}
	})
	t.Run("mtls full-chain", func(t *testing.T) {
		writeTools(t)
		if err := ensureCA("."); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"--tools", "tools.json", "--mtls", "--no-mint", "--addr", ":99999"}, &out, &errb); code != 1 {
			t.Fatalf("run(--mtls --no-mint, bad-addr) = %d, want 1 (stderr=%s)", code, errb.String())
		}
		if !strings.Contains(errb.String(), "mTLS full-chain mode") {
			t.Fatalf("missing mtls full-chain banner in stderr: %s", errb.String())
		}
	})
}

func TestStackEndToEndThroughProxy(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tools.json"), []byte(testManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := stackOptions{
		toolsFile:      filepath.Join(dir, "tools.json"),
		certsDir:       dir,
		jwtCA:          filepath.Join(dir, "ca.pem"),
		issuer:         defaultIssuer,
		audience:       defaultAudience,
		proxyAuditFile: filepath.Join(dir, "proxy-audit.jsonl"),
		mcpAuditFile:   filepath.Join(dir, "audit-mcp.jsonl"),
		tlsCertFile:    filepath.Join(dir, "server-cert.pem"),
		tlsKeyFile:     filepath.Join(dir, "server-key.pem"),
	}
	stack, err := buildStack(opts)
	if err != nil {
		t.Fatalf("buildStack: %v", err)
	}
	defer stack.close()

	ts := httptest.NewTLSServer(stack.proxy.Handler())
	defer ts.Close()
	client := ts.Client()
	mcpURL := ts.URL + "/mcp"

	// initialize through the proxy.
	body, status, hdr := rpc(t, client, mcpURL, stack.opToken, "", 1, "initialize", map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "backend-test", "version": "0.0.1"},
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

	// Allowed tools/call forwarded to the loopback backend in TrustProxy mode.
	body, status, _ = rpc(t, client, mcpURL, stack.opToken, session, 2, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT * FROM t", "max_rows": 2}})
	if status != http.StatusOK {
		t.Fatalf("db_query status = %d, body=%s", status, body)
	}
	if !strings.Contains(string(body), "alice") {
		t.Fatalf("db_query result missing rows: %s", body)
	}

	// db_query with default row cap (no max_rows): all rows returned.
	body, _, _ = rpc(t, client, mcpURL, stack.opToken, session, 2, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT * FROM t"}})
	if !strings.Contains(string(body), "carol") {
		t.Fatalf("db_query(default cap) missing rows: %s", body)
	}

	// trade_exec executes for the operator token.
	body, status, _ = rpc(t, client, mcpURL, stack.opToken, session, 3, "tools/call", map[string]any{"name": "trade_exec", "arguments": map[string]any{"symbol": "AAPL", "side": "buy", "amount": 10}})
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"filled"`) {
		t.Fatalf("trade_exec status = %d, body=%s", status, body)
	}

	// Auditor token lacks mcp:trade_exec: denied at the backend capability gate.
	body, status, _ = rpc(t, client, mcpURL, stack.audToken, session, 4, "tools/call", map[string]any{"name": "trade_exec", "arguments": map[string]any{"symbol": "AAPL", "side": "buy", "amount": 10}})
	if status != http.StatusOK {
		t.Fatalf("trade_exec(deny) status = %d, body=%s", status, body)
	}
	if !strings.Contains(string(body), "-32602") || !strings.Contains(string(body), "requires capability") {
		t.Fatalf("trade_exec(deny) did not answer -32602: %s", body)
	}

	// Argument barrier on the backend.
	body, _, _ = rpc(t, client, mcpURL, stack.opToken, session, 5, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT * FROM t", "max_rows": 5000}})
	if !strings.Contains(string(body), "-32602") {
		t.Fatalf("db_query(max_rows=5000) was not refused: %s", body)
	}

	// No credential: the proxy admission gate rejects first (401).
	body, status, _ = rpc(t, client, mcpURL, "", session, 6, "tools/call", map[string]any{"name": "db_query", "arguments": map[string]any{"sql": "SELECT 1"}})
	if status != http.StatusUnauthorized {
		t.Fatalf("no-credential status = %d, want 401 (body=%s)", status, body)
	}

	stack.close()

	// Both audit sinks saw the decisions.
	proxyAudit, err := os.ReadFile(opts.proxyAuditFile)
	if err != nil {
		t.Fatalf("proxy audit file: %v", err)
	}
	if !strings.Contains(string(proxyAudit), `"proxy:/mcp"`) || !strings.Contains(string(proxyAudit), `"no client credential presented"`) {
		t.Fatalf("proxy audit missing entries: %s", proxyAudit)
	}
	mcpAudit, err := os.ReadFile(opts.mcpAuditFile)
	if err != nil {
		t.Fatalf("mcp audit file: %v", err)
	}
	if !strings.Contains(string(mcpAudit), `"agent_id":"agent-001"`) || !strings.Contains(string(mcpAudit), `"decision":"allow"`) {
		t.Fatalf("mcp audit missing allow entries: %s", mcpAudit)
	}
	if !strings.Contains(string(mcpAudit), `"decision":"deny"`) {
		t.Fatalf("mcp audit missing deny entries: %s", mcpAudit)
	}
}

// rpc performs one JSON-RPC POST and returns the raw response body (SSE frames
// collapsed to the last JSON payload), the HTTP status, and the response
// headers.
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
