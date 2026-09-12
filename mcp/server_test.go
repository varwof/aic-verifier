// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcp_server "github.com/mark3labs/mcp-go/server"

	"github.com/varwof/aic-verifier"
	pki "github.com/varwof/types"
)

func newTestHandler(t *testing.T, counters *map[string]int) (*Registry, http.Handler, *aicverifier.AuditLogger, string) {
	t.Helper()
	reg := loadTestRegistry(t)
	logger, path := newTestAudit(t)
	handlers := map[string]ToolHandler{}
	handlers["db_query"] = func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
		(*counters)["db_query"]++
		var sql string
		_ = json.Unmarshal(args["sql"], &sql)
		return map[string]any{"rows": []any{}, "sql": sql}, nil
	}
	handlers["bulk_load"] = func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
		(*counters)["bulk_load"]++
		return map[string]any{"loaded": 1}, nil
	}
	h, err := NewHandler(ServerConfig{ServerName: "test", Audit: logger}, reg, handlers)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return reg, h, logger, path
}

func newTestAudit(t *testing.T) (*aicverifier.AuditLogger, string) {
	t.Helper()
	path := t.TempDir() + "/audit.jsonl"
	l, err := aicverifier.NewAuditLogger(path, nil, 1<<20, 2)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

// buildMCPRequest assembles a full JSON-RPC request with the admitted identity
// attached exactly the way enforcement.ServeHTTP re-attaches it in production.
func buildMCPRequest(ac *aicverifier.AuthContext, id string, method string, params []byte, sessionID string) *http.Request {
	msg, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"method":  method,
		"params":  json.RawMessage(params),
	})
	req := httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", bytes.NewReader(msg))
	req.RemoteAddr = "[::1]:4444"
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set(mcp_server.HeaderKeySessionID, sessionID)
	}
	if ac != nil {
		req = req.WithContext(context.WithValue(req.Context(), mcpAuthKey{}, ac))
	}
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	return req
}

// enforceCall builds a full JSON-RPC request, replays it through the
// enforcement layer with an explicit AuthContext, and returns the recorder.
// FromContext wiring itself is covered by TestServeHTTPFailClosed; this helper
// exercises every allow/deny branch with a controlled identity and the same
// context-identity an admitted request carries.
func enforceCall(e *enforcement, ac *aicverifier.AuthContext, id string, method string, params []byte) *httptest.ResponseRecorder {
	req := buildMCPRequest(ac, id, method, params, "")
	rec := httptest.NewRecorder()
	base := auditStart(e.audit, ac, req)
	e.serveMessage(rec, req, ac, json.RawMessage(id), method, params, base)
	return rec
}

// initSession runs a full initialize through the enforcement layer and returns
// the session ID the server assigned (echoed by subsequent requests).
func initSession(t *testing.T, e *enforcement, ac *aicverifier.AuthContext) string {
	t.Helper()
	params := mcp.InitializeParams{
		ProtocolVersion: "2025-11-25",
		ClientInfo:      mcp.Implementation{Name: "itest", Version: "1.0"},
	}
	data, _ := json.Marshal(params)
	rec := enforceCall(e, ac, `1`, "initialize", data)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize: code = %d, body=%s", rec.Code, rec.Body.String())
	}
	if sess := rec.Result().Header.Get(mcp_server.HeaderKeySessionID); sess == "" {
		t.Fatalf("initialize did not assign a session id")
	} else {
		return sess
	}
	return ""
}

// enforceCallSession is enforceCall with the server-assigned session ID echoed
// back, as a real MCP client does after initialize.
func enforceCallSession(e *enforcement, ac *aicverifier.AuthContext, id string, method string, params []byte, sessionID string) *httptest.ResponseRecorder {
	req := buildMCPRequest(ac, id, method, params, sessionID)
	rec := httptest.NewRecorder()
	base := auditStart(e.audit, ac, req)
	e.serveMessage(rec, req, ac, json.RawMessage(id), method, params, base)
	return rec
}

// readAudit polls the audit file until it contains needle or the deadline
// passes. Returns the parsed entries seen.
func readAudit(t *testing.T, path, needle string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(data), needle) {
			return parseAuditLines(t, data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(path)
	t.Fatalf("audit file never contained %q; last content:\n%s", needle, string(data))
	return nil
}

func parseAuditLines(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var env struct {
			Entry map[string]any `json:"entry"`
			TST   string         `json:"tst"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			t.Fatalf("bad audit line: %v: %s", err, line)
		}
		if env.Entry == nil {
			t.Fatalf("audit line without entry: %s", line)
		}
		if env.TST != "" {
			env.Entry["_tst"] = env.TST
		}
		out = append(out, env.Entry)
	}
	return out
}

func TestNewHandlerMissingTool(t *testing.T) {
	reg := loadTestRegistry(t)
	if _, err := NewHandler(ServerConfig{}, reg, map[string]ToolHandler{}); err == nil {
		t.Fatalf("expected missing-handler error")
	}
	if _, err := NewHandler(ServerConfig{}, nil, nil); err == nil {
		t.Fatalf("expected nil registry error")
	}
}

func TestServeMessageDenyUnknownTool(t *testing.T) {
	counters := map[string]int{}
	_, h, _, path := newTestHandler(t, &counters)
	e := h.(*enforcement)
	ac := &aicverifier.AuthContext{AgentID: "agent-1", Capabilities: []string{"mcp:db_query"}}
	rec := enforceCall(e, ac, `1`, "tools/call", json.RawMessage(`{"name":"bogus","arguments":{"sql":"x"}}`))
	assertJSONError(t, rec, "unknown tool")
	if counters["db_query"] != 0 {
		t.Fatalf("handler ran for unknown tool")
	}
	lines := readAudit(t, path, `"action":"mcp_tools_call"`)
	if got := lines[len(lines)-1]["decision"]; got != "deny" {
		t.Fatalf("decision = %v, want deny", got)
	}
	if got := lines[len(lines)-1]["level"]; got != "WARN" {
		t.Fatalf("level = %v, want WARN", got)
	}
}

func TestServeMessageDenyCapability(t *testing.T) {
	counters := map[string]int{}
	_, h, _, path := newTestHandler(t, &counters)
	e := h.(*enforcement)
	ac := &aicverifier.AuthContext{AgentID: "agent-1", Capabilities: []string{"mcp:db_read"}}
	rec := enforceCall(e, ac, `2`, "tools/call", json.RawMessage(`{"name":"db_query","arguments":{"sql":"select 1","max_rows":10}}`))
	assertJSONError(t, rec, "requires capability")
	if counters["db_query"] != 0 {
		t.Fatalf("handler ran without capability")
	}
	lines := readAudit(t, path, `"decision":"deny"`)
	e2 := lines[len(lines)-1]
	if e2["deny_reason"] == "" {
		t.Fatalf("missing deny_reason")
	}
	if e2["agent_id"] != "agent-1" {
		t.Fatalf("agent_id = %v", e2["agent_id"])
	}
	if !strings.Contains(e2["target_id"].(string), "sha256:") {
		t.Fatalf("target_id lacks digest: %v", e2["target_id"])
	}
}

func TestServeMessageDenyOutOfBoundsArgs(t *testing.T) {
	counters := map[string]int{}
	_, h, _, _ := newTestHandler(t, &counters)
	e := h.(*enforcement)
	rec := enforceCall(e, &aicverifier.AuthContext{Capabilities: []string{"mcp:db_query"}},
		`3`, "tools/call", json.RawMessage(`{"name":"db_query","arguments":{"sql":"select 1","max_rows":5000}}`))
	assertJSONError(t, rec, "> max 1000")
	if counters["db_query"] != 0 {
		t.Fatalf("handler ran with out-of-bounds args")
	}
}

func TestServeMessageAllow(t *testing.T) {
	counters := map[string]int{}
	_, h, _, path := newTestHandler(t, &counters)
	e := h.(*enforcement)
	ac := &aicverifier.AuthContext{AgentID: "agent-1", Principal: "p1", Capabilities: []string{"mcp:db_query"}}
	sess := initSession(t, e, ac)
	rec := enforceCallSession(e, ac, `4`, "tools/call", json.RawMessage(`{"name":"db_query","arguments":{"sql":"select 1","max_rows":50}}`), sess)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"structuredContent"`) || !strings.Contains(body, "select 1") {
		t.Fatalf("unexpected result body: %s", body)
	}
	if counters["db_query"] != 1 {
		t.Fatalf("handler ran %d times, want 1", counters["db_query"])
	}
	lines := readAudit(t, path, `"action":"mcp_tools_call"`)
	last := lines[len(lines)-1]
	if last["decision"] != "allow" || last["level"] != "INFO" {
		t.Fatalf("audit = decision %v level %v", last["decision"], last["level"])
	}
	ti := last["target_id"].(string)
	if !strings.HasPrefix(ti, "db_query args{max_rows,sql} sha256:") {
		t.Fatalf("target_id redaction mismatch: %s", ti)
	}
}

func TestServeMessageInitializePassThrough(t *testing.T) {
	counters := map[string]int{}
	_, h, _, path := newTestHandler(t, &counters)
	e := h.(*enforcement)
	ac := &aicverifier.AuthContext{AgentID: "agent-1"}
	params := mcp.InitializeParams{
		ProtocolVersion: "2025-11-25",
		ClientInfo:      mcp.Implementation{Name: "itest", Version: "1.0"},
	}
	data, _ := json.Marshal(params)
	rec := enforceCall(e, ac, `1`, "initialize", data)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("protocol not negotiated: %s", body)
	}
	if !strings.Contains(body, `"name":"test"`) {
		t.Fatalf("serverInfo missing: %s", body)
	}
	readAudit(t, path, `"action":"mcp_initialize"`)
}

func TestServeHTTPFailClosed(t *testing.T) {
	counters := map[string]int{}
	_, h, _, _ := newTestHandler(t, &counters)
	// No admission middleware put an AuthContext in the context; capability
	// gated tools must fail closed rather than run.
	body := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"db_query","arguments":{"sql":"select 1"}}}`)
	req := httptest.NewRequest(http.MethodPost, "http://mcp.test/mcp", bytes.NewReader(body))
	req.RemoteAddr = "10.0.0.9:999"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertJSONError(t, rec, "requires capability")
	if counters["db_query"] != 0 {
		t.Fatalf("handler ran without admission")
	}
}

func TestToolImplFailClosed(t *testing.T) {
	reg := loadTestRegistry(t)
	spec := reg.Find("db_query")
	ran := false
	impl, err := newToolImpl(spec, func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
		ran = true
		return map[string]any{"rows": 0}, nil
	})
	if err != nil {
		t.Fatalf("newToolImpl: %v", err)
	}
	// No AuthContext in context (the enforcement guarded the path already, but
	// a direct SDK embedder must still fail closed).
	out, err := impl.handle(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "db_query", Arguments: map[string]any{"sql": "select 1", "max_rows": 10}},
	})
	if err == nil || !strings.Contains(err.Error(), "unauthenticated") {
		t.Fatalf("expected fail-closed error, got %v (result %v)", err, out)
	}
	if ran {
		t.Fatalf("handler ran without admission")
	}
}

func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, wantSubstr string) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with JSON-RPC error", rec.Code)
	}
	body := rec.Body.String()
	var resp struct {
		Error struct {
			Code    int32  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("not a JSON-RPC error response: %v (%s)", err, body)
	}
	if resp.Error.Code != jsonRPCInvalidParams {
		t.Fatalf("code = %d, want %d (%s)", resp.Error.Code, jsonRPCInvalidParams, body)
	}
	if !strings.Contains(resp.Error.Message, wantSubstr) {
		t.Fatalf("message %q missing %q", resp.Error.Message, wantSubstr)
	}
}

func TestCapsAllow(t *testing.T) {
	ac := &aicverifier.AuthContext{
		Capabilities: []string{"mcp:db_query"},
		AIC: &aicverifier.AIC{
			Capabilities: []pki.Capability{{SchemeId: "mcp", CapabilityId: "db_write"}},
		},
	}
	cases := []struct {
		required string
		want     bool
	}{
		{"", true},
		{"mcp:db_query", true},
		{"db_query", false},
		{"mcp:*", true},
		{"mcp:db_write", true},
		{"mcp:admin", false},
		{"scheme:db_query", false},
	}
	for i, tc := range cases {
		if got := capsAllow(ac, tc.required); got != tc.want {
			t.Errorf("case %d (%q): got %v want %v", i, tc.required, got, tc.want)
		}
	}
	if capsAllow(nil, "x") {
		t.Errorf("nil auth context must not grant capabilities")
	}
	if !capsAllow(nil, "") {
		t.Errorf("empty requirement is always satisfied")
	}
}

func TestTrustProxyIdentityFromHeaders(t *testing.T) {
	counters := map[string]int{}
	reg := loadTestRegistry(t)
	logger, path := newTestAudit(t)
	handlers := map[string]ToolHandler{
		"db_query": func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
			counters["db_query"]++
			return map[string]any{"rows": 1}, nil
		},
		"bulk_load": func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
			counters["bulk_load"]++
			return map[string]any{"loaded": 1}, nil
		},
	}
	h, err := NewHandler(ServerConfig{ServerName: "test", Audit: logger, TrustProxy: true}, reg, handlers)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	e := h.(*enforcement)

	headerReq := func(agentID string, caps []string, id string, method string, params []byte, session string) *http.Request {
		req := buildMCPRequest(nil, id, method, params, session)
		req.Header.Set("X-AIC-Agent-Id", agentID)
		req.Header.Set("X-AIC-Principal-Uid", "principal-"+agentID)
		if len(caps) > 0 {
			req.Header.Set("X-AIC-Capabilities-Full", strings.Join(caps, ","))
		}
		return req
	}
	do := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	// initialize with operator identity headers: the backend has NO in-process
	// AuthContext (nil context), only the server-asserted headers.
	initParams, _ := json.Marshal(mcp.InitializeParams{
		ProtocolVersion: "2025-11-25",
		ClientInfo:      mcp.Implementation{Name: "itest", Version: "1.0"},
	})
	rec := do(headerReq("agent-001", []string{"mcp:db_query", "mcp:trade_exec"}, `10`, "initialize", initParams, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize: code=%d body=%s", rec.Code, rec.Body.String())
	}
	sess := rec.Result().Header.Get(mcp_server.HeaderKeySessionID)
	if sess == "" {
		t.Fatal("no session id after initialize")
	}

	// tools/call allow: identity came from headers only, capability + barriers pass.
	rec = do(headerReq("agent-001", []string{"mcp:db_query", "mcp:trade_exec"}, `11`, "tools/call",
		json.RawMessage(`{"name":"db_query","arguments":{"sql":"select 1","max_rows":10}}`), sess))
	if !strings.Contains(rec.Body.String(), `"rows":1`) {
		t.Fatalf("db_query allow body = %s", rec.Body.String())
	}
	if counters["db_query"] != 1 {
		t.Fatalf("db_query handler not reached via headers identity")
	}

	// capability deny: auditor (db_query only) calls bulk_load → -32602.
	rec = do(headerReq("agent-002", []string{"mcp:db_query"}, `12`, "tools/call",
		json.RawMessage(`{"name":"bulk_load","arguments":{"ids":["a","b"]}}`), sess))
	assertJSONError(t, rec, "requires capability")
	if counters["bulk_load"] != 0 {
		t.Fatalf("bulk_load ran without capability")
	}

	// fail closed: no identity headers at all → capability deny (ac nil).
	rec = do(buildMCPRequest(nil, `13`, "tools/call",
		json.RawMessage(`{"name":"db_query","arguments":{"sql":"select 1","max_rows":10}}`), sess))
	assertJSONError(t, rec, "requires capability")
	if counters["db_query"] != 1 {
		t.Fatalf("db_query ran without identity headers")
	}

	// audit: allow + deny entries present, deny carries the header-supplied agent.
	lines := readAudit(t, path, `"action":"mcp_tools_call"`)
	var sawAllow, sawDenAgent bool
	for _, e2 := range lines {
		if e2["decision"] == "allow" && e2["agent_id"] == "agent-001" {
			sawAllow = true
		}
		if e2["decision"] == "deny" && e2["agent_id"] == "agent-002" {
			sawDenAgent = true
		}
	}
	if !sawAllow || !sawDenAgent {
		t.Fatalf("missing allow/deny audit entries; entries: %v", lines)
	}
}
