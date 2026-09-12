// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Package mcp implements an AIC-gated MCP (Model Context Protocol) server for
// aic-verifier: an HTTP/Streamable transport carrying an embedded MCP server
// (github.com/mark3labs/mcp-go), guarded by the aic-verifier admission pipeline.
//
// The tool surface is declared in a tools manifest (tools.json): each tool
// binds a name/description/inputSchema (tools/list) to a required_capability
// and a set of deterministic parameter barriers (tools/call). aic-verifier
// decides who is admitted; the manifest decides what may be called and which
// arguments stay in bounds. Every initialize / tools/list / tools/call
// decision (allow or deny) is written to the aic-verifier audit log; denied
// calls are never delivered to the underlying tool handler.
//
// Protocol version: the server pins MCP 2025-11-25 (Streamable HTTP revision
// with the initialize handshake and optional SSE GET channel). Newer
// revisions (2026-07-28 stateless core) are intentionally not advertised, so
// the example stays on a stable, widely supported protocol revision.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/varwof/aic-verifier"
)

// SpecVersion is the MCP protocol revision this server pins and advertises.
// 2025-11-25 is the last revision built on the initialize handshake with an
// optional SSE GET channel. Kept as a constant so the transport and the README
// stay in sync.
const SpecVersion = "2025-11-25"

// jsonRPCInvalidParams is the code returned for denied tools/call requests
// (invalid tool / capability barrier / argument barrier). The mcp-go SDK maps
// tool-handler errors to INTERNAL_ERROR, so enforcement answers -32602 itself.
const jsonRPCInvalidParams = int32(-32602)

// ToolHandler executes a permitted tool call. args holds the raw JSON values
// of the arguments already proven to satisfy every parameter barrier.
type ToolHandler func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error)

// ServerConfig configures the produced http.Handler.
type ServerConfig struct {
	// ServerName is returned in initialize (implementation.name).
	ServerName string
	// ServerVersion is returned in initialize (implementation.version).
	ServerVersion string
	// Audit is the aic-verifier audit logger receiving every MCP decision
	// (allow + deny). Nil disables MCP-level audit entries.
	Audit *aicverifier.AuditLogger
	// Logger emits operational logs (default slog.Default()).
	Logger *slog.Logger
	// TrustProxy makes the handler trust the identity headers the aic-verifier
	// reverse proxy injects after admission (X-AIC-*), instead of looking for
	// an in-process AuthContext. Use this ONLY for a backend reachable
	// exclusively from the aic-verifier proxy on a trusted network (e.g. a
	// loopback listener); the headers are trivially forgeable by any direct
	// client, so a directly reachable backend must keep the bearer/mTLS
	// admission wrapper instead.
	TrustProxy bool
}

// NewHandler builds the AIC-gated MCP http.Handler for the given manifest
// (registry) and tool implementations. Every tool in the registry must have a
// handler in handlers; a missing handler is a startup error (fail-closed).
//
// The returned handler performs per-tool capability and parameter-barrier
// enforcement plus audit. It expects to be wrapped by the aic-verifier admission
// handler (Config.Handler) so AuthContext is present in the request context
// (or, with TrustProxy, to run as a trusted-loopback backend behind the
// aic-verifier reverse proxy which forwards the verified identity in X-AIC-*
// headers); requests that never went through either path fail closed at
// tools/call.
func NewHandler(sc ServerConfig, reg *Registry, handlers map[string]ToolHandler) (http.Handler, error) {
	if reg == nil {
		return nil, fmt.Errorf("mcp: nil tool registry")
	}
	if sc.ServerName == "" {
		sc.ServerName = "aic-verifier-mcp"
	}
	if sc.ServerVersion == "" {
		sc.ServerVersion = "0.1.0"
	}
	logger := sc.Logger
	if logger == nil {
		logger = slog.Default()
	}

	srv := server.NewMCPServer(sc.ServerName, sc.ServerVersion)
	for i := range reg.Tools {
		spec := &reg.Tools[i]
		h, ok := handlers[spec.Name]
		if !ok {
			return nil, fmt.Errorf("mcp: no handler registered for tool %q", spec.Name)
		}
		tool := mcp.Tool{
			Name:           spec.Name,
			Description:    spec.Description,
			RawInputSchema: spec.InputSchema,
		}
		impl, err := newToolImpl(spec, h)
		if err != nil {
			return nil, fmt.Errorf("mcp: tool %q: %w", spec.Name, err)
		}
		srv.AddTool(tool, impl.handle)
	}

	transport := server.NewStreamableHTTPServer(srv,
		server.WithStreamableHTTPProtocolVersions(SpecVersion),
	)

	return &enforcement{handler: transport, reg: reg, audit: sc.Audit, log: logger, trustProxy: sc.TrustProxy}, nil
}

// enforcement sits between the aic-verifier admission handler (outer) and the
// embedded MCP transport. tools/call is gated on the capability binding and
// the parameter barriers BEFORE the request reaches the tool handler: a denied
// call answers with a JSON-RPC error (code -32602) and an audit WARN and is
// never forwarded. Every other JSON-RPC method passes through and is audited
// after the fact. All per-request state lives on the stack (race-free under
// concurrent requests).
type enforcement struct {
	handler    http.Handler
	reg        *Registry
	audit      *aicverifier.AuditLogger
	log        *slog.Logger
	trustProxy bool
}

// mcpAuthKey carries the admitted AuthContext through to tool handlers. It is
// this package's own unexported key: only the enforcement layer sets it, so
// tool wrappers without it always fail closed.
type mcpAuthKey struct{}

// ServeHTTP implements http.Handler.
func (e *enforcement) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ac *aicverifier.AuthContext
	if e.trustProxy {
		// Identity arrives in the server-asserted X-AIC-* headers (proxy
		// admission already ran upstream and stripped the credential + any
		// client-supplied identity namespace). Missing headers fail closed:
		// ac stays nil and capsAllow / the tool wrapper deny.
		ac = aicverifier.AuthContextFromHeaders(r)
	} else {
		ac = aicverifier.FromContext(r.Context())
	}
	// Re-attach the admitted identity under this package's own context key so
	// the tool handlers (executed deep inside the mcp-go transport) see it. The
	// key is unexported here: a tool wrapper that runs without the enforcement
	// layer NEVER sees an identity, so direct SDK embedding fails closed.
	if ac != nil {
		r = r.WithContext(context.WithValue(r.Context(), mcpAuthKey{}, ac))
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	base := auditStart(e.audit, ac, r)

	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if len(body) > 0 && json.Unmarshal(body, &msg) == nil && msg.Method != "" {
		e.serveMessage(w, r, ac, msg.ID, msg.Method, msg.Params, base)
		return
	}
	e.handler.ServeHTTP(w, r)
}

// serveMessage routes one JSON-RPC message. tools/call is gated in-band; the
// other methods (initialize, ping, tools/list, notifications) pass through.
func (e *enforcement) serveMessage(w http.ResponseWriter, r *http.Request, ac *aicverifier.AuthContext, id json.RawMessage, method string, params []byte, base *auditBase) {
	if method != "tools/call" {
		e.handler.ServeHTTP(w, r)
		base.auditAllow(method, "", nil)
		return
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	spec := e.reg.Find(p.Name)
	if spec == nil {
		msg := fmt.Sprintf("unknown tool %q", p.Name)
		e.deny(w, id, msg)
		base.auditDeny("tools/call", p.Name, msg, p.Arguments)
		return
	}
	if !capsAllow(ac, spec.RequiredCapability) {
		msg := fmt.Sprintf("tool %q requires capability %q", p.Name, spec.RequiredCapability)
		e.deny(w, id, msg)
		base.auditDeny("tools/call", p.Name, msg, p.Arguments)
		return
	}
	if err := validateArgs(spec, p.Arguments); err != nil {
		msg := fmt.Sprintf("tool %q: %v", p.Name, err)
		e.deny(w, id, msg)
		base.auditDeny("tools/call", p.Name, msg, p.Arguments)
		return
	}
	e.handler.ServeHTTP(w, r)
	base.auditAllow("tools/call", spec.Name, p.Arguments)
}

// deny writes a JSON-RPC error response (code -32602).
func (e *enforcement) deny(w http.ResponseWriter, id json.RawMessage, message string) {
	resp, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    jsonRPCInvalidParams,
			"message": message,
		},
	})
	if err != nil {
		http.Error(w, "enforcement error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// capsAllow reports whether the admitted identity carries the tool capability.
// Both the full scheme:capabilityId form (from the parsed AIC) and the bare
// capability id list are matched against the required pattern.
func capsAllow(ac *aicverifier.AuthContext, required string) bool {
	if required == "" {
		return true
	}
	if ac != nil && ac.AIC != nil {
		for _, c := range ac.AIC.Capabilities {
			if aicverifier.MatchCapability(c.FullID(), required) {
				return true
			}
		}
	}
	if ac != nil {
		for _, id := range ac.Capabilities {
			if aicverifier.MatchCapability(id, required) {
				return true
			}
		}
	}
	return false
}
