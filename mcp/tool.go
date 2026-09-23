// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/varwof/aic-verifier"
)

// toolImpl binds a ToolSpec to its handler with the capability gate and the
// parameter barriers re-checked inside the handler (defense in depth: the
// enforcement middleware already rejected out-of-policy calls, but a direct
// SDK invocation — tests, embedders — goes through the same checks).
type toolImpl struct {
	spec *ToolSpec
	impl ToolHandler
}

// toolAuthKey carries the admitted identity into a tool handler's derived
// context (see newToolImpl.handle). It is distinct from mcpAuthKey so handler
// code receives the identity only when the enforcement layer ran.
type toolAuthKey struct{}

// AuthContextFromToolContext returns the admitted identity that a tool handler
// received. It is nil when the handler ran outside the aic-verifier
// enforcement layer (fail-closed for directly embedded SDK users).
func AuthContextFromToolContext(ctx context.Context) *aicverifier.AuthContext {
	if ctx == nil {
		return nil
	}
	ac, _ := ctx.Value(toolAuthKey{}).(*aicverifier.AuthContext)
	return ac
}

func newToolImpl(spec *ToolSpec, impl ToolHandler) (*toolImpl, error) {
	if spec == nil || impl == nil {
		return nil, fmt.Errorf("nil spec or handler")
	}
	return &toolImpl{spec: spec, impl: impl}, nil
}

func (t *toolImpl) handle(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// The enforcement middleware guarantees ac is present (and already gated
	// capability + barriers); an embedder that calls the SDK directly without
	// the enforcement layer fails closed because the context key is never set.
	ac, _ := ctx.Value(mcpAuthKey{}).(*aicverifier.AuthContext)
	if ac == nil {
		return nil, fmt.Errorf("tool %q: unauthenticated", t.spec.Name)
	}
	if !capsAllow(ac, t.spec.RequiredCapability) {
		return nil, fmt.Errorf("tool %q requires capability %q", t.spec.Name, t.spec.RequiredCapability)
	}
	// Surface the admitted identity to the tool handler. The key stays a
	// per-request value (never the mcpAuthKey): handler code calls
	// AuthContextFromToolContext, not FromContext, so a handler executed
	// without the enforcement layer still fails closed.
	if ac != nil {
		ctx = context.WithValue(ctx, toolAuthKey{}, ac)
	}
	raw := req.Params.RawArguments
	if len(raw) == 0 {
		if args, ok := req.Params.Arguments.(map[string]any); ok {
			b, err := json.Marshal(args)
			if err != nil {
				return nil, fmt.Errorf("tool %q: arguments: %w", t.spec.Name, err)
			}
			raw = b
		}
	}
	if err := validateArgs(t.spec, raw); err != nil {
		return nil, err
	}

	var args map[string]json.RawMessage
	_ = json.Unmarshal(raw, &args)
	out, err := t.impl(ctx, args)
	if err != nil {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{mcp.TextContent{Type: "text", Text: err.Error()}},
		}, nil
	}
	st, _ := json.Marshal(out)
	return &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.TextContent{Type: "text", Text: string(st)}},
		StructuredContent: out,
	}, nil
}
