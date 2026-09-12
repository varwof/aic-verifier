// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/varwof/aic-verifier"
)

// MCP audit actions written to the aic-verifier audit log.
const (
	auditInitialize = "mcp_initialize"
	auditToolsList  = "mcp_tools_list"
	auditToolsCall  = "mcp_tools_call"
)

// auditBase carries the identity + timing + audit logger for one JSON-RPC
// request. All allow/deny decisions during the request share one entry so the
// record is internally consistent.
type auditBase struct {
	start  time.Time
	ac     *aicverifier.AuthContext
	logger *aicverifier.AuditLogger
	entry  aicverifier.AuditEntry
}

// auditStart seeds the audit entry from the admitted identity (AgentId,
// PrincipalUid, capabilities, DA hash and AIC fingerprint) plus the request
// source. Pass nil logger to disable MCP-level audit entries.
func auditStart(logger *aicverifier.AuditLogger, ac *aicverifier.AuthContext, r *http.Request) *auditBase {
	base := &auditBase{start: time.Now(), ac: ac, logger: logger}
	e := aicverifier.NewAuditEntryFromConn(clientIP(r), "mcp", "mcp", certFromAC(ac))
	e.Action = ""
	e.Target = "mcp"
	if ac != nil {
		e.AgentId = ac.AgentID
		e.PrincipalUid = ac.Principal
		e.Capabilities = append([]string(nil), ac.Capabilities...)
		e.DaHash = aicverifier.DAHash(ac.ClientCert)
		e.AICFingerprint = aicverifier.AICFingerprint(ac.ClientCert)
	}
	base.entry = e
	return base
}

// certFromAC returns the identity certificate used to seed the audit entry.
// For Bearer AIC-JWT, the synthesized carrier certificate carries the AIC, so
// this yields the same agent/principal/caps that admission derived.
func certFromAC(ac *aicverifier.AuthContext) *x509.Certificate {
	if ac == nil {
		return nil
	}
	return ac.ClientCert
}

// auditAllow logs an admitted MCP request. The action derives from the
// JSON-RPC method; for tools/call the entry carries the redacted argument
// digest in TargetID.
func (b *auditBase) auditAllow(method, toolName string, args json.RawMessage) {
	if b.logger == nil {
		return
	}
	e := b.entry
	e.Action = actionForMethod(method)
	e.Decision = "allow"
	e.Level = "INFO"
	e.TargetID = targetID(toolName, method, args)
	e.Duration = time.Since(b.start).Round(time.Millisecond).String()
	b.log(e)
}

// auditDeny logs a rejected MCP request (always WARN with the failure reason).
func (b *auditBase) auditDeny(method, toolName, reason string, args json.RawMessage) {
	if b.logger == nil {
		return
	}
	e := b.entry
	e.Action = actionForMethod(method)
	e.Decision = "deny"
	e.Level = "WARN"
	e.DenyReason = reason
	e.TargetID = targetID(toolName, method, args)
	e.Duration = time.Since(b.start).Round(time.Millisecond).String()
	b.log(e)
}

func (b *auditBase) log(e aicverifier.AuditEntry) {
	b.logger.Log(e)
}

// actionForMethod maps a JSON-RPC method to its audit action.
func actionForMethod(method string) string {
	switch method {
	case "initialize":
		return auditInitialize
	case "tools/list":
		return auditToolsList
	case "tools/call":
		return auditToolsCall
	default:
		return "mcp_" + strings.ReplaceAll(strings.ReplaceAll(method, "/", "_"), ".", "_")
	}
}

// targetID builds the audit TargetID. For tools/call it is
// "<tool> args{k,v} sha256:<digest>;bytes:<n>" — argument names visible,
// values never echoed (redaction by digest, same style as supervision
// evidence summaries).
func targetID(toolName, method string, args json.RawMessage) string {
	if len(args) == 0 {
		if toolName != "" {
			return toolName
		}
		return method
	}
	var keys []string
	var values map[string]json.RawMessage
	if json.Unmarshal(args, &values) == nil {
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	sum := sha256.Sum256(args)
	return fmt.Sprintf("%s args{%s} sha256:%s;bytes:%d",
		toolName, strings.Join(keys, ","), hex.EncodeToString(sum[:]), len(args))
}

// clientIP extracts the caller address from RemoteAddr.
func clientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr != "" {
			return r.RemoteAddr
		}
		return "unknown"
	}
	return host
}
