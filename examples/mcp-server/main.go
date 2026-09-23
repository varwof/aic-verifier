// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command mcp-server demonstrates an AIC-gated MCP (Model Context Protocol)
// server on top of aic-verifier. The tool surface comes from tools.json; every
// initialize / tools/list / tools/call decision lands in the aic-verifier audit
// log; tools/call is denied (JSON-RPC -32602) when the caller lacks the tool's
// required_capability or an argument crosses a parameter barrier.
//
// Default mode (local mint) — one command boots everything and prints tokens:
//
//	$ go run .                        # tools.json must be in the working dir
//	# TOKEN_OP=$(...) ; TOKEN_AUD=$(...)   (print the two lines from stderr)
//
// Full-chain mode (user-signer + issuer) — do not mint locally; trust the
// issuer CA and hand this server a token minted by the aic-agent pipeline:
//
//	$ cd <aic-agent> && go run ./cmd/call-bearer --remote-issuer $ISSUER \
//	    --signer-url https://user-signer.example:8461 --target https://mcp:9444/mcp \
//	    --assertion '{"scheme_id":"mcp","capability_id":"mcp:db_query"}' ...
//	$ cd <aic-verifier>/examples/mcp-server && \
//	    go run . --no-mint --jwt-ca <issuer-ca>.pem
//
// The server pins MCP 2025-11-25 (see the mcp package).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/varwof/types/aicjwt"

	"github.com/varwof/aic-verifier"
	aicmcp "github.com/varwof/aic-verifier/mcp"
)

// flag defaults. issuer/audience are shared with the minted tokens.
const (
	defaultAddr     = ":9444"
	defaultManifest = "tools.json"
	defaultCA       = "ca.pem"
	defaultIssuer   = "aic-verifier-mcp-demo"
	defaultAudience = "mcp-demo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// mcpStack is everything run() needs to serve: the AIC-gated MCP handler, the
// demo tokens printed for the operator, and the audit logger to flush on exit.
type mcpStack struct {
	handler  http.Handler
	opToken  string
	audToken string
	audit    *aicverifier.AuditLogger
}

func (s *mcpStack) close() error {
	if s == nil || s.audit == nil {
		return nil
	}
	return s.audit.Close()
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddr, "HTTP listen address")
	toolsFile := fs.String("tools", defaultManifest, "tool manifest (tools.json)")
	jwtCA := fs.String("jwt-ca", defaultCA, "PEM CA(s) trusted for Bearer AIC-JWT (kid = CA SPKI hash)")
	issuer := fs.String("issuer", defaultIssuer, "required AIC-JWT iss claim")
	audience := fs.String("audience", defaultAudience, "required AIC-JWT aud claim")
	auditFile := fs.String("audit-file", "audit-mcp.jsonl", "aic-verifier audit JSON Lines file")
	tlsCertFile := fs.String("tls-cert", "server-cert.pem", "TLS server certificate (self-signed when missing)")
	tlsKeyFile := fs.String("tls-key", "server-key.pem", "TLS server key (self-signed when missing)")
	noMint := fs.Bool("no-mint", false, "do not mint demo tokens (full-chain mode): a token issued by user-signer+issuer must be presented")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stack, err := buildStack(*toolsFile, *jwtCA, *issuer, *audience, *auditFile, *noMint)
	if err != nil {
		fmt.Fprintf(stderr, "mcp-server: %v\n", err)
		return 1
	}
	defer stack.close()

	if !*noMint {
		fmt.Fprintf(stderr, "OPERATOR TOKEN (mcp:db_query + mcp:trade_exec):\n%s\n\n", stack.opToken)
		fmt.Fprintf(stderr, "AUDITOR TOKEN (mcp:db_query only):\n%s\n\n", stack.audToken)
	} else {
		fmt.Fprintf(stderr, "Full-chain mode: present a token minted by user-signer+issuer;\n"+
			"trust root = %s. The token must carry the mcp:* capabilities it wants to call.\n", *jwtCA)
	}

	// TLS terminator. Bearer AIC-JWT transport safety forbids bearer tokens
	// over plaintext, so the examples terminates TLS with a self-signed cert
	// (mTLS / real PKI is configured through the same fields in production).
	if err := ensureServerTLS(*tlsCertFile, *tlsKeyFile); err != nil {
		fmt.Fprintf(stderr, "mcp-server: tls: %v\n", err)
		return 1
	}
	srv := &http.Server{
		Addr:    *addr,
		Handler: stack.handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	fmt.Fprintf(stderr, "AIC-gated MCP server listening on %s (manifest %s, audit %s)\n", *addr, *toolsFile, *auditFile)
	if err := srv.ListenAndServeTLS(*tlsCertFile, *tlsKeyFile); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(stderr, "mcp-server: %v\n", err)
		return 1
	}
	return 0
}

// buildStack assembles the fail-closed MCP stack: tool manifest, audit sink,
// embedded MCP handler, optional demo-token minting and the aic-verifier
// admission wrapper. run() serves the returned handler; tests mount it on
// httptest.
func buildStack(toolsFile, jwtCA, issuer, audience, auditFile string, noMint bool) (*mcpStack, error) {
	// 1. Tool manifest (unguessable surface + per-tool barriers).
	manifest, err := os.ReadFile(toolsFile)
	if err != nil {
		return nil, err
	}
	reg, err := aicmcp.LoadJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("tools.json: %w", err)
	}

	// 2. Audit sink (nil file disables entries).
	audit, err := aicverifier.NewAuditLogger(auditFile, nil, 64<<20, 5)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}

	// 3. MCP handler: embedded mcp-go Streamable HTTP server (pinned to
	// 2025-11-25) behind the aic-verifier admission pipeline.
	mcpHandler, err := aicmcp.NewHandler(aicmcp.ServerConfig{
		ServerName:    "aic-verifier-mcp-demo",
		ServerVersion: "0.1.0",
		Audit:         audit,
	}, reg, exampleTools())
	if err != nil {
		return nil, err
	}

	// 4. Default mode: mint the two demo identities before the admission
	// handler is built (it loads JWTCAFile). In full-chain mode (--no-mint) the
	// issuer CA must already exist and the token is minted externally by the
	// user-signer + issuer pipeline.
	opToken, audToken := "", ""
	if !noMint {
		var err error
		opToken, audToken, err = mintLocalTokens(issuer, audience)
		if err != nil {
			return nil, err
		}
	}

	// 5. aic-verifier admission. Rejected credentials are additionally written by
	// the Denied hook (admission-level audits live next to the mcp_* decision
	// audits in the same file).
	conf := &aicverifier.Config{
		JWTCAFile:   jwtCA,
		JWTIssuer:   issuer,
		JWTAudience: []string{audience},
		AuthMode:    aicverifier.BearerOnly,
		RequireAIC:  true,
		// ReplayProtection is disabled because one MCP client session marshals
		// initialize + many tools/call requests over a SINGLE bearer credential;
		// one-time-use nonces would force a re-mint per JSON-RPC request. In
		// the full-chain mode the issuer mints short-lived tokens, so each new
		// token still bounds abuse; production deployments that want one-time
		// bearer semantics should share the replay store across gateways.
		ReplayProtection: boolPtr(false),
		Hooks: &aicverifier.Hooks{
			Denied: func(r *http.Request, err *aicverifier.AuthError) {
				if audit == nil {
					return
				}
				entry := aicverifier.NewAuditEntryDenied(clientIP(r), "mcp", "mcp", err.Error(), nil)
				audit.Log(entry)
			},
		},
	}
	admitted, err := conf.Handler(mcpHandler)
	if err != nil {
		return nil, fmt.Errorf("admission: %w", err)
	}
	return &mcpStack{handler: admitted, opToken: opToken, audToken: audToken, audit: audit}, nil
}

// mintLocalTokens creates (or reuses) the demo CA and signs the operator and
// auditor tokens.
func mintLocalTokens(iss, aud string) (operator, auditor string, err error) {
	if err := ensureCA(); err != nil {
		return "", "", err
	}
	ca, err := readCAPair(caCert, caKey)
	if err != nil {
		return "", "", err
	}
	operator, err = signAICJWT(ca, "agent-001", iss, aud, []aicjwt.Capability{
		{Scheme: "mcp", ID: "db_query"},
		{Scheme: "mcp", ID: "trade_exec"},
	})
	if err != nil {
		return "", "", err
	}
	auditor, err = signAICJWT(ca, "agent-002", iss, aud, []aicjwt.Capability{
		{Scheme: "mcp", ID: "db_query"},
	})
	if err != nil {
		return "", "", err
	}
	return operator, auditor, nil
}

// exampleTools implements the two manifest tools with deterministic demo
// behavior so the smoke test over curl is reproducible.
func exampleTools() map[string]aicmcp.ToolHandler {
	return map[string]aicmcp.ToolHandler{
		"db_query": func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
			maxRows := 10
			if v, ok := jsonNumber(args, "max_rows"); ok {
				maxRows = v
			}
			rows := []any{[]any{1, "alice"}, []any{2, "bob"}, []any{3, "carol"}}
			if maxRows < len(rows) {
				rows = rows[:maxRows]
			}
			return map[string]any{"rows": rows, "returned": len(rows)}, nil
		},

		"trade_exec": func(ctx context.Context, args map[string]json.RawMessage) (map[string]any, error) {
			var symbol, side string
			_ = json.Unmarshal(args["symbol"], &symbol)
			_ = json.Unmarshal(args["side"], &side)
			amount := int64(0)
			if v, ok := jsonNumber(args, "amount"); ok {
				amount = int64(v)
			}
			return map[string]any{
				"order_id": fmt.Sprintf("ord-%d", time.Now().UnixNano()),
				"symbol":   symbol,
				"side":     side,
				"amount":   amount,
				"status":   "filled",
			}, nil
		},
	}
}

// jsonNumber reads an integer argument value; a helper keeps the demo handlers
// independent from the enforcement layer's (unexported) constraint code.
func jsonNumber(args map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := args[key]
	if !ok || len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	return n, true
}

// clientIP mirrors the enforcement helper for the Denied hook's audit entry.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr != "" {
			return r.RemoteAddr
		}
		return "unknown"
	}
	return host
}

// boolPtr is a small helper for pointer-valued Config fields.
func boolPtr(v bool) *bool { return &v }

// ensureServerTLS writes a self-signed server certificate (SAN: localhost)
// when not already present, so the example runs with a single command.
func ensureServerTLS(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "aic-verifier mcp example server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := writePEM(certFile, "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(keyFile, "EC PRIVATE KEY", keyDER)
}
