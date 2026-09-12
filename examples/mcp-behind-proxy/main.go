// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command mcp-behind-proxy runs the AIC-gated MCP server in its canonical
// deployment topology: the aic-verifier reverse proxy terminates TLS, runs the
// bearer AIC-JWT admission pipeline and forwards each admitted request to a
// loopback-only MCP backend, which trusts the proxy's server-asserted X-AIC-*
// identity headers (aic-verifier/mcp TrustProxy mode) instead of re-verifying a
// credential. One command boots the whole stack:
//
//	$ go run .                        # from examples/mcp-behind-proxy
//	OPERATOR TOKEN (mcp:db_query + mcp:trade_exec): <…>   # stderr, $OP
//	AUDITOR TOKEN (mcp:db_query only):           <…>         # stderr, $AUD
//	AIC-gated MCP proxy listening on :9443 -> backend http://127.0.0.1:<port>
//
//	$ curl -k https://localhost:9443/mcp \
//	     -H "Content-Type: application/json" -H "Authorization: Bearer $OP" \
//	     -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
//	          "params":{"protocolVersion":"2025-11-25","capabilities":{},
//	          "clientInfo":{"name":"curl","version":"1.0"}}}'
//
// Full-chain mode (user-signer + issuer) is identical to the standalone
// example: --no-mint --jwt-ca <issuer-ca>.pem and a token minted by the
// aic-agent pipeline.
//
// Both layers are audited: proxy admission decisions go to --proxy-audit-file,
// the MCP initialize / tools/list / tools/call decisions to --mcp-audit-file.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/varwof/types/aicjwt"

	"github.com/varwof/aic-verifier"
	aicmcp "github.com/varwof/aic-verifier/mcp"
)

// flag defaults. issuer/audience are shared with the minted tokens.
const (
	defaultAddr     = ":9443"
	defaultManifest = "../mcp-server/tools.json"
	defaultCA       = "ca.pem"
	defaultIssuer   = "aic-verifier-mcp-demo"
	defaultAudience = "mcp-demo"
)

func main() {
	addr := flag.String("addr", defaultAddr, "aic-verifier proxy listen address (TLS)")
	backendPort := flag.String("backend-port", "0", "MCP backend TCP port on 127.0.0.1 (0 = auto-assigned)")
	toolsFile := flag.String("tools", defaultManifest, "tool manifest (tools.json)")
	jwtCA := flag.String("jwt-ca", defaultCA, "PEM CA(s) trusted for Bearer AIC-JWT (kid = CA SPKI hash)")
	issuer := flag.String("issuer", defaultIssuer, "required AIC-JWT iss claim")
	audience := flag.String("audience", defaultAudience, "required AIC-JWT aud claim")
	proxyAuditFile := flag.String("proxy-audit-file", "proxy-audit.jsonl", "aic-verifier audit JSON Lines file for proxy admission decisions")
	mcpAuditFile := flag.String("mcp-audit-file", "audit-mcp.jsonl", "aic-verifier audit JSON Lines file for MCP decisions")
	tlsCertFile := flag.String("tls-cert", "server-cert.pem", "TLS server certificate (self-signed when missing)")
	tlsKeyFile := flag.String("tls-key", "server-key.pem", "TLS server key (self-signed when missing)")
	noMint := flag.Bool("no-mint", false, "do not mint demo tokens (full-chain mode): a token issued by user-signer+issuer must be presented")
	flag.Parse()

	// 1. Tool manifest (unguessable surface + per-tool barriers).
	manifest, err := os.ReadFile(*toolsFile)
	if err != nil {
		log.Fatalf("mcp-behind-proxy: read %s: %v", *toolsFile, err)
	}
	reg, err := aicmcp.LoadJSON(manifest)
	if err != nil {
		log.Fatalf("mcp-behind-proxy: tools.json: %v", err)
	}

	// 2. Two audit sinks: the proxy's admission pipeline and the MCP backend's
	// decision layer. Separate files because both run in this process.
	proxyAudit, err := aicverifier.NewAuditLogger(*proxyAuditFile, nil, 64<<20, 5)
	if err != nil {
		log.Fatalf("mcp-behind-proxy: proxy audit: %v", err)
	}
	mcpAudit, err := aicverifier.NewAuditLogger(*mcpAuditFile, nil, 64<<20, 5)
	if err != nil {
		log.Fatalf("mcp-behind-proxy: mcp audit: %v", err)
	}

	// 3. MCP backend handler: embedded mcp-go Streamable HTTP server (pinned
	// to 2025-11-25) in TrustProxy mode. Identity arrives in the X-AIC-*
	// headers the proxy injects after admission; the backend does NOT re-verify
	// a credential (the proxy strips it) and MUST NOT be reachable except via
	// the proxy — we bind it to 127.0.0.1 below.
	mcpHandler, err := aicmcp.NewHandler(aicmcp.ServerConfig{
		ServerName:    "aic-verifier-mcp-demo",
		ServerVersion: "0.1.0",
		Audit:         mcpAudit,
		TrustProxy:    true,
	}, reg, exampleTools())
	if err != nil {
		log.Fatalf("mcp-behind-proxy: %v", err)
	}

	// 4. Loopback-only backend listener. Plaintext is fine: it is reachable
	// only from this process on the loopback interface.
	ln, err := net.Listen("tcp", "127.0.0.1:"+*backendPort)
	if err != nil {
		log.Fatalf("mcp-behind-proxy: backend listen: %v", err)
	}
	backendURL := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}
	backend := &http.Server{Handler: mcpHandler}
	go func() {
		if err := backend.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("mcp-behind-proxy: backend: %v", err)
		}
	}()

	// 5. Default mode: mint the two demo identities before the admission
	// handler is built (it loads JWTCAFile). In full-chain mode (--no-mint) the
	// issuer CA must already exist and the token is minted externally by the
	// user-signer + issuer pipeline.
	opToken, audToken := "", ""
	if !*noMint {
		var err error
		opToken, audToken, err = mintLocalTokens(*issuer, *audience)
		if err != nil {
			log.Fatalf("mcp-behind-proxy: mint: %v", err)
		}
	}

	// 6. The reverse proxy: bearer admission + unified TLS termination. The
	// /mcp route forwards admitted requests to the loopback MCP backend and
	// injects the server-asserted X-AIC-* identity headers (IdentityAIC mode);
	// the client-supplied Authorization header and the whole identity header
	// namespace are stripped before forwarding (SDK reverse-proxy policy).
	conf := &aicverifier.Config{
		JWTCAFile:   *jwtCA,
		JWTIssuer:   *issuer,
		JWTAudience: []string{*audience},
		AuthMode:    aicverifier.BearerOnly,
		RequireAIC:  true,
		// ReplayProtection is disabled because one MCP client session marshals
		// initialize + many tools/call requests over a SINGLE bearer credential;
		// one-time-use nonces would force a re-mint per JSON-RPC request. In
		// the full-chain mode the issuer mints short-lived tokens, so each new
		// token still bounds abuse; production deployments that want one-time
		// bearer semantics should share the replay store across gateways.
		ReplayProtection: boolPtr(false),
		AuditLogger:      proxyAudit,
		IdentityMode:     aicverifier.IdentityAIC,
		TLSCertFile:      *tlsCertFile,
		TLSKeyFile:       *tlsKeyFile,
		Hooks: &aicverifier.Hooks{
			// The proxy's admission pipeline does not audit per-request decisions
			// by itself; record allows and denies here so proxy-audit.jsonl shows
			// the outer gate next to the backend's mcp_* decision entries.
			Authenticated: func(ac *aicverifier.AuthContext, r *http.Request) error {
				if proxyAudit == nil || ac == nil {
					return nil
				}
				entry := aicverifier.NewAuditEntryFromConn(clientIP(r), "mcp", "proxy:"+r.URL.Path, ac.ClientCert)
				entry.Decision = "allow"
				entry.Level = "INFO"
				proxyAudit.Log(entry)
				return nil
			},
			Denied: func(r *http.Request, err *aicverifier.AuthError) {
				if proxyAudit == nil {
					return
				}
				entry := aicverifier.NewAuditEntryDenied(clientIP(r), "mcp", "proxy:"+r.URL.Path, err.Error(), nil)
				entry.Level = "WARN"
				proxyAudit.Log(entry)
			},
		},
	}
	// The high-risk scope is the whole MCP surface: per-tool capability gating
	// happens at the backend (the proxy's Route.RequiredCapabilities cannot
	// distinguish individual tools behind one /mcp path).
	proxy, err := aicverifier.NewServer(conf, []aicverifier.Route{
		{Path: "/mcp", Target: backendURL},
	})
	if err != nil {
		log.Fatalf("mcp-behind-proxy: aic-verifier server: %v", err)
	}
	if err := ensureServerTLS(*tlsCertFile, *tlsKeyFile); err != nil {
		log.Fatalf("mcp-behind-proxy: tls: %v", err)
	}

	if !*noMint {
		fmt.Fprintf(os.Stderr, "OPERATOR TOKEN (mcp:db_query + mcp:trade_exec):\n%s\n\n", opToken)
		fmt.Fprintf(os.Stderr, "AUDITOR TOKEN (mcp:db_query only):\n%s\n\n", audToken)
	} else {
		fmt.Fprintf(os.Stderr, "Full-chain mode: present a token minted by user-signer+issuer;\n"+
			"trust root = %s. The token must carry the mcp:* capabilities it wants to call.\n", *jwtCA)
	}

	log.Printf("AIC-gated MCP proxy listening on %s -> backend %s (manifest %s)", *addr, backendURL, *toolsFile)
	if err := proxy.ListenAndServe(*addr); err != nil {
		log.Fatalf("mcp-behind-proxy: %v", err)
	}
}

// mintLocalTokens creates (or reuses) the demo CA and signs the operator and
// auditor tokens. Note the capability convention: aicjwt.Capability.ID is the
// bare action identifier ("db_query"); the full identifier is scheme:id and is
// produced by FullID(). Minting a prefixed id here would double the scheme.
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

// boolPtr is a small helper for pointer-valued Config fields.
func boolPtr(v bool) *bool { return &v }

// clientIP mirrors the SDK reverse-proxy helper for the audit hooks.
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
		Subject:      pkix.Name{CommonName: "aic-verifier mcp example proxy"},
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
