// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command mcp-behind-proxy runs the AIC-gated MCP server in its canonical
// deployment topology: the aic-verifier reverse proxy terminates TLS, runs the
// admission pipeline and forwards each admitted request to a loopback-only MCP
// backend, which trusts the proxy's server-asserted X-AIC-* identity headers
// (aic-verifier/mcp TrustProxy mode) instead of re-verifying a credential. One
// command boots the whole stack:
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
// Front-end can instead verify mTLS AIC client certificates:
//
//	$ go run . --mtls            # prints client-cert.pem/client-key.pem
//	$ curl -k https://localhost:9443/mcp --cert client-cert.pem --key client-key.pem \
//	     -H "Content-Type: application/json" \
//	     -d '<initialize as above>'
//
// Demo artifacts (ca.pem, client-*.pem, server-*.pem) land in --certs (default
// the current directory) so the example never forces writes into a shared
// checkout.
//
// Full-chain mode (user-signer + core) is identical for both front ends:
// --no-mint with the appropriate trust root (--jwt-ca for the bearer front end,
// or the AIC CA for --mtls) and a credential minted by the aic-agent pipeline.
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
	"io"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// stackOptions captures the flag surface of the command so run() builds the
// stack once and tests can assemble the same topology directly.
type stackOptions struct {
	addr           string
	backendPort    string
	toolsFile      string
	certsDir       string
	jwtCA          string
	issuer         string
	audience       string
	proxyAuditFile string
	mcpAuditFile   string
	tlsCertFile    string
	tlsKeyFile     string
	mtls           bool
	noMint         bool
}

// proxyStack is the assembled topology: the aic-verifier reverse proxy, its
// loopback-only MCP backend, the demo credentials for printing, and the two
// audit sinks (closed explicitly so tests can flush before asserting).
type proxyStack struct {
	proxy      *aicverifier.Server
	backend    *http.Server
	backendURL string
	opToken    string
	audToken   string
	proxyAudit *aicverifier.AuditLogger
	mcpAudit   *aicverifier.AuditLogger
}

func (s *proxyStack) close() {
	if s.backend != nil {
		_ = s.backend.Close()
	}
	if s.proxyAudit != nil {
		_ = s.proxyAudit.Close()
	}
	if s.mcpAudit != nil {
		_ = s.mcpAudit.Close()
	}
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-behind-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := stackOptions{}
	fs.StringVar(&opts.addr, "addr", defaultAddr, "aic-verifier proxy listen address (TLS)")
	fs.StringVar(&opts.backendPort, "backend-port", "0", "MCP backend TCP port on 127.0.0.1 (0 = auto-assigned)")
	fs.StringVar(&opts.toolsFile, "tools", defaultManifest, "tool manifest (tools.json)")
	fs.StringVar(&opts.certsDir, "certs", ".", "directory for demo artifacts (ca.pem, client-*.pem, server-*.pem)")
	fs.StringVar(&opts.jwtCA, "jwt-ca", "", "PEM CA(s) trusted for Bearer AIC-JWT (kid = CA SPKI hash)")
	fs.StringVar(&opts.issuer, "issuer", defaultIssuer, "required AIC-JWT iss claim")
	fs.StringVar(&opts.audience, "audience", defaultAudience, "required AIC-JWT aud claim")
	fs.StringVar(&opts.proxyAuditFile, "proxy-audit-file", "proxy-audit.jsonl", "aic-verifier audit JSON Lines file for proxy admission decisions")
	fs.StringVar(&opts.mcpAuditFile, "mcp-audit-file", "audit-mcp.jsonl", "aic-verifier audit JSON Lines file for MCP decisions")
	fs.StringVar(&opts.tlsCertFile, "tls-cert", "", "TLS server certificate (self-signed when missing)")
	fs.StringVar(&opts.tlsKeyFile, "tls-key", "", "TLS server key (self-signed when missing)")
	fs.BoolVar(&opts.mtls, "mtls", false, "front-end mTLS: admit AIC X.509 client certificates instead of Bearer AIC-JWT")
	fs.BoolVar(&opts.noMint, "no-mint", false, "do not mint demo credentials (full-chain mode): a credential issued by user-signer+issuer must be presented")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if opts.jwtCA == "" {
		opts.jwtCA = dirPath(opts.certsDir, "ca.pem")
	}
	if opts.tlsCertFile == "" {
		opts.tlsCertFile = dirPath(opts.certsDir, "server-cert.pem")
	}
	if opts.tlsKeyFile == "" {
		opts.tlsKeyFile = dirPath(opts.certsDir, "server-key.pem")
	}

	stack, err := buildStack(opts)
	if err != nil {
		fmt.Fprintf(stderr, "mcp-behind-proxy: %v\n", err)
		return 1
	}
	defer stack.close()

	if opts.mtls {
		if opts.noMint {
			fmt.Fprintf(stderr, "mTLS full-chain mode: present an AIC X.509 client cert issued by\n"+
				"user-signer + core (trust root = %s); the cert's AIC extension must\n"+
				"carry the mcp:* capabilities it wants to call.\n", dirPath(opts.certsDir, defaultCA))
		} else {
			fmt.Fprintf(stderr, "mTLS OPERATOR AIC CERT: client-cert.pem / client-key.pem\n"+
				"(present with -H use: curl --cert client-cert.pem --key client-key.pem, or via\n"+
				"the aic-agent mcpclient with AICCertPEM/AICKeyPEM)\n")
		}
	} else if !opts.noMint {
		fmt.Fprintf(stderr, "OPERATOR TOKEN (mcp:db_query + mcp:trade_exec):\n%s\n\n", stack.opToken)
		fmt.Fprintf(stderr, "AUDITOR TOKEN (mcp:db_query only):\n%s\n\n", stack.audToken)
	} else {
		fmt.Fprintf(stderr, "Full-chain mode: present a token minted by user-signer+issuer;\n"+
			"trust root = %s. The token must carry the mcp:* capabilities it wants to call.\n", opts.jwtCA)
	}

	fmt.Fprintf(stderr, "AIC-gated MCP proxy listening on %s -> backend %s (manifest %s)\n", opts.addr, stack.backendURL, opts.toolsFile)
	if err := stack.proxy.ListenAndServe(opts.addr); err != nil {
		fmt.Fprintf(stderr, "mcp-behind-proxy: %v\n", err)
		return 1
	}
	return 0
}

// buildStack assembles the canonical deployment topology: loopback MCP backend
// in TrustProxy mode, demo credential minting, and the aic-verifier reverse
// proxy that terminates TLS, runs the admission pipeline and forwards admitted
// requests with the server-asserted X-AIC-* identity headers.
func buildStack(o stackOptions) (*proxyStack, error) {
	// 1. Tool manifest (unguessable surface + per-tool barriers).
	manifest, err := os.ReadFile(o.toolsFile)
	if err != nil {
		return nil, err
	}
	reg, err := aicmcp.LoadJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("tools.json: %w", err)
	}

	// 2. Two audit sinks: the proxy's admission pipeline and the MCP backend's
	// decision layer. Separate files because both run in this process.
	proxyAudit, err := aicverifier.NewAuditLogger(o.proxyAuditFile, nil, 64<<20, 5)
	if err != nil {
		return nil, fmt.Errorf("proxy audit: %w", err)
	}
	mcpAudit, err := aicverifier.NewAuditLogger(o.mcpAuditFile, nil, 64<<20, 5)
	if err != nil {
		return nil, fmt.Errorf("mcp audit: %w", err)
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
		return nil, err
	}

	// 4. Loopback-only backend listener. Plaintext is fine: it is reachable
	// only from this process on the loopback interface.
	ln, err := net.Listen("tcp", "127.0.0.1:"+o.backendPort)
	if err != nil {
		return nil, fmt.Errorf("backend listen: %w", err)
	}
	backendURL := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}
	backend := &http.Server{Handler: mcpHandler}
	go func() {
		_ = backend.Serve(ln)
	}()

	// 5. Default mode: mint the demo credentials before the admission handler
	// is built. Bearer mode mints two AIC-JWTs; mTLS mode mints one AIC
	// X.509 client certificate signed by the same demo CA. In full-chain mode
	// (--no-mint) the issuer CA must already exist and the credential is minted
	// externally by the user-signer + issuer pipeline.
	opToken, audToken := "", ""
	if !o.mtls {
		if !o.noMint {
			opToken, audToken, err = mintLocalTokens(o.issuer, o.audience, o.certsDir)
			if err != nil {
				return nil, fmt.Errorf("mint: %w", err)
			}
		}
	} else {
		if err := ensureCA(o.certsDir); err != nil {
			return nil, fmt.Errorf("CA: %w", err)
		}
		if !o.noMint {
			if err := mintAICClientCert(o.certsDir); err != nil {
				return nil, fmt.Errorf("mint AIC client cert: %w", err)
			}
		}
	}

	// 6. The reverse proxy: admission + unified TLS termination. The /mcp
	// route forwards admitted requests to the loopback MCP backend and
	// injects the server-asserted X-AIC-* identity headers (IdentityAIC mode);
	// the client-supplied credential header and the whole identity header
	// namespace are stripped before forwarding (SDK reverse-proxy policy).
	conf := &aicverifier.Config{
		AuthMode:    aicverifier.BearerOnly,
		JWTCAFile:   o.jwtCA,
		JWTIssuer:   o.issuer,
		JWTAudience: []string{o.audience},
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
		TLSCertFile:      o.tlsCertFile,
		TLSKeyFile:       o.tlsKeyFile,
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
	if o.mtls {
		// mTLS front end: verify the AIC X.509 client certificate against the
		// demo CA (and any chain it trusts) instead of a bearer JWT. IdentityAIC
		// below reads the AIC extension the cert carries, so the capability set
		// comes from the certificate, not a token claim.
		conf.AuthMode = aicverifier.MTLSOnly
		conf.CACertFile = dirPath(o.certsDir, defaultCA)
		conf.JWTCAFile = ""
		conf.JWTIssuer = ""
		conf.JWTAudience = nil
	}
	// The high-risk scope is the whole MCP surface: per-tool capability gating
	// happens at the backend (the proxy's Route.RequiredCapabilities cannot
	// distinguish individual tools behind one /mcp path).
	proxy, err := aicverifier.NewServer(conf, []aicverifier.Route{
		{Path: "/mcp", Target: backendURL},
	})
	if err != nil {
		return nil, fmt.Errorf("aic-verifier server: %w", err)
	}
	if err := ensureServerTLS(o.tlsCertFile, o.tlsKeyFile); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return &proxyStack{
		proxy:      proxy,
		backend:    backend,
		backendURL: backendURL.String(),
		opToken:    opToken,
		audToken:   audToken,
		proxyAudit: proxyAudit,
		mcpAudit:   mcpAudit,
	}, nil
}

// mintLocalTokens creates (or reuses) the demo CA and signs the operator and
// auditor tokens. Note the capability convention: aicjwt.Capability.ID is the
// bare action identifier ("db_query"); the full identifier is scheme:id and is
// produced by FullID(). Minting a prefixed id here would double the scheme.
func mintLocalTokens(iss, aud, dir string) (operator, auditor string, err error) {
	if err := ensureCA(dir); err != nil {
		return "", "", err
	}
	ca, err := readCAPair(dirPath(dir, caCert), dirPath(dir, caKey))
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
