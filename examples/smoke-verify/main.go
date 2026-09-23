// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command smoke-verify runs a minimal aic-verifier-protected HTTP service
// against a real varwof PKI (no demo CA), for smoke testing the SDK.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	aicverifier "github.com/varwof/aic-verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("smoke-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", ":9443", "listen address")
	caFile := fs.String("ca", "", "CA that issued the client AIC certificates")
	certFile := fs.String("cert", "", "server certificate (leaf or chain)")
	keyFile := fs.String("key", "", "server key")
	capability := fs.String("cap", "", "required capability id")
	opID := fs.String("op", "", "concrete operation to authorize (CLC); empty skips")
	opParams := fs.String("op-params", "", "operation parameters as JSON")
	requireAIC := fs.Bool("require-aic", true, "require the AIC extension (false also admits a human certificate whose PrincipalAuthorization covers the capability)")
	evidenceDir := fs.String("evidence-dir", "", "write one DSSE/CLC decision-record envelope per decided operation into this directory (empty = emit nothing)")
	evidenceTTL := fs.Duration("evidence-ttl", 5*time.Minute, "pin this RATS §10 freshness bound on each record (0 = no context)")
	evidenceAudience := fs.String("evidence-audience", "", "audience the evidence is addressed to")
	challenge := fs.Bool("challenge", false, "answer a refusable denial with 403 + application/problem+json carrying a CLC challenge")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	srv, err := buildServer(smokeOptions{
		addr:             *addr,
		caFile:           *caFile,
		certFile:         *certFile,
		keyFile:          *keyFile,
		capability:       *capability,
		opID:             *opID,
		opParams:         *opParams,
		requireAIC:       *requireAIC,
		evidenceDir:      *evidenceDir,
		evidenceTTL:      *evidenceTTL,
		evidenceAudience: *evidenceAudience,
		challenge:        *challenge,
	})
	if err != nil {
		fmt.Fprintln(stderr, "aic-verifier:", err)
		return 1
	}
	fmt.Fprintf(stderr, "aic-verifier smoke service on %s (require AIC, cap=%q)\n", *addr, *capability)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		fmt.Fprintln(stderr, "smoke-verify:", err)
		return 1
	}
	return 0
}

// smokeOptions carries the parsed command-line values that shape the service.
type smokeOptions struct {
	addr, caFile, certFile, keyFile string
	capability, opID, opParams      string
	requireAIC                      bool
	evidenceDir                     string
	evidenceTTL                     time.Duration
	evidenceAudience                string
	challenge                       bool
}

// buildServer assembles the aic-verifier config, the /whoami mux and the mTLS
// http.Server without binding a listener, so tests can mount it on httptest.
func buildServer(o smokeOptions) (*http.Server, error) {
	if o.caFile == "" || o.certFile == "" || o.keyFile == "" {
		return nil, fmt.Errorf("--ca, --cert and --key are required")
	}

	conf := &aicverifier.Config{
		CACertFile:           o.caFile,
		TLSCertFile:          o.certFile,
		TLSKeyFile:           o.keyFile,
		AuthMode:             aicverifier.MTLSOnly,
		RequireAIC:           o.requireAIC,
		RequiredCapabilities: []string{o.capability},
	}
	if o.capability == "" {
		conf.RequiredCapabilities = nil
	}
	if o.evidenceDir != "" {
		conf.Evidence = &aicverifier.EvidenceConfig{
			Sink:       &aicverifier.FileSink{Dir: o.evidenceDir, RecorderID: "smoke-verify"},
			TTL:        o.evidenceTTL,
			Audience:   o.evidenceAudience,
			RecorderID: "smoke-verify",
		}
	}
	if o.challenge {
		conf.Challenges = &aicverifier.ChallengeConfig{TTL: 5 * time.Minute, Audience: o.evidenceAudience}
	}
	if o.opID != "" {
		op := aicverifier.Operation{ID: o.opID}
		if o.opParams != "" {
			if err := json.Unmarshal([]byte(o.opParams), &op.Params); err != nil {
				return nil, fmt.Errorf("--op-params: %w", err)
			}
		}
		conf.RequiredOperations = []aicverifier.Operation{op}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		ac := aicverifier.FromContext(r.Context())
		if ac == nil {
			http.Error(w, "no AuthContext", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "agent=%s principal=%s caps=%v\n", ac.AgentID, ac.Principal, ac.Capabilities)
	})

	handler, err := conf.Handler(mux)
	if err != nil {
		return nil, err
	}
	// The middleware style leaves the listener to the caller: require and
	// verify the client certificate against the same CA the SDK uses.
	caPEM, err := os.ReadFile(o.caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca file contains no certificates")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}
	return &http.Server{Addr: o.addr, Handler: handler, TLSConfig: tlsCfg}, nil
}
