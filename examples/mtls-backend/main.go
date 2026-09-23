// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command mtls-backend demonstrates the aic-verifier SDK protecting a real HTTP
// API with mTLS client certificate + AIC authorization:
//
//	$ go run ./gen-cert --out dev-certs   # CA + server cert + AIC client cert
//	$ go run .                           # AIC-protected mTLS proxy on :9444
//	$ curl -k --cert dev-certs/client-cert.pem --key dev-certs/client-key.pem \
//	       https://localhost:9444/api
//
// The proxy requires a client certificate issued by the demo CA carrying an
// AIC extension, runs the admission pipeline, then forwards to the sample
// backend (:9081), injecting X-AIC-* identity headers.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/varwof/aic-verifier"
	"github.com/varwof/aic-verifier/examples/supervision-demo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mtls-backend", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("certs", "dev-certs", "directory with ca-cert.pem / server-cert.pem / server-key.pem")
	addr := fs.String("addr", ":9444", "aic-verifier mTLS proxy listen address")
	backend := fs.String("backend", "http://127.0.0.1:9081", "backend real API base URL")
	denyRisk := fs.Bool("deny-risk", false, "DemoApprover denies every transfer (demonstrates the deny(approval_required) audit path)")
	auditFile := fs.String("audit-file", "", "audit JSON Lines file read by the evidence exporter")
	supervisionLog := fs.String("supervision-log", "", "supervision event JSON Lines file")
	tsaURL := fs.String("tsa-url", "", "RFC 3161 timestamping URL for audit + supervision events")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target, err := url.Parse(*backend)
	if err != nil {
		fmt.Fprintln(stderr, "bad backend:", err)
		return 1
	}

	conf := &aicverifier.Config{
		CACertFile:             *dir + "/ca-cert.pem",
		TLSCertFile:            *dir + "/server-cert.pem",
		TLSKeyFile:             *dir + "/server-key.pem",
		AuthMode:               aicverifier.MTLSOnly,
		RequireAIC:             true,
		RequiredCapabilities:   []string{"api:read"},
		DisallowRepresentative: true,
		EnforceConstraints:     true,
	}

	// Wire the runtime supervision demo: DemoApprover + /api/transfer trigger,
	// supervision store + built-in evidence exporter (compliance preset logic).
	if err := superv.Wire(conf, superv.Options{
		DenyRisk:       *denyRisk,
		AuditLogFile:   *auditFile,
		SupervisionLog: *supervisionLog,
		TSAURL:         *tsaURL,
	}); err != nil {
		fmt.Fprintln(stderr, "supervision demo:", err)
		return 1
	}

	server, err := buildServer(conf, target)
	if err != nil {
		fmt.Fprintln(stderr, "aic-verifier server:", err)
		return 1
	}

	go startBackend(":9081", conf.EvidenceExporter)

	fmt.Fprintf(stderr, "AIC-protected mTLS proxy listening on %s -> backend %s\n", *addr, *backend)
	if err := server.ListenAndServe(*addr); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// buildServer assembles the AIC-protected reverse proxy around the shared
// route table: the high-risk transfer route comes FIRST so matchRoute picks it
// over the /api prefix when path starts with /api/transfer.
func buildServer(conf *aicverifier.Config, target *url.URL) (*aicverifier.Server, error) {
	return aicverifier.NewServer(conf, []aicverifier.Route{
		{
			Path:                 superv.TransferPath,
			Target:               target,
			RequiredCapabilities: []string{superv.TransferCapability},
		},
		{
			Path:                 "/api",
			Target:               target,
			RequiredCapabilities: []string{"api:read"},
		},
	})
}

// startBackend serves the sample backend together with the /evidence demo
// endpoint, which exports the evidence bundle for a given operation id (the
// same process that runs the proxy; not a public Server route).
func startBackend(addr string, exporter aicverifier.EvidenceExporter) {
	srv := &http.Server{Addr: addr, Handler: backendMux(exporter)}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(log.Writer(), "backend:", err)
	}
}

// backendMux builds the sample backend handler: the identity-echoing /api
// routes and, when an evidence exporter is available, the /evidence demo
// endpoint that exports the evidence bundle for a given operation id.
func backendMux(exporter aicverifier.EvidenceExporter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		ident := map[string]string{}
		for _, h := range []string{"X-AIC-Agent-Id", "X-AIC-Principal-Uid",
			"X-AIC-Capabilities", "X-Agent-ID", "X-Forwarded-For"} {
			if v := r.Header.Get(h); v != "" {
				ident[h] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend":  "real-api-mtls",
			"identity": ident,
		})
	})
	mux.HandleFunc("/api/transfer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend": "real-api-mtls",
			"route":   superv.TransferPath,
			"status":  "transferred",
		})
	})
	// Example-only evidence export: GET /evidence?operation_id=op-<hex>.
	if exporter != nil {
		mux.HandleFunc("/evidence", func(w http.ResponseWriter, r *http.Request) {
			bundle, err := exporter.Export(r.Context(), aicverifier.EvidenceQuery{
				OperationID:        r.URL.Query().Get("operation_id"),
				IncludeSupervision: true,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(bundle)
		})
	}
	return mux
}
