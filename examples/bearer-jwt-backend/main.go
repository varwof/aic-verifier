// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command bearer-jwt-backend demonstrates the aic-verifier SDK protecting a real
// HTTP API:
//
//	$ go run ./gen-bearer            # creates ca.pem + prints a Bearer token
//	$ go run . --addr :9443          # AIC-protected reverse proxy on :9443
//	$ curl -k https://localhost:9443/api --header "Authorization: Bearer $TOKEN"
//
// The proxy verifies the Bearer AIC-JWT, runs the admission pipeline, then
// forwards the request to the sample backend (started on :9080 by this binary
// unless --backend is given), injecting X-AIC-* identity headers.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/varwof/aic-verifier"
	"github.com/varwof/aic-verifier/examples/supervision-demo"
)

func main() {
	addr := flag.String("addr", ":9443", "aic-verifier proxy listen address")
	backend := flag.String("backend", "http://127.0.0.1:9080", "backend real API base URL")
	serveBackend := flag.Bool("serve-backend", true, "start the sample backend on :9080")
	denyRisk := flag.Bool("deny-risk", false, "DemoApprover denies every transfer (demonstrates the deny(approval_required) audit path)")
	auditFile := flag.String("audit-file", "", "audit JSON Lines file read by the evidence exporter")
	supervisionLog := flag.String("supervision-log", "", "supervision event JSON Lines file")
	tsaURL := flag.String("tsa-url", "", "RFC 3161 timestamping URL for audit + supervision events")
	flag.Parse()

	target, err := url.Parse(*backend)
	if err != nil {
		log.Fatal("bad backend:", err)
	}

	conf := &aicverifier.Config{
		JWTCAFile:              "ca.pem",
		JWTIssuer:              "aic-verifier-example",
		JWTAudience:            []string{"myapi"},
		AuthMode:               aicverifier.BearerOnly,
		RequireAIC:             true,
		RequiredCapabilities:   []string{"api:read"},
		DisallowRepresentative: true,
		EnforceConstraints:     true,
		TLSCertFile:            "server-cert.pem",
		TLSKeyFile:             "server-key.pem",
	}

	// Wire the runtime supervision demo: DemoApprover + /api/transfer trigger,
	// supervision store + built-in evidence exporter (compliance preset logic).
	if err := superv.Wire(conf, superv.Options{
		DenyRisk:       *denyRisk,
		AuditLogFile:   *auditFile,
		SupervisionLog: *supervisionLog,
		TSAURL:         *tsaURL,
	}); err != nil {
		log.Fatal("supervision demo:", err)
	}

	if err := ensureServerTLS(conf.TLSCertFile, conf.TLSKeyFile); err != nil {
		log.Fatal("tls:", err)
	}

	if *serveBackend {
		go startBackend(":9080", conf.EvidenceExporter)
	}

	// The high-risk transfer route comes FIRST so matchRoute picks it over the
	// /api prefix when path starts with /api/transfer.
	server, err := aicverifier.NewServer(conf, []aicverifier.Route{
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
	if err != nil {
		log.Fatal("aic-verifier server:", err)
	}

	log.Printf("AIC-protected proxy listening on %s -> backend %s", *addr, *backend)
	if err := server.ListenAndServe(*addr); err != nil {
		log.Fatal(err)
	}
}

// startBackend serves the sample backend together with the /evidence demo
// endpoint, which exports the evidence bundle for a given operation id (the
// same process that runs the proxy; not a public Server route).
func startBackend(addr string, exporter aicverifier.EvidenceExporter) {
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
			"backend":  "real-api",
			"identity": ident,
		})
	})
	mux.HandleFunc("/api/transfer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend": "real-api",
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
	srv := &http.Server{Addr: addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "backend:", err)
	}
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
		Subject:      pkix.Name{CommonName: "aic-verifier example server"},
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
	if err := writePEMFile(certFile, "CERTIFICATE", der); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEMFile(keyFile, "EC PRIVATE KEY", keyDER)
}

func writePEMFile(path, typ string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
