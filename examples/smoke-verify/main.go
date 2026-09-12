// Command smoke-verify runs a minimal aic-verifier-protected HTTP service
// against a real varwof PKI (no demo CA), for smoke testing the SDK.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	aicverifier "github.com/varwof/aic-verifier"
)

func main() {
	addr := flag.String("addr", ":9443", "listen address")
	caFile := flag.String("ca", "", "CA that issued the client AIC certificates")
	certFile := flag.String("cert", "", "server certificate (leaf or chain)")
	keyFile := flag.String("key", "", "server key")
	capability := flag.String("cap", "", "required capability id")
	requireAIC := flag.Bool("require-aic", true, "require the AIC extension (false also admits a human certificate whose PrincipalAuthorization covers the capability)")
	flag.Parse()
	if *caFile == "" || *certFile == "" || *keyFile == "" {
		log.Fatal("--ca, --cert and --key are required")
	}

	conf := &aicverifier.Config{
		CACertFile:           *caFile,
		TLSCertFile:          *certFile,
		TLSKeyFile:           *keyFile,
		AuthMode:             aicverifier.MTLSOnly,
		RequireAIC:           *requireAIC,
		RequiredCapabilities: []string{*capability},
	}
	if *capability == "" {
		conf.RequiredCapabilities = nil
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
		fmt.Fprintln(os.Stderr, "aic-verifier:", err)
		os.Exit(1)
	}
	// The middleware style leaves the listener to the caller: require and
	// verify the client certificate against the same CA the SDK uses.
	caPEM, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatal("ca file contains no certificates")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}
	srv := &http.Server{Addr: *addr, Handler: handler, TLSConfig: tlsCfg}
	log.Printf("aic-verifier smoke service on %s (require AIC, cap=%q)", *addr, *capability)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
