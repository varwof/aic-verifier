// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/varwof/aic-verifier"
	pki "github.com/varwof/types"
)

// testAICCert builds a self-signed certificate carrying an AIC extension,
// exactly like the aic-verifier white-box test fixture.
func testAICCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aic := &pki.AIC{
		AgentId: "agent-1",
		PrincipalUid: pki.PrincipalUid{
			Version: 1, Realm: "pki", Identifier: "user-1",
			KeyHash:  make([]byte, 32),
			HashAlgo: pki.AlgorithmIdentifier{Algorithm: pki.OIDSHA256},
		},
		Capabilities: []pki.Capability{{
			SchemeId: "std/database-v1", CapabilityId: "query:SELECT",
			Parameters: []byte(`{"limit":10}`),
		}},
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "API_ISSUE", Description: "test"},
			RequestedLifetime:  3600,
			Timestamp:          time.Now().UTC(),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(*aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: pki.OIDAIC, Value: aicDER},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

// writeCertPEM writes a cert to dir and returns the path, for CACertFile.
func writeCertPEM(t *testing.T, dir string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// decisionServer builds a real server from the public Config API (the same
// entry point an HTTP middleware consumer uses), trusting the given cert.
func decisionServer(t *testing.T, cert *x509.Certificate) *aicverifier.DecisionServer {
	t.Helper()
	caFile := writeCertPEM(t, t.TempDir(), cert)
	core, err := aicverifier.NewDecisionServer(&aicverifier.Config{
		AuthMode:   aicverifier.MTLSOnly,
		CACertFile: caFile,
		AdminToken: "test-reload-token",
	})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	t.Cleanup(func() { core.Close() })
	return core
}

func serveAndConnect(t *testing.T, core *aicverifier.DecisionServer) *DecisionClient {
	t.Helper()
	gs := grpc.NewServer()
	NewDecisionService(core).Register(gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return NewDecisionClient(conn)
}

func TestDecisionServiceEndToEnd(t *testing.T) {
	cert := testAICCert(t)
	core := decisionServer(t, cert)
	client := serveAndConnect(t, core)

	view := &aicverifier.RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodPost, Path: "/query", ClientIP: "10.0.0.7"}
	ac, err := client.Decide(context.Background(), view)
	if err != nil {
		t.Fatalf("wire Decide: %v", err)
	}
	if ac == nil || ac.AgentID != "agent-1" || len(ac.Capabilities) != 1 {
		t.Fatalf("wire ac = %+v, want agent-1 with one capability", ac)
	}
	if ac.Serial == "" || ac.ClientCert == nil || !ac.ClientCert.Equal(cert) {
		t.Error("wire decision lost the certificate identity")
	}

	// The wire decision must equal the in-process decision of the same core.
	directAC, err := core.Decide(context.Background(), view)
	if err != nil {
		t.Fatalf("direct Decide: %v", err)
	}
	if directAC.Principal != ac.Principal || directAC.AgentID != ac.AgentID || directAC.Serial != ac.Serial {
		t.Errorf("wire %+v != direct %+v", ac, directAC)
	}
}

// Denials are decisions: granted:false travels as an OK gRPC call, and the
// client surfaces the typed AuthError.
func TestDecisionServiceCarriesDenial(t *testing.T) {
	cert := testAICCert(t)
	core := decisionServer(t, cert)
	client := serveAndConnect(t, core)

	bad := testAICCert(t) // unrelated leaf, not in the trusted pool
	_, err := client.Decide(context.Background(), &aicverifier.RequestView{CertChain: []*x509.Certificate{bad}, TransportSecure: true})
	ae := aicverifier.AsAuthError(err)
	if ae == nil || ae.Code != aicverifier.ErrChainInvalid || ae.Status != http.StatusForbidden {
		t.Fatalf("wire denial = %v, want chain_invalid/403", err)
	}
}

// Standard grpc interceptors keep working: the reference binding registers a
// real unary method, so authz/obs tooling sees the exact full method name.
func TestDecisionServiceInterceptorSeesMethod(t *testing.T) {
	cert := testAICCert(t)
	core := decisionServer(t, cert)
	var seen string
	gs := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		seen = info.FullMethod
		_ = metadata.AppendToOutgoingContext(ctx, "x-client", "test")
		return handler(ctx, req)
	}))
	NewDecisionService(core).Register(gs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go gs.Serve(lis)
	defer gs.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	if _, err := NewDecisionClient(conn).Decide(context.Background(), &aicverifier.RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true}); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if seen != ServiceName+"/"+MethodName {
		t.Fatalf("interceptor saw %q, want the reference full method", seen)
	}
}

// A nil core is a config error, not a crash.
func TestDecisionServiceNilCore(t *testing.T) {
	resp, err := (&DecisionService{}).Decide(context.Background(), &aicverifier.DecideRequestDTO{})
	if err != nil {
		t.Fatalf("nil-core Decide: %v", err)
	}
	if resp == nil || resp.Granted {
		t.Fatalf("nil-core resp = %+v, want granted:false", resp)
	}
}
