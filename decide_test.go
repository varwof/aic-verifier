// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicverifier

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/varwof/register/semantics"
)

func decideAuth(t testing.TB, cert *x509.Certificate) *authenticator {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &authenticator{cfg: &Config{}, tlsCAs: pool, log: testLogger()}
}

// A: the decision core serves the same admission the HTTP middleware did,
// from a transport-neutral view.
func TestDecideMTLSAdmitsFromView(t *testing.T) {
	cert := testAICCert(t, false)
	a := decideAuth(t, cert)

	view := &RequestView{
		CertChain:       []*x509.Certificate{cert},
		TransportSecure: true,
		Method:          http.MethodPost,
		Path:            "/query",
		RawQuery:        "limit=5",
		ClientIP:        "10.0.0.7",
	}
	ac, err := a.Decide(context.Background(), view)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ac == nil {
		t.Fatal("ac is nil")
	}
	if ac.Bearer || ac.AgentID != "agent-1" || ac.Serial == "" {
		t.Errorf("ac = %+v, want agent-1 via mTLS with serial", ac)
	}
	if len(ac.Capabilities) != 1 || ac.Capabilities[0] != "query:SELECT" {
		t.Errorf("capabilities = %v, want [query:SELECT]", ac.Capabilities)
	}
}

// A direct peer-less call (an empty view) is refused exactly like an HTTP
// request without a credential.
func TestDecideNoCredential(t *testing.T) {
	a := decideAuth(t, testAICCert(t, false))
	_, err := a.Decide(context.Background(), &RequestView{})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Code != ErrNoCredential || ae.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want ErrNoCredential/401", err)
	}
}

// Fail-closed (S2) survives the refactor: a cert presented to a gateway with
// no mTLS CA pool is refused, never silently accepted.
func TestDecideMTLSWithoutConfiguredCA(t *testing.T) {
	cert := testAICCert(t, false)
	a := &authenticator{cfg: &Config{}, log: testLogger()}
	_, err := a.Decide(context.Background(), &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Code != ErrChainInvalid {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

// Non-TLS carriers get the same bearer gate as non-TLS HTTP requests.
func TestDecideBearerNeedsTransportSecurity(t *testing.T) {
	cert := testAICCert(t, false)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	a := &authenticator{
		cfg:      &Config{AuthMode: BearerOnly},
		verifier: NewJWTVerifier([]*x509.Certificate{cert}),
		log:      testLogger(),
	}
	_, err := a.Decide(context.Background(), &RequestView{BearerToken: "any", TransportSecure: false})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Code != ErrBearerNeedsTLS {
		t.Fatalf("err = %v, want ErrBearerNeedsTLS over a clear transport", err)
	}
	_, err = a.Decide(context.Background(), &RequestView{BearerToken: "not-a-real-token", TransportSecure: true})
	if !errors.As(err, &ae) || ae.Code != ErrInvalidBearer {
		t.Fatalf("err = %v, want ErrInvalidBearer over TLS", err)
	}
}

// VerifiedCert is the adapter-owned verification path: an embedding that
// already verified the credential (queue adapter, TLS over its own CA) feeds
// the leaf straight to the core and the pipeline still decides over it.
func TestDecideVerifiedCertBypassesChainVerification(t *testing.T) {
	cert := testAICCert(t, false)
	a := &authenticator{cfg: &Config{AuthMode: MTLSOrBearer}, log: testLogger()}
	ac, err := a.Decide(context.Background(), &RequestView{VerifiedCert: cert, ClientIP: "10.0.0.7"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ac == nil || ac.AgentID != "agent-1" {
		t.Fatalf("ac = %+v, want agent-1", ac)
	}
}

// A pipeline refusal is the core's refusal too, carrying the ErrorCode.
func TestDecideDeniedByPipeline(t *testing.T) {
	cert := testAICCert(t, false)
	a := decideAuth(t, cert)
	a.cfg.RequiredCapabilities = []string{"nope:cap"}
	_, err := a.Decide(context.Background(), &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodGet, Path: "/x"})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Code != ErrDenied || ae.Status != http.StatusForbidden {
		t.Fatalf("err = %v, want ErrDenied/403", err)
	}
}

// Carriers that cannot build an *http.Request express the supervision hook on
// the view instead of the config.
func TestDecideSupervisionViaViewHook(t *testing.T) {
	cert := testAICCert(t, false)
	a := decideAuth(t, cert)
	view := &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodPost, Path: "/trade"}
	view.RequireApprovalWith = func(*AuthContext) bool { return true }

	_, err := a.Decide(context.Background(), view)
	var ae *AuthError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "approval_required") {
		t.Fatalf("err = %v, want approval_required when the view demands approval", err)
	}

	view.RequireApprovalWith = func(*AuthContext) bool { return false }
	if _, err := a.Decide(context.Background(), view); err != nil {
		t.Fatalf("no approval wanted on the view must admit: %v", err)
	}
}

// Evidence requirement evaluation works through the view hook, with no HTTP
// request involved.
func TestDecideEvidenceRequirementViaViewHook(t *testing.T) {
	cert := testAICCert(t, false)
	a := decideAuth(t, cert)
	a.cfg.EvidenceRequirement = wireRequirement()

	satisfyingView := &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodGet, Path: "/x"}
	satisfyingView.EvidenceFactsWith = func(*AuthContext) ([]semantics.EvidenceFact, error) {
		return []semantics.EvidenceFact{
			fact("human-authorization", "alice", true),
			fact("human-authorization", "bob", true),
			fact("policy-permit", "policy-1", true),
		}, nil
	}
	ac, err := a.Decide(context.Background(), satisfyingView)
	if err != nil {
		t.Fatalf("satisfied requirement must admit: %v", err)
	}
	if ac.Satisfaction == nil || !ac.Satisfaction.Satisfied() {
		t.Fatalf("satisfaction = %+v, want satisfied", ac.Satisfaction)
	}

	missingView := &RequestView{CertChain: []*x509.Certificate{cert}, TransportSecure: true, Method: http.MethodGet, Path: "/x"}
	missingView.EvidenceFactsWith = func(*AuthContext) ([]semantics.EvidenceFact, error) {
		return []semantics.EvidenceFact{fact("human-authorization", "alice", true)}, nil
	}
	_, err = a.Decide(context.Background(), missingView)
	var ae *AuthError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "policy-permit") {
		t.Fatalf("err = %v, want a refusal naming the missing role", err)
	}
	if ae.Satisfaction == nil || !ae.Satisfaction.Satisfied() == false && len(ae.Satisfaction.MissingRoles) == 0 {
		t.Errorf("refusal should carry the unsatisfied satisfaction detail: %+v", ae.Satisfaction)
	}
}

func TestDecisionServerSharedCore(t *testing.T) {
	cert := testAICCert(t, false)
	s, err := NewDecisionServer(&Config{AdminToken: "test-reload-token"})
	if err != nil {
		t.Fatalf("NewDecisionServer: %v", err)
	}
	defer s.Close()

	ac, err := s.Decide(context.Background(), &RequestView{VerifiedCert: cert, ClientIP: "10.0.0.7"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ac == nil || ac.AgentID != "agent-1" {
		t.Fatalf("ac = %+v, want agent-1", ac)
	}

	// Rejected cert digest facts keep admission of an unknown leaf honest: the
	// refused path records the leaf bytes it saw; here we assert the digests
	// match the presented leaf when evidence is off the wire.
	certSum := sha256.Sum256(cert.Raw)
	f := (&authenticator{cfg: &Config{Evidence: &EvidenceConfig{Sink: &FileSink{Dir: t.TempDir()}, RecorderID: "pep-1"}}, log: testLogger()}).admissionFacts(&RequestView{PresentedCert: cert}, nil)
	if len(f) == 0 || string(f[0].Digest.Value) != string(certSum[:]) {
		t.Fatalf("facts = %+v, want the presented cert digest", f)
	}
}
