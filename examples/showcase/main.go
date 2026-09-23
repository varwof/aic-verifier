// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command showcase runs the whole AIC + CLC + decision-record path on a local
// machine and prints each step, so the claims in docs/comparison.md can be
// seen rather than asserted:
//
//  1. identity        — an AIC-JWT is minted per request from an agent key; the
//     gateway trusts the issuing key by SPKI hash (kid).
//  2. constraint      — the gateway requires a concrete operation with typed
//     parameter bounds; a grant whose bounds cover it is
//     admitted, one that does not is refused.
//  3. decision record — every decision, admission and refusal alike, is frozen
//     into a signed, content-addressed record.
//  4. reproducibility — a third party re-runs the language over the frozen
//     inputs and recomputes the verdict; forging the verdict
//     makes verification fail.
//
// It is self-contained: no external service, no client SDK import. The token
// is minted directly with github.com/varwof/types/aicjwt, the same way the
// aic-agent SDK does, so this example does not make the server SDK depend on
// the client SDK.
//
//	go run ./examples/showcase
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"time"

	aicverifier "github.com/varwof/aic-verifier"
	"github.com/varwof/register/semantics"
	"github.com/varwof/types/aicjwt"
)

const (
	issuer   = "https://issuer.showcase.example"
	audience = "https://data-api.showcase.example"
	realm    = "realm/demo"
	scheme   = "std/database-v1"
	opQuery  = scheme + ":query:SELECT"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "showcase:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "aic-showcase-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	evDir := filepath.Join(dir, "evidence")

	banner("AIC + CLC + decision record — end to end")

	// ── 1. identities ───────────────────────────────────────────────────
	// Each agent key is its own trust root here: the JWT CA file holds the
	// agent certificates, and the token kid is the issuing CA's SPKI hash.
	wide, err := newAgent("wide")
	if err != nil {
		return err
	}
	narrow, err := newAgent("narrow")
	if err != nil {
		return err
	}
	fmt.Printf("  identity   %s  kid=%s\n", wide.name, short(wide.kid))
	fmt.Printf("  identity   %s  kid=%s\n", narrow.name, short(narrow.kid))

	jwtCA := filepath.Join(dir, "jwt-ca.pem")
	if err := writeJWTCA(jwtCA, wide, narrow); err != nil {
		return err
	}

	// ── 2. gateway ──────────────────────────────────────────────────────
	// The gateway requires ONE concrete operation: query:SELECT with the
	// parameter bounds {limit: 5, db: "*"}. The agent must hold a grant that
	// covers it — the decision is on typed parameters, not a scope string.
	// EmitOutcome makes the middleware report an outcome record once the
	// downstream handler returns, so the decision/outcome pair is the
	// attributable effect chain (P3-gap1).
	gateway := &aicverifier.Config{
		AuthMode:           aicverifier.BearerOnly,
		JWTCAFile:          jwtCA,
		JWTIssuer:          issuer,
		JWTAudience:        []string{audience},
		RequireAIC:         true,
		RequiredOperations: []aicverifier.Operation{{ID: opQuery, Params: map[string]any{"limit": 5, "db": "*"}}},
		Evidence: &aicverifier.EvidenceConfig{
			Sink:        &aicverifier.FileSink{Dir: evDir, RecorderID: "showcase"},
			RecorderID:  "showcase",
			TTL:         5 * time.Minute,
			Audience:    audience,
			EmitOutcome: true,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	handler, err := gateway.Handler(backend())
	if err != nil {
		return err
	}
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	serverCA := filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		return err
	}
	fmt.Printf("  gateway    requires %s %s\n", opQuery, `{"limit":5,"db":"*"}`)

	// ── 3. two grants, one operation ────────────────────────────────────
	step("wide grant {limit:10} vs required {limit:5}  → expect admit")
	if err := call(srv.URL, serverCA, wide, `{"limit":10,"db":"*"}`); err != nil {
		return err
	}

	step("narrow grant {limit:3} vs required {limit:5}  → expect refuse")
	if err := call(srv.URL, serverCA, narrow, `{"limit":3,"db":"*"}`); err != nil {
		return err
	}

	// ── 4. decision records + independent recomputation ─────────────────
	step("every decision left a record — admission and refusal alike")
	paths, err := records(evDir)
	if err != nil {
		return err
	}
	var allowPath string
	for _, p := range paths {
		rec, err := aicverifier.LoadEvidenceRecord(p)
		if err != nil {
			return fmt.Errorf("%s does not reproduce: %w", filepath.Base(p), err)
		}
		fmt.Printf("  record     %s\n", filepath.Base(p))
		fmt.Printf("             verdict=%s reason=%s inputs=%s\n",
			rec.Verdict, orNone(rec.Reason), short(hex(rec.InputDigest.Value)))
		if rec.Verdict == "allow" {
			allowPath = p
		}
	}
	if allowPath == "" {
		return fmt.Errorf("no admission record was emitted")
	}

	step("a third party re-runs the language over the frozen inputs")
	rec, err := aicverifier.LoadEvidenceRecord(allowPath)
	if err != nil {
		return err
	}
	decision, err := rec.Recompute()
	if err != nil {
		return err
	}
	fmt.Printf("  recorded   %s\n", rec.Verdict)
	fmt.Printf("  recomputed %s  ← derived, never trusted\n", decision.Verdict)

	// ── 5. effect evidence: the decision → outcome linkage ──────────────
	// EmitOutcome makes the middleware report an outcome record after the
	// downstream handler returned. A consumer verifies the whole directory:
	// each outcome's decisionDigest must resolve to a decision record present
	// in the same set, or it is an orphan — a gap, not consent (P3-gap2).
	step("the middleware reported an outcome; a consumer verifies the linkage")
	rep, err := aicverifier.VerifyEvidenceDir(evDir, nil)
	if err != nil {
		return err
	}
	fmt.Printf("  verified   decision=%d admission=%d outcome=%d orphans=%d\n",
		rep.Decision, rep.Admission, rep.Outcome, rep.OrphanOutcome)
	if rep.Outcome != 1 || rep.OrphanOutcome != 0 || len(rep.Failures) != 0 {
		return fmt.Errorf("expected exactly one linked outcome and no orphans, got %+v", rep)
	}

	step("an outcome pointing at a missing decision is a gap, not consent")
	outcomePath, err := outcomeRecord(evDir)
	if err != nil {
		return err
	}
	orphanPath := filepath.Join(evDir, "outcome-orphan.json")
	if err := relinkOutcome(outcomePath, orphanPath, "deadbeef"); err != nil {
		return err
	}
	rep, err = aicverifier.VerifyEvidenceDir(evDir, nil)
	if err != nil {
		return err
	}
	fmt.Printf("  verified   decision=%d admission=%d outcome=%d orphans=%d\n",
		rep.Decision, rep.Admission, rep.Outcome, rep.OrphanOutcome)
	if rep.Outcome != 1 || rep.OrphanOutcome != 1 {
		return fmt.Errorf("expected 1 linked + 1 orphan outcome, got %+v", rep)
	}

	step("forge the verdict (a well-formed edit), verify again → expect failure")
	if err := forgeVerdict(allowPath); err != nil {
		return err
	}
	if _, err := aicverifier.LoadEvidenceRecord(allowPath); err == nil {
		return fmt.Errorf("forged record still verified — the verdict is not bound to its inputs")
	} else {
		fmt.Printf("  rejected   %v\n", err)
	}

	banner("all steps completed")
	return nil
}

// ── agent identity + token minting (the aicjwt layer, no client SDK) ─────

type agent struct {
	name  string
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	kid   string // SPKI hash of the issuing cert; the JWT trust-root key
	thumb string // RFC 7638 JWK thumbprint; the cnf jkt / principal key_hash
}

func newAgent(name string) (*agent, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano() % 1e9),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	kid, err := aicjwt.SPKIHash(cert, "sha-256")
	if err != nil {
		return nil, err
	}
	jwk, err := aicjwt.PublicKeyToJWK(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	thumb, err := aicjwt.JWKThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	return &agent{name: name, key: key, cert: cert, kid: kid, thumb: thumb}, nil
}

// mint produces one fresh Bearer AIC-JWT carrying the agent's grant. A new jti
// each call keeps the gateway's replay protection satisfied.
func (a *agent) mint(grantParams string) (string, error) {
	now := time.Now()
	jti, err := randToken()
	if err != nil {
		return "", err
	}
	outer := &aicjwt.OuterClaims{
		Iss: issuer,
		Sub: realm + ":" + a.name,
		Aud: aicjwt.Audience{audience},
		Iat: now.Unix(),
		Exp: now.Add(time.Hour).Unix(),
		Jti: jti,
		Cnf: &aicjwt.Cnf{Jkt: a.thumb},
		Aic: &aicjwt.AICClaims{
			Ver:            1,
			Principal:      aicjwt.Principal{Realm: realm, ID: a.name, KeyHash: a.thumb, HashAlg: "sha-256"},
			DelegationMode: aicjwt.ModeAuthorized,
			Capabilities: []aicjwt.Capability{
				{Scheme: scheme, ID: "query:SELECT", Params: json.RawMessage(grantParams)},
			},
		},
	}
	header := aicjwt.Header{Alg: "ES256", Typ: aicjwt.TypOuter, Kid: a.kid}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(outer)
	if err != nil {
		return "", err
	}
	return aicjwt.SignCompact(hb, pb, "ES256", a.key)
}

func (a *agent) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

func writeJWTCA(path string, agents ...*agent) error {
	var out []byte
	for _, a := range agents {
		out = append(out, a.pem()...)
	}
	return os.WriteFile(path, out, 0o600)
}

func randToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ── the protected API ────────────────────────────────────────────────────

// backend is the protected API. It only runs when the request was admitted.
func backend() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		ac := aicverifier.FromContext(r.Context())
		agentID := "?"
		if ac != nil {
			agentID = ac.AgentID
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rows":2,"served_to":"` + agentID + `"}`))
	})
	return mux
}

// call mints one fresh bearer token for the agent's grant and requests the API.
func call(baseURL, serverCA string, a *agent, grantParams string) error {
	token, err := a.mint(grantParams)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/query", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	if err := useCA(client, serverCA); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  response   %d %s\n", resp.StatusCode, trim(body))
	return nil
}

func useCA(client *http.Client, caFile string) error {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("server CA file has no certificates")
	}
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return nil
}

// ── record verification helpers ──────────────────────────────────────────

// records returns every decision-record envelope under dir (outcome and
// admission records are structurally different payloads and are not decisions).
func records(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		env, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var outer struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(env, &outer); err != nil {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(outer.Payload)
		if err != nil {
			continue
		}
		var st struct {
			PredicateType string `json:"predicateType"`
		}
		if err := json.Unmarshal(payload, &st); err != nil {
			continue
		}
		if st.PredicateType != semantics.PredicateTypeCLCDecision {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no decision record was emitted in %s", dir)
	}
	sort.Strings(files)
	return files, nil
}

// outcomeRecord finds the single outcome-record envelope in dir. It is the
// purely structural sibling of records(): the same file would be named directly
// if this example owned the naming scheme, but it does not.
func outcomeRecord(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var found string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		var env struct {
			Payload string `json:"payload"`
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var st map[string]any
		if err := json.Unmarshal(payload, &st); err != nil {
			continue
		}
		if pt, _ := st["predicateType"].(string); pt == aicverifier.OutcomeRecordPredicateType {
			found = filepath.Join(dir, e.Name())
			break
		}
	}
	if found == "" {
		return "", fmt.Errorf("no outcome record in %s", dir)
	}
	return found, nil
}

// relinkOutcome copies an outcome envelope but rewrites its decisionDigest so
// the copy points at a decision that is not in the directory. The envelope stays
// well-formed and structurally valid — only the linkage is broken, and a
// consumer's VerifyEvidenceDir must report it as an orphan gap, not as consent.
func relinkOutcome(src, dst, digest string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	var b64 string
	if err := json.Unmarshal(env["payload"], &b64); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		return err
	}
	pred, ok := st["predicate"].(map[string]any)
	if !ok {
		return fmt.Errorf("record has no predicate to relink")
	}
	pred["decisionDigest"] = digest
	payload, err = json.Marshal(st)
	if err != nil {
		return err
	}
	env["payload"], err = json.Marshal(base64.StdEncoding.EncodeToString(payload))
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dst, append(out, '\n'), 0o600)
}

// forgeVerdict rewrites the recorded verdict inside the DSSE payload, keeping
// the envelope well-formed. It must still fail verification: the verdict is
// recomputed from the frozen inputs, so an edit that does not follow from them
// is rejected — by digest and by recomputation.
func forgeVerdict(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return err
	}
	var b64 string
	if err := json.Unmarshal(env["payload"], &b64); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	var st map[string]any
	if err := json.Unmarshal(payload, &st); err != nil {
		return err
	}
	pred, ok := st["predicate"].(map[string]any)
	if !ok {
		return fmt.Errorf("record has no predicate to forge")
	}
	pred["verdict"] = "deny"
	forged, err := json.Marshal(st)
	if err != nil {
		return err
	}
	env["payload"], err = json.Marshal(base64.StdEncoding.EncodeToString(forged))
	if err != nil {
		return err
	}
	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

func hex(b []byte) string { return fmt.Sprintf("%x", b) }

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func banner(s string) { fmt.Printf("\n── %s ──\n", s) }
func step(s string)   { fmt.Printf("\n  ▸ %s\n", s) }
func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}
func trim(b []byte) string {
	s := string(b)
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
