# aic-verifier

**Identity says who is calling. AIC says what this agent is allowed to do — and proves it offline.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/aic-verifier)](https://pkg.go.dev/github.com/varwof/aic-verifier)
[![Status](https://img.shields.io/badge/status-preview-orange)](#stability)
[![IETF](https://img.shields.io/badge/IETF-draft--wei--aic--identity--cert-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)
[![IETF](https://img.shields.io/badge/IETF-draft--wei--aic--jwt-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

[English](README.md) · [中文](README_CN.md)

---

## Why

An API key or a scope list says *what is generally allowed*. It does not say
**which agent** is acting, **on whose authority**, **within what exact bounds**,
or **what was actually recorded**. When the caller is an autonomous agent that
can be prompt-injected, replayed, or delegated to, "the platform checks the
token" is a promise, not a proof.

`aic-verifier` turns that promise into an enforcement point: a small Go library
you wrap around any HTTP service — or run as a reverse proxy — that, per request,
verifies an **AIC** (Agent Identity Certificate) and decides the exact operation
against the capabilities the certificate carries. The verdict is three-valued
(`allow` / `allow_unresolved` / `deny`), refusals happen **before** your handler
ever runs, and every decision can be emitted as a **recomputable, offline-verifiable
evidence record** bound to the principal that authorized it.

> **Enforcement point, not a gateway.** `aic-verifier` is the embeddable admission
> core of the [varwof gateway](https://github.com/varwof/gateway). It decides and
> records; routing, proxying beyond the bundled reverse proxy, and execution belong
> to the caller. `aic-exec` is the command-execution boundary built on top.

It evaluates the **CLC-1.8** revision of the capability language and depends on
[`register v0.6.0`](https://github.com/varwof/register) (the CLC reference
implementation) and [`types v0.6.0`](https://github.com/varwof/types) (AIC /
AIC-JWT structures).

---

## What it does

| Area | Capability |
|---|---|
| **Credentials** | mTLS client certificate carrying an AIC X.509 extension, or `Authorization: Bearer <AIC-JWT>`; `AuthMode` = `MTLSOnly` / `BearerOnly` / `MTLSOrBearer` |
| **Decision pipeline** | certificate validity → CRL/OCSP revocation → roles → AIC decision → capability ∩ principal authorization → parameter bounds → **allow / allow_unresolved / deny** |
| **Capability language** | CLC-1.8 concrete operations, capability id matching, parameter bounds (`max_rows`, enums, …), authorization constraints (CIDR, time window, concurrency), residual obligations |
| **Delegation** | DA / DA-v2 signature verification, delegation chains, `EffectiveDelegationCapabilities`, DA freshness, principal-key binding, representative-mode rejection |
| **Integration** | middleware (`Handler` / `AuthMiddleware`) around your handler; reverse proxy (`NewServer`) injecting `X-AIC-*`; transport-independent `DecisionServer` (`Decide`, HTTP, gRPC, admin, health) |
| **Evidence** | per-decision DSSE-wrapped CLC decision records, plus admission and outcome records; `FileSink`/`SlogSink`; **key-endorsed signing** (`EvidenceConfig.Signer` / `SignKeyFile` / `Sign`, with `RequireSignature` to fail closed); per-admission nonces; RATS §10 freshness; profiles; requirement binding |
| **Evidence verification** | `VerifyEvidenceDir` (structure + signature + decision↔outcome linkage, orphan reporting), `VerifyEvidenceEnvelope`, `VerifyFnFromKey` / `VerifyFnFromPublicKey` (pinned key), `RecordSigner.VerifyFn()`, `LoadEvidenceRecord` |
| **Evidence export** | `FileEvidenceExporter` → `EvidenceBundle` v0.1 (manifest / operation / subject / authorization / decision / supervision / Merkle-chained audit / signatures), with the **bundle itself signable** (`EvidenceBundle.Sign` / `VerifySignature`) and **human-readable renderings** (`RenderMarkdown` / `RenderCSV` / `RenderText`, `WriteRendered`) |
| **Challenges** | `CLC-CHALLENGE-v1`: a *remediable* refusal answered with RFC 9457 `application/problem+json` + `Retry-After`, listing what evidence is missing |
| **Audit** | Merkle-chained `AuditLogger` (TSA-signable), `VerifyAuditEntry`, `FilterAuditFile`, `ArchiveAuditFile` |
| **Supervision** | runtime human approval (`ApprovalRequester`), break-glass with mandatory recording (`OverrideRecorder`), `RequireApproval` trigger, `SupervisionPolicy`, append-only `SupervisionStore` |
| **Policy** | OU→role `AuthorizationPolicy`, PKCS#7-signed policy files (`SignPolicy`/`VerifySignedPolicy`), fail-closed hot reload (`ReloadPolicy*`, admin token) |
| **Plugins** | `CapabilityPlugin`, capability `Registry`, `ConstraintEvaluator`, `ParameterValidator`, `GeoResolver` — per-`Config` isolation (several gateways, one process) |
| **Identity hygiene** | `IdentityMode` (backends never see the raw cert unless you want them to), log-field masking for serials / emails / tokens / paths |
| **Ops** | `/healthz`-style `HealthReport`, `DecisionMetrics`, `Config.Validate()`, TLS helpers, cipher-suite policy, OCSP stapling |
| **Carriers** | `mcp/` subpackage (AIC-gated MCP server) and `grpc/` subpackage (`AICDecisionService`, codec `aic-json-v1`) |

Full `Config`, record shapes and constants: **[docs/reference.md](docs/reference.md)**.

---

## Quick start (2 minutes)

Four steps; the demo generates its own CA and certificates, so there is nothing
to configure first.

**1. Get the code and generate demo certificates** — a CA plus a server
certificate and an agent certificate that carries an AIC extension:

```bash
git clone https://github.com/varwof/aic-verifier && cd aic-verifier
go run ./examples/mtls-backend/gen-cert -out ./demo-certs
```

**2. Start the protected service** — it terminates mTLS on `:9444` and forwards
admitted requests to a demo backend on `:9081` (started by the same process).
Leave it running in this shell:

```bash
go run ./examples/mtls-backend --certs ./demo-certs
```

**3. Call it as the agent** — in a second shell, present the agent certificate:

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api
# {"backend":"real-api-mtls","identity":{"X-Forwarded-For":"127.0.0.1, 127.0.0.1"}}
```

**4. Watch a refusal** — ask for something the agent is not allowed to do; the
request never reaches the backend:

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api/transfer
# {"code":"access_denied","message":"agent missing required capabilities"}
```

Stop the demo with `Ctrl-C` in the first shell. What the request left behind —
the decision record, and how to recompute it — is
**[docs/quickstart.md](docs/quickstart.md)**, which also covers calling the API
without a client certificate and reading the record back.

---

## Simple examples

### Wrap your own handler (middleware)

```go
conf := &aicverifier.Config{
    CACertFile:           "certs/ca-cert.pem",
    AuthMode:             aicverifier.MTLSOnly,
    RequireAIC:           true,
    RequiredCapabilities: []string{"demo/example-v1:api:read"},
}

mux := http.NewServeMux()
mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
    ac := aicverifier.FromContext(r.Context()) // agent id, principal, caps, verdict
    fmt.Fprintf(w, "hello %s\n", ac.AgentID)
})

handler, err := conf.Handler(mux) // runs the whole pipeline around mux
if err != nil {
    log.Fatal(err)
}
srv := &http.Server{
    Addr:      ":8443",
    Handler:   handler,
    TLSConfig: muxTLSConfig, // ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: <your CA>
}
log.Fatal(srv.ListenAndServeTLS("certs/server-cert.pem", "certs/server-key.pem"))
```

### Reverse proxy, backend untouched

```go
target, _ := url.Parse("http://127.0.0.1:8080")
server, err := aicverifier.NewServer(conf, []aicverifier.Route{
    {Path: "/api", Target: target, RequiredCapabilities: []string{"demo/example-v1:api:read"}},
})
log.Fatal(server.ListenAndServe(":9444")) // injects X-AIC-* identity headers
```

### Authorize one operation, in-process

A capability can carry **parameter bounds**; asking for more than the grant
allows is a deny, not a warning.

```go
dec, err := aicverifier.AuthorizeOperation(aic, pa,
    "std/database-v1:query:SELECT",
    map[string]any{"limit": 50})       // grant says {"limit": 100} -> allow
switch dec.Verdict {
case semantics.VerdictAllow:
case semantics.VerdictAllowUR:          // residual obligation, not allow
default:                                // VerdictDeny; dec.Reason is normative
}
```

### Bearer AIC-JWT only

```go
conf := &aicverifier.Config{
    JWTCAFile:  "certs/jwt-ca.pem",
    AuthMode:   aicverifier.BearerOnly,
    JWTIssuer:  "aic-verifier-example",     // optional iss pin
    JWTAudience: []string{"myapi"},         // optional aud pin
}
```

### Transport-independent decisions (HTTP + gRPC + in-process agree)

```go
core, _ := aicverifier.NewDecisionServer(conf)
ac, err := core.Decide(ctx, &aicverifier.RequestView{
    BearerToken:     token,
    TransportSecure: true,
})
// same Config -> identical verdict from HTTP, gRPC (grpc.NewDecisionService),
// or any in-process carrier.
```

### Turn on evidence, then verify it offline

```go
signer, _ := aicverifier.LoadRecordSignerFile("/etc/aic/evidence-key.pem", "pep-1")
conf.Evidence = &aicverifier.EvidenceConfig{
    Sink:             &aicverifier.FileSink{Dir: "/var/lib/aic/evidence", RecorderID: "pep-1"},
    Audience:         "https://gateway-a.example",
    TTL:              5 * time.Minute,     // RATS §10.1 freshness clock
    Signer:           signer,              // key-endorse every record (RSA/ECDSA/Ed25519)
    RequireSignature: true,                // refuse to start without a signing key
    Strict:           true,                // fail closed if the sink is down
}
// ...later, off the hot path:
rep, err := aicverifier.VerifyEvidenceDir("/var/lib/aic/evidence",
    signer.VerifyFn())                     // pinned key; verifies sigs + linkage
```

### Export a bundle, sign it, and render it for a human

```go
exporter := &aicverifier.FileEvidenceExporter{
    AuditFile:         "/var/lib/aic/audit.jsonl",
    SupervisionFile:   "/var/lib/aic/supervision.jsonl",
    EvidenceDir:       "/var/lib/aic/evidence",
    Signer:            signer,             // sign the package itself, not just the records
}
bundle, _ := exporter.Export(ctx, aicverifier.EvidenceQuery{AgentID: "agent-001"})
bundle.VerifySignature(signer.VerifyFn())  // a holder re-checks the export
bundle.WriteRendered("/tmp/evidence.md",    aicverifier.RenderMarkdown) // or RenderCSV / RenderText
```

### Answer a remediable refusal with a challenge

```go
conf.Challenges = &aicverifier.ChallengeConfig{
    TTL:        2 * time.Minute,
    Audience:   "https://gateway-a.example",
    RetryAfter: 10 * time.Second,          // becomes the Retry-After header
}
// A denial short on §8.4 evidence returns 403 application/problem+json with a
// CLC-CHALLENGE-v1 body: what is missing, and when a corrected retry is welcome.
```

### Runtime human approval / break-glass

```go
conf.SupervisionPolicy = aicverifier.SupervisionPolicy{RequireRuntimeApproval: true}
conf.ApprovalRequester = myApprover   // nil + RequireRuntimeApproval => startup error
conf.RequireApproval = func(ac *aicverifier.AuthContext, r *http.Request) bool {
    return r.Method != http.MethodGet // route writes through a human
}
// break-glass requires a recorder too, so an unlogged override is never available.
```

### Gate an MCP server

```go
reg, _ := mcp.LoadJSON(registryJSON)
h, _ := mcp.NewHandler(mcp.ServerConfig{ServerName: "aic-tools", Version: "0.1"},
    reg, map[string]mcp.ToolHandler{"echo": echoHandler})
// wrap h with conf.Handler(...) (or conf.AuthMiddleware) to admit by AIC first;
// each tool call can read the verified identity via mcp.AuthContextFromToolContext.
```

More runnable paths: **[docs/examples.md](docs/examples.md)** and the
[`examples/`](examples/) tree (`mtls-backend`, `bearer-jwt-backend`,
`mcp-server`, `mcp-behind-proxy`, `supervision-demo`, `showcase`,
`inspect-record`, `smoke-verify`).

---

## The decision pipeline

Per request, one pipeline runs and produces one decision:

1. **Credential** — mTLS chain verification, or AIC-JWT parse + verify (bearer
   never travels in cleartext: the request must arrive over TLS).
2. **Revocation** — CRL and/or OCSP (optional; configured per `CRLCache` / `OCSPCache`).
3. **Roles** — OU→role mapping (`AuthorizationPolicy`), `RequireRoles`, admin OU.
4. **AIC decision** — capability ∩ principal authorization over the *exact*
   operation, including parameter bounds.
5. **Constraints** — CIDR / time-window / concurrency (`EnforceConstraints`);
   residual obligations the executor must discharge stay `allow_unresolved`.
6. **Verdict** — `allow` / `allow_unresolved` / `deny`, with a stable reason code.

Refusals are typed: `*aicverifier.AuthError` carries the HTTP status, a stable
reason code, the records the refusal produced, and — when presenting evidence
could fix it — an RFC 9457 problem document with a `CLC-CHALLENGE-v1` challenge.

`allow_unresolved` is **not** allow. A recognized-but-unevaluated constraint is
never silently promoted; it stays visible and must be discharged at the effect
boundary.

---

## Evidence, not logs

A decision is not much use if nobody can check it later. With `Evidence` set, the
SDK emits a **CLC decision record** (inputs frozen at the canonical boundaries, a
digest over them, the verdict and its stable reason), optionally signed and
wrapped in a DSSE envelope, through an `EvidenceSink`. Refusals that never reach
the language layer produce an **admission record** instead, and the proxy or
middleware can report what the effect boundary observed as an **outcome record**.

- **One record per (authority source, operation).** A record whose verdict does
  not reproduce is impossible by construction — it is recomputed from the same
  grants.
- **Refusals are recorded too**, so intent is as auditable as action.
- **Recomputable offline.** `register/cmd/record -verify` re-runs the language over
  a record the holder did not produce; `VerifyEvidenceDir` additionally binds each
  outcome to the decision actually present and reports orphans instead of counting
  them as consent.
- **Key-endorsed when you want it.** `EvidenceConfig.Sign` appends a DSSE signature
  over `PAE(payloadType, payload)` to every record; a deployment that needs
  "which admission point issued this" gets it, and one that does not pays nothing
  (records stay content-recomputable, just unsigned).

Details and the profiles that pin the shape: **[docs/evidence.md](docs/evidence.md)**.

---

## Compliance fit

The properties above map directly onto hard requirements regulators write down.
All of the following are *public* requirements, matched to what the SDK actually
does — not a certification claim.

| Requirement (public source) | What `aic-verifier` provides |
|---|---|
| Strong authentication / unique identity — HIPAA §164.312(d),(a)(2)(i); EO 14028 MFA; 中国网安法 §24 真实身份 | mTLS AIC certificate or AIC-JWT, key-bound (SPKI / `cnf`) |
| Least privilege / fine-grained authorization — PIPL §51(四); HIPAA §164.312(a)(1); EO 14028 §4(i) | per-operation capability ∩ principal authorization with parameter bounds — decided per action, not per session |
| Least-privilege **enforcement** at the action boundary — NIST SP 800-207 | fail-closed refusal *before* the handler; `allow_unresolved` never silently allow |
| Immutable / attributable audit trail — SEC 17a-4(f); HIPAA §164.312(b); EU AI Act Art 12; 中国网安法 §21 | Merkle-chained audit log + DSSE decision records, per-admission nonce, optional TSA timestamp |
| Evidence verifiable offline / accountable — SEC 17a-4(f)(2)(iv),(f)(3)(v); EU AI Act Art 12(3)(d) | records recomputable without the online authority; pinned-key verification; exportable `EvidenceBundle` |
| Human oversight / approval — EU AI Act Art 14(4)(5),(26); PIPL §24; 算法推荐规定 §7 | `RequireApproval` → `ApprovalRequester`, break-glass with mandatory `OverrideRecorder`, auditable supervision events |
| Real-time revocation | CRL / OCSP in the pipeline; short-lived credentials by design |

**What this does not do:** it constrains no path that bypasses the enforcement
point. Evidence proves the admission decision; it does not prove source truth or
that a downstream effect succeeded (that is the effect-boundary's job). It is not
an accredited certification.

---

## Configuration you will actually touch

| Field | What it does |
|---|---|
| `CACertFile` / `JWTCAFile` | trust anchors for mTLS client certs / bearer tokens |
| `AuthMode` | `MTLSOnly`, `BearerOnly`, `MTLSOrBearer` (default) |
| `RequireAIC` | reject certificates that carry no AIC extension |
| `RequiredCapabilities` / `RequiredOperations` | capability ids, or concrete operations with parameter bounds, the caller must satisfy |
| `EnforceConstraints` | evaluate authorization constraints (time window, CIDR, `max_rows`) |
| `AdmissionConfig` | CRL/OCSP, roles, SPIFFE, delegation chain, monitoring hooks |
| `Evidence` / `EvidenceProfile` / `EvidenceRequirement` | records, their shape, and the sufficiency bar |
| `Challenge` / `ChallengeCarrier` | whether a refusable refusal carries a challenge, and how it is rendered |
| `SupervisionPolicy` / `ApprovalRequester` / `OverrideRecorder` | runtime approval and break-glass |
| `AuthorizationPolicy` / `Constraints` / `ParameterValidators` | per-`Config` isolation of policy and registries |
| `IdentityMode` | how much verified identity is disclosed to a backend |
| `ServerOptions` / `StreamBody` / `LogFile` / `Logger` | proxy server tuning, body streaming, logging |

The full list, with types and defaults, is in **[docs/reference.md](docs/reference.md)**
and **[docs/api.md](docs/api.md)**; `config.example.json` is kept in sync with the
JSON surface by CI.

---

## Documentation map

| You want to… | Start here |
|---|---|
| Try it in two minutes | [quickstart.md](docs/quickstart.md) |
| Decide between *middleware* and *reverse proxy*, and see the code | [api.md](docs/api.md) · [architecture.md](docs/architecture.md) |
| Turn on evidence and understand what a record means | [evidence.md](docs/evidence.md) |
| Know every `Config` field, record shape, constant and version | [reference.md](docs/reference.md) |
| Understand *why* a decision is (or is not) trusted | [threat-model.md](docs/threat-model.md) |
| Put it in production: TLS, keys, monitoring, rotation | [deployment.md](docs/deployment.md) |
| Run the examples end to end | [examples.md](docs/examples.md) |
| Compare SDK vs full gateway, and current non-goals | [comparison.md](docs/comparison.md) |

---

## Stability

Before v1.0 the surface is split two ways so an embedder can tell what is safe
to build on:

| Surface | Contract |
|---|---|
| **Frozen until v1.0** — `Config`, `Handler` / `AuthMiddleware`, `NewServer` + `Server.{Listen,Serve,Addr,ListenAndServe,Close}`, `NewDecisionServer` + `DecisionServer.{Decide,Health,AdminHandler,ReloadPolicy,Close}`, `AuthContext`, `AuthError`, `DecisionMetrics` | additive-only: no field is renamed or removed and no default changes without a documented deprecation. The CLC revision such a binary decides with only moves with an explicit `CLCRevision` bump. |
| **Experimental** — plugin/registry hooks (`PluginRegistry`, `CapabilityRegistry`, `RegisterGeoResolver`, parameter validators), supervision/evidence interfaces (`ApprovalRequester`, `OverrideRecorder`, `EvidenceExporter`), and anything under an `examples/` or `mcp/` package | may change in a minor release while the surrounding format stabilises. |

`Config.Close` (also reached through `Server.Close` / `DecisionServer.Close`)
releases the config-owned background resources — audit logger, nonce-cache
cleanup, supervision store, SDK log file. CRL and OCSP refresh loops remain the
caller's to stop (`CRLCache.Start`, `StartOCSPStapling`).

---

## Requirements

| Requirement | Why |
|---|---|
| **Go 1.26 or newer** | the module declares `go 1.26`; no cgo |
| `github.com/varwof/register v0.6.0` | the CLC evaluator and the decision-record format |
| `github.com/varwof/types v0.6.0` | AIC / AIC-JWT structures |
| `github.com/varwof/pkcs7 v0.1.1` | the semantics-layer detached signature check |
| `github.com/mark3labs/mcp-go v1.0.0` | only if you import the `mcp` subpackage |

They come in with `go get`; there are no local `replace` directives and nothing
is vendored. The SDK itself needs no external service: CRL/OCSP responders and an
RFC 3161 timestamp authority are optional and only used when you configure them.

For the demo above you additionally need `curl` (any mTLS-capable client works)
and three free local ports: **9444** (proxy), **9081** (demo backend it starts
itself), and later **9443** (the evidence demo).

---

## Related repositories

| Repository | Role |
|---|---|
| [varwof/types](https://github.com/varwof/types) | Shared Go types: AIC, AIC-JWT, capabilities |
| [varwof/register](https://github.com/varwof/register) | Capability registry, PKCS#7 signing, CLC semantics (the reference implementation this SDK evaluates with) |
| [varwof/capability](https://github.com/varwof/capability) | CLC specification and conformance corpus |
| [varwof/aic-agent](https://github.com/varwof/aic-agent) | Consumer-side SDK that mints and carries the credential this verifier checks |
| [varwof/aic-exec](https://github.com/varwof/aic-exec) | AIC-gated command executor built on this admission core |
| [varwof/gateway-core](https://github.com/varwof/gateway-core) · [varwof/gateway](https://github.com/varwof/gateway) | Full gateway; this SDK is its embeddable admission core |

## License

Apache-2.0. See [LICENSE](LICENSE).

See also [SECURITY.md](SECURITY.md) (vulnerability reporting, guarantees,
hardening), [CONTRIBUTING.md](CONTRIBUTING.md) (development and the check
list), and [CHANGELOG.md](CHANGELOG.md).
