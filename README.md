# aic-verifier

Give any HTTP service the ability to check **who the agent is, what it is allowed
to do, and what was actually recorded** — for agents that present an AIC
(Agent Identity Certificate) over mTLS or as a signed JWT.

It is a small Go library, not a gateway: wrap your handler, or put the bundled
reverse proxy in front of an API.

[English](README.md) · [中文](README_CN.md)

> **Status**: early. The API may change before the first stable release. It
> evaluates **CLC-1.5**; see [docs/DESIGN.md](docs/DESIGN.md) for the layering and
> [docs/evidence.md](docs/evidence.md) for the evidence side.

## What it does

Per request, one pipeline decides: certificate validity → CRL/OCSP → roles →
AIC decision → capability ∩ (principal authorization) → parameter bounds →
**allow / allow_unresolved / deny**, and (optionally) writes a decision record
you can recompute later.

- **Two transports**: mTLS client certificate carrying the AIC extension, or
  `Authorization: Bearer <AIC-JWT>`.
- **Two integration styles**: `(*Config).Handler` / `AuthMiddleware` around your
  own handler, or `Server` as a reverse proxy that injects `X-AIC-*` identity
  headers.
- **Evidence, not logs**: each decision can be emitted as a DSSE-wrapped CLC
  decision record, plus admission records for refusals that happen before the
  language layer and outcome records from the effect boundary.

## Requirements

| Requirement | Why |
|---|---|
| **Go 1.26 or newer** | the module declares `go 1.26`; no cgo |
| `github.com/varwof/register v0.3.0` | the CLC evaluator and the decision-record format |
| `github.com/varwof/types v0.6.0` | AIC / AIC-JWT structures |
| `github.com/varwof/pkcs7 v0.1.0` | the semantics-layer detached signature check |
| `github.com/mark3labs/mcp-go v1.0.0` | only if you import the `mcp` subpackage |

They come in with `go get`; there are no local `replace` directives and nothing
is vendored. The SDK itself needs no external service: CRL/OCSP responders and an
RFC 3161 timestamp authority are optional and only used when you configure them.

For the demo below you additionally need `curl` (any mTLS-capable client works)
and three free local ports: **9444** (proxy), **9081** (demo backend it starts
itself), and later **9443** (the evidence demo).

## Quick start (2 minutes)

Four steps, each one short. The demo generates its own CA and certificates, so
there is nothing to configure first.

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

## Use it in your own service

Wrap an existing handler — the SDK authenticates the request, refuses early,
and hands your handler the verified identity:

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

Or run the reverse proxy and keep your backend untouched:

```go
target, _ := url.Parse("http://127.0.0.1:8080")
server, err := aicverifier.NewServer(conf, []aicverifier.Route{
    {Path: "/api", Target: target, RequiredCapabilities: []string{"demo/example-v1:api:read"}},
})
log.Fatal(server.ListenAndServe(":9444"))
```

Refusals are typed: `*aicverifier.AuthError` carries the HTTP status, a stable
reason code, the records the refusal produced, and — when presenting evidence
could fix it — an RFC 9457 problem document with a `CLC-CHALLENGE-v1` challenge.

## Configuration you will actually touch

| Field | What it does |
|---|---|
| `CACertFile` / `JWTCAFile` | trust anchors for mTLS client certs / bearer tokens |
| `AuthMode` | `MTLSOnly`, `BearerOnly`, `MTLSOrBearer` (default) |
| `RequireAIC` | reject certificates that carry no AIC extension |
| `RequiredCapabilities` | capability ids the caller must hold (on `Config` and per `Route`) |
| `EnforceConstraints` | evaluate authorization constraints (time window, CIDR, `max_rows`) |
| `AdmissionConfig` | CRL/OCSP, roles, SPIFFE, delegation chain, monitoring hooks |
| `Evidence` | sink, evidence profile, freshness TTL, signing, outcome emission |
| `Challenge` | whether a refusable refusal carries a challenge, and its TTL/audience |

The full list, with types and defaults, is in **[docs/api.md](docs/api.md)**.

## Evidence in one paragraph

A decision is not much use if nobody can check it later. With `Evidence` set, the
SDK emits a CLC decision record (inputs frozen at the canonical boundaries, a
digest over them, the verdict and its stable reason), optionally signed, wrapped
in a DSSE envelope, through an `EvidenceSink`; refusals that never reach the
language layer produce an admission record instead, and the proxy can report what
the effect boundary observed. Recognised-but-unevaluated constraints stay visible
as residual obligations — `allow_unresolved`, never silently `allow`. Details and
the profiles that pin the shape: [docs/evidence.md](docs/evidence.md).

## Examples

| Example | Shows |
|---|---|
| [`examples/mtls-backend`](examples/mtls-backend) | mTLS + AIC, reverse proxy, identity headers, supervision/evidence demo |
| [`examples/bearer-jwt-backend`](examples/bearer-jwt-backend) | the same service protected by `Authorization: Bearer` AIC-JWT |
| [`examples/mcp-server`](examples/mcp-server) / [`mcp-behind-proxy`](examples/mcp-behind-proxy) | AIC-gated MCP server, and one behind the proxy |
| [`examples/smoke-verify`](examples/smoke-verify) | minimal server used by the smoke test and the quick start |
| [`examples/inspect-record`](examples/inspect-record) | read a decision record back and recompute its verdict |
| [`examples/supervision-demo`](examples/supervision-demo) | approver + evidence exporter wiring used by the mTLS example |

## Related repositories

- [`varwof/types`](https://github.com/varwof/types) — AIC and AIC-JWT structures
- [`varwof/register`](https://github.com/varwof/register) — the CLC reference
  implementation this SDK evaluates with (pinned at `v0.3.0`)
- [`varwof/capability`](https://github.com/varwof/capability) — the CLC
  specification and its conformance corpora

## License

Apache-2.0.
