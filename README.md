# aic-verifier

Service-side SDK for AIC (Agent Identity Certificate) authorization over HTTP.

`aic-verifier` is an independent, re-embeddable Go library derived from the
varwof gateway-core admission engine. It lets you protect a real HTTP API with
AIC authorization using a few lines of code — without deploying a full gateway.

> **Status**: early. The API, and the CLC revision it evaluates (currently
> CLC-1.3), may change before the first stable release.

## Features

- **Two transport modes** for presenting an agent's AIC:
  - **Bearer AIC-JWT** (`Authorization: Bearer ...`, signed by a CA you trust)
  - **mTLS client certificate** (client cert carrying the AIC X.509 extension)
- **Unified admission pipeline** per request: certificate validity → CRL/OCSP
  (optional) → role checks → SPIFFE (optional) → AIC decision → capability
  intersection → parameter boundary validation (P∩C).
- **Reverse proxy server** that forwards admitted requests to your real API
  backend and injects `X-AIC-*` identity headers.
- **Middleware** (`AuthMiddleware`) for embedding the same checks into an
  existing `net/http` server.
- **Capability filtering** against per-route `RequiredCapabilities`.
- Optional: audit logging, risk monitoring, nonce/replay cache, delegation
  chain verification, constraints enforcement.

## Install

```bash
go get github.com/varwof/aic-verifier@latest
```

Requires Go 1.26+. It builds against the published `github.com/varwof/types
v0.6.0` and `github.com/varwof/register v0.2.0`; no local `replace`
directives are needed.
## Quick start (Bearer AIC-JWT)

```sh
cd examples/bearer-jwt-backend
go run ./gen-bearer > token.txt        # writes ca.pem + prints a signed token
go run .                                # AIC proxy on :9443 -> backend :9080
curl -k https://localhost:9443/api \
     -H "Authorization: Bearer $(cat token.txt)"
```

## Quick start (mTLS + X.509 AIC extension)

```sh
cd examples/mtls-backend
go run ./gen-cert --out dev-certs      # CA + server cert + AIC client cert
go run .                               # AIC mTLS proxy on :9444 -> backend :9081
curl -k --cert dev-certs/client-cert.pem --key dev-certs/client-key.pem \
     https://localhost:9444/api
```

## Embedded middleware

```go
conf := &aicverifier.Config{
    JWTCAFile:                "ca.pem",
    JWTIssuer:                "aic-verifier-example",
    JWTAudience:              []string{"myapi"},
    AuthMode:                 aicverifier.BearerOnly, // or MTLSOnly / Mutual
    RequireAIC:               true,
    RequiredCapabilities:     []string{"api:read"},
    DisallowRepresentative:   true,
    EnforceConstraints:       true,
}

handler, err := conf.Handler(http.HandlerFunc(apiHandler))
http.ListenAndServeTLS(":9443", "server-cert.pem", "server-key.pem", handler)
```

Inside `apiHandler`, read the admitted identity with `aicverifier.FromContext(r.Context())`.

## Reverse proxy

```go
server, err := aicverifier.NewServer(conf, []aicverifier.Route{
    {Path: "/api", Target: backendURL, RequiredCapabilities: []string{"api:read"}},
})
server.ListenAndServe(":9443")
```

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the admission pipeline, trust model,
and the difference between this SDK and the full gateway.

## What it does not do

- **No network calls.** Verification is offline: AIC signatures, the
  delegation chain and the capability language are evaluated against the
  trust anchors the deployer configures.
- **No trust decisions of its own.** The JWT CA, the client CA and the
  capability registry are inputs, not defaults.
- **No execution evidence.** A verified request is an authorization
  decision (who may do what), not a record that the action ran.

## Related repositories

| Repository | Role |
|---|---|
| [varwof/types](https://github.com/varwof/types) | Shared Go types: AIC, AIC-JWT, capabilities |
| [varwof/register](https://github.com/varwof/register) | Capability registry, PKCS#7 signing, CLC semantics |
| [varwof/capability](https://github.com/varwof/capability) | Capability definitions, CLC spec and conformance corpus |
| [varwof/core](https://github.com/varwof/core) | CA and AIC issuance |
| [varwof/client](https://github.com/varwof/client) | CLI for issuance and delegation signing |
| [varwof/gateway-core](https://github.com/varwof/gateway-core) · [varwof/gateway](https://github.com/varwof/gateway) | Full gateway; this SDK is its embeddable admission core |
| [varwof/aic-agent](https://github.com/varwof/aic-agent) | Consumer-side SDK that presents AIC credentials to a service using this verifier |

## License

Apache-2.0. See [LICENSE](LICENSE).