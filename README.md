# aic-verifier

Service-side SDK for AIC (Agent Identity Certificate) authorization over HTTP.

`aic-verifier` is an independent, re-embeddable Go library derived from the
varwof gateway-core admission engine. It lets you protect a real HTTP API with
AIC authorization using a few lines of code — without deploying a full gateway.

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

## License

Apache-2.0. See [LICENSE](LICENSE).