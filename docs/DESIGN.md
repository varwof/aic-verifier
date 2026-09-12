# aic-verifier design

`aic-verifier` is the service side of AIC (Agent Identity Certificate)
authorization over HTTP, packaged as a standalone library. Its admission
engine is extracted from the varwof gateway-core so a plain API service can
enforce AIC without running a gateway.

## Trust model

A service operator configures the CAs it trusts:

- `JWTCAFile` (for Bearer AIC-JWT): the CA that issues the agent credential
  key. Token `kid` is the CA SPKI hash; `cnf.jkt` binds the presenter key.
- `CACertFile` (for mTLS): the CA that issues client certificates. Client
  certificates must chain to this CA and carry the AIC X.509 extension.

Two modes (`AuthMode`):

- `BearerOnly`: an `Authorization: Bearer <AIC-JWT>` header is required and
  verified against `JWTCAFile`.
- `MTLSOnly`: a validated mTLS client certificate is required.
- `Mutual`: either credential admits; the pipeline evaluates whichever is
  presented (mTLS chain wins when both are present).

## Admission pipeline

For every request the SDK runs `RunAccessPipeline` (same engine core as
gateway-core `pipeline.go`):

1. Chain validity (time window, CA scope: `CheckFullChain` or `CheckLeafOnly`).
2. Optional CRL / OCSP revocation checks (offline-tolerant; fail-closed per
   configuration).
3. Optional RBAC role allow-list from the certificate.
4. Optional SPIFFE trust-domain / allow-list enforcement.
5. Optional offline maximum certificate lifetime.
6. AIC decision (`CheckAdmission`): AIC present, capability requirements,
   representative delegation constraints, user-auth requirements, nonce/replay
   checks, parameter size limits.
7. P∩C capability intersection and parameter boundary validation.
8. Scheme plugins for declared capabilities (phase-one connection decisions).

Differences from the gateway:

- No network listener / connection throttle / full PKI management.
- The SDK does not mint certificates; it consumes them.
- Reverse-proxy serving is optional (`Server`) but middleware is the primary
  integration path.

## Identity propagation

Admitted requests get `X-AIC-*` headers injected before forwarding to the
backend (`identity.go`):

- `X-AIC-Agent-Id`
- `X-AIC-Principal-Uid`
- `X-AIC-Capabilities`

Client-supplied identity headers are stripped first so a caller cannot spoof
them. Embedded users read the same values from `AuthContext` via
`aicverifier.FromContext`.

## Security hardening (post-v0.1)

| Ref | Fix | File |
|-----|-----|------|
| S1  | `IdentityMode` moved to `Config`; proxy reads from config, never from the attacker-controlled `X-AICN-Identity-Mode` header. | `identity.go`, `server.go` |
| S2  | `buildChain` rejects a nil CA pool (fail-closed) instead of silently passing; `Authenticate` denies any client certificate presented without a configured mTLS CA. | `aicverifier.go` |
| S3  | Proxy strips `Authorization` and `Proxy-Authorization` headers before forwarding; the backend receives only server-asserted `X-AIC-*` headers. | `server.go` |

### `Config.IdentityMode`

Defaults to `IdentityForwardClientCert`. The reverse proxy uses this value
directly; in middleware style, callers pass the mode via
`aicverifier.SetIdentityHeaderMode` and must ensure it originates from server
configuration, never from client request headers.

## Callbacks and configuration surface

### Hooks (`Config.Hooks`)

`Hooks` is the reserved extension point for lifecycle callbacks:

- `Authenticated (ctx, r) error` — runs on every admitted request before the
  upstream handler; returning an error denies the request with 403.
- `Denied (r, *AuthError)` — fires on every pipeline or route-level rejection.
- `Forwarded (r, resp)` — fires after a reverse-proxy round trip (proxy style).

Plugins (`PluginRegistry`, capability schemes), `AuditLogger`,
`CRLCache`/`OCSPCache` and `UserCertResolver` remain the deeper extension
points already provided.

### Configurable server

`Config.ServerOptions` tunes the embedded `http.Server` in proxy style:
`ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, `IdleTimeout`,
`MaxHeaderBytes`. Zero values fall back to safe defaults
(`ReadHeaderTimeout=30s`, `IdleTimeout=120s`).

### Log file

`Config.LogFile`, when non-empty, appends SDK logs to that file (0644) instead
of stdout. Callers that need programmatic control pass `Config.Logger` instead;
`Config.CloseLogger()` releases the opened file.

### Verification files

Authorization verification is configured from files: `CACertFile` (mTLS CA
bundle), `JWTCAFile` (AIC-JWT trust root), plus optional `UserCert` /
`UserCertResolver` and `CRLCache`/`OCSPCache` for revocation.
`BackendRootCA` (one or more PEM files) is appended to the system roots for
the reverse proxy's outbound TLS to HTTPS backends, so internal PKIs can be
trusted for backend calls.

### JSON configuration (`LoadConfigFile` / `ParseConfig`)

All of the above can be set from a single JSON file (`config.example.json`):
listener timeouts, log file, TLS/mTLS files, JWT policy, auth/identity modes,
and admission policy. Unknown fields are rejected so typos surface as errors.