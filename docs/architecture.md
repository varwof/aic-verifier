# aic-verifier architecture

`aic-verifier` is the service side of AIC (Agent Identity Certificate)
authorization over HTTP, packaged as a standalone library. Its admission
engine is extracted from the varwof gateway-core so a plain API service can
enforce AIC without running a gateway.

## Where this fits

```
 protocol carriers                        admission core                        effects
 ────────────────                          ──────────────                        ───────
 HttpClient / compiler produced           aicverifier.RunAccessPipeline         HTTP middleware
   mTLS client cert            ──▶    chain→CRL/OCSP→roles→AIC→CLC         ──▶   handler / backend
   Authorization: Bearer AIC-JWT        capability ∩ PA constraints                  │
   (RATS §10 decision context)                  │  verdict                        evidence:
                                                                                decision/admission/
       peer (any carrier)                            │                          outcome records + DSSE
   gRPC carrier (NewDecisionServer)       CLC decision (semantics)                    │
   queue / in-process Decide()          allow/allow_unresolved/deny             audit (merkle) + supervision
```

`aic-verifier` is a **library**: it does not own the network listener, the
certificate minting, or the policy authoring tool. It owns the decision and the
records. The repo layout mirrors that:

| Area | Files |
|---|---|
| AuthN entry (HTTP) | `aicverifier.go` (`Authenticate`, `Handler`) |
| Admission pipeline | `config.go`, `clc.go`, `decision.go`, `delegation_chain.go`, `constraints.go` |
| Revocation & freshness | `crl.go`, `ocsp.go`, `nonce_cache.go`, `jwt.go` |
| Identity propagation | `identity.go` |
| Evidence | `evidence*.go`, `admission_record.go`, `evidence_sink.go`, `evidence_verify.go`, `evidence_profile.go`, `evidence_signing.go` |
| Challenge / refusal shape | `challenge.go` (`CLC-CHALLENGE-v1`) |
| DecisionServer (transport-independent) | `decide.go`, `admin.go` |
| Audit & supervision | `audit.go`, `merkle.go`, `supervision.go` |
| Reverse proxy | `server.go` (routes, `X-AIC-*`, outcome reporting) |
| gRPC binding | `grpc/` (subpackage, imports `google.golang.org/grpc`) |
| MCP admin panel | `mcp/` (subpackage, imports `mark3labs/mcp-go`) |

## Trust model

A service operator configures the CAs it trusts:

- `JWTCAFile` (for Bearer AIC-JWT): the CA that issues the agent credential
  key. Token `kid` is the CA SPKI hash; `cnf.jkt` binds the presenter key.
- `CACertFile` (for mTLS): the CA that issues client certificates. Client
  certificates must chain to this CA and carry the AIC X.509 extension.

Three modes (`AuthMode`):

- `BearerOnly`: an `Authorization: Bearer <AIC-JWT>` header is required and
  verified against `JWTCAFile`.
- `MTLSOnly`: a validated mTLS client certificate is required.
- `MTLSOrBearer` (default): either credential admits; the pipeline evaluates
  whichever is presented (mTLS chain wins when both are present).

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

## Request flow (middleware style)

```
 client request
   │
   ▼
 middleware handler ── tls.ValidClientCertPair (earliest TLS validation)
   │
   ├─ bearer?   Authenticate reads Authorization: Bearer <aic+jwt>
   │            kid→SPKI→JWTCAFile; jti single-use (ReplayProtection); cnf.jkt
   ├─ mtls?     peer cert chain → buildChain (CACertFile) → CRL/OCSP → roles/SPIFFE
   │
   ▼
 RunAccessPipeline: chain → CRL/OCSP → RBAC → AIC decision → CLC capability ∩ PA
   │            → parameter bounds →  verdict
   │
   ├─ deny ──▶ AuthError (JSON) or application/problem+json (RFC 9457, challenge)
   │              admission record / CLC decision record already emitted
   │
   ├─ allow_unresolved ──▶ DischargeObligations ? evaluate : refuse (never silent allow)
   │
   ▼
 allow: inject X-AIC-* (proxy) / AuthContext on context (middleware)
   │
   ├─ handler runs ──▶ (EmitOutcome) middleware probes status → outcome record
   │
   ▼
 response → auth audit log (optional, TSA-signed) 
```

## Reverse-proxy style

`NewServer(cfg, routes)` builds one `http.Server`; every request goes through
the same middleware (so outcomes are emitted once), then a route match
(`Route.Path` prefix) schedules forwarding. The proxy strips client-supplied
`X-AIC-*` / `Authorization` / `Proxy-Authorization` headers before injecting
its own and contacting the backend; `BackendRootCA` pins HTTPS backends.
Transport failures are reported as `OutcomeIndeterminate` (never a forged 502
outcome).

## Transport-independent decisions

`NewDecisionServer(cfg)` exposes the same admission on `Decide(ctx, view)`,
`Health`, gRPC (`Verify`/`Decide`), and `AdminHandler` surfaces, so HTTP, gRPC,
queue and in-process carriers agree on the identical decision for one `Config`.
`ReloadPolicy` swaps the authorization policy at runtime.

## Read the SDK in this order

`config.go` (surface) → `aicverifier.go` (entry) → `decision.go` / `clc.go`
(core semantics) → `evidence*.go` (records) → `challenge.go` (refusal shape) →
`server.go` (proxy) → `decide.go`/`admin.go` (transport-independent core) →
`grpc/` & `mcp/` (wire bindings).