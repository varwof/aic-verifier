# aic-verifier documentation

This is the developer and operator documentation for `aic-verifier`. It is
meant to be read without the source: everything below describes the surfaces,
shapes and guarantees, and points at the files to open when you want the code.

## Reading paths

| You want to… | Start here |
|---|---|
| Try it in two minutes | [quickstart.md](quickstart.md) |
| Decide between *middleware* and *reverse proxy*, and see the code | [api.md](api.md) · [architecture.md](architecture.md) |
| Turn on evidence and understand what a record means | [evidence.md](evidence.md) |
| Know every `Config` field, record shape, constant and version | [reference.md](reference.md) |
| Understand *why* a decision is (or is not) trusted | [threat-model.md](threat-model.md) |
| Put it in production: TLS, keys, monitoring, rotation | [deployment.md](deployment.md) |
| Run the examples end to end | [examples.md](examples.md) |
| Compare SDK vs full gateway, and current non-goals | [comparison.md](comparison.md) |

## The two integration styles in one paragraph

1. **Middleware** — `cfg.Handler(mux)` wraps your own `http.Handler`. The SDK
   authenticates each request, refuses early, and puts the verified
   `*AuthContext` on the request context (`aicverifier.FromContext`). You keep
   your routing and your handler code.[`api.md`](api.md) is the reference.
2. **Reverse proxy** — `NewServer(cfg, routes)` runs one `http.Server` in
   front of a backend and injects `X-AIC-*` identity headers. Your backend
   does not change at all.[`architecture.md`](architecture.md) has the flow.

The **DecisionServer** adds a third, transport-independent style:
`NewDecisionServer(cfg)` exports the same admission as `Decide()`, HTTP, gRPC
and an admin handler, so HTTP and non-HTTP carriers make the identical decision
for one `Config`.

## What you always get

- Missing/invalid credential → typed `*AuthError`, request never reaches the
  handler/backend.
- `allow_unresolved` is never silently `allow`.
- With `Evidence` configured: recomputable DSSE-wrapped decision/admission/
  outcome records, each bound to a per-admission nonce, with verified linkage.
- Authorization policy (capabilities, roles, constraints, challenges) is
  configured, never taken from the request.

## Repository layout

```
aicverifier.go   HTTP entry (Authenticate, Handler/AuthMiddleware)
config.go        Config, LoadConfigFile/ParseConfig
decision.go      CLC decision core + capability ∩ principal authorization
clc.go           CLCRevision, Authorize* helpers
aic.go           AIC structures, AICFingerprint, HasAIC
identity.go      AuthContext, FromContext, X-AIC-* propagation
challenge.go     CLC-CHALLENGE-v1 refusal shape
evidence*.go     decision/admission/outcome records, sinks, verify, profiles
server.go        reverse proxy (Routes, outcome reporting)
decide.go        DecisionServer (transport-independent Decide/Admin/Health)
audit.go         audit logging (merkle-chained, TSA-signable)
mcp/             optional MCP admin-panel subpackage
examples/        runnable end-to-end examples (see examples.md)
smoke/           CLC corpus smoke suite (build tag smoke)
```

## Other entry pages

- [SECURITY.md](../SECURITY.md) — guaranteed properties, reporting, hardening
- [CONTRIBUTING.md](../CONTRIBUTING.md) — build/test gates, conventions
- [CHANGELOG.md](../CHANGELOG.md) — release history