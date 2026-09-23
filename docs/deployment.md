# aic-verifier deployment

How to run `aic-verifier` in production: TLS, TLS notes, evidence operations,
monitoring, key rotation, and the reverse-proxy-vs-middleware decision made
concrete. It assumes you know what the SDK does; this page is the operational
playbook.

## 1. Decide your integration style

| | Middleware (`cfg.Handler`) | Reverse proxy (`NewServer`) |
|---|---|---|
| Touches my handler | yes — it wraps it | no — backend untouched |
| TLS termination | you (embed `tls.Config`) | you can let the proxy do it (`ServerOptions` + TLSCertFile) or front it |
| Identity delivery | `AuthContext` on request context | `X-AIC-*` headers |
| Backend platform | any HTTP code you control | any backend, incl. non-Go |
| Refusal | typed JSON / problem+json to the caller | same |

Choose middleware when you own the handler and want identity in-process; choose
the proxy when you host a backend you don't want to modify. Both can be on one
`Config` only if you run the proxy *behind* the middleware — the SDK's
`NewServer` already composes the middleware for the same `Config`, so do not
double-wrap.

## 2. TLS is yours

`aic-verifier` authenticates over a connection you brought up. In production:

- Terminate mTLS with `tls.RequireAndVerifyClientCert` and a `ClientCAs` pool
  containing exactly the CAs you trust. `MTLSServerConfig` / `ClientTLSConfig`
  helpers build sane configurations.
- For Bearer + HTTPS: keep token lifetimes short, `ReplayProtection` on, and
  front with your usual TLS terminator — nothing about a bearer token proves who
  wrote it on the wire.
- Use `BackendRootCA` + HTTPS for proxy→backend when the backend is remote, so
  the identity headers are not sent in cleartext.

## 3. Keys

| Key | Where it sits | You should |
|---|---|---|
| mTLS/JWT CAs | CA key material | keep off the service host; rotate per CA policy |
| Evidence `Sign`/`KeyID` | whichever key signs records | keep operationally separate from front TLS; needs file? It is an in-memory func — load from your KMS/HSM at startup |
| Audit TSA | external RFC 3161 authority | optional; gives non-repudiation for audit entries |
| Server TLS | your TLS terminator | standard rotation |

Never put a private key in `config.example.json` or in a config file with
permissive permissions. `Config.LogFile` is created 0644, evidence files are
whatever the sink's umask is — set your deployment's umask deliberately.

## 4. Evidence operations

- Choose a sink: `FileSink{Dir: ...}` for durable per-record envelopes,
  `SlogSink` for thin deployments, a custom sink for a database. Set a
  `RecorderID` (or a full `RecorderDescriptor`) so multi-instance deployments
  can attribute records.
- Set a profile explicitly (`clc-decision+admission+outcome@1` when you want all
  three payloads) — an unknown profile **fails at configuration time**, which is
  the point.
- `TTL` adds the RATS §10.1 clock; the per-admission nonce is always there, so a
  zero-TTL deployment still gets collision-resistant, recomputable records.
- Decide on `Strict`. Ops flow:
  - Keep sink availability in your health checks — a silent sink gap with
    `Strict=false` looks like "no records" for reasons you want to know.
  - Monitor `Gaps` (count of emissions that left no record); alert on it.
  - Run `VerifyEvidenceDir` periodically (e.g. a daily job) and page on
    `OrphanOutcome > 0` or any `Failures`.
  - Archive: `FileSink` names files by digest; back them up (they are your
    audit trail, cheap to store, immutable-append).
- Golden-hour recovery: if the sink dies mid-run and `Strict=false`, the
  records are lost. `Strict=true` refuses instead — choose per contract.

## 5. Monitoring & logging

- `Logger`/`LogFile`: structured SDK logs. In production prefer `Logger` (slog)
  routed to your collector over a file.
- `AuditLogger`/`AuditLogFile` + `AuditTSAURL`: tamper-evident audit. If you
  claim any audit promise, run it with TSA in your trusted authority region.
- `AuthError.Stage` + `Code` are stable — build your denial dashboards on these,
  not on parsing response bodies.
- Watch `Config.Gaps` and challenge/`Retry-After` behavior on the supervision
  path: an approval system can be a second admission path; log approvals and
  denied-overrides explicitly.

## 6. Multi-instance & scaling

- **DecisionState**: the SDK keeps nonce/replay state (`NonceCache`), revocation
  caches, and supervision state. If you run multiple replicas, either:
  - let each replica have its own cache and rely on the TTL/clock for replay
    (acceptable for short TTL deployments), **or**
  - put nonce/replay + revocation behind a shared store (your decision), since
    the SDK's `NonceCache` is in-memory per process.
- The `DecisionServer` (transport-independent) is the right scaling seam: run a
  fleet of identical `Config`s and decide in-process; or centralize decisions
  with gRPC `Decide`/`Verify` for multi-carrier uniformity.
- CLC is deterministic per `Config`: two replicas with the same policy make the
  same decision. Keep `Config` in sync (differential in CI when you can).

## 7. Rotation & failure drills

- **CA rotation**: add the new CA to `CACertFile`/`JWTCAFile` first; drain the
  old, then remove. Validate with a staging request presenting a long-lived cert.
- **Evidence key rotation**: emit with the new `KeyID` and verify old records
  still recompute (they carry their own digest; the key only matters for
  signature verification). Transition consumers who pin `VerifyFnFromPublicKey`.
- **Drill**: kill the CRL/OCSP responder and confirm **fail-closed** (requests
  denied); kill the evidence sink with `Strict=true` and confirm refusals; pivot
  the clock and confirm the freshness/`TTL` checks trip. The SDK's tests cover
  these; your deployment should, too.

## 8. Checklist

- [ ] `AuthMode` is one transport unless transitioning
- [ ] `RequireAIC` is `true`; capabilities are least-privilege per route
- [ ] `EnforceConstraints` on; `DisallowRepresentative` set where unwanted
- [ ] mTLS list uses `RequireAndVerifyClientCert` + correct `ClientCAs`
- [ ] Bearer: `ReplayProtection` on, short `exp`, `JWTIssuer`/`JWTAudience` tight
- [ ] Evidence: profile set, sink healthy, `Gaps` monitored, periodic
      `VerifyEvidenceDir`
- [ ] Audit: merkle + optional TSA on
- [ ] `ServerOptions` timeouts set for your LBs
- [ ] CA/key rotation drill done
- [ ] `hack/consumer-view.sh` green (deps from proxy) — CI enforces it