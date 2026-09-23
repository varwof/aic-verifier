# aic-verifier threat model

What an attacker can and cannot break, who is trusted, and the controls that
hold. This page complements [SECURITY.md](../SECURITY.md) (policy, reporting,
hardening) with the analysis itself; [architecture.md](architecture.md) has the
system's normal operation.

**In scope.** Everything in package `aicverifier` when used through its
documented surfaces (`Config`, `Handler`/`AuthMiddleware`, `Server`,
`NewDecisionServer`, evidence/audit helpers) with correctly-configured trust
material.

**Assumed attacker.** Remote, unauthenticated by definition: anyone who can
reach your HTTP endpoint. She can send any request, present any client
certificate she can obtain, mint her own tokens, and read all public material
(including TLS handshakes on the wire). She does **not** hold your CA keys, your
configuration, the trusted services you configured, or keys stored outside the
reach of the network.

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Admission decision | the actual GATE: what may run | in-memory pipeline result, mirrored into records |
| Evidence records | replayable proof of decisions/effects | the sink (files/log/dep) |
| Caller identity (principal/agent) | who the operation is attributed to | certificate/token → `AuthContext` |
| Trust material | CA certs, JWT CA, evidence signing key | config files / embedder key store |
| Audit chain | tamper-evident log of decisions | audit file + merkle root + optional TSA |

## Trusted components

- **The embedder's `tls.Config`** — with `RequireAndVerifyClientCert` + `ClientCAs`
  the handshake is the first checkpoint. If the embedder does *not* verify client
  certs, `CACertFile`-based chain building still runs, but the notion of "who
  presented this" is weaker (see controls below).
- **Configured CAs** (`CACertFile`, `JWTCAFile`) — whoever holds these keys can
  mint identities the SDK will admit (subject to capabilities). Compromise of a
  CA = compromise of identity.
- **External responders** — CRL/OCSP endpoints and the optional RFC 3161 TSA.
  The SDK **fails closed** on lookups it cannot complete, but a compromised/
  lying responder can still assert "not revoked" or stamp a witness over content
  you gave it.
- **Supervision/approval hooks** (`ApprovalRequester`, `OverrideRecorder`) —
  pluggable by design; a broken or over-permissive hook can widen the admission
  set. Default: a broken hook denies/logs loudly, and never widens.

## Threats and controls

### T1 — Forge an identity
*Attacker presents a self-signed cert or self-minted token claiming to be a real agent/principal.*

- **mTLS**: chain must verify to `CACertFile`; `HasAIC`/`RequireAIC` demands the
  AIC extension; `EnforceConstraints` checks principal authorization claims;
  `max_rows`/`time:window`/`network:cidr` are evaluated by the language.
- **Bearer**: `kid`→SPKI must resolve under `JWTCAFile`, `sub`/`aud`/`iss` checked
  against `JWTIssuer`/`JWTAudience`, and `cnf.jkt` binds the presenter key.
- **Replay**: `ReplayProtection` (single-use `jti`) + per-admission nonce make a
  captured token/cert useless *after* first use.
- **Residual**: a fresh CA-issued cert for a stolen/unknown key is out of model
  (it is a CA key compromise, see [Escalation](#escalation)).

### T2 — Amplify privileges / capability confusion
*Attacker with a legitimate low-privilege identity requests a high-privilege operation.*

- Capability requirements are checked per route/operation (`RequiredCapabilities`,
  `RequiredOperations`); `P ∩ C` intersects the declared AIC/PA grants against the
  requested operation (`capability_not_authorized`).
- Delegation chains are bounded (`DefaultMaxChainLength=8`) and representative
  mode can be forbidden (`DisallowRepresentative`).
- **Control**: misconfiguration (too-broad `RequiredCapabilities`) is the main
  realistic path; it fails *open*, so defense is review + least-privilege
  defaults.

### T3 — Parameter-bounds bypass / constraint evasion
*Attacker declares a constraint it doesn't intend to honor, or asks for params
outside the declared bounds.*

- Parameters are bounded (`DefaultMaxBodyBytes=1MiB`, per-operation param
  validators); `max_rows` and friends are evaluated by the CLC core.
- `allow_unresolved` is a distinct verdict and cannot be turned into `allow`
  without an explicit discharge rule (`UnresolvedEvaluator`/`DischargeObligations`
  naming the exact obligation types). There is no code path that silently
  releases an obligation.
- Constraint registry isolates: an unknown constraint type in a strict mode
  fails closed rather than passing (see `config_isolation_test.go`).

### T4 — Spoof identity propagation
*Caller sets `X-AIC-*` headers, or requests the backend trust a client-claimed identity.*

- The proxy **strips** client-supplied `X-AIC-*`, `Authorization`, and
  `Proxy-Authorization` before injecting its own server-asserted headers
  (`identity.go`); the backend only ever sees server-derived values.
- `IdentityMode` comes from `Config`, never from the attacker-controlled
  `X-AIC-Identity-Mode` header (S1).
- In middleware style, identity is read from `AuthContext` (on context), not from
  headers.

### T5 — Tamper with evidence / reorder an audit trail
*Attacker edits a record file, replays an old record, or reorders the audit log.*

- Records are wrapped in a DSSE envelope, signed when `Evidence.Sign`/`KeyID` is
  set, and their input digest **recomputes** from the record's own inputs
  (`LoadEvidenceRecord` / `CheckEvidenceEnvelope` refuse a mismatch).
- Each decision binds a per-admission nonce; two identical requests are two
  distinct records, so replaying an old decision under a new context is visible.
- Outcome `DecisionDigest` linkage is verified against the decisions actually
  present (`VerifyEvidenceDir`): an outcome that doesn't resolve is an orphan,
  never silent consent.
- Audit entries are merkle-chained and optionally TSA-witnessed; a mutation
  breaks the chain, and a stale/rolled-back log is detectable against the
  published merkle root.

### T6 — DoS / resource exhaustion
*Flood of admissions, or a flood of evidence-required challenges that pound a gate.*

- The SDK is check→answer; connection/rate limiting is the edge's job (the SDK
  is not a DDoS filter). Challenge TTL and the client-side `Retry-After` lower
  bound cap damage from *corrected-presentation* retries.
- `Config.ServerOptions` timeouts default to safe values in proxy style.

### T7 — Evidence-suppression / gap
*Sink is down or an admission is silently dropped.*

- `EvidenceConfig.Strict` converts emission failure into a refusal; `Gaps`
  counts emissions that left no record so ops can alert. Failure is visible, not
  silent.

## Escalation

- **CA key compromise** (mTLS `CACertFile` or JWT `JWTCAFile`): an attacker with
  real CA keys can mint identities that pass authentication. Mitigation is
  operational: rotate/revoke the CA, CRL/OCSP the minted certs, and turn
  `EnforceConstraints`/supervision up. The SDK cannot defend against its own
  trust root lying.
- **Server key compromise** (your TLS cert): passive wire decryption; an attacker
  who can terminate TLS observes bearer tokens mid-flight. Mitigation: short
  token lifetimes, `ReplayProtection`, no reuse of tokens cross-CN.
- **Evidence signing key compromise**: forged *records*. Signatures only prove
  "the configured key signed it", so keep the key where only the recorder sits.
  When outcome attribution must survive even this, bind the outcome key to the
  execution boundary (currently a deployment responsibility).

## Controls matrix (quick reference)

| Control | Threat |
|---|---|
| `CACertFile` chain verify, `HasAIC`, `RequireAIC` | T1 |
| `JWTCAFile` + `kid`/`cnf.jkt` + `JWTIssuer`/`JWTAudience` | T1 |
| `ReplayProtection` + per-admission nonce | T1, T5 |
| `RequiredCapabilities`/`RequiredOperations` + P∩C | T2 |
| param bounds, constraint registry isolation | T3 |
| header strip/reinject, `IdentityMode` from config | T4 |
| DSSE signing, digest recompute, linkage verify, merkle+TSA audit | T5 |
| `ServerOptions` timeouts, challenge TTL/Retry-After | T6 |
| `Strict` + `Gaps` | T7 |

## Out of scope

- No sandboxing of the effect itself (that is the execution boundary; outcomes
  report what it observed).
- No network policy/rate limiter (edge responsibility).
- No defense against a compromised trust root (see Escalation).
- DoS by raw volume without an edge.

## References

- [SECURITY.md](../SECURITY.md) — reporting + guarantees
- [deployment.md](deployment.md) — TLS, keys, monitoring that make the controls
  real
- [evidence.md](evidence.md) — record shapes and verify paths
- [reference.md](reference.md) — config constants used above