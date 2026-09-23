# Security

`aic-verifier` sits on the admission path of an HTTP service: it decides whether
a caller presenting an AIC credential may reach an operation, and it records what
it admitted and what the effect boundary reported. This page describes what the
SDK does and does not guarantee, how to deploy it without lowering your bar, and
how to report a vulnerability.

## Supported versions

Before v1.0 the SDK is evolving and only the **latest release** is supported.
Security fixes land on `main` and are released as the next `v0.x`; there are no
backports to older minors. The `v0.2.0` series and anything older will not
receive fixes.

If you must pin: pin to the latest `v0.x`, keep `go.sum` checked in, and stay
within one minor of `HEAD`. When a CLC revision bump (recommended) or a security
fix lands, plan to move the whole SDK forward rather than patching in place.

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Report privately via the
GitHub Security Advisory flow on this repository
(`Security` tab → `Report a vulnerability`) — the advisory is only visible to the
maintainers until you confirm disclosure. If you cannot use the advisory form,
open a *private* issue describing the problem and mark it sensitive; the
maintainers will reply on the thread.

Please include:

1. What you observed: the operation you attempted, the refusal or error you
   received (with its `code` / `stage`), and — when evidence is enabled —
   whether any record was emitted at all. A report that says "the request was
   refused and no record appeared" is much more useful than "it failed".
2. The version affected and your configuration shape (transport, `AuthMode`,
   `Evidence` settings, downstream placement).
3. A minimal reproduction: the request, the certificate/token, and what you
   expected versus what happened. For record/evidence problems, include the
   envelope or directory layout — linkage bugs are hard to reason about from a
   prose description alone.
4. Whether you believe the issue is exploitable, and in what deployment
   configuration.

You can expect an acknowledgement within **three business days**, a triage
verdict (confirmed / needs more info / out of scope as designed) within a week,
and — for a confirmed, in-scope issue — a fixed release or a documented workaround
as soon as a fix can be built and checked, consistent with the supported-version
policy above.

## What this SDK guarantees

The claims below hold when the SDK is used through its documented surfaces
(`Config` / `Handler` / `AuthMiddleware` / `Server` / `NewDecisionServer`) with
the trusted material it is configured with. "Guaranteed" here means: enforced by
the SDK's own code and covered by its tests, not promised in prose.

### Admission is decided, never assumed

Per request, one pipeline decides: certificate validity → CRL/OCSP → roles →
AIC decision → capability ∩ (principal authorization) → parameter bounds →
**allow / allow_unresolved / deny**. Every step runs from the material the SDK
itself verified (peer certificate, token, CA trust), and a request that fails any
step is refused before the handler sees it. A missing AIC, an expired certificate,
an untrusted signer, a capability the caller does not hold, and an
out-of-bounds parameter all end in a typed `AuthError` with a stable reason —
never in a request that falls through to the backend by accident.

`allow_unresolved` **is not** `allow`. The decision carries residual obligations
(`Unresolved`) that the deployment must discharge under an explicit rule
(`UnresolvedEvaluator`, or the built-in `ConnectionConstraintEvaluator` for
`network:cidr`) or refuse. The SDK contains no code path that silently converts an
undischarged obligation into a release.

### The transport boundary is the embedder's

The SDK authenticates an *already-established* connection. It does not terminate
TLS for you in a way that implies the caller is the same one whose certificate
was presented — that property comes from your `tls.Config`, which you own:

- **mTLS** — you must set `ClientAuth: tls.RequireAndVerifyClientCert` and
  `ClientCAs` (see `MTLSServerConfig`). `Config.CACertFile` is the trust anchor
  the SDK checks chains against; it is an input to validation, not the wire
  protection itself.
- **Bearer** — the credential is the `Authorization` header; nothing about the
  socket proves who wrote it. Use `ReplayProtection` (single-use `jti`) and a
  short token lifetime, and remember that the token is only as private as the
  channel it traveled on (use HTTPS).

### Evidence recomputes, and linkage is verified, not assumed

With `Evidence` set, the SDK emits a DSSE-wrapped CLC decision record whose
inputs are frozen at the canonical boundaries, a digest over them, the verdict
and its stable reason; refusal paths that precede the language layer emit an
admission record; the effect boundary can report an outcome record. Three
properties are enforced:

- **Uniqueness** — every decision is bound to a randomness-backed per-admission
  nonce (RATS §10.2), so digest collisions across admissions are not possible by
  construction, with or without a TTL clock.
- **Recompute** — `LoadEvidenceRecord` and the verify helpers recompute the
  digest from the record's own inputs and refuse a mismatch.
- **Linkage** — `VerifyEvidenceDir` verifies an outcome's `decisionDigest`
  against the decisions actually present in the same directory; an outcome that
  does not resolve to a decision is reported as an orphan and counts **neither as
  consent nor as an admission**, rather than being swallowed into a happy total.

### Trust boundaries

| Boundary | Owner | Goes the other way |
|---|---|---|
| TLS termination and client-cert verification | the embedder's `tls.Config` | the SDK validates against `CACertFile` on top of the handshake |
| CRL / OCSP responders | external services, configured via `CRLCache` / `OCSPCache` | availability and freshness are theirs; the SDK fails closed on lookups it cannot do |
| RFC 3161 timestamp authority (`AuditTSAURL`) | external service | only used by the audit path when configured |
| Evidence emission key (`Evidence.Sign`, `KeyID`) | the deployment | used to sign records; keep it operationally separate from the caller-facing trust |
| Supervision hooks (`ApprovalRequester`, `OverrideRecorder`) | pluggable, partial | a broken hook refuses or logs loudly; it never widens the admission set by default |
| Execution boundary | the deployment | outcome records report what the boundary *observed*; see non-goals |

## Known limitations and non-goals

- **Effect truthfulness belongs to the execution boundary.** An outcome record
  says "the effect boundary reported this result", signed over the gateway's
  configured evidence key. It is evidence *about* the boundary's report, not a
  cryptographic proof that the boundary executed faithfully. The key used to sign
  outcome records is currently the same shared `Evidence.Sign` / `KeyID` as other
  records; a deployment that needs outcome attribution separated from the
  gateway's own signatures has to either keep that key under the boundary's
  control or wait for a dedicated outcome-signing key (see
  [docs/comparison.md §5](docs/comparison.md)). Nothing in the SDK claims
  otherwise.
- **CRL/OCSP freshness is external.** The SDK fails closed on a responder it
  cannot reach, but it cannot make a reachable-but-stale responder tell the truth.
- **No policy authoring.** The SDK evaluates CLC capabilities; it does not ship a
  GUI or an authoring tool, and it evaluates exactly the revision it declares
  (`CLCRevision`, currently CLC-1.8). It refuses to read a revision it does not
  understand rather than downgrading.
- **DoS-by-credential volume.** Minting and checking credentials is cheap, but a
  flood is still a flood. Put the instance behind the usual rate/connection
  limiting that your edge already provides; the SDK adds per-admission nonce and
  challenge TTL machinery but is not a DDoS filter.

## Deployment hardening checklist

- Terminate mTLS with `RequireAndVerifyClientCert`; never enable optional/empty
  client certificates when you mean mTLS.
- Start with `AuthMode: MTLSOrBearer` only for a transition; go single-transport
  as soon as you can. If a caller did not have an AIC until recently,
  `RequireAIC: true` is the flag that actually forces the matter.
- Keep `ReplayProtection` on and token lifetimes short for bearer callers,
  especially when the token estate is large.
- Turn `Evidence.Strict: true` only when you have confirmed your sink is healthy —
  it converts silent record loss into refusals, which is the contract you want
  under audit requirements.
- Put the evidence signing key in the hands of the piece of the deployment that
  must own the records, not the same key material that terminates the front TLS.
- Monitor the gap: `Evidence.Gaps` counts emissions that left no record. Alert on
  it; silence here is how obligations quietly stop being discharged.
- Verify your evidence directory periodically with `VerifyEvidenceDir`; treat a
  nonzero orphan count as an investigation, not a footnote.
- Refresh `register` / `types` together with this SDK on CLC revision bumps; the
  SDK's `consumer-view` CI gate keeps the published dependency surface honest.
- Do not relax the strict-schema `config.example.json` parsing (unknown fields
  rejected); it exists so a typo cannot silently disable a control.

## Dependency and supply-chain posture

- No vendoring, no local `replace` directives. The module builds against the
  published `github.com/varwof/register`, `github.com/varwof/types`, and
  `github.com/varwof/pkcs7`; the `mcp` subpackage additionally needs
  `mark3labs/mcp-go`.
- `go.sum` is checked in; CI runs `go mod tidy && git diff --exit-code` and the
  `consumer-view` script, which re-resolves the module graph from the proxy to
  catch accidental coupling to the sibling checkout.
- Only review and update dependencies via the normal PR process; a dependency PR
  that lands without a `go.sum` change was not reviewed.