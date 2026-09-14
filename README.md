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

## Decision records at the enforcement point

The decision happens here, so the evidence is produced here.  Set
`Config.Evidence` and every decided operation is frozen into a CLC Decision
Record, wrapped in a DSSE/in-toto envelope, and handed to a sink:

```go
cfg := &aicverifier.Config{
    // ...the usual admission configuration...
    Evidence: &aicverifier.EvidenceConfig{
        Sink:       &aicverifier.FileSink{Dir: "/var/lib/aic/evidence", RecorderID: "pep-1"},
        TTL:        5 * time.Minute,               // RATS §10 explicit clock on the record
        Audience:   "https://gateway-a.example",
        RecorderID: "pep-1",
        // Strict: true,                           // fail closed if the sink is down
        // OnError: func(ctx aicverifier.EvidenceContext, err error) { gaps.Inc() },
    },
}
// then: go run ./cmd/record -verify /var/lib/aic/evidence/<name>.json   (register module)
```

A sink is handed the record **and** the context it belongs to — `EvidenceContext`
carries the recorder id, operation id, method/path, trace id, principal/agent/
serial, whether the request was admitted or refused, and the instant — so a sink
can correlate evidence with audit and tracing instead of writing an orphan file.
It returns a `RecordRef` (input digest, verdict, and the path for file-like
sinks), which the SDK reports back:

- `AuthContext.Evidence` — what an admitted request produced;
- `AuthError.Evidence` — what a refused request produced, next to the challenge.

An emission failure is reported through `EvidenceConfig.OnError` (evidence gaps
are worth counting, not just logging) and, when `Strict` is set, refuses the
request.

What this gives you, and what it deliberately does not:

- **One record per (authority source, operation).**  The AIC capability set and
  the principal authorization are recorded separately, because each is a
  decision over its own grant set; the combined (deny-overrides) verdict stays
  in `AuthContext`.  A record whose verdict does not reproduce is impossible by
  construction — `RecordWith` recomputes it from the same grants.
- **Refusals are recorded too.**  A refused operation carries its decisions into
  the error, so the refusal is as auditable as the admission; combined with
  `Config.Challenges` the caller gets the machine-readable "what is missing"
  *and* the replayable "why it was refused".
- **`SlogSink`** (default) writes a compact summary; **`FileSink`** writes one
  envelope per record, named by input digest, verifiable with
  `cmd/record -verify` from the `register` module.
- **Off by default.**  A deployment that only decides online emits nothing; a
  deployment that needs the record more than the request sets `Strict: true`.

Effect evidence (did the action actually run, and with what result) is out of
scope here — that belongs to the execution boundary.

### Who emitted this record

Every emitted envelope carries two provenance subjects by digest (never by
label):

| Subject | Digest of | Read back with |
|---|---|---|
| `evidence-profile` | the `EvidenceProfile` (shape) | `ProfileSubjectDigest` |
| `evidence-recorder` | the `RecorderDescriptor` (which admission point) | `RecorderSubjectDigest` |

```go
cfg.Evidence.Recorder = &aicverifier.RecorderDescriptor{ID: "pep-7", Kind: "aic-verifier"}
```

A consumer holding the descriptor can tell which recorder produced a record; one
that does not can still tell whether two records came from the same recorder.
`RecorderID` alone remains a display hint (it also names log fields and file
names), which is why the descriptor — not the string — is what gets hashed.
All three payload types carry it.

### Evidence profiles: the shape is a value

Which evidence a deployment emits is declared, not implied by scattered flags:

```go
cfg := &aicverifier.Config{
    EvidenceProfile: "clc-decision+admission+outcome@1",
    Evidence: &aicverifier.EvidenceConfig{
        Sink:       &aicverifier.FileSink{Dir: "/var/lib/aic/evidence", RecorderID: "pep-1"},
        RecorderID: "pep-1",
    },
}
```

Built-in shapes: `clc-decision@1`, `clc-decision+admission@1`,
`clc-decision+admission+outcome@1`.  A profile names the container
(`dsse+in-toto` today), which payloads are produced, whether records carry a
freshness context and the source chain, and which requirement is bound; the
plumbing (sink, strict, error hook, recorder id) stays with the deployment.

Three properties make this the place to adapt to another consumer:

- **An unknown profile name fails configuration** — a deployment that asks for a
  shape we do not produce hears about it at start-up, not from missing records.
- **The profile identity is content-addressed** and lands in the statement's
  subjects (`evidence-profile`), so a consumer can tell which shape it received
  by digest rather than by trusting a label — `ProfileSubjectDigest` reads it
  back.
- **Changing the shape is changing a value** (a new profile, and for a foreign
  container an adapter), not an edit to the decision path.

### Principal-authorization constraints are language-level obligations

A human certificate carries its authority in the `PrincipalAuthorization` (PA)
extension, constraints included.  Those constraints are now declarations the
language carries — the same as the AIC's — instead of a check that ran beside the
decision:

- **Before**: the human path passed `nil` constraints into CLC, so a PA
  `time:window` was only enforced by the connection-level check (and only when
  `EnforceConstraints` was on), and a PA `max_rows` was **silently ignored**:
  neither the connection registry nor CLC evaluated it.
- **Now**: PA constraints reach the decision.  `time:window` / `network:cidr`
  become residual obligations (`allow_unresolved`, fail-closed by default) and
  `max_rows` is evaluated by the core (`max_rows:violated`).  The emitted record
  carries the same constraints, so the record reproduces the verdict.

This is a **behavior change** on the human path, deliberately fail-closed.  A
deployment that relied on the connection-level check to release those requests
must now say so explicitly:

```go
cfg.DischargeObligations = true
cfg.ObligationsUnderstood = []string{"varwof/constraint-v1:time", "varwof/constraint-v1:network"}
cfg.UnresolvedEvaluator = aicverifier.ConnectionConstraintEvaluator(clientIP) // names the check
```

`ConnectionConstraintEvaluator` runs the same connection-level evaluators the SDK
already had (source CIDR, time window, ...), but only for the obligation types the
registry actually registers: a type it cannot evaluate is *not* discharged
(ignoring is not discharging).  A deployment that would rather implement its own
discharge policy sets `UnresolvedEvaluator` directly.

### One pipeline, one emission point, honest payloads

Not every refusal reaches the language layer — no credential, an untrusted
chain, a revoked certificate, an unparsable AIC, a missing capability.  Folding
those into a CLC record would lie (an empty grant recomputes to
`capability_not_authorized`, which is not the same statement as "the chain is
untrusted").  So the pipeline records them as a second, honest payload type:

| Where the refusal happened | Payload | Predicate type |
|---|---|---|
| Language layer (scope, params, constraints) | CLC Decision Record | `https://varwof.com/clc/v1/decision-record` |
| Before the language layer | Admission Record | `https://varwof.com/aic/v1/admission-record` |

Both ride the same DSSE/in-toto envelope, the same sink and the same
`EvidenceContext`, and one refusal produces exactly one record — an admission
record is never added on top of CLC records that already describe the decision.
`CheckEvidenceEnvelope` validates either payload through one entry point.

An admission record carries the stage (`ErrChainInvalid`, `ErrDenied`, ...), the
bounded reason, the identity the pipeline got as far as establishing, and the
**digests** of the facts it rested on (client certificate, requested operations)
as the statement's subjects.  It never claims a CLC verdict.

### The evidence face: requirement in, facts in, verdict out

CLC's evidence side is wired here too, with the same division the language
makes: the *requirement* comes from this deployment's configuration, the
*facts* come from the deployment's own verifiers, and the SDK decides nothing
about either.

```go
cfg := &aicverifier.Config{
    EvidenceRequirement: requirement,          // CLC-REQUIREMENT-v1, validated; never from the request
    EvidenceFacts: func(r *http.Request, ac *aicverifier.AuthContext) ([]semantics.EvidenceFact, error) {
        return myVerifiers.Facts(r)            // type, protected subject id, issuance time, VERIFIED
    },
    Challenges: &aicverifier.ChallengeConfig{TTL: 5 * time.Minute, Audience: "https://gw.example"},
}
// then: ac.Satisfaction  → satisfied / violated / unknown (+ missing roles)
```

Anything that is not an explicit `satisfied` refuses, and the refusal carries
the machine-readable challenge naming what is still missing.  An error from the
facts provider is fail-closed; a malformed requirement is a configuration
error.  When a requirement is configured, the emitted records also bind its
digest, so a record says *which sufficiency bar* was applied.  `Satisfaction`
answers "was enough evidence presented" — never "is this action authorized";
neither result stands in for the other.

### The execution side: an interface, not a claim

Whether the action actually ran — and with what effect — is the execution
boundary's business (EMILIA AEB or equivalent), so the SDK defines the shape and
the linkage, and nothing else:

```go
outcome, err := aicverifier.ReportOutcome(sink, evCfg, ctx, aicverifier.OutcomeRecord{
    Outcome:        aicverifier.OutcomeObserved,   // or your own classification
    OperationID:    op.ID,
    DecisionDigest: ac.Evidence[0].Digest,         // the decision this effect followed
    StatusCode:     200,
})
```

- `Outcome` is a plain string: `executed` / `failed` / `indeterminate` are
  recommended tokens, but the *classification* belongs to the deployment (the
  SDK observed an HTTP status at most).
- `DecisionDigest` links the effect back to the decision record it followed — so
  "this effect happened under that decision" is one lookup, not two unrelated
  logs.  An empty linkage is a gap for the consumer to notice, never consent.
- `FileSink` writes it as `<recorder>-outcome-<digest>.json`;
  `CheckEvidenceEnvelope` recognises all three payloads.

### One decision, two views

The SDK carries two evidence views, and they now have one authority:

- The **Decision Record** (`Config.Evidence`) is the machine-replayable object:
  frozen inputs, verdict, residual obligations, independently re-computable.
- The **Evidence Bundle** (`FileEvidenceExporter`) is the human-facing
  attribution report: subject, audit chain, supervision, signature slots.

Attach the record and the bundle stops being a second decision format:

```go
rec, err := aicverifier.LoadEvidenceRecord("/var/lib/aic/evidence/<file>.json")
bundle, err := exporter.Export(ctx, aicverifier.EvidenceQuery{OperationID: id, Record: rec})
if err := bundle.CheckDecisions(); err != nil { /* refuse: summary contradicts the record */ }
```

`EvidenceDecision.Decision` / `ReasonCodes` are then **derived from the record**
(including `allow_unresolved` and its obligations), and `CheckDecisions` fails
closed when a bundle's summary disagrees with the record it carries.  A bundle
without a record is still a useful report — it is just not replayable evidence.

## Design

See [docs/DESIGN.md](docs/DESIGN.md) for the admission pipeline, trust model,
and the difference between this SDK and the full gateway.

## What it does not do

- **No network calls.** Verification is offline: AIC signatures, the
  delegation chain and the capability language are evaluated against the
  trust anchors the deployer configures.
- **No trust decisions of its own.** The JWT CA, the client CA and the
  capability registry are inputs, not defaults.
- **No execution evidence.** A verified request is an authorization decision
  (who may do what), not a record that the action ran.  It *can* emit a
  replayable **decision** record (`Config.Evidence`) saying what was authorized
  and why; whether the effect happened belongs to the execution boundary.

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