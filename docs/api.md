# API reference

Everything lives in package `aicverifier`
(`github.com/varwof/aic-verifier`); decisions and records come from
`github.com/varwof/register/semantics`. This page covers the surface you are
meant to use; `go doc github.com/varwof/aic-verifier` has the exhaustive list,
and the same content is on pkg.go.dev.

## Two integration styles

| Style | Entry point | What it gives you |
|---|---|---|
| Middleware | `(*Config).Handler(next) (http.Handler, error)` | wraps your own handler; the verified identity is on the request context |
| Middleware (inline) | `(*Config).AuthMiddleware(next) http.Handler` | same, panics on a bad config so it can be used inside `http.Server{...}` |
| Reverse proxy | `NewServer(c *Config, routes []Route) (*Server, error)` | listens on one address, forwards admitted requests, injects `X-AIC-*` |

Inside a handler, read the verified identity with
`aicverifier.FromContext(ctx) *AuthContext`; it is `nil` when the pipeline did not
run (which also means the request never reached the handler).

## Configuration

`Config` carries everything; all fields are optional except the ones the mode you
pick requires. Grouped by what you reach for:

| Group | Fields |
|---|---|
| TLS / transports | `TLSCertFile`, `TLSKeyFile`, `CACertFile` (mTLS trust anchor), `JWTCAFile`, `BackendRootCA`, `AuthMode` (`MTLSOnly` / `BearerOnly` / `MTLSOrBearer`), `IdentityMode` |
| Bearer tokens | `JWTIssuer`, `JWTAudience`, `ReplayProtection` |
| What is required | `RequireAIC`, `RequiredCapabilities`, `RequiredOperations`, `EnforceConstraints`, `DisallowRepresentative`, `RequireUserAuth` |
| Principal authorization | `UserCert`, `UserCertResolver`, `DischargeObligations`, `ObligationsUnderstood`, `UnresolvedEvaluator` |
| Decision context (RATS §10) | `RequireFreshDecisionContext`, `DecisionContext` |
| Evidence | `Evidence *EvidenceConfig`, `EvidenceProfile`, `EvidenceRequirement`, `EvidenceFacts`, `EvidenceExporter` |
| Refusal shape | `Challenges *ChallengeConfig`, `ChallengeCarrier` |
| Operational | `CRLCache`, `OCSPCache`, `AuditLogger`, `AuditLogFile`, `AuditTSAURL`, `NonceCache`, `Logger`, `LogFile`, `StreamBody`, `Hooks`, `ServerOptions` |
| Plugins / approvals | `PluginRegistry`, `CapabilityRegistry`, `ApprovalRequester`, `OverrideRecorder`, `SupervisionPolicy`, `SupervisionStore`, `RequireApproval` |

## Routes (reverse proxy)

```go
type Route struct {
    Path                 string   // URL path prefix, e.g. "/api"
    Target               *url.URL // backend base URL
    AllowMethods         []string // optional method allowlist
    RequiredCapabilities []string // capability ids the caller must hold
}
```

## Decisions (the CLC surface)

```go
func AuthorizeOperation(aic *AIC, pa *PrincipalAuthorization, opID string, params map[string]any) (semantics.Decision, error)
func AuthorizeCapabilities(caps []Capability, opID string, params map[string]any) (semantics.Decision, error)
func AuthorizeCapabilitiesWithConstraints(caps, constraints []Capability, opID string, params map[string]any) (semantics.Decision, error)
func AuthorizeGrants(grants []semantics.Grant, opID string, params map[string]any) (semantics.Decision, error)
```

The result is a CLC `semantics.Decision`:

| Field | Meaning |
|---|---|
| `Verdict` | `allow`, `allow_unresolved`, or `deny` |
| `Reason` | stable reason code (`capability_not_authorized`, `max_rows:violated`, …) |
| `Unresolved` | recognized-but-unevaluated constraints carried by `allow_unresolved` |

`allow_unresolved` **is not** `allow`: the operation carries obligations nobody has
discharged. A deployment either evaluates them under a pinned rule —
`ConnectionConstraintEvaluator(clientIP)` is the built-in one for
`network:cidr` — or refuses. Nothing in the SDK silently turns an obligation into
a release.

Verdicts and reason codes are the language's, not the SDK's; the specification and
its corpus live in [`varwof/capability`](https://github.com/varwof/capability).

## Identity and refusals

```go
type AuthContext struct {
    ClientCert   *x509.Certificate
    Principal    string
    AgentID      string
    SPIFFEID     string
    Roles        []string
    Capabilities []string
    AIC          *AIC
    Bearer       bool
    Serial       string
    Verdict      string
    Reason       string
    Unresolved   []string
    OperationDecisions []OperationDecision
    Evidence     []RecordRef
    Satisfaction *semantics.RequirementResult
}
```

```go
type AuthError struct {
    Code         ErrorCode
    Status       int
    Message      string
    Stage        string
    Evidence     []RecordRef
    Problem      *ProblemDetails
    Satisfaction *semantics.RequirementResult
}
```

`AuthError` is what a middleware refusal returns (as JSON, or as
`application/problem+json` when `Problem` is set). It carries the records the
refusal itself produced, so a caller can log or forward them next to the answer.

## Evidence

```go
type EvidenceConfig struct {
    Sink       EvidenceSink            // nil → SlogSink with the SDK logger
    Strict     bool                    // emission failure denies the request
    TTL        time.Duration           // pins a freshness context on the record
    Audience   string                  // relying party the evidence is addressed to
    RecorderID string                  // which admission point emitted it
    Now        func() time.Time
    OnError    func(ctx EvidenceContext, err error)
    Gaps       *GapCounter             // counts emissions that left no record
    Sign       func(pae []byte) ([]byte, error)
    KeyID      string
    EmitOutcome bool                   // proxy reports what the effect boundary saw
    // Profile, Requirement, ... see go doc
}
```

```go
type EvidenceSink interface {
    Emit(ctx EvidenceContext, rec semantics.DecisionRecord, env semantics.Envelope) (RecordRef, error)
    EmitAdmission(ctx EvidenceContext, rec AdmissionRecord, env semantics.Envelope) (RecordRef, error)
}
```

`FileSink{Dir: ...}` writes one DSSE envelope per record; `SlogSink` logs them;
your own sink can do whatever a deployment needs. `RecordRef` reports the digest
and, for file-like sinks, where the record went.

Reading records back:

| Call | Use |
|---|---|
| `LoadEvidenceRecord(path)` | one file → re-computed `*semantics.DecisionRecord` |
| `CheckEvidenceEnvelope(env)` | validate either payload type through one entry point |
| `VerifyEvidenceDir(dir, verifyFn)` | whole directory; per-file failures are collected, not fatal |
| `VerifyFnFromPublicKey(pub)` | the `verifyFn` above, from a pinned emission key |
| `(*EvidenceBundle).CheckDecisions()` | a report bundle built by an exporter: its decision section must reference a record that still recomputes |

Payload kinds and their predicate types: `AdmissionRecordPredicateType`
(`aic/v1/admission-record`), `OutcomeRecordPredicateType`
(`aic/v1/outcome-record`), and CLC decision records from
`register/semantics`. See [evidence.md](evidence.md) for the shapes and for the
evidence profiles that pin them.

## Refusals that carry a challenge

```go
type ChallengeConfig struct {
    TTL         time.Duration          // how long a corrected presentation is welcome
    Audience    string
    RetryAfter  time.Duration          // becomes Retry-After
    ObtainHints []semantics.ObtainHint // where the missing item can be obtained
    Now func() time.Time; NewID, NewNonce func() string
}
```

Set `Config.Challenges` and a refusable denial answers `403` with
`application/problem+json` (`ProblemDetails`) carrying `CLC-CHALLENGE-v1`: what is
required, a nonce, the action digest, and when the retry stops being welcome. A
denial with nothing to obtain stays a plain refusal — the SDK will not dress up a
hard no as "try later".

## Helpers worth knowing

| Call | Use |
|---|---|
| `BuildSourceChain(clientCert, aic, userCert)` | the material this admission relied on, as a CLC source chain |
| `ConnectionConstraintEvaluator(clientIP)` | discharge `network:cidr` obligations at the connection |
| `HasAIC(cert)`, `AICFingerprint(cert)`, `ExtractRoles(cert)`, `ExtractSPIFFEIDFromCert(cert)` | inspect a peer certificate |
| `MTLSServerConfig`, `ClientTLSConfig`, `LoadCA`, `LoadCert` | TLS plumbing with the SDK's defaults |
| `CanonicalJSON(v)` | the JCS bytes the digests are taken over |

## Versioning

`Version` is the SDK version; `CLCRevision` is the language revision it evaluates
(currently `CLC-1.5`, from `register/semantics`). A record carries the revision it
was decided under, and an implementation refuses a revision it cannot read rather
than downgrading silently.
