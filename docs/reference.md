# aic-verifier reference

The complete, code-accurate reference for `aic-verifier`: configuration, record
shapes, constants, versions and conventions. Use it as a lookup while you read
[api.md](api.md) (the how-to) or [architecture.md](architecture.md) (the why).

> Every identifier here is the real Go identifier from package `aicverifier`.
> `go doc github.com/varwof/aic-verifier` is the exhaustive source of truth;
> this page is the curated copy.

## Package and versions

| Item | Value |
|---|---|
| Module | `github.com/varwof/aic-verifier` |
| Go | `go 1.26`, no cgo |
| `Version` | package constant (currently the release this tree is on) |
| `CLCRevision` | `semantics.CLCRevision` → **CLC-1.8** (via `register`) |
| Decision language record | `clc-v1` (RecordLang) |
| Record container | DSSE/in-toto envelope |

## Config: the surface

`Config` is the single knob group. All fields are optional except the ones the
chosen `AuthMode` requires. Grouped as you will actually reach for them:

### TLS / transports

| Field | Meaning |
|---|---|
| `TLSCertFile` / `TLSKeyFile` | server cert/key for the reverse proxy's own TLS (optional; usually the embedder terminates TLS) |
| `CACertFile` | mTLS trust anchor — client certificates must chain to this CA |
| `JWTCAFile` | Bearer trust root — token `kid` (SPKI hash) must resolve to a key under this CA |
| `BackendRootCA` | PEM bundle appended to system roots for the proxy's *outbound* TLS to HTTPS backends |
| `AuthMode` | `MTLSOnly` · `BearerOnly` · `MTLSOrBearer` (default) |
| `IdentityMode` | how the proxy propagates identity (`IdentityForwardClientCert`, …) |

### What is required / decided

| Field | Meaning |
|---|---|
| `RequireAIC` | reject certificates carrying no AIC extension |
| `RequiredCapabilities` | capability ids the caller must hold (also per `Route`) |
| `RequiredOperations` | operation ids the caller must hold |
| `EnforceConstraints` | evaluate authorization constraints (time window, CIDR, `max_rows`, …) |
| `DisallowRepresentative` | forbid representative delegation |
| `RequireUserAuth` | require a human principal certificate |
| `AuthContext` fields | verdict, reason, capabilities via `FromContext` |

### Bearer tokens

| Field | Meaning |
|---|---|
| `JWTIssuer` / `JWTAudience` | what a bearer token must claim |
| `ReplayProtection` | single-use `jti` (default on for Bearer mode) |

### Principal authorization

| Field | Meaning |
|---|---|
| `UserCert` / `UserCertResolver` | human certificate (PA) material |
| `DischargeObligations` / `ObligationsUnderstood` / `UnresolvedEvaluator` | how `allow_unresolved` residual obligations are discharged (explicit, never silent) |

### Decision context (RATS §10)

| Field | Meaning |
|---|---|
| `RequireFreshDecisionContext` | demand a fresh per-admission decision context |
| `DecisionContext` | optional explicit `semantics.DecisionContext` |

### Evidence

| Field | Meaning |
|---|---|
| `Evidence *EvidenceConfig` | sink, profile, TTL, audience, recorder, signing, gaps; see below |
| `EvidenceProfile` | declares the record shape (`clc-decision@1`, `clc-decision+admission@1`, `clc-decision+admission+outcome@1`) |
| `EvidenceRequirement` | CLC-REQUIREMENT-v1 the deployment binds |
| `EvidenceFacts` | deployment's own verifier facts (SSL, never from the request) |
| `EvidenceExporter` | human-facing bundle exporter |

### Refusal shape

| Field | Meaning |
|---|---|
| `Challenges *ChallengeConfig` | TTL, audience, `Retry-After`, obtain hints |
| `ChallengeCarrier` | how the problem document is dressed |

### Operational

| Field | Meaning |
|---|---|
| `CRLCache` / `OCSPCache` | revocation refreshers (caller-started loops) |
| `AuditLogger` / `AuditLogFile` / `AuditTSAURL` | merkle-chained audit; optional RFC 3161 timestamping |
| `NonceCache` | replay protection state |
| `Logger` / `LogFile` | SDK logs (file = 0644, released via `Config.CloseLogger()`) |
| `StreamBody` | body streaming on the decisions path |
| `Hooks` | `Authenticated` / `Denied` / `Forwarded` lifecycle callbacks |
| `ServerOptions` | proxy `http.Server` timeouts (`ReadHeaderTimeout=30s`, `IdleTimeout=120s` defaults) |

### Plugins / administration

| Field | Meaning |
|---|---|
| `PluginRegistry` / `CapabilityRegistry` | capability scheme plugins (phase-one connection decisions) |
| `ApprovalRequester` / `OverrideRecorder` / `SupervisionPolicy` / `SupervisionStore` | human-in-the-loop supervision |
| `RequireApproval` | gate high-risk operations behind approval |

Full defaults and validation rules: `config.go` + `config_validate_test.go`;
JSON form: `config.example.json` (unknown fields rejected).

## EvidenceConfig

```go
type EvidenceConfig struct {
    Sink       EvidenceSink  // FileSink{Dir}, SlogSink, or yours
    Strict     bool          // emission failure → refuse the request
    TTL        time.Duration // RATS §10.1 clock; per-admission nonce (§10.2) always bound
    Audience   string
    RecorderID string
    Now        func() time.Time
    OnError    func(ctx EvidenceContext, err error)
    Gaps       *GapCounter   // emissions that left no record — monitor this
    Sign       func(pae []byte) ([]byte, error)
    KeyID      string
    EmitOutcome bool         // middleware + proxy report the effect boundary's status
}
```

Record paths: `FileSink.Dir`→ one envelope per record named by input digest;
`LoadEvidenceRecord(path)` recomputes from the record's own inputs and refuses a
mismatch; `CheckEvidenceEnvelope(env)` accepts all three payload types;
`VerifyEvidenceDir(dir, fn)` is the linkage check (orphan outcomes reported via
`OrphanOutcome`, never counted as consent).

## Record shapes

All three payloads share the DSSE/in-toto envelope and carry the `evidence-
profile` and `evidence-recorder` subjects by digest.

| Payload | Predicate type | Produced when |
|---|---|---|
| CLC Decision Record | `https://varwof.com/clc/v1/decision-record` | language layer decides (scope, params, constraints) |
| Admission Record | `https://varwof.com/aic/v1/admission-record` | refusal *before* the language layer (e.g. chain invalid) |
| Outcome Record | `https://varwof.com/aic/v1/outcome-record` | the effect boundary reports (`executed`/`failed`/`indeterminate`) |

Admission records carry the stage (`ErrChainInvalid`, `ErrDenied`, …), the
bounded reason, and digest-subjects of the facts they rested on — and never a CLC
verdict. Outcome records carry `DecisionDigest` linking back to the decision they
followed.

## Refusals

`*AuthError` carries `Code` (stable), `Status`, `Stage`, the `Evidence` records
the refusal produced, and — when `Config.Challenges` is set and the denial is
remediable — a `Problem` describing an RFC 9457 `application/problem+json`
document with a `CLC-CHALLENGE-v1` `challenge` member. A hard no is never dressed
up as a challenge.

## Constants worth knowing

| Constant | Value | Meaning |
|---|---|---|
| `CLCRevision` | `"CLC-1.8"` | language revision decided with |
| `AdmissionRecordPredicateType` | `aic/v1/admission-record` | admission payload |
| `OutcomeRecordPredicateType` | `aic/v1/outcome-record` | outcome payload |
| `ProblemContentType` | `application/problem+json` | RFC 9457 shape |
| `ProblemTypeEvidenceRequired` | `clc/v1/problems/evidence-required` | challenge problem type |
| `RolePrefix` | `gateway:` | synthetic role prefix |
| `DefaultMaxBodyBytes` | 1 MiB | parameter size limit |
| `DefaultMaxChainLength` | 8 | delegation chain cap |
| Constraint keys | `time:window`, `network:cidr`, `max_rows`, `op:readonly`, `session:*`, `geo-fence` | language constraint ids |
| `SecureCipherSuites` | (list) | recommended server cipher suites |

## Conventions

- **Identity headers** — the proxy strips client-supplied `X-AIC-*`,
  `Authorization`, `Proxy-Authorization` and injects `X-AIC-Agent-Id`,
  `X-AIC-Principal-Uid`, `X-AIC-Capabilities`.
- **`allow_unresolved` ≠ `allow`** — residual obligations must be discharged
  under an explicit rule or denied.
- **Provenance by digest** — recorder/profile identity is content-addressed into
  the statement subjects, read back with
  `ProfileSubjectDigest` / `RecorderSubjectDigest`.
- **Fail-closed revisions** — a record from a revision the SDK cannot read is
  refused, never downgraded.