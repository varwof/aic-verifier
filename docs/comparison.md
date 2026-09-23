# Where this stack sits: AIC + CLC + decision records

This document positions the three pieces against the alternatives an evaluator
would normally reach for, and states plainly what is proven and what is not.
It is written to be **falsifiable**: every claim names the artifact that backs
it, and §5 lists what the stack does *not* yet establish.

- **AIC** — the identity carrier (X.509 extension or `aic+jwt`).
- **CLC** — the capability/constraint language (`capability`, `register`).
- **Decision records** — the signed, recomputable evidence of an admission.

---

## 1. The three claims, and what backs each

| Claim | Mechanism | Evidence artifact |
|---|---|---|
| **Who the caller is** | AIC in an X.509 extension **or** an `aic+jwt` bearer; token `kid` is the issuing-CA SPKI hash, `cnf.jkt` binds the presenter key (RFC 7638) | `types` (AIC wire), `aic-verifier` trust model (`docs/architecture.md`) |
| **What it may do, and under which bounds** | CLC evaluates a *concrete operation* against grants: id subsumption, parameter sub-typing, set intersection, deny-overrides | `register/semantics/*.go`; 120 vectors + 1184 property cases |
| **That the decision is reproducible** | Every decision is frozen into a Decision Record; a third party re-runs the language over the frozen inputs and compares digest + verdict | `register`: `cmd/record -verify`; DSSE/in-toto envelope |

The third row is the part most stacks lack, and the part this document argues
is the actual differentiator.

---

## 2. Comparison

Legend: ● first-class · ◐ partial / with effort · ○ absent.

| | **AIC + CLC + records** | mTLS / SPIFFE | OAuth 2 JWT scopes | OPA / Rego | XACML 3.0 | Cedar |
|---|---|---|---|---|---|---|
| Identity bound to a key | ● cert or `cnf.jkt` | ● | ● `cnf` only if sender-constrained | inherited | inherited | inherited |
| **Typed parameter bounds** (e.g. `rows ≤ 10`) | ● number / set / object, recursive | ○ | ○ scopes are opaque strings | ◐ expressible, untyped data | ◐ expression language | ◐ |
| **Subsumption** (grant ⊇ request, decided) | ● `Entails` | ○ | ○ string equality only | ◐ data-dependent | ● | ● |
| **Set intersection / emptiness** (decided) | ● `Intersect` | ○ | ○ | ◐ | ● | ● |
| **Residual obligations** ("I recognise this but cannot settle it here") | ● `allow_unresolved` + `unresolved[]` | ○ | ○ | ○ | ● obligations | ◐ |
| Deny-overrides combination of independent sources | ● `combine.go`, obligations never dropped | ○ | ○ | ◐ | ● | ● |
| **Canonical, signed decision record** | ● DSSE v1 + in-toto Statement | ○ | ○ logs vary | ○ | ○ | ○ |
| **Third-party recomputation of the verdict** | ● `register`: `cmd/record -verify` | ○ | ○ | ◐ `opa eval`, not the *decision* | ○ | ◐ |
| **Cross-implementation conformance target** | ◐ 3 impls, 120 vectors, differential fuzz (§4 caveat) | n/a | n/a | ● one impl | ◐ many impls, no shared suite | ● single impl |
| Statically decidable policy | ● bounded, terminating | n/a | ● trivial | ○ data-dependent | ● | ● |
| Operates offline | ● no PDP service required | ● | ◐ introspection optional | ● | ● | ● |

Reading the table: it is **not** that the alternatives are weak — XACML in
particular matches the expressiveness. It is that the combination *decidable
reasoning + canonical signed record + recomputable verdict* is rarely supplied
as one coherent, versioned artifact.

---

## 3. Why each axis matters, concretely

- **Typed bounds, not scopes.** `query:SELECT {"limit":10}` is a grant that a
  request with `{"limit":50}` provably violates. An OAuth scope
  `db:read` cannot express it; the bound usually leaks into application code,
  where it is neither decided nor recorded.
- **Subsumption before execution.** `std/database-v1:*` covers
  `std/database-v1:query:SELECT` by segment (trailing-`*` grammar), not by
  lexical prefix — so the coverage question has a definite answer *before* the
  action runs.
- **Honest limits via obligations.** `time:window` and `network:cidr` are
  *recognised but not evaluated* by the core; the verdict is
  `allow_unresolved` with the obligation listed, not a silent `allow`. This is
  the difference between "we cannot check this" and "we checked and it passed".
- **Records, not logs.** A Decision Record carries the frozen inputs, their
  digest, the verdict and the reason. Verification re-runs the language — the
  verdict is *derived*, never trusted. That is what turns "we wrote a log" into
  "the decision reproduces".

### The differentiator, in one sentence

> A **decidable** policy language whose every decision can be **recomputed by a
> third party from a canonical, signed record**, with a **cross-implementation
> conformance suite** as the correctness target.

Any two of those exist somewhere; all three in one versioned stack is the
claim.

---

## 4. Conformance: how the language is held honest

- **Corpus** (`capability/data/_vectors/clc-v1/`): `vectors.json` **120**,
  `property-cases.json` **1184**, plus evidence/crosswalk/offline sets. CI
  enforces the corpus count against the spec appendix.
- **Three implementations** — Go (`register/semantics`), Python, TypeScript —
  run the same corpus. Latest parity report: rev 14, **0 differences**.
- **Differential fuzzing**: axis-directed case generation (100k + 2k boundary),
  comparing decoded and canonical paths. Divergences are *classified and
  attributed*, not merely counted.
- **Canonicalisation**: inputs are normalised the same way everywhere (JCS /
  RFC 8785, 512-octet cap, depth 32, explicit duplicate-key policy), which is
  what makes a digest comparable across languages.

**Caveat, stated by the spec itself** (`capability-language-core-v1.md`): the
reference implementations **share an author**, so the independent-implementation
bar is *not yet met*. Cross-implementation agreement here is strong evidence of
internal consistency; it is not yet evidence of independent interpretation.
This is the single most important honesty item in the stack.

---

## 5. What is *not* established

| Not proven | Why it matters |
|---|---|
| **Execution / effect non-repudiation** | Records bind the **decision**, not what the backend actually did. The SDK now *attributes* the effect (observed outcome + `decisionDigest` linkage, orphan-checked by `VerifyEvidenceDir`) but the **truthfulness** of "executed / failed / with-what-result" still belongs to the execution boundary (EMILIA AEB). Claim "authorization, and the attributable outcome chain, is non-repudiable", **not** "execution is". |
| **Independent implementations** | All three share an author (§4). An external re-implementation is the missing signal. |
| **Formal verification of the semantics** | The reasoning is decidable and tested, but there is no machine-checked proof (e.g. Coq/TLA⁺) of the meet/subsumption laws. |
| **External security review** | The audit trail is internal. No third-party assessment has been published. |
| **Frozen language** | CLC is at revision 1.8 and moving; pre-1.0 semantics may still shift. |
| **Decision performance at scale** | No published latency/throughput comparison against XACML/OPA engines. |

---

## 6. How to demonstrate it

```bash
go run ./examples/showcase
```

It runs the full path on a local machine — identity → CLC decision → admission /
refusal → signed decision record → **independent recomputation** →
middleware-reported outcome → **linkage verification** (an outcome pointed at a
missing decision is an orphan gap, not consent) → forged-verdict refusal — and
prints each step in a few seconds. The point of the demo is the binding steps:
without "forge ⇒ verification fails" and "broken linkage ⇒ reported as a gap",
evidence is just a file.

The showcase is self-contained (no external service and no client-SDK import);
it mints the AIC-JWT directly with `github.com/varwof/types/aicjwt`.

### Where the pieces live

| Piece | Repository |
|---|---|
| AIC identity wire format (`aicjwt`, X.509 extension) | [`varwof/types`](https://github.com/varwof/types) |
| CLC language spec, vectors, conformance corpus | [`varwof/capability`](https://github.com/varwof/capability) |
| CLC Go implementation + `cmd/record -verify` | [`varwof/register`](https://github.com/varwof/register) |
| Server SDK: enforcement + decision records (this repo) | `aic-verifier` |
| Client SDK: mint and carry the AIC credential | [`varwof/aic-agent`](https://github.com/varwof/aic-agent) |

