# Examples

Every example under `examples/` is self-contained: it generates or prints its
own certificates and tokens, needs no external PKI, and documents the exact run
commands in its header. The quick start ([quickstart.md](quickstart.md)) walks
the first one in full; this page is the index with the exact commands.

## 1. mtls-backend — the canonical mTLS + AIC proxy

A real HTTP API protected by mTLS client certificates that carry the AIC
extension, fronted by the reverse proxy.

```bash
# in examples/mtls-backend
go run ./gen-cert --out dev-certs    # CA + server cert + AIC client cert
go run .                             # AIC-protected mTLS proxy on :9444
# in another shell
curl -k --cert dev-certs/client-cert.pem --key dev-certs/client-key.pem \
     https://localhost:9444/api
# authorised → the demo backend answers with {"backend":"real-api-mtls", ...}
curl -k --cert dev-certs/client-cert.pem --key dev-certs/client-key.pem \
     https://localhost:9444/api/transfer
# refused → access_denied (missing required capabilities)
```

Also exercises the **supervision demo** (`examples/supervision-demo`): a
`DemoApprover` implementing `aicverifier.ApprovalRequester` plus the
evidence-exporter wiring.

## 2. bearer-jwt-backend — the same service, Bearer AIC-JWT

The mTLS demo mirrored onto `Authorization: Bearer <AIC-JWT>` (RFC-style token
over the header):

```bash
go run ./gen-bearer                  # ca.pem + the server TLS pair; prints a token
go run . --addr :9443                # AIC-protected reverse proxy on :9443
curl -k https://localhost:9443/api --header "Authorization: Bearer $TOKEN"
```

## 3. inspect-record — read a record back

Needs a decision record on disk (run the quick start or `smoke-verify` first):

```bash
go run ./examples/inspect-record records/smoke-verify-<digest>.json
```

Prints the language revision, operation, verdict, input digest, and
`recomputed` verdict — the recompute is the check (`LoadEvidenceRecord`).

## 4. mcp-server — AIC-gated MCP server

An MCP (`Model Context Protocol`) server where every `initialize` /
`tools/list` / `tools/call` decision lands in the audit log, and `tools/call`
is denied (JSON-RPC `-32602`) when the caller lacks the tool's
`required_capability` or an argument crosses a parameter barrier. The tool
surface comes from `tools.json`.

Default (local mint) boots everything and prints two tokens:

```bash
go run .                        # tools.json must be in the working dir
# TOKEN_OP=$(...) ; TOKEN_AUD=$(...)   (the two lines from stderr)
curl -k https://localhost:9444/mcp -H "Authorization: Bearer $TOKEN_OP" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Full-chain mode (user-signer + issuer) trusts the issuer CA instead of minting
locally — see the header for the pairing with `aic-agent`.

## 5. mcp-behind-proxy — the canonical MCP topology

The same MCP server behind the reverse proxy: the proxy terminates TLS, runs
admission, and forwards to a loopback-only backend that trusts the server's
`X-AIC-*` identity headers (`mcp/` `TrustProxy` mode). One command boots the
stack (`:9443` → loopback backend) and prints operator vs auditor tokens so you
can watch a capability-denied `tools/call`.

## 6. showcase — the effect-evidence walk, asserted end to end

Runs the whole AIC + CLC + decision-record path on a local machine, printing
each step so the claims in [comparison.md](comparison.md) are **seen**: identity
minting, constraint checks, decision/admission/outcome records, the
reproducibility check, and the orphan-outcome verification case. It is
self-contained (no external service, no client-SDK import) and is part of CI —
`go run ./examples/showcase` must exit 0.

```bash
go run ./examples/showcase
```

## 7. smoke-verify — minimal server for smoke tests

A minimal `aic-verifier`-protected HTTP service used by the smoke suite and the
quick start; also demonstrates the evidence directory and challenge flags.

## How they pair with aic-agent

The `aic-agent` examples (`call-bearer`, `call-mtls`, `smoke-call`) drive these
service examples end to end — see
[varwof/aic-agent docs/examples.md](https://github.com/varwof/aic-agent/blob/main/docs/examples.md)
for the pairing commands; each example header names its peer.