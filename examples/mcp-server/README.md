# AIC-gated MCP server example

This example runs an AIC-protected, HTTP-based **MCP** (Model Context Protocol)
server on top of aic-verifier. It is the reference wiring for the `aic-verifier/mcp`
package: an embedded mcp-go Streamable HTTP server pinned to a fixed protocol
revision, guarded by the aic-verifier admission pipeline, with a JSON tools
manifest that binds every tool to a capability and to deterministic parameter
barriers.

```
┌────────────┐   Bearer AIC-JWT (mcp:*)   ┌──────────────────────────────────────────────┐
│  MCP client │ ─────────────────────────▶ │  aic-verifier admission (bearer verify → AIC →  │
│  (curl /any)│   HTTPS /mcp, JSON-RPC 2.0 │  decision → audit)                           │
└────────────┘                             └──────────────┬───────────────────────────────┘
                                                           │
                                              ┌────────────▼──────────────────────────────┐
                                              │  aic-verifier/mcp enforcement                  │
                                              │   initialize → audit allow                  │
                                              │   tools/list  → audit allow                  │
                                              │   tools/call  → capability + param barriers │
                                              │                 (deny → -32602 + WARN)       │
                                              └──────────────┬───────────────────────────────┘
                                                             │
                                              ┌────────────▼──────────────────────────────┐
                                              │  mcp-go Streamable HTTP server (2025-11-25) │
                                              │  db_query            trade_exec             │
                                              └──────────────────────────────────────────────┘
```

## Quick start (default: local-mint mode)

One command boots everything and prints two demo tokens:

```
$ go run .                      # from examples/mcp-server
OPERATOR TOKEN (mcp:db_query + mcp:trade_exec):
<…>                             # export as $OP
AUDITOR TOKEN (mcp:db_query only):
<…>                             # export as $AUD
AIC-gated MCP server listening on :9444 (manifest tools.json, audit audit-mcp.jsonl)
```

The server self-signs `server-cert.pem` / `server-key.pem` and a demo JWT CA
`ca.pem` / `ca-key.pem` on first run (a `kid = CA SPKI hash` trust root, the same
form aic-verifier derives from `--jwt-ca`).

### Smoke test

```
$ OP=$(<op.token); AUD=$(<aud.token)                 # real clients get tokens from the issuer
$ SESS=$(curl -sk -D - https://localhost:9444/mcp \
      -H "Content-Type: application/json" -H "Authorization: Bearer $OP" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
           "params":{"protocolVersion":"2025-11-25","capabilities":{},
           "clientInfo":{"name":"curl","version":"1.0"}}}' \
      | grep -i '^mcp-session-id' | awk '{print $2}')

# tools/list + a valid call
$ curl -sk https://localhost:9444/mcp -H "Content-Type: application/json" \
      -H "Mcp-Session-Id: $SESS" -H "Authorization: Bearer $OP" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
$ curl -sk https://localhost:9444/mcp -H "Content-Type: application/json" \
      -H "Mcp-Session-Id: $SESS" -H "Authorization: Bearer $OP" \
      -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
           "params":{"name":"db_query","arguments":{"sql":"SELECT * FROM users","max_rows":2}}}'

# parameter barrier: max_rows 5000 > max 1000  → JSON-RPC -32602, audited WARN
# capability barrier: trade_exec with the AUDITOR token → -32602, audited WARN
# admission barrier: a malformed bearer token → 401, audited via Hooks.Denied
```

Every decision lands in `audit-mcp.jsonl`:

```
mcp_initialize    allow INFO target_id=initialize
mcp_tools_list    allow INFO target_id=tools/list
mcp_tools_call    allow INFO target_id=db_query args{max_rows,sql} sha256:<digest>;bytes:<n>
mcp_tools_call    deny  WARN target_id=db_query  args{max_rows,sql} sha256:<digest> deny_reason=param "max_rows" 5000 > max 1000
mcp_tools_call    deny  WARN target_id=trade_exec args{amount,side,symbol} sha256:<digest> deny_reason=tool "trade_exec" requires capability "mcp:trade_exec"
```

Argument values are never echoed: `target_id` carries the argument **names** and
a SHA-256 digest of the values, then the `bytes` size (same redaction style as
supervision evidence summaries). Admission-level rejects are written by the
`Hooks.Denied` callback next to the `mcp_*` decisions.

## Protocol version and SDK

The server pins **MCP 2025-11-25** (Streamable HTTP with the `initialize`
handshake and optional SSE GET channel). It intentionally does **not**
advertise the 2026-07-28 stateless-core revision, so the demo stays on a
stable, widely supported revision — see `mcp.SpecVersion` and
`server.WithStreamableHTTPProtocolVersions`. Transport + schema plumbing comes
from the community Go SDK [`github.com/mark3labs/mcp-go`
(v1.0.0)](https://github.com/mark3labs/mcp-go), not hand-rolled JSON-RPC/SSE.
Server-side SDK input-schema validation is left **off**: enforcement is the
deterministic barrier layer in `aic-verifier/mcp`, which answers denied calls with
JSON-RPC `-32602` before the tool handler runs (the SDK maps tool-handler
errors to `-32603`, so `-32602` responses are generated by the enforcement
middleware, not by handlers).

## tools.json

The manifest declares the whole tool surface: the `tools/list` advertisement
(name, description, JSON-Schema `input_schema`) plus the `tools/call` gate
(`required_capability` and `parameter_constraints`). Unknown fields anywhere in
the document are rejected at startup (`DisallowUnknownFields`).

```json
{
  "version": 1,
  "tools": [
    {
      "name": "db_query",
      "description": "Run a read-only SQL statement …",
      "input_schema": {
        "type": "object",
        "properties": {
          "sql":      { "type": "string",  "minLength": 1, "maxLength": 200 },
          "max_rows": { "type": "integer", "minimum": 1,  "maximum": 1000 }
        },
        "required": ["sql"]
      },
      "required_capability": "mcp:db_query",
      "parameter_constraints": [
        { "name": "sql",      "pattern": "^SELECT ", "max_length": 200 },
        { "name": "max_rows", "min": 1, "max": 1000 }
      ]
    }
  ]
}
```

Barriers are the deterministic subset (no code evaluation):
`min` / `max` (numbers), `min_length` / `max_length` (strings and arrays),
`enum` (strings), `pattern` (Go regexp, unanchored search — anchor with `^…$`).
A barrier binds only its own value kind: strings get length/enum/pattern,
numbers get min/max, arrays get length — a value whose kind no barrier fits is
never silently coerced. Capabilities match against the AIC `scheme:id` full ids
(and direct ids), with glob support (`mcp:*`, `db_*`).

## Two client-token modes

| Mode | Who mints the token | Trust root | When to use |
|------|--------------------|------------|-------------|
| **Local mint (default)** | the example itself (`ca.pem` + `ca-key.pem`, `kid = CA SPKI hash`) | `--jwt-ca ca.pem` (auto-created) | single-machine demo / loopback smoke |
| **Full chain (optional)** | user-signer (delegation + DA at `https://user-signer:8461`) → issuer mints the outer AIC-JWT | `--no-mint --jwt-ca <issuer-ca>.pem` | real user-approved, DA-backed authorization |

Full-chain wiring (against aic-agent, which lives in a separate repository):

```
cd <aic-agent>
go run ./cmd/call-bearer \
  --remote-issuer https://issuer.example:8445 \
  --signer-url    https://user-signer.example:8461 \
  --target        https://mcp.example:9444/mcp \
  --assertion     '{"scheme_id":"mcp","capability_id":"mcp:db_query"}'

cd <aic-verifier>/examples/mcp-server
go run . --no-mint --jwt-ca <issuer-ca>.pem
```

The full-chain token carries the DA-backed capability set; the server treats it
exactly like any other admitted AIC-JWT (admission → capability gate → audit).
Because one MCP session multiplexes `initialize` + many `tools/call` over a
**single** credential, the example disables one-time-use nonce replay
protection (`ReplayProtection: false`) — the issuer's short-lived tokens bound
abuse; production gateways that need single-use bearer semantics should share
the replay store across nodes. HSM-backed signing is a `user-signer` backend
concern and not part of this example.

## Behind the reverse proxy

The canonical deployment keeps the MCP server **behind** the aic-verifier reverse
proxy instead of terminating its own TLS: the proxy does bearer admission and
forwards identity to a loopback-only backend in `TrustProxy` mode. See
`examples/mcp-behind-proxy` for the wiring, the two audit streams, and the
security boundary that makes `TrustProxy` safe.

## Out of scope for this phase

- **MCP OAuth 2.1 resource-server / dynamic registration**: the demo gates
  `/mcp` with aic-verifier AIC bearer admission directly. OAuth 2.1 + token
  exchange against the issuer is a documented follow-up.
- **issuer service itself** and **user-signer HSM support** (backends only).
- **A separate `mcp-server` repository / release packaging**.