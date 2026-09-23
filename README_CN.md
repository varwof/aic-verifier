# aic-verifier

**身份说明"谁在调用"；AIC 说明"这个智能体被允许做什么"——并且能离线证明。**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-blue)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/aic-verifier)](https://pkg.go.dev/github.com/varwof/aic-verifier)
[![Status](https://img.shields.io/badge/status-preview-orange)](#稳定性)
[![IETF](https://img.shields.io/badge/IETF-draft--wei--aic--identity--cert-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)
[![IETF](https://img.shields.io/badge/IETF-draft--wei--aic--jwt-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

[English](README.md) · [中文](README_CN.md)

---

## 为什么

一个 API key 或一份 scope 列表说的是*一般被允许什么*。它说不出**是哪个智能体**在动手、
**代表谁**、**边界到底在哪**，也留不下**实际发生了什么**。当调用方是一个可能被提示注入、
被重放、被层层转授的自主智能体时，"平台会校验令牌"是一句承诺，不是一份证明。

`aic-verifier` 把这份承诺变成一个**执行点**：一个小的 Go 库，包在你任意 HTTP 服务外面——或
以反向代理的方式挡在 API 前面——它对每个请求验证 **AIC**（Agent Identity Certificate），
并依据证书里携带的能力**对精确操作**做裁决。裁决是三值的（`allow` / `allow_unresolved` /
`deny`），拒绝发生在你的 handler **运行之前**，而每一次裁决都可以落成一条**可复算、
可离线验证、绑定到授权主体**的证据记录。

> **它是执行点，不是网关。** `aic-verifier` 是 [varwof gateway](https://github.com/varwof/gateway)
> 可嵌入的准入核心。它负责裁决与记录；路由、自带反代之外的各种转发、以及"执行"，都属于调用方。
> `aic-exec` 就是建立在它之上的命令执行边界。

它求值的是能力语言的 **CLC-1.8** 修订版，依赖
[`register v0.6.0`](https://github.com/varwof/register)（CLC 参考实现）与
[`types v0.6.0`](https://github.com/varwof/types)（AIC / AIC-JWT 结构）。

---

## 它做什么

| 领域 | 能力 |
|---|---|
| **凭据** | 带 AIC X.509 扩展的 mTLS 客户端证书，或 `Authorization: Bearer <AIC-JWT>`；`AuthMode` = `MTLSOnly` / `BearerOnly` / `MTLSOrBearer` |
| **裁决管线** | 证书有效性 → CRL/OCSP 吊销 → 角色 → AIC 裁决 → 能力 ∩ 主体授权 → 参数边界 → **allow / allow_unresolved / deny** |
| **能力语言** | CLC-1.8 具体操作、能力 ID 匹配、参数边界（`max_rows`、枚举……）、授权约束（CIDR、时间窗、并发）、残差义务 |
| **委托** | DA / DA-v2 签名校验、委托链、`EffectiveDelegationCapabilities`、DA 新鲜度、主体密钥绑定、代表模式拒绝 |
| **集成方式** | 中间件（`Handler` / `AuthMiddleware`）包住你的 handler；反向代理（`NewServer`）注入 `X-AIC-*`；传输无关的 `DecisionServer`（`Decide`、HTTP、gRPC、admin、health） |
| **证据** | 每次裁决的 DSSE 封装 CLC 裁决记录，另加 admission 与 outcome 记录；`FileSink`/`SlogSink`；**可选 DSSE 签名**（`EvidenceConfig.Sign`）；per-admission nonce；RATS §10 新鲜度；profile；requirement 绑定 |
| **证据验证** | `VerifyEvidenceDir`（结构 + 签名 + 裁决↔结果链接，孤儿上报）、`VerifyEvidenceEnvelope`、`VerifyFnFromPublicKey`（钉公钥）、`LoadEvidenceRecord` |
| **证据导出** | `FileEvidenceExporter` → `EvidenceBundle` v0.1（manifest / operation / subject / authorization / decision / supervision / Merkle 审计链 / signatures） |
| **挑战** | `CLC-CHALLENGE-v1`：可补救的拒绝以 RFC 9457 `application/problem+json` + `Retry-After` 应答，并列出缺什么证据 |
| **审计** | Merkle 链式 `AuditLogger`（可 TSA 签名）、`VerifyAuditEntry`、`FilterAuditFile`、`ArchiveAuditFile` |
| **监督** | 运行时人工审批（`ApprovalRequester`）、破玻璃的强制记录（`OverrideRecorder`）、`RequireApproval` 触发点、`SupervisionPolicy`、append-only `SupervisionStore` |
| **策略** | OU→角色 `AuthorizationPolicy`、PKCS#7 签名策略文件（`SignPolicy`/`VerifySignedPolicy`）、fail-closed 热重载（`ReloadPolicy*`、admin token） |
| **插件** | `CapabilityPlugin`、能力 `Registry`、`ConstraintEvaluator`、`ParameterValidator`、`GeoResolver`——按 `Config` 隔离（一个进程多个网关） |
| **身份卫生** | `IdentityMode`（除非你要求，后端看不到原始证书）、日志字段脱敏（序列号/邮箱/令牌/路径） |
| **运维** | `/healthz` 式 `HealthReport`、`DecisionMetrics`、`Config.Validate()`、TLS 助手、密码套件策略、OCSP stapling |
| **载体** | `mcp/` 子包（受 AIC 保护的 MCP 服务）与 `grpc/` 子包（`AICDecisionService`，codec `aic-json-v1`） |

完整 `Config`、记录形状与常量见 **[docs/reference.md](docs/reference.md)**。

---

## 快速开始（两分钟）

四步，每步都很短。演示会自己生成 CA 和证书，不用先做配置。

**1. 取代码并生成演示证书** —— 一个 CA，加一张服务端证书和一张带 AIC 扩展的 agent 证书：

```bash
git clone https://github.com/varwof/aic-verifier && cd aic-verifier
go run ./examples/mtls-backend/gen-cert -out ./demo-certs
```

**2. 起受保护的服务** —— 它在 `:9444` 上终止 mTLS，把获准的请求转发到同一个进程起的
演示后端 `:9081`。让它在当前 shell 一直运行：

```bash
go run ./examples/mtls-backend --certs ./demo-certs
```

**3. 以 agent 身份访问** —— 另开一个 shell，用 agent 证书调用：

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api
# {"backend":"real-api-mtls","identity":{"X-Forwarded-For":"127.0.0.1, 127.0.0.1"}}
```

**4. 看一次拒绝** —— 请求一个 agent 无权做的操作，请求根本到不了后端：

```bash
curl -sS --cert demo-certs/client-cert.pem --key demo-certs/client-key.pem \
     --cacert demo-certs/ca-cert.pem https://localhost:9444/api/transfer
# {"code":"access_denied","message":"agent missing required capabilities"}
```

在第一个 shell 按 `Ctrl-C` 停掉演示。这次请求留下了什么、怎么复算，见
**[docs/quickstart.md](docs/quickstart.md)**（也包含不带客户端证书的调用会怎样）。

---

## 简易示例

### 包住你自己的 handler（中间件）

```go
conf := &aicverifier.Config{
    CACertFile:           "certs/ca-cert.pem",
    AuthMode:             aicverifier.MTLSOnly,
    RequireAIC:           true,
    RequiredCapabilities: []string{"demo/example-v1:api:read"},
}

mux := http.NewServeMux()
mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
    ac := aicverifier.FromContext(r.Context()) // 智能体 id、主体、能力、裁决
    fmt.Fprintf(w, "hello %s\n", ac.AgentID)
})

handler, err := conf.Handler(mux) // 把整条管线套在 mux 外面
if err != nil {
    log.Fatal(err)
}
srv := &http.Server{
    Addr:      ":8443",
    Handler:   handler,
    TLSConfig: muxTLSConfig, // ClientAuth: tls.RequireAndVerifyClientCert，ClientCAs: 你的 CA
}
log.Fatal(srv.ListenAndServeTLS("certs/server-cert.pem", "certs/server-key.pem"))
```

### 反向代理，后端一行不改

```go
target, _ := url.Parse("http://127.0.0.1:8080")
server, err := aicverifier.NewServer(conf, []aicverifier.Route{
    {Path: "/api", Target: target, RequiredCapabilities: []string{"demo/example-v1:api:read"}},
})
log.Fatal(server.ListenAndServe(":9444")) // 注入 X-AIC-* 身份头
```

### 在进程内授权一个操作

能力可以**携带参数边界**；申请超过授权范围是拒绝，不是警告。

```go
dec, err := aicverifier.AuthorizeOperation(aic, pa,
    "std/database-v1:query:SELECT",
    map[string]any{"limit": 50})       // 授权写着 {"limit": 100} -> allow
switch dec.Verdict {
case semantics.VerdictAllow:
case semantics.VerdictAllowUR:          // 残差义务，不等于 allow
default:                                // VerdictDeny；dec.Reason 是规范原因码
}
```

### 只用 Bearer AIC-JWT

```go
conf := &aicverifier.Config{
    JWTCAFile:  "certs/jwt-ca.pem",
    AuthMode:   aicverifier.BearerOnly,
    JWTIssuer:  "aic-verifier-example",     // 可选 iss 钉定
    JWTAudience: []string{"myapi"},         // 可选 aud 钉定
}
```

### 传输无关的裁决（HTTP + gRPC + 进程内结果一致）

```go
core, _ := aicverifier.NewDecisionServer(conf)
ac, err := core.Decide(ctx, &aicverifier.RequestView{
    BearerToken:     token,
    TransportSecure: true,
})
// 同一个 Config -> HTTP、gRPC（grpc.NewDecisionService）或任何进程内载体裁决完全一致。
```

### 打开证据，然后离线验证

```go
conf.Evidence = &aicverifier.EvidenceConfig{
    Sink:     &aicverifier.FileSink{Dir: "/var/lib/aic/evidence", RecorderID: "pep-1"},
    Audience: "https://gateway-a.example",
    TTL:      5 * time.Minute,             // RATS §10.1 新鲜度时钟
    Sign:     myDSSESigner,                // 可选：给每条记录做密钥背书
    KeyID:    "pep-1-key",
    Strict:   true,                        // sink 挂了就 fail closed
}
// ...之后，在热路径之外：
rep, err := aicverifier.VerifyEvidenceDir("/var/lib/aic/evidence",
    aicverifier.VerifyFnFromPublicKey(pub))  // 钉公钥；校验签名 + 链接
```

### 用挑战应答一次可补救的拒绝

```go
conf.Challenges = &aicverifier.ChallengeConfig{
    TTL:        2 * time.Minute,
    Audience:   "https://gateway-a.example",
    RetryAfter: 10 * time.Second,          // 变成 Retry-After 头
}
// 缺 §8.4 证据的拒绝返回 403 application/problem+json，正文是 CLC-CHALLENGE-v1：
// 缺什么，以及何时可以带着修正后的出示重试。
```

### 运行时人工审批 / 破玻璃

```go
conf.SupervisionPolicy = aicverifier.SupervisionPolicy{RequireRuntimeApproval: true}
conf.ApprovalRequester = myApprover   // 若为 nil 且 RequireRuntimeApproval => 启动即报错
conf.RequireApproval = func(ac *aicverifier.AuthContext, r *http.Request) bool {
    return r.Method != http.MethodGet // 写操作路由给人工
}
// 破玻璃同样要求 recorder，所以"没记录的破玻璃"永远不会存在。
```

### 给 MCP 服务做门禁

```go
reg, _ := mcp.LoadJSON(registryJSON)
h, _ := mcp.NewHandler(mcp.ServerConfig{ServerName: "aic-tools", Version: "0.1"},
    reg, map[string]mcp.ToolHandler{"echo": echoHandler})
// 用 conf.Handler(...)（或 conf.AuthMiddleware）包住 h 先按 AIC 准入；
// 每个工具调用可以通过 mcp.AuthContextFromToolContext 读到已验证身份。
```

更多可跑路径见 **[docs/examples.md](docs/examples.md)** 与
[`examples/`](examples/) 目录（`mtls-backend`、`bearer-jwt-backend`、
`mcp-server`、`mcp-behind-proxy`、`supervision-demo`、`showcase`、
`inspect-record`、`smoke-verify`）。

---

## 裁决管线

每个请求走同一条管线，产出一个裁决：

1. **凭据** —— mTLS 链校验，或 AIC-JWT 解析 + 验证（bearer 从不走明文：请求必须经 TLS）。
2. **吊销** —— CRL 和/或 OCSP（可选；按 `CRLCache` / `OCSPCache` 配置）。
3. **角色** —— OU→角色映射（`AuthorizationPolicy`）、`RequireRoles`、admin OU。
4. **AIC 裁决** —— 针对*精确操作*做能力 ∩ 主体授权，含参数边界。
5. **约束** —— CIDR / 时间窗 / 并发（`EnforceConstraints`）；执行器必须履行的残差义务保持
   `allow_unresolved`。
6. **裁决** —— `allow` / `allow_unresolved` / `deny`，带稳定原因码。

拒绝是有类型的：`*aicverifier.AuthError` 带着 HTTP 状态、稳定原因码、这次拒绝产生的记录，
以及在"补交证据就能过"时附上的 RFC 9457 problem 文档与 `CLC-CHALLENGE-v1` 挑战。

`allow_unresolved` **不是** allow。已识别但未求值的约束绝不会被静默提升，它保持可见，
必须在执行边界被履行。

---

## 是证据，不是日志

只给一个"允许"没什么用，如果事后没人能查。配置了 `Evidence` 之后，SDK 会发出一条
**CLC 裁决记录**（输入在规范边界处冻结、对输入取摘要、给出裁决与稳定原因码），可选地签名
并包在 DSSE 信封里，通过 `EvidenceSink` 输出。到不了语言层的拒绝改发 **admission 记录**；
代理或中间件还可以把执行边界观察到的效果作为 **outcome 记录**回报。

- **每个（授权来源，操作）一条记录。** 一条裁决无法复算的记录在构造上不可能存在——它由同一
  组授权重新算出。
- **拒绝也被记录**，所以"意图"和"动作"一样可审计。
- **可离线复算。** `register/cmd/record -verify` 能对一条非持有者产出的记录重跑语言；
  `VerifyEvidenceDir` 还会把每条 outcome 绑到目录里真实存在的裁决上，并对孤儿上报，
  绝不当作"同意"。
- **想要密钥背书时就有。** `EvidenceConfig.Sign` 会给每条记录附上覆盖
  `PAE(payloadType, payload)` 的 DSSE 签名；需要"这是哪个准入点发的"的部署拿得到，
  不需要的部署不付任何字节（记录仍是内容可复算的，只是未签名）。

细节与固定形状的 profile 见 **[docs/evidence.md](docs/evidence.md)**。

---

## 合规契合

上面这些性质，直接对应监管写进条文里的硬要求。以下均为*公开*要求，对应到 SDK 实际做的事——
不是认证声明。

| 要求（公开出处） | `aic-verifier` 提供什么 |
|---|---|
| 强身份认证 / 唯一标识 —— HIPAA §164.312(d),(a)(2)(i)；EO 14028 MFA；中国网安法 §24 真实身份 | mTLS AIC 证书或 AIC-JWT，密钥绑定（SPKI / `cnf`） |
| 最小权限 / 细粒度授权 —— PIPL §51(四)；HIPAA §164.312(a)(1)；EO 14028 §4(i) | 逐操作的能力 ∩ 主体授权，含参数边界——按动作裁决，不按会话 |
| 动作边界上的最小权限**执行** —— NIST SP 800-207 | 在 handler 之前 fail-closed 拒绝；`allow_unresolved` 绝不静默 allow |
| 不可篡改 / 可归因审计 —— SEC 17a-4(f)；HIPAA §164.312(b)；EU AI Act Art 12；中国网安法 §21 | Merkle 链式审计 + DSSE 裁决记录，per-admission nonce，可选 TSA 时间戳 |
| 证据可离线核验 / 可追责 —— SEC 17a-4(f)(2)(iv),(f)(3)(v)；EU AI Act Art 12(3)(d) | 记录不依赖在线权威即可复算；钉公钥验证；可导出 `EvidenceBundle` |
| 人工监督 / 审批 —— EU AI Act Art 14(4)(5),(26)；PIPL §24；算法推荐规定 §7 | `RequireApproval` → `ApprovalRequester`，破玻璃强制 `OverrideRecorder`，可审计的监督事件 |
| 实时吊销 | 管线内的 CRL / OCSP；设计上鼓励短时凭据 |

**它不做什么：** 它约束不了绕过执行点的任何路径。证据证明的是准入裁决，不证明来源真实，
也不证明下游效果已成功（那是执行边界的职责）。它不是经认可的认证。

---

## 你实际会碰到的配置

| 字段 | 作用 |
|---|---|
| `CACertFile` / `JWTCAFile` | mTLS 客户端证书 / bearer 令牌的信任锚 |
| `AuthMode` | `MTLSOnly`、`BearerOnly`、`MTLSOrBearer`（默认） |
| `RequireAIC` | 拒绝没有 AIC 扩展的证书 |
| `RequiredCapabilities` / `RequiredOperations` | 调用方必须满足的能力 ID，或带参数边界的具体操作 |
| `EnforceConstraints` | 求值授权约束（时间窗、CIDR、`max_rows`） |
| `AdmissionConfig` | CRL/OCSP、角色、SPIFFE、委托链、监控钩子 |
| `Evidence` / `EvidenceProfile` / `EvidenceRequirement` | 记录、记录的形状，以及充分性门槛 |
| `Challenge` / `ChallengeCarrier` | 可补救的拒绝是否带挑战，以及如何渲染 |
| `SupervisionPolicy` / `ApprovalRequester` / `OverrideRecorder` | 运行时审批与破玻璃 |
| `AuthorizationPolicy` / `Constraints` / `ParameterValidators` | 策略与注册表的按 `Config` 隔离 |
| `IdentityMode` | 向其后端披露多少已验证身份 |
| `ServerOptions` / `StreamBody` / `LogFile` / `Logger` | 代理服务器调优、body 流式、日志 |

完整字段、类型与默认值见 **[docs/reference.md](docs/reference.md)** 与
**[docs/api.md](docs/api.md)**；`config.example.json` 与 JSON 接口面由 CI 保持一致。

---

## 文档地图

| 你想…… | 从这里开始 |
|---|---|
| 两分钟试一下 | [quickstart.md](docs/quickstart.md) |
| 在*中间件*与*反向代理*之间做选择，并看代码 | [api.md](docs/api.md) · [architecture.md](docs/architecture.md) |
| 打开证据并理解一条记录的含义 | [evidence.md](docs/evidence.md) |
| 了解每个 `Config` 字段、记录形状、常量与版本 | [reference.md](docs/reference.md) |
| 理解一次裁决*为什么*（不）可信 | [threat-model.md](docs/threat-model.md) |
| 上生产：TLS、密钥、监控、轮换 | [deployment.md](docs/deployment.md) |
| 端到端跑示例 | [examples.md](docs/examples.md) |
| 比较 SDK 与完整网关，以及当前非目标 | [comparison.md](docs/comparison.md) |

---

## 稳定性

v1.0 之前，接口面分成两类，方便嵌入方判断哪些可以放心依赖：

| 接口面 | 契约 |
|---|---|
| **冻结至 v1.0** —— `Config`、`Handler` / `AuthMiddleware`、`NewServer` 及 `Server.{Listen,Serve,Addr,ListenAndServe,Close}`、`NewDecisionServer` 及 `DecisionServer.{Decide,Health,AdminHandler,ReloadPolicy,Close}`、`AuthContext`、`AuthError`、`DecisionMetrics` | 只做增量：不改名、不删字段、不无公告地改默认值；二进制实际使用的 CLC 版本只在显式提升 `CLCRevision` 时才变动。 |
| **实验性** —— 插件/注册钩子（`PluginRegistry`、`CapabilityRegistry`、`RegisterGeoResolver`、参数校验器）、监督/证据接口（`ApprovalRequester`、`OverrideRecorder`、`EvidenceExporter`），以及 `examples/`、`mcp/` 下的包 | 在周边格式稳定之前，可能在次版本中变化。 |

`Config.Close`（`Server.Close` / `DecisionServer.Close` 也会触达）会释放 Config 持有的后台资源——审计日志器、nonce 缓存清理协程、监督存储、SDK 日志文件。CRL 与 OCSP 刷新循环仍由调用方自行停止（`CRLCache.Start`、`StartOCSPStapling`）。

---

## 依赖要求

| 要求 | 说明 |
|---|---|
| **Go 1.26 或更高** | 模块声明 `go 1.26`；不用 cgo |
| `github.com/varwof/register v0.6.0` | CLC 求值器与裁决记录格式 |
| `github.com/varwof/types v0.6.0` | AIC / AIC-JWT 结构 |
| `github.com/varwof/pkcs7 v0.1.1` | 语义层分离签名校验 |
| `github.com/mark3labs/mcp-go v1.0.0` | 只有 import `mcp` 子包才需要 |

依赖随 `go get` 进来，仓库里没有 `replace`、也没有 vendor。SDK 本身不依赖任何外部服务：
CRL/OCSP 响应端与 RFC 3161 时间戳服务都是可选的，配置了才会用。

下面的演示另需 `curl`（任何能出示客户端证书的客户端都行）和三个空闲端口：
**9444**（代理）、**9081**（演示后端，进程自己起）、以及后面用到的 **9443**（证据演示）。

---

## 相关仓库

| 仓库 | 角色 |
|---|---|
| [varwof/types](https://github.com/varwof/types) | 共享 Go 类型：AIC、AIC-JWT、能力 |
| [varwof/register](https://github.com/varwof/register) | 能力注册表、PKCS#7 签名、CLC 语义（本 SDK 用来求值的参考实现） |
| [varwof/capability](https://github.com/varwof/capability) | CLC 规范及其一致性语料 |
| [varwof/aic-agent](https://github.com/varwof/aic-agent) | 消费侧 SDK：铸造并携带本验证器所校验的凭据 |
| [varwof/aic-exec](https://github.com/varwof/aic-exec) | 基于本准入核心的、受 AIC 保护的命令执行器 |
| [varwof/gateway-core](https://github.com/varwof/gateway-core) · [varwof/gateway](https://github.com/varwof/gateway) | 完整网关；本 SDK 是其可嵌入的准入核心 |

## 许可证

Apache-2.0。见 [LICENSE](LICENSE)。

另见 [SECURITY.md](SECURITY.md)（漏洞上报、安全承诺、加固清单）、
[CONTRIBUTING.md](CONTRIBUTING.md)（开发与检查清单）、
[CHANGELOG.md](CHANGELOG.md)。
