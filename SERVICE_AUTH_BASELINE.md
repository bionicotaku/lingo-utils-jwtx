# 微服务统一认证基线指引

> 适用范围：`services/*` 下所有业务服务（Catalog、Search、Feed、Progress、Media、Report、Template 等）以及 Gateway。本指引定义服务之间调用时必须具备的入站/出站安全基线能力。

---

## 1. 背景

- 每个微服务既可能暴露 gRPC/HTTP 接口给其他服务调用，又会主动调用下游服务或第三方。
- 为保持一致的安全策略，需要**统一的双向认证机制**：  
  - **入站（Inbound）**：对所有来自其他服务的调用做身份校验。  
  - **出站（Outbound）**：调用下游前获取自身身份凭证，并附带在请求中。
- 项目默认选型为 **GCP 服务账号签发的 Identity Token（OIDC JWT）**，兼容未来上云后的 Cloud Run/GKE Workload Identity。

---

## 2. 核心组件职责

### 2.1 JWT 拦截器（Inbound）

每个服务需要提供“统一 gRPC/HTTP 拦截器”来校验来访者身份：

| 要求                         | 说明                                                                 |
| --------------------------- | -------------------------------------------------------------------- |
| Token 来源                  | `Authorization: Bearer <JWT>`（gRPC metadata 或 HTTP Header）        |
| 验证方式                    | `google.golang.org/api/idtoken.Validate` + Google JWKS               |
| 必验字段                    | `iss`、`aud`、`exp`、`nbf`、`sub`/`email`                            |
| 白名单                      | 允许的服务账号（`AUDIENCE`、`ALLOWED_SUBJECTS`）在配置中声明         |
| 失败处理                    | 返回 `codes.Unauthenticated`（gRPC）或 `401` Problem Details（HTTP） |
| 上下文注入                  | 在 `context` 写入调用方身份（后续用例可做细粒度授权）                |
| 可观测性                    | 记录结构化日志（`caller_service`、`audience`）、Span tag、指标       |

> 注：若服务既提供 gRPC 又提供 HTTP，需要分别实现 gRPC Unary／HTTP Middleware 版本，逻辑保持一致。

### 2.2 Service Token Provider（Outbound）

每个服务调用下游前必须获取**自己的** Identity Token：

| 要求                     | 说明                                                                                                 |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| Audience                | 单一受众值（通常形如 `https://<service>.internal.dev`），与下游校验保持一致                         |
| 生成方式                | `idtoken.NewTokenSource`（默认使用 ADC）；如需代表其他服务账号，使用 `impersonate.IDTokenSource`     |
| 缓存策略                | 以 `(audience, targetServiceAccount)` 为 key 复用 `oauth2.TokenSource`，token 过期前 5 分钟刷新       |
| 误差处理                | 获取失败返回可重试错误，并记录结构化日志/指标，确保问题可观测                                           |
| 接口形式                | 建议定义通用接口 `ServiceTokenProvider.Token(ctx, audience) (string, error)`                        |
| 安全要求                | 严禁在仓库中保存长久 Service Account JSON；本地开发使用 `gcloud auth application-default login`     |

调用时统一通过 `metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)` 或 HTTP Header 注入。

---

## 3. 配置约定

统一在各服务 `internal/infra/config` 中定义以下字段，并支持环境变量覆盖：

```yaml
auth:
  required: true
  audience: "https://catalog.internal.dev"
  issuer: "https://accounts.google.com"
  allowed_subjects:
    - "svc-gateway@project.iam.gserviceaccount.com"
service_auth:
  default_audience: ""                # 可选，作为 outbound 默认值
  target_service_account: ""          # 若为空则使用当前进程默认身份
  include_email: true                 # 需要在 token 中包含 email 声明
```

配置校验规则：

- `required=true` 且 `audience`/`issuer` 缺失时启动失败。
- `allowed_subjects` 为空默认拒绝所有请求（fail-secure）。
- Outbound 未配置 audience 时应在编译阶段或启动阶段给出明确错误。

---

## 4. 标准落地步骤

1. **扩展配置结构**：为服务添加 `AuthConfig` 与 `ServiceAuthConfig`，并在 README 说明需要设置的环境变量。
2. **实现拦截器**：在 `internal/infra/auth` 下实现 `UnaryJWT`（gRPC）与可选的 HTTP 版本。
3. **接入入口程序**：在 `cmd/grpc/main.go`/`cmd/http/main.go` 中注册拦截器；使用 `config.Auth.Required` 控制是否强制校验。
4. **实现 Token Provider**：在 `internal/infra/auth` 或 `internal/infra/grpc` 中实现出站凭证获取逻辑，并注入 Transport 层。
5. **编写单元测试**：覆盖以下场景：
   - Token 缺失 / 格式错误
   - audience/issuer 不符
   - Token 过期
   - 白名单拒绝
   - Service Token Provider 失败回退逻辑
6. **集成测试**：使用 `gcloud auth print-identity-token` 生成真实 token，对 gRPC/HTTP 路径做联调。

---

## 5. 推荐的包结构

```
services/<service>/
├── internal/
│   ├── infra/
│   │   ├── auth/
│   │   │   ├── interceptor.go       # gRPC/HTTP inbound
│   │   │   └── service_token.go     # outbound token provider
│   │   ├── grpc/                    # gRPC wireup，注入 service token
│   │   ├── middleware/              # 其他中间件
│   │   └── config/                  # Auth 配置加载与校验
```

Outbound 逻辑也可以下沉到 `pkg/grpcx`（后续演进计划），以便服务之间复用。

---

## 6. 验收清单

| 项目                                | 通过标准                                                          |
| ----------------------------------- | ----------------------------------------------------------------- |
| 启动配置校验                        | 无缺失/非法值；启动日志打印允许的 issuers/audiences               |
| gRPC inbound 拦截器                 | 拿空 token 返回 `codes.Unauthenticated`；合法 token 正常通过      |
| 出站调用附带 token                  | 抓包/日志可见 `authorization: Bearer ...`；过期自动刷新            |
| 观察性                              | 日志包含 `caller_service`、`audience` 等字段；提供失败计数指标     |
| 联调脚本                            | `services/template/test/run_gateway_grpc_demo.sh` 成功             |
| 测试覆盖                            | 单测覆盖关键分支；如使用 fake JWKS/TokenSource                    |

---

## 7. 常见问题（FAQ）

**Q1: 本地开发没有 GCP 权限怎么办？**  
→ 使用 `gcloud auth application-default login`，并确保服务账号 JSON 未提交仓库。若仍无法获取 token，可在配置中临时设置 `auth.required=false`，但提交前必须还原。

**Q2: 是否仍需要 mTLS？**  
→ Identity Token 已提供身份认证，但可与 mTLS 组合增强安全性（例如保护链路、抵御重放）。mTLS 可以作为下一阶段增强项。

**Q3: 如何处理多租户或多 Audience 情况？**  
→ 每个受众单独配置一条 IssuerConfig（可以复用相同的 issuer 名称），调用方根据目标服务选择对应的 audience。

**Q4: Gateway 以外的服务是否需要 HTTP 拦截器？**  
→ 若对外也暴露 REST（例如媒体回调），必须实现 HTTP 版本拦截器；否则可仅维护 gRPC 版本。

---

## 8. 下一步计划

1. 抽象公共库 `pkg/jwtx`（封装 JWKS 缓存、Identity Token Provider）。
2. 将 Outbound 配置接入 `wireup` 模块的依赖注入，减少每个服务的重复代码。
3. 构建自动化集成测试，验证各服务间的 token 互通性。

落实本指引后，可确保所有微服务在本地与未来上线环境中具备一致、可观测、可扩展的认证能力。***
