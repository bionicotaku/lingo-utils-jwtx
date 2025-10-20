# Gateway ↔ Template 使用 GCP 服务账号 Identity Token 鉴权指南

本文档说明如何在本地环境下，让 `Gateway` 与 `Template` 服务同时扮演调用方与被调用方，基于 **GCP 服务账号签发的 Identity Token** 实现统一认证。目标是让 `services/template/test/run_gateway_grpc_demo.sh` 通过“真实认证”联调测试。

---

## 1. 背景与目标

- **HTTP 入口**：Gateway 作为外部入口，需要验证来自调用方（脚本或其他客户端）的 GCP Identity Token。
- **gRPC 调用**：Gateway 作为调用方向 Template 发起 gRPC 请求时，同样需要携带服务身份；Template 要验证并授权。
- **验收标准**：修改完成后，执行 `services/template/test/run_gateway_grpc_demo.sh`，脚本应在真实 JWT 校验开启的情况下运行成功。

---

## 2. 总体流程

```
┌──────────────────────┐
│ run_gateway_grpc_demo│
│  1. gcloud 获取 token │
│  2. 调 Gateway (HTTP) │
└─────────┬────────────┘
          │ Bearer <Identity Token>
          ▼
┌──────────────────────┐        ┌──────────────────────┐
│      Gateway HTTP     │        │      Template gRPC    │
│ - 校验 token (JWKS)    │───────▶│ - 校验 token (JWKS)    │
│ - 转发至 Template gRPC │ Service│ - 返回业务响应         │
└──────────────────────┘  Token  └──────────────────────┘
```

1. 脚本使用 `gcloud auth print-identity-token --impersonate-service-account` 生成 **针对 Gateway Audience** 的 Identity Token。
2. Gateway 校验 HTTP 请求头 `Authorization: Bearer ...`，确认 `iss=https://accounts.google.com`、`aud=<Gateway Audience>`。
3. Gateway 调用 Template 前，通过 Google IAM **代表服务账号** 获取第二个 Identity Token（Audience = Template 配置），放入 gRPC metadata `authorization`。
4. Template 拦截器校验 gRPC token，确保只有授权服务账号可访问。

---

## 3. 依赖与前置条件

| 组件 / 工具           | 说明与版本要求                                                |
| --------------------- | ------------------------------------------------------------- |
| `gcloud` CLI          | 已登录 (`gcloud auth application-default login`)              |
| GCP 服务账号          | 至少 1 个（脚本 impersonation 与 Gateway outbound 可共用）    |
| IAM 权限              | 当前开发者账号需有 `roles/iam.serviceAccountTokenCreator`     |
| Go 依赖               | 已在 `go.work` 管理下，无需额外安装                          |

建议创建 `.env.dev` 或 shell profile，提前导出以下环境变量：

```bash
export SERVICE_ACCOUNT_EMAIL="svc-gateway@<project>.iam.gserviceaccount.com"
export GCP_PROJECT_ID="<project-id>"
```

---

## 4. 必要的配置项

### 4.1 Gateway 运行参数

| 变量                     | 建议值 / 说明                              |
| ----------------------- | ------------------------------------------ |
| `GATEWAY_MODE`          | `test` 或 `production`（development 模式默认跳过 JWT 验证） |
| `SUPABASE_JWKS_URL`     | `https://www.googleapis.com/oauth2/v3/certs`|
| `JWT_ISSUER`            | `https://accounts.google.com`             |
| `JWT_AUDIENCE`          | `https://gateway.local.dev`（示例）        |
| `SERVICE_ACCOUNT_EMAIL` | 供 service auth impersonation 使用         |

在 `routes.yaml` 的目标路由中增加：

```yaml
auth: user
backend:
  type: grpc
  service: "template"
  grpc:
    service: "template.v1.TemplateService"
    method: "SayHello"
    endpoint: "127.0.0.1:9090"
    deadline: "1s"
    service_auth:
      type: google_identity
      audience: "https://template.local.dev"
      target_service_account: "${SERVICE_ACCOUNT_EMAIL}"
```

### 4.2 Template 服务配置

新增/扩展 `internal/infra/config.Config`：

| 字段                     | 说明                                        |
| ----------------------- | ------------------------------------------- |
| `AUTH_REQUIRED`         | `true` → 强制所有 gRPC 调用携带 token        |
| `AUTH_AUDIENCE`         | 如 `https://template.local.dev`             |
| `AUTH_ISSUER`           | `https://accounts.google.com`              |
| `AUTH_ALLOWED_SUBJECTS` | 允许访问的 `sub`/email（逗号分隔）          |

Template gRPC 拦截器需基于上述参数验证 token。

---

## 5. 代码改造要点

### 5.1 Template (`services/template`)

1. **配置扩展**：`internal/infra/config/config.go` 添加 `Auth` 子结构。
2. **JWT 拦截器**：新增文件 `internal/infra/auth/jwt.go`，使用 `google.golang.org/api/idtoken`：
   - 从 metadata 读取 `authorization`。
   - `idtoken.Validate(ctx, token, cfg.Audience)` 验证签名与 Audience。
   - 校验 `payload.Issuer == cfg.Issuer`，比对 `sub`/`email` 白名单。
   - 将来访者身份写入 `context`（可选）。
3. **入口接入**：`cmd/grpc/main.go` 将 `auth.UnaryStub` 替换为新的 `UnaryJWT`。当 `cfg.Auth.Required=false` 时可降级为仅记录警告。
4. **测试**：补全拦截器 UT，覆盖合法、无 token、无效 audience、白名单失败等场景。

### 5.2 Gateway (`services/gateway`)

1. **路由配置**：如上文第 4 节改写 `routes.yaml`，目标路由 `auth: user` 并声明 `service_auth`。
2. **JWT 校验**：保持 `test/production` 模式，使 `pkg/jwtx.Validator` 真正调用 Google JWKS。
3. **Service Token 提供器**：新增 `internal/infra/auth/service_token.go`：
   - 对每个 `(audience, service-account)` 缓存 `oauth2.TokenSource`。
   - 默认走 `idtoken.NewTokenSource(ctx, audience)`；若配置 `target_service_account`，走 `impersonate.IDTokenSource`。
   - 提供 `Token(ctx) (string, error)`。
4. **gRPC 调用链**：
   - 修改 `internal/app/transport/invoker/invoker.go`，在调用前附加 `authorization` metadata。
   - `Invoker` 构造函数接收 `ServiceAuthProvider`，在路由配置缺省时跳过。
5. **依赖装配**：`internal/infra/wireup/deps.go` 初始化 `ServiceAuthProvider`，注入给 `invoker.New`。
6. **测试**：为 invoker/service auth 编写 UT / e2e，验证 token 缺失时返回 502、成功时透传响应等。

---

## 6. 本地运行步骤

1. **授权登录**  
   ```bash
   gcloud auth application-default login
   gcloud auth application-default set-quota-project <project-id>
   gcloud iam service-accounts add-iam-policy-binding \
     "${SERVICE_ACCOUNT_EMAIL}" \
     --member="user:<your-email>" \
     --role="roles/iam.serviceAccountTokenCreator"
   ```

2. **准备环境变量**  
   ```bash
   export SERVICE_ACCOUNT_EMAIL="svc-gateway@<project>.iam.gserviceaccount.com"
   export GCP_PROJECT_ID="<project-id>"
   export SUPABASE_JWKS_URL="https://www.googleapis.com/oauth2/v3/certs"
   export JWT_ISSUER="https://accounts.google.com"
   export JWT_AUDIENCE="https://gateway.local.dev"
   export TEMPLATE_AUTH_AUDIENCE="https://template.local.dev"
   export TEMPLATE_AUTH_ALLOWED_SUBJECTS="$SERVICE_ACCOUNT_EMAIL"
   export TEMPLATE_AUTH_REQUIRED=true
   ```

3. **生成 HTTP 调用 Token**  
   由脚本自动执行，也可手动验证：
   ```bash
   gcloud auth print-identity-token \
     --audiences="$JWT_AUDIENCE" \
     --impersonate-service-account="$SERVICE_ACCOUNT_EMAIL"
   ```

4. **运行联调脚本**  
   ```bash
   services/template/test/run_gateway_grpc_demo.sh
   ```

---

## 7. 验收检查

脚本执行成功后应看到：

- Gateway 日志出现 `JWT validator created`、`Service auth token issued` 等信息。
- Template 日志打印 `validated service caller`（或自定义字段），无 `unauthenticated` 错误。
- 终端输出 `Gateway Response: {"message":"Hello, Demo"}`。

如脚本失败，可检查：

| 场景                               | 排查建议                                                     |
| ---------------------------------- | ------------------------------------------------------------ |
| Gateway 返回 401                   | `JWT_AUDIENCE` / `JWT_ISSUER` 是否正确；token 是否过期        |
| Gateway → Template 返回 502/Unauth | service auth 未生效；检查 `service_auth` 配置与 impersonation |
| Template 报 `audience mismatch`    | `AUTH_AUDIENCE` 与 Gateway 生成的 audience 不一致             |
| `permission denied`               | 当前账号缺乏 impersonation 权限，重新绑定 `roles/iam.serviceAccountTokenCreator` |

---

## 8. 后续扩展

- **缓存优化**：为服务端 token provider 增加 TTL 与懒刷新，减少 IAM 调用量。
- **mTLS 组合**：引入开发 CA，实现 “Identity Token + mTLS” 双重校验。
- **通用库沉淀**：将 JWT 校验/TokenProvider 下沉至 `pkg/jwtx`，各服务一致复用。
- **CI 适配**：在 CI 中通过 Workload Identity 获取 token，跑通端到端测试。

---

## 9. 参考资料

- [Google Identity Tokens](https://cloud.google.com/docs/authentication/identity-tokens)
- [IAM Service Account Credentials API](https://cloud.google.com/iam/docs/impersonating-service-accounts)
- 项目规范：`CLAUDE.md`、`docs/ai-context/project-structure.md`

完成本文步骤，即可在本地环境下使用 GCP 服务账号 Identity Token 贯通 Gateway 与 Template 的相互认证，并满足联调脚本验收标准。*** End Patch
