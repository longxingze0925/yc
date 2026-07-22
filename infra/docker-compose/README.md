# Docker Compose

本目录提供 Signal/Relay/API 的本地最小运行编排，同时启动 PostgreSQL 和 Redis。

Relay 不提供明文降级。启动 Compose 前必须提供客户端信任的 PEM 证书链和对应私钥：

```bash
export RELAY_TLS_CERT_PATH=/absolute/path/to/relay-fullchain.pem
export RELAY_TLS_KEY_PATH=/absolute/path/to/relay-private-key.pem
docker compose -f infra/docker-compose/compose.yml config
docker compose -f infra/docker-compose/compose.yml up --build
```

本地开发可以使用临时 CA 签发的证书，但客户端必须显式信任该 CA，并按证书 SAN 校验 Relay 域名；不得关闭证书校验。

生成 30 天有效的本地 CA 和 Relay 证书：

```bash
infra/docker-compose/generate-local-relay-cert.sh
export RELAY_TLS_CERT_PATH=/tmp/remote-control-relay-tls/relay-local-fullchain.pem
export RELAY_TLS_KEY_PATH=/tmp/remote-control-relay-tls/relay-local.key
docker compose -f infra/docker-compose/compose.yml config
```

客户端测试信任根为 `/tmp/remote-control-relay-tls/relay-local-ca.crt`。脚本不会修改系统信任库，默认输出目录位于 `/tmp`，私钥不会写入仓库；共享和生产环境禁止使用该本地 CA。

本地端口：

- API HTTP：`127.0.0.1:18080`
- Signal HTTP/WebSocket：`127.0.0.1:18081`
- Relay QUIC（UDP）：`127.0.0.1:18082`
- Relay TLS 443 fallback（TCP，本地映射默认 18082）：`127.0.0.1:18082`
- PostgreSQL：`127.0.0.1:15432`
- Redis：`127.0.0.1:16379`

可通过同名环境变量覆盖端口、数据库账号和以下共享密钥：

- `REMOTE_TOKEN_SECRET`
- `REMOTE_SERVICE_TOKEN`
- `REMOTE_RELAY_TOKEN_SECRET`
- `REMOTE_MFA_SECRET_KEY`（无填充 Base64URL 编码的 32 字节密钥）
- `RELAY_TLS_CERT_PATH`（必填，PEM 证书链的绝对路径）
- `RELAY_TLS_KEY_PATH`（必填，PEM 私钥的绝对路径）

默认密钥仅用于本地开发，共享环境必须覆盖。Compose 会先运行 `migrate` 服务：只对 Compose 内部的空 `public` schema 应用已冻结 `0001`，非空 schema 只执行结构验证，不会覆盖或修复已有数据库。

当前边界：

- API 使用 PostgreSQL Repository；仅显式设置 `REMOTE_STORAGE_BACKEND=memory` 且不提供 `DATABASE_URL` 时才启用开发内存模式。
- Signal 使用 `REDIS_URL` 保存在线状态、WebSocket 连接映射和 hello 握手重放记录；运行时 Redis 不可用会启动失败，不会退回内存，内存后端仅用于单元测试。
- API 在会话状态事务提交后通过 `REMOTE_SIGNAL_PUSH_URL` 调用 Signal 的服务鉴权内部入口；Signal 只推送已持久化通知，不写会话权威状态。
- Relay 在同一数值端口分别监听 QUIC/UDP 和 TLS/TCP，TLS ALPN 为 `rctl-relay-v1`；两种传输的第一条应用消息都必须是有界 `relay_open`，认证前不会转发 payload。
- Relay 只转发应用层 E2EE 不透明 payload，不持有业务会话解密密钥。
- Relay 的 `relay_open_nonce` 重放缓存当前是有界进程内缓存，只满足单实例 V1。部署多个 Relay 进程共享同一节点身份前，必须改为共享原子去重后端，否则阻断多实例发布。
