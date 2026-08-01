# 生产部署

本目录是官方托管服务的单机首版部署基线，与 `infra/docker-compose` 的本地开发编排完全分离。PostgreSQL 和 Redis 不暴露到公网，API 和 Signal 共用 `443/TCP`，Relay 使用 `18082/TCP+UDP`。

## 一键安装

在全新 Ubuntu/Debian 公网服务器上以 `root` 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/yc/main/ops/install.sh)
```

安装器提供三种模式：

1. 域名 + Let's Encrypt 可信证书。
2. 纯公网 IPv4 + 自签名 IP SAN 证书，适合个人 iPhone/Windows 内测。
3. 域名或公网 IPv4 + 已有证书。

纯 IP 模式安装完成后，将输出的 `root-ca.crt` 安装到 iPhone，然后在“设置 -> 通用 -> 关于本机 -> 证书信任设置”中开启完全信任。客户端仍会校验 TLS，不使用跳过证书校验的降级方式。

## 非交互安装

```bash
RCTL_DEPLOY_MODE=ip_self_signed \
RCTL_PUBLIC_HOST=203.0.113.10 \
RCTL_AUTO_INSTALL_DOCKER=1 \
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/yc/main/ops/install.sh)
```

如果服务器已有 Nginx/Caddy 占用 `80/443`，可以在安装前改用空闲端口：

```bash
RCTL_PUBLIC_HTTP_PORT=8080 \
RCTL_PUBLIC_HTTPS_PORT=8443 \
RCTL_RELAY_PUBLIC_PORT=18082 \
RCTL_DEPLOY_MODE=ip_self_signed \
RCTL_PUBLIC_HOST=203.0.113.10 \
RCTL_SKIP_PUBLIC_IP_CHECK=1 \
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/yc/main/ops/install.sh)
```

安装器会先用 `ss` 检查这三个端口；发现占用时会显示监听进程并停止安装，不会覆盖已有软件。若使用域名自动证书，`80/TCP` 仍必须能临时提供 Let's Encrypt HTTP 校验。

域名自动证书：

```bash
RCTL_DEPLOY_MODE=domain \
RCTL_PUBLIC_HOST=remote.example.com \
RCTL_LETSENCRYPT_EMAIL=admin@example.com \
RCTL_AUTO_INSTALL_DOCKER=1 \
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/yc/main/ops/install.sh)
```

已有证书模式还需设置 `RCTL_TLS_CERT_PATH` 和 `RCTL_TLS_KEY_PATH`。如证书链使用私有 CA，同时设置 `RCTL_CLIENT_CA_CERT_PATH`。

## 管理命令

安装后使用 `remote-control` 管理：

```text
remote-control status
remote-control start
remote-control stop
remote-control logs [service]
remote-control diagnose
remote-control client-config
remote-control create-account
remote-control backup
remote-control restore /path/to/backup.dump
remote-control update
remote-control renew-certificate
remote-control restart
remote-control uninstall
```

安装目录默认为 `/opt/remote-control`，配置为 `config/.env`，证书为 `certificates/`，备份为 `backups/`。更新前会自动执行 PostgreSQL 备份并生成 SHA-256 文件。

## 防火墙和 DNS

需要放行：

```text
HTTP_PORT/TCP       域名证书签发和 HTTP 跳转（默认 80）
HTTPS_PORT/TCP      API + Signal WebSocket（默认 443）
HTTPS_PORT/UDP      HTTP/3（可选）
RELAY_PORT/TCP      Relay TLS fallback（默认 18082）
RELAY_PORT/UDP      Relay QUIC（默认 18082）
```

域名模式要求 A 记录已指向该服务器。纯 IP 模式要求输入 IPv4 与至少一个外部观测源的结果一致；在多出口 NAT 环境中可显式设置 `RCTL_SKIP_PUBLIC_IP_CHECK=1` 跳过安装阶段检查。

## 客户端构建参数

`remote-control client-config` 输出：

```text
RCTL_OFFICIAL_API_URL=https://HOST
RCTL_OFFICIAL_SIGNAL_URL=wss://HOST/ws
RCTL_OFFICIAL_RELAY_URL=HOST:18082
```

将这三项设置为 GitHub `testflight` Environment variables，再构建 iOS/Windows 客户端。纯 IP 自签名模式还需先在测试设备上安装根证书。
