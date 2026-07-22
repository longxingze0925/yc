# Desktop App

Windows/Linux 统一桌面客户端的 Slint 壳层与网络基础。

当前已提供：

- API / Signal / Relay 自定义配置校验和原子持久化。
- HTTP 登录、MFA challenge/verify 数据模型。
- 账号 token 内存管理和平台安全持久化接口。
- 本机 Ed25519 设备身份、签名注册、设备列表和签名会话创建。
- Signal 握手模型、状态机与运输接口桩。

服务配置默认从用户配置目录的 `services.json` 加载，也可以通过以下环境变量整组覆盖：

```text
RCTL_API_URL
RCTL_SIGNAL_URL
RCTL_RELAY_URL
RCTL_SERVER_KEY_FINGERPRINT
```

安全边界：

- 当前平台安全存储适配器未接入，token 和设备私钥只在进程内保存。
- Signal WebSocket 已接入 token + 设备签名握手、显式断开和有界重连；只有通过 `hello_ok` 回显校验才标记上线。QUIC/Relay 和 OPAQUE 临时验证码客户端仍未接入。
- 服务器指纹可持久化且不进入 Debug 输出，但 pinning 尚未接入 HTTP 运输。
- Windows/Ubuntu 原生采集、渲染、输入、隐私屏和本地输入保护仍明确返回 `unsupported`。
