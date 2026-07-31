# Desktop App

Windows/Linux 统一桌面客户端的 Slint 壳层与网络基础。

当前已提供：

- API / Signal / Relay 自定义配置校验和原子持久化。
- HTTP 登录、MFA challenge/verify 数据模型。
- 账号 token 内存管理和平台安全持久化接口。
- 本机 Ed25519 设备身份、签名注册、设备列表和签名会话创建。
- Signal token + 设备签名握手、LAN Direct QUIC/E2EE 会话和 Relay 控制面。
- Windows WGC 优先、DXGI fallback 抓屏，GStreamer/x264 H.264 编码和 SendInput 输入回传。
- Ubuntu X11 抓屏、GStreamer/x264 H.264 编码和 XTest 输入回传。

服务配置默认从用户配置目录的 `services.json` 加载，也可以通过以下环境变量整组覆盖：

```text
RCTL_API_URL
RCTL_SIGNAL_URL
RCTL_RELAY_URL
RCTL_SERVER_KEY_FINGERPRINT
```

安全边界：

- 当前平台安全存储适配器未接入，token 和设备私钥只在进程内保存。
- Signal WebSocket 只有通过 `hello_ok` 回显校验才标记上线；会话断开会释放按键、采集、编码和传输资源。
- 服务器指纹可持久化且不进入 Debug 输出，但 pinning 尚未接入 HTTP 运输。
- Windows/Ubuntu 隐私屏、本地输入保护和安装包签名仍未进入 Mobile MVP。

## Windows Mobile MVP

Windows 10/11 真机需要 64 位 MSVC 构建环境和 GStreamer 1.0 MSVC x86_64 full runtime。
编码器会调用以下运行时组件：

```text
gst-launch-1.0
rawvideoparse
videoconvert
x264enc
multipartmux
fdsink
```

在 PowerShell 中设置官方服务的编译期地址后运行：

```powershell
$env:RCTL_OFFICIAL_API_URL = "https://api.example.com"
$env:RCTL_OFFICIAL_SIGNAL_URL = "wss://signal.example.com/ws"
$env:RCTL_OFFICIAL_RELAY_URL = "relay.example.com:443"
powershell -ExecutionPolicy Bypass -File .\tools\windows-mobile-mvp.ps1 -Mode Build
powershell -ExecutionPolicy Bypass -File .\tools\windows-mobile-mvp.ps1 -Mode Run
```

脚本会定位 GStreamer、检查所需插件、执行 Windows 测试并生成
`apps/desktop/target/release/remote-desktop.exe`。启动后登录同一账号，开启“允许我的设备远程
访问”，iPhone 才能从“我的设备”发起会话。

`.github/workflows/windows.yml` 会在 Windows Server runner 上做原生编译测试；手动运行时还可
输出未签名的内部测试 EXE。该制品不包含 GStreamer，且尚未做 Authenticode/安装器，只用于
Mobile MVP 真机联调。
