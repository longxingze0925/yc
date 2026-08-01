# iOS Controller Kit

`RemoteControllerKit` 是 iOS 16+ 主控端的 Swift Package，包含应用状态模型、API/Signal
wire model、Keychain 设备身份、VideoToolbox H.264 解码、Metal NV12 渲染和输入映射。

固定技术栈：

```text
SwiftUI/UIKit 壳层
Rust Core FFI 边界
VideoToolbox
Metal
```

当前边界：

- iOS 只声明 `controller`，不得声明 `controlled` 或无人值守被控能力。
- `platform` 固定为 `ios`，系统版本单独写入 `os_version`。
- Rust FFI 已提供签名密钥交换、key-confirm、加密输入、关键帧请求和加密视频接收边界；
  候选发现、Signal 会话消息和 QUIC socket 由 `NativeSecureTransportDriver` 接入。
- `project.yml` 和 `App/**` 已提供 iOS App target、登录、我的设备、一键连接和远控页面源码；
  使用 XcodeGen 生成工程后仍需在 macOS/Xcode 环境配置团队签名。
- `tools/build-ios-core-xcframework.sh` 生成 Rust 静态 XCFramework；Release 构建必须注入官方
  API/Signal 地址，不在普通 UI 中展示服务地址或证书。
- XCFramework 存在时 SwiftPM 会自动链接 `RemoteIOSFFI` 并启用 `REMOTE_CORE_FFI`；应用启动前
  需要通过 `NativeRustCoreSessionBridge.shared.install(driverFactory:)` 注册底层 driver。

Apple 工具链可用时，应在 iOS 16+ Simulator/真机目标执行 Package tests，并完成 Xcode
编译。Linux 无 Swift 或 Apple SDK 时只能执行源码和 wire-contract 静态检查，不能把以下项目
标记为通过：

- VideoToolbox H.264 真机解码和关键帧恢复。
- Metal 画面非空、分辨率、色彩和横竖屏验证。
- 虚拟键盘、蓝牙/USB 键盘、鼠标和触控板输入。
- iOS 16 与当前 iOS 主版本真机网络矩阵。

## 无 Mac 的云端构建与 TestFlight

仓库提供 `.github/workflows/ios-testflight.yml`。普通 push/PR 只在 GitHub 的 macOS
runner 上完成 Rust XCFramework 和 iOS Simulator 编译；TestFlight 上传只允许手动触发，
并从 GitHub Environment `testflight` 读取签名材料。

先在 Apple Developer 和 App Store Connect 创建与应用一致的 App ID 和 App 记录，再在
GitHub 仓库的 `Settings -> Environments -> testflight` 配置：

Variables：

- `APPLE_TEAM_ID`：Apple Developer Team ID。
- `IOS_BUNDLE_ID`：唯一 Bundle ID，例如 `com.example.remote.controller`。
- `RCTL_OFFICIAL_API_URL`：正式 HTTPS API 地址。
- `RCTL_OFFICIAL_SIGNAL_URL`：正式 WSS Signal 地址。
- `RCTL_OFFICIAL_RELAY_URL`：Windows 被控端使用的 Relay 地址，例如 `relay.example.com:443`。

Secrets：

- `IOS_DISTRIBUTION_CERTIFICATE_BASE64`：Apple Distribution `.p12` 的 base64 内容。
- `IOS_DISTRIBUTION_CERTIFICATE_PASSWORD`：导出 `.p12` 时设置的密码。
- `IOS_PROVISIONING_PROFILE_BASE64`：与 Bundle ID 对应的 App Store provisioning profile
  的 base64 内容。
- `ASC_KEY_ID`：App Store Connect API Key ID。
- `ASC_ISSUER_ID`：App Store Connect Issuer ID。
- `ASC_PRIVATE_KEY_BASE64`：`AuthKey_*.p8` 的 base64 内容。

在 GitHub Actions 中打开 `iOS`，运行 `Run workflow`：第一次选择
`build_mode=signed_archive` 验证签名归档；归档成功后再选择
`build_mode=testflight` 上传。证书、profile 和 API 私钥只进入临时
keychain/目录，任务结束会删除，不写入仓库或构建产物。

`tools/ios-testflight.sh` 会强制校验 HTTPS/WSS、Team ID、Bundle ID 和 provisioning
profile 的绑定关系，并输出 IPA、dSYM 和 SHA-256。上传后仍需在 App Store Connect 中等待
Apple 处理完成，再把构建加入 TestFlight 内部测试。

### 个人签名侧载

手动运行 `iOS` workflow 时选择 `build_mode=unsigned_ipa`，不读取
`testflight` Environment，也不需要 Apple Distribution 证书。任务会生成包含
arm64 真机 Rust Core 的未签名 IPA，并上传为 `ios-unsigned-<run_number>` artifact。

下载 artifact 并解压后，可在 Windows 上使用个人 Apple ID 签名工具重签
`RemoteController-*-unsigned.ipa` 后安装到自有 iPhone。免费个人签名通常需要每
7 天重新签名安装，且可用 entitlement 少于 TestFlight/App Store 签名。
