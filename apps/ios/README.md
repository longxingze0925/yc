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
- OPAQUE 和 Rust QUIC/E2EE FFI 未接入时，验证码及无人值守凭据明文发送会被阻止。
- Package 不包含可发布的 Xcode App target、签名配置或 TestFlight 配置。

Apple 工具链可用时，应在 iOS 16+ Simulator/真机目标执行 Package tests，并完成 Xcode
编译。Linux 无 Swift 或 Apple SDK 时只能执行源码和 wire-contract 静态检查，不能把以下项目
标记为通过：

- VideoToolbox H.264 真机解码和关键帧恢复。
- Metal 画面非空、分辨率、色彩和横竖屏验证。
- 虚拟键盘、蓝牙/USB 键盘、鼠标和触控板输入。
- iOS 16 与当前 iOS 主版本真机网络矩阵。
