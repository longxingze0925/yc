# 远程控制软件项目

本项目目标是开发一套商业级远程控制软件。**桌面端采用统一客户端**：Windows 10/11 与 Ubuntu Desktop 26.04 LTS 的桌面客户端是同一个软件，登录账号后自动把当前设备加入"我的设备"，默认同时具备主控能力（控制其他设备）和被控能力（允许其他设备控制本机）。iOS 16 及以上仅作为主控端。平台边界：

- Windows 10/11：主控 + 被控
- Ubuntu Desktop 26.04 LTS x86_64：主控 + 被控
- iOS 16 及以上：仅主控

当前只聚焦移动主控闭环：先交付 `Ubuntu 被控 -> iOS 主控`，再交付 `Windows 被控 -> iOS 主控`。普通用户使用官方托管服务，同一账号下直接从“我的设备”一键连接，不配置服务器地址、证书、设备 ID 或临时验证码。

核心技术路线：

```text
Rust Core
P2P over QUIC
QUIC Relay fallback
TLS 443 Relay extreme fallback
Slint Desktop UI
SwiftUI/UIKit iOS UI
H.264 first
V1 Core hosted baseline + V1 Commercial private deployment
```

## 文档入口

- [项目级 AI 开发规则](AGENTS.md)
- [产品规格说明书](docs/spec/20260719170217641_产品规格说明书.md)
- [系统架构设计](docs/spec/20260719170217641_系统架构设计.md)
- [协议设计](docs/spec/20260719170217641_协议设计.md)
- [安全与密钥协议设计](docs/spec/20260719171718533_安全与密钥协议设计.md)
- [NAT 穿透与连接状态机设计](docs/spec/20260719171718533_NAT穿透与连接状态机设计.md)
- [认证与无人值守凭据设计](docs/spec/20260719171718533_认证与无人值守凭据设计.md)
- [账号 MFA 与风险验证设计](docs/spec/20260719190000001_账号MFA与风险验证设计.md)
- [访问控制与条件访问设计](docs/spec/20260719190000002_访问控制与条件访问设计.md)
- [隐私屏与本地输入保护设计](docs/spec/20260719190000003_隐私屏与本地输入保护设计.md)
- [供应链与客户端防伪设计](docs/spec/20260719190000004_供应链与客户端防伪设计.md)
- [反诈与滥用防护设计](docs/spec/20260719193000001_反诈与滥用防护设计.md)
- [远程重启与会话恢复设计](docs/spec/20260719193000002_远程重启与会话恢复设计.md)
- [键盘 IME 与快捷键输入设计](docs/spec/20260719193000003_键盘IME与快捷键输入设计.md)
- [媒体质量控制与能力协商设计](docs/spec/20260719193000004_媒体质量控制与能力协商设计.md)
- [会话录制与合规审计边界设计](docs/spec/20260719193000005_会话录制与合规审计边界设计.md)
- [企业区域路由与数据驻留设计](docs/spec/20260719193000006_企业区域路由与数据驻留设计.md)
- [数据库设计](docs/spec/20260719170217641_数据库设计.md)
- [审计与权限数据模型修订](docs/spec/20260719171718533_审计与权限数据模型修订.md)
- [客户端设计](docs/spec/20260719170217641_客户端设计.md)
- [服务端设计](docs/spec/20260719170217641_服务端设计.md)
- [测试方案](docs/plan/20260719170217641_测试方案.md)
- [里程碑计划](docs/plan/20260719170217641_里程碑计划.md)
- [AI 开发任务清单](docs/plan/20260719170217641_AI开发任务清单.md)
- [M0 实现前冻结决策](docs/decision/20260721000000001_M0实现前冻结决策.md)
- [登录设备身份与受信任主控设备契约](docs/decision/20260721000000002_登录设备身份与受信任主控设备契约.md)
- [远控竞品与开源项目对比补充](docs/research/20260719193000007_远控竞品与开源项目对比补充.md)

说明：`docs/research/**` 只作为调研背景和竞品参考，不是规范源。后续开发和验收以 `AGENTS.md`、已接受的 `docs/decision/**`、`docs/spec/**` 和 `docs/plan/**` 为准。

## 历史方案和开发记录

以下文档只保留背景和阶段记录。新的 AI 开发必须以“文档入口”中的定稿文档为准，不得把历史计划作为当前优先级来源。

- [产品技术规格](docs/spec/20260719162947669_远程控制软件产品技术规格.md)
- [AI 开发实施计划](docs/plan/20260719162947669_AI开发实施计划.md)
- [核心架构决策记录](docs/decision/20260719162947669_核心架构决策记录.md)
- [P0 本地开发说明](docs/development/20260719164500000_P0本地开发说明.md)
- [P1 信令和数据模型说明](docs/development/20260719165613101_P1信令和数据模型说明.md)

## 工程结构

```text
crates/
  remote-core/       设备身份、会话状态机、权限策略
  remote-protocol/   协议消息、错误码、消息头编解码
  remote-store/      PostgreSQL 数据记录模型
  remote-transport/  连接路径、候选链路、传输抽象
  remote-crypto/     密钥和会话密钥类型
  remote-capture/    Windows/Ubuntu 屏幕采集抽象
  remote-render/     Windows/Ubuntu/iOS 渲染抽象
services/
  api-server/        P0 HTTP 健康检查空服务
  signal-server/     HTTP + WebSocket 信令服务
  relay-server/      P0 Relay 空服务
apps/
  desktop/           Windows/Linux 桌面客户端
  ios/               iOS 主控端
  admin-web/         管理后台
infra/
  docker-compose/    本地编排和 V1 Commercial 私有化部署
  migrations/        数据库迁移
```

## 本地开发

安装 Rust 工具链后执行：

```bash
make fmt-check
make lint
make test
make check
```

## 服务端一键部署

生产编排支持域名证书和纯公网 IPv4 自签名 IP SAN 证书：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/longxingze0925/yc/main/ops/install.sh)
```

详见 [生产部署说明](infra/production/README.md)。

## 当前阶段

已完成的账号、设备注册、Signal 鉴权、P2P/Relay 和 Ubuntu 抓屏基础继续复用。当前进入 `Mobile MVP`，按 `TM001-TM006` 交付 iOS 主控闭环；原 M3-M7 全平台矩阵作为后续 V1 Core 门禁保留。

首个最小可运行闭环：

```text
iOS 登录 -> 我的设备 -> 一键连接 -> P2P 优先/Relay 自动兜底 -> Ubuntu/Windows 采集编码 -> iOS 显示 -> 触控和键盘回传
```

## 第一版边界

Mobile MVP 必须做：

- 官方账号登录和我的设备
- 桌面端一次开启“允许我的设备远程访问”
- iOS 一键连接 Ubuntu，随后复用链路连接 Windows
- H.264 画面、基础触控鼠标、滚轮、文本和基础键盘
- P2P 优先、Relay 自动兜底、E2EE、断开和资源释放

以下完整清单是后续 V1 Core 范围，不阻塞 Mobile MVP 内测：

必须做：

- 账号登录
- 账号 MFA 和高风险操作验证
- 反诈与滥用防护基础能力
- 设备绑定
- 设备在线状态
- 设备 ID + 验证码连接
- 被控端确认
- 无人值守访问
- 远程桌面
- 鼠标键盘控制
- 键盘、IME 和常用组合键处理
- 多显示器基础支持
- 媒体能力协商、动态码率、降帧和关键帧请求
- 文本剪贴板同步
- 基础文件传输
- 隐私屏和本地输入保护的独立权限及安全恢复
- 远程重启被控设备并以新会话恢复
- P2P + Relay
- 会话日志
- 一键断开
- 安装包签名、更新 manifest 签名和 SBOM

暂不承诺：

- iOS 被控端完整远控
- Android
- macOS
- 浏览器被控端
- 浏览器主控端
- 绕过系统权限的静默控制
- 远程开机、WOL、智能插座唤醒或带外管理唤醒
- 未签名或来源不可验证的客户端更新
- Wayland 下完全等同 X11 的输入控制
- 首版 4K/144fps 游戏级体验
- 生产会话录制或服务端集中录屏
- V1 Core 多区域数据驻留承诺
