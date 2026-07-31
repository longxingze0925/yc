import RemoteControllerKit
import SwiftUI

@main
struct RemoteControllerApp: App {
    @StateObject private var model = ControllerAppModel()

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .task { await model.bootstrap() }
        }
    }
}

private struct RootView: View {
    @ObservedObject var model: ControllerAppModel

    var body: some View {
        Group {
            switch model.phase {
            case .launching:
                ProgressView()
            case .needsServiceConfiguration:
                AppUnavailableView(
                    title: "服务暂不可用",
                    systemImage: "network.slash",
                    message: "当前版本未配置官方服务"
                )
            case .signedOut:
                LoginView(model: model)
            case .authenticating:
                ProgressView("正在登录")
            case let .mfa(challenge):
                MFAView(model: model, challenge: challenge)
            case .signedIn:
                DeviceListView(model: model)
            }
        }
        .alert(
            "操作失败",
            isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.errorMessage = nil } }
            ),
            actions: { Button("好") { model.errorMessage = nil } },
            message: { Text(model.errorMessage ?? "") }
        )
        .fullScreenCover(item: Binding(
            get: { model.activeSession },
            set: { if $0 == nil { model.dismissSession() } }
        )) { launch in
            RemoteSessionScreen(launch: launch) {
                model.dismissSession()
            }
        }
    }
}

private struct LoginView: View {
    @ObservedObject var model: ControllerAppModel
    @State private var account = ""
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("邮箱", text: $account)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                    SecureField("密码", text: $password)
                        .textContentType(.password)
                }
                Section {
                    Button("登录") {
                        Task { await model.login(email: account, password: password) }
                    }
                    .disabled(account.trimmingCharacters(in: .whitespaces).isEmpty || password.isEmpty)
                }
            }
            .navigationTitle("远控")
        }
    }
}

private struct MFAView: View {
    @ObservedObject var model: ControllerAppModel
    let challenge: MFAChallenge
    @State private var factor: String
    @State private var code = ""

    init(model: ControllerAppModel, challenge: MFAChallenge) {
        self.model = model
        self.challenge = challenge
        _factor = State(initialValue: challenge.allowedFactors.first ?? "totp")
    }

    var body: some View {
        NavigationStack {
            Form {
                if challenge.allowedFactors.count > 1 {
                    Picker("验证方式", selection: $factor) {
                        ForEach(challenge.allowedFactors, id: \.self) { value in
                            Text(value == "totp" ? "身份验证器" : "恢复码").tag(value)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                TextField(factor == "totp" ? "6 位验证码" : "恢复码", text: $code)
                    .textContentType(.oneTimeCode)
                    .keyboardType(factor == "totp" ? .numberPad : .asciiCapable)
                Button("验证") {
                    Task {
                        await model.verifyMFA(
                            challengeID: challenge.mfaChallengeID,
                            factor: factor,
                            code: code
                        )
                    }
                }
                .disabled(code.isEmpty)
            }
            .navigationTitle("验证登录")
        }
    }
}

private struct DeviceListView: View {
    @ObservedObject var model: ControllerAppModel

    var body: some View {
        NavigationStack {
            List(model.devices.filter(\.canBeControlled)) { device in
                Button {
                    Task { await model.connect(to: device) }
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: device.platform == .windows ? "desktopcomputer" : "pc")
                            .font(.title3)
                            .frame(width: 32)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(device.displayName)
                                .foregroundStyle(.primary)
                            Text([device.platform.rawValue, device.osVersion].compactMap { $0 }.joined(separator: "  "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Circle()
                            .fill(device.status == .online ? Color.green : Color.secondary)
                            .frame(width: 8, height: 8)
                        Image(systemName: "chevron.right")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .disabled(device.status != .online)
            }
            .overlay {
                if model.devices.filter(\.canBeControlled).isEmpty {
                    AppUnavailableView(
                        title: "没有可控设备",
                        systemImage: "desktopcomputer",
                        message: "登录同一账号的电脑会显示在这里"
                    )
                }
            }
            .navigationTitle("我的设备")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        Task { await model.logout() }
                    } label: {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                    }
                    .accessibilityLabel("退出登录")
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        Task { await model.refreshDevices() }
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .accessibilityLabel("刷新设备")
                }
            }
            .refreshable { await model.refreshDevices() }
        }
    }
}

struct AppUnavailableView: View {
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage)
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(24)
    }
}
