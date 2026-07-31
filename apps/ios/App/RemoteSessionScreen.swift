import RemoteControllerKit
import SwiftUI

struct RemoteSessionScreen: View {
    let launch: SessionLaunch
    let dismiss: () -> Void
    @Environment(\.scenePhase) private var scenePhase
    @State private var startupError: String?
    @State private var coordinator: RemoteSessionCoordinator?
    @State private var renderer: MetalRemoteRenderer?

    var body: some View {
        Group {
            if let coordinator, let renderer {
                ActiveRemoteSessionView(
                    coordinator: coordinator,
                    renderer: renderer,
                    dismiss: dismiss
                )
            } else if let startupError {
                AppUnavailableView(
                    title: "会话启动失败",
                    systemImage: "exclamationmark.triangle",
                    message: startupError
                )
                .safeAreaInset(edge: .bottom) {
                    Button("关闭", action: dismiss)
                        .buttonStyle(.borderedProminent)
                        .padding()
                }
            } else {
                ProgressView("正在连接 \(launch.deviceName)")
            }
        }
        .task { await start() }
        .onChange(of: scenePhase) { phase in
            guard phase == .background, let coordinator else { return }
            Task {
                await coordinator.applicationDidEnterBackground()
                dismiss()
            }
        }
    }

    @MainActor
    private func start() async {
        guard coordinator == nil, startupError == nil else { return }
        do {
            let renderer = try MetalRemoteRenderer()
            let value = RemoteSessionCoordinator(
                descriptor: launch.descriptor,
                transportFactory: RustCoreSessionTransportFactory(),
                renderer: renderer
            )
            self.renderer = renderer
            coordinator = value
            await value.establish()
        } catch {
            startupError = error.localizedDescription
        }
    }
}

private struct ActiveRemoteSessionView: View {
    @ObservedObject var coordinator: RemoteSessionCoordinator
    let renderer: MetalRemoteRenderer
    let dismiss: () -> Void
    @State private var zoomScale: CGFloat = 1
    @State private var keyboardPresented = false
    @State private var shortcutsPresented = false

    private var selectedDisplay: DisplayDescriptor? {
        coordinator.displays.first { $0.displayID == coordinator.selectedDisplayID }
            ?? coordinator.displays.first
    }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            MetalRemoteView(renderer: renderer, zoomScale: zoomScale)
                .ignoresSafeArea()
            if let display = selectedDisplay {
                RemoteInputOverlay(
                    sessionID: coordinator.descriptor.sessionID,
                    displayID: display.displayID,
                    remoteSize: CGSize(width: CGFloat(display.width), height: CGFloat(display.height)),
                    zoomScale: $zoomScale,
                    keyboardPresented: $keyboardPresented,
                    onEvent: { event in
                        Task { await coordinator.sendInput(event) }
                    },
                    onShortcutPalette: { shortcutsPresented = true }
                )
                .ignoresSafeArea()
            }
        }
        .safeAreaInset(edge: .top) {
            HStack(spacing: 18) {
                Button {
                    keyboardPresented.toggle()
                } label: {
                    Image(systemName: "keyboard")
                }
                Button {
                    shortcutsPresented = true
                } label: {
                    Image(systemName: "command")
                }
                Spacer()
                Text(statusText)
                    .font(.caption)
                    .lineLimit(1)
                Button(role: .destructive) {
                    Task {
                        await coordinator.close()
                        dismiss()
                    }
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .accessibilityLabel("断开")
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 16)
            .frame(height: 44)
            .background(.black.opacity(0.78))
        }
        .sheet(isPresented: $shortcutsPresented) {
            ShortcutPanel(coordinator: coordinator)
                .presentationDetents([.height(210)])
        }
        .onDisappear {
            Task { await coordinator.close(reason: "view_disappeared") }
        }
    }

    private var statusText: String {
        switch coordinator.lifecycle {
        case .connected: return "已连接"
        case .connecting, .establishingSecureSession: return "连接中"
        case .reconnecting: return "正在重连"
        case let .degraded(reason): return "网络较差  \(reason)"
        case let .failed(reason): return reason
        case .closing, .closed: return "已断开"
        case .idle, .waitingForApproval: return "等待连接"
        }
    }
}

private struct ShortcutPanel: View {
    @ObservedObject var coordinator: RemoteSessionCoordinator
    @Environment(\.dismiss) private var dismiss

    private let shortcuts: [(String, RemoteShortcut)] = [
        ("复制", .copy),
        ("粘贴", .paste),
        ("剪切", .cut),
        ("撤销", .undo),
        ("重做", .redo),
        ("切换窗口", .switchWindow),
        ("系统键", .superKey)
    ]

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 96))], spacing: 12) {
            ForEach(shortcuts, id: \.0) { item in
                Button(item.0) {
                    guard let displayID = coordinator.selectedDisplayID else { return }
                    Task {
                        await coordinator.sendInput(.shortcut(
                            sessionID: coordinator.descriptor.sessionID,
                            displayID: displayID,
                            shortcut: item.1
                        ))
                        dismiss()
                    }
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
    }
}
