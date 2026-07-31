import Combine
import Foundation

@MainActor
public final class RemoteSessionCoordinator: ObservableObject {
    @Published public private(set) var lifecycle: SessionLifecycleState = .idle
    @Published public private(set) var stats = RemoteSessionStats()
    @Published public private(set) var displays: [DisplayDescriptor] = []
    @Published public private(set) var selectedDisplayID: String?
    @Published public private(set) var permissions: SessionPermissions
    @Published public private(set) var errorMessage: String?

    public let descriptor: SessionDescriptor
    public let renderer: any RemoteFrameRendering

    private let transportFactory: any SessionTransportFactory
    private let decoder: any RemoteH264Decoding
    private var transport: (any SessionTransport)?
    private var incomingEventsTask: Task<Void, Never>?
    private var lastKeyframeRequestAt = Date.distantPast
    private var closeStarted = false

    public init(
        descriptor: SessionDescriptor,
        transportFactory: any SessionTransportFactory,
        decoder: any RemoteH264Decoding = H264Decoder(),
        renderer: any RemoteFrameRendering
    ) {
        self.descriptor = descriptor
        self.transportFactory = transportFactory
        self.decoder = decoder
        self.renderer = renderer
        permissions = descriptor.permissions
        configureDecoder()
    }

    deinit {
        incomingEventsTask?.cancel()
        decoder.setHandlers(onFrame: nil, onFailure: nil)
        decoder.invalidate()
        renderer.clear()
    }

    public func establish() async {
        guard lifecycle == .idle, !closeStarted else { return }
        lifecycle = .connecting
        do {
            let transport = try await transportFactory.makeTransport(for: descriptor)
            guard !closeStarted else {
                await transport.close(reason: "session_closed_while_connecting")
                return
            }
            self.transport = transport
            consumeIncomingEvents(from: transport)
            try await transport.establish()
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func sendInput(_ event: InputEvent) async {
        guard permissions.inputControl else {
            fail(SessionTransportError.permissionDenied("输入控制").localizedDescription)
            return
        }
        guard event.sessionID == descriptor.sessionID,
              lifecycle == .connected,
              let transport else {
            fail(SessionTransportError.invalidState.localizedDescription)
            return
        }
        do {
            try await transport.sendInput(event)
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func selectDisplay(_ displayID: String) async {
        guard displays.contains(where: { $0.displayID == displayID }), let transport else { return }
        do {
            try await transport.selectDisplay(displayID)
            selectedDisplayID = displayID
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func requestMediaQuality(_ profile: MediaQualityProfile) async {
        guard let displayID = selectedDisplayID, let transport else { return }
        do {
            try await transport.requestMediaQuality(profile, displayID: displayID)
        } catch {
            fail(error.localizedDescription)
        }
    }

    public func close(reason: String = "user_closed") async {
        guard !closeStarted else { return }
        closeStarted = true
        lifecycle = .closing
        incomingEventsTask?.cancel()
        incomingEventsTask = nil

        if permissions.inputControl,
           let displayID = selectedDisplayID ?? displays.first?.displayID,
           let transport {
            try? await transport.sendInput(.releaseAll(
                sessionID: descriptor.sessionID,
                displayID: displayID
            ))
        }
        if let transport {
            await transport.close(reason: reason)
        }
        transport = nil
        decoder.setHandlers(onFrame: nil, onFailure: nil)
        decoder.invalidate()
        renderer.clear()
        lifecycle = .closed
    }

    public func applicationDidEnterBackground() async {
        await close(reason: "application_backgrounded")
    }

    private func configureDecoder() {
        decoder.setHandlers(
            onFrame: { [weak self] pixelBuffer, metadata in
                Task { @MainActor [weak self] in
                    guard let self, !self.closeStarted else { return }
                    self.renderer.display(pixelBuffer)
                    self.stats.decodeMillis = max(
                        0,
                        Double(Date.now.epochMillis - metadata.presentationTimeMillis)
                    )
                }
            },
            onFailure: { [weak self] error, frameID in
                Task { @MainActor [weak self] in
                    self?.handleDecoderFailure(error, frameID: frameID)
                }
            }
        )
    }

    private func consumeIncomingEvents(from transport: any SessionTransport) {
        incomingEventsTask?.cancel()
        incomingEventsTask = Task { [weak self] in
            do {
                for try await event in transport.incomingEvents {
                    guard !Task.isCancelled, let self else { return }
                    await self.handle(event)
                }
            } catch is CancellationError {
                return
            } catch {
                guard !Task.isCancelled else { return }
                await self?.fail(error.localizedDescription)
            }
        }
    }

    private func handle(_ event: SessionIncomingEvent) {
        guard !closeStarted else { return }
        switch event {
        case let .lifecycle(state):
            lifecycle = state
        case let .h264(accessUnit):
            guard lifecycle == .connected else { return }
            decoder.decode(accessUnit)
        case let .stats(value):
            stats = value
        case let .displays(value):
            displays = value
            if selectedDisplayID == nil || !value.contains(where: { $0.displayID == selectedDisplayID }) {
                selectedDisplayID = value.first(where: \.isPrimary)?.displayID ?? value.first?.displayID
            }
        case let .permissions(value):
            permissions = value
        case let .privacyMode(_, state, errorCode):
            if let errorCode {
                errorMessage = "隐私模式\(state)：\(errorCode)"
            }
        case let .remoteError(_, message):
            fail(message)
        }
    }

    private func handleDecoderFailure(_ error: H264DecoderError, frameID: UInt64?) {
        errorMessage = error.localizedDescription
        let now = Date()
        guard now.timeIntervalSince(lastKeyframeRequestAt) >= 1,
              let displayID = selectedDisplayID,
              let transport,
              !closeStarted else { return }
        lastKeyframeRequestAt = now
        Task {
            try? await transport.requestKeyframe(displayID: displayID, lastFrameID: frameID)
        }
    }

    private func fail(_ message: String) {
        guard !closeStarted else { return }
        lifecycle = .failed(message)
        errorMessage = message
    }
}
