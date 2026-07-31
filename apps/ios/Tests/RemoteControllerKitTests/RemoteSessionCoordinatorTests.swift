import CoreVideo
import Foundation
import XCTest
@testable import RemoteControllerKit

final class RemoteSessionCoordinatorTests: XCTestCase {
    @MainActor
    func testFrameInputAndCloseReleaseFormCompleteSession() async throws {
        let descriptor = makeDescriptor()
        let transport = FakeSessionTransport()
        let decoder = FakeDecoder()
        let renderer = FakeRenderer()
        let coordinator = RemoteSessionCoordinator(
            descriptor: descriptor,
            transportFactory: FakeTransportFactory(transport: transport),
            decoder: decoder,
            renderer: renderer
        )

        await coordinator.establish()
        transport.emit(.displays([DisplayDescriptor(
            displayID: "primary",
            name: "Primary",
            width: 1_920,
            height: 1_080,
            scaleFactor: 1,
            isPrimary: true
        )]))
        transport.emit(.lifecycle(.connected))
        transport.emit(.h264(H264AccessUnit(
            data: Data([0, 0, 0, 1, 0x65, 1]),
            presentationTimeMillis: 1,
            isKeyframe: true,
            frameID: 7
        )))
        try await waitUntil { decoder.decodedFrameIDs == [7] }

        await coordinator.sendInput(.pointer(
            sessionID: descriptor.sessionID,
            displayID: "primary",
            point: NormalizedPoint(x: 0.5, y: 0.25)
        ))
        await coordinator.close()
        await coordinator.close()

        XCTAssertEqual(transport.establishCount, 1)
        XCTAssertEqual(transport.closeCount, 1)
        XCTAssertEqual(transport.inputs.map(\.inputKind), [.mouseMove, .releaseAllKeys])
        XCTAssertEqual(decoder.invalidateCount, 1)
        XCTAssertEqual(renderer.clearCount, 1)
        XCTAssertEqual(coordinator.lifecycle, .closed)
    }

    @MainActor
    func testLateEventsAreIgnoredAfterClose() async throws {
        let transport = FakeSessionTransport()
        let decoder = FakeDecoder()
        let coordinator = RemoteSessionCoordinator(
            descriptor: makeDescriptor(),
            transportFactory: FakeTransportFactory(transport: transport),
            decoder: decoder,
            renderer: FakeRenderer()
        )
        await coordinator.establish()
        transport.emit(.lifecycle(.connected))
        try await waitUntil { coordinator.lifecycle == .connected }
        await coordinator.close()
        transport.emit(.h264(H264AccessUnit(
            data: Data([0, 0, 0, 1, 0x65]),
            presentationTimeMillis: 1,
            isKeyframe: true,
            frameID: 99
        )))
        await Task.yield()

        XCTAssertTrue(decoder.decodedFrameIDs.isEmpty)
        XCTAssertEqual(coordinator.lifecycle, .closed)
    }

    @MainActor
    private func waitUntil(
        attempts: Int = 100,
        condition: @escaping @MainActor () -> Bool
    ) async throws {
        for _ in 0..<attempts {
            if condition() { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("condition did not become true")
    }

    private func makeDescriptor() -> SessionDescriptor {
        SessionDescriptor(
            sessionID: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!,
            accountID: "account-1",
            controllerDeviceID: "ios-1",
            controlledDeviceID: "ubuntu-1",
            controlledDeviceName: "Ubuntu",
            permissions: .requestedControllerDefaults,
            permissionsDigest: Data(repeating: 1, count: 32),
            expiresAtEpochMillis: 4_102_444_800_000
        )
    }
}

private final class FakeTransportFactory: SessionTransportFactory, @unchecked Sendable {
    private let transport: FakeSessionTransport

    init(transport: FakeSessionTransport) {
        self.transport = transport
    }

    func makeTransport(for descriptor: SessionDescriptor) async throws -> any SessionTransport {
        transport
    }
}

private final class FakeSessionTransport: SessionTransport, @unchecked Sendable {
    let incomingEvents: AsyncThrowingStream<SessionIncomingEvent, Error>

    private let continuation: AsyncThrowingStream<SessionIncomingEvent, Error>.Continuation
    private let lock = NSLock()
    private var storedInputs: [InputEvent] = []
    private var storedEstablishCount = 0
    private var storedCloseCount = 0

    init() {
        var continuation: AsyncThrowingStream<SessionIncomingEvent, Error>.Continuation!
        incomingEvents = AsyncThrowingStream { continuation = $0 }
        self.continuation = continuation
    }

    var inputs: [InputEvent] { lock.withLock { storedInputs } }
    var establishCount: Int { lock.withLock { storedEstablishCount } }
    var closeCount: Int { lock.withLock { storedCloseCount } }

    func emit(_ event: SessionIncomingEvent) {
        continuation.yield(event)
    }

    func establish() async throws {
        lock.withLock { storedEstablishCount += 1 }
    }

    func sendInput(_ event: InputEvent) async throws {
        lock.withLock { storedInputs.append(event) }
    }

    func requestMediaQuality(_ profile: MediaQualityProfile, displayID: String) async throws {}
    func requestKeyframe(displayID: String, lastFrameID: UInt64?) async throws {}
    func selectDisplay(_ displayID: String) async throws {}
    func requestClipboard(enabled: Bool) async throws {}
    func requestPrivacyMode(_ mode: String, enabled: Bool) async throws {}
    func requestFileTransfer(fileURL: URL) async throws {}

    func close(reason: String) async {
        lock.withLock { storedCloseCount += 1 }
        continuation.finish()
    }
}

private final class FakeDecoder: RemoteH264Decoding, @unchecked Sendable {
    private let lock = NSLock()
    private var storedFrameIDs: [UInt64] = []
    private var storedInvalidateCount = 0

    var decodedFrameIDs: [UInt64] { lock.withLock { storedFrameIDs } }
    var invalidateCount: Int { lock.withLock { storedInvalidateCount } }

    func setHandlers(
        onFrame: H264Decoder.FrameHandler?,
        onFailure: H264Decoder.FailureHandler?
    ) {}

    func decode(_ accessUnit: H264AccessUnit) {
        lock.withLock { storedFrameIDs.append(accessUnit.frameID) }
    }

    func invalidate() {
        lock.withLock { storedInvalidateCount += 1 }
    }
}

private final class FakeRenderer: RemoteFrameRendering, @unchecked Sendable {
    private let lock = NSLock()
    private var storedClearCount = 0

    var clearCount: Int { lock.withLock { storedClearCount } }

    func display(_ pixelBuffer: CVPixelBuffer) {}

    func clear() {
        lock.withLock { storedClearCount += 1 }
    }
}
