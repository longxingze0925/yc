import CryptoKit
import Foundation
import Security

public enum SignalEvent: Sendable {
    case connecting
    case authenticated(connectionID: String)
    case onlineDevices([SignalOnlineDevice])
    case sessionState(sessionID: UUID, state: String, eventID: String?)
    case disconnected(String)
    case authenticationFailed(String)
}

public struct SignalOnlineDevice: Decodable, Equatable, Sendable {
    public let accountID: String
    public let deviceID: String
    public let publicKeyID: String
    public let publicKeyVersion: UInt32
    public let clientCapabilitiesHash: String
    public let status: DeviceStatus
    public let lastSeenEpochMillis: Int64
    public let connectionID: String

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
        case clientCapabilitiesHash = "client_capabilities_hash"
        case status
        case lastSeenEpochMillis = "last_seen_epoch_millis"
        case connectionID = "connection_id"
    }
}

struct SignalHelloResponse: Encodable, Sendable {
    let accountID: String
    let deviceID: String
    let clientNonce: String
    let timestamp: UInt64
    let clientSupportedProtocolVersions: [UInt16]
    let clientMinProtocolVersion: UInt16
    let publicKeyID: String
    let publicKeyVersion: UInt32
    let clientSupportedProtocolVersionsHash: String
    let clientCapabilities: ClientCapabilities
    let clientCapabilitiesHash: String
    let deviceSignature: String

    private enum CodingKeys: String, CodingKey {
        case accountID = "account_id"
        case deviceID = "device_id"
        case clientNonce = "client_nonce"
        case timestamp
        case clientSupportedProtocolVersions = "client_supported_protocol_versions"
        case clientMinProtocolVersion = "client_min_protocol_version"
        case publicKeyID = "public_key_id"
        case publicKeyVersion = "public_key_version"
        case clientSupportedProtocolVersionsHash = "client_supported_protocol_versions_hash"
        case clientCapabilities = "client_capabilities"
        case clientCapabilitiesHash = "client_capabilities_hash"
        case deviceSignature = "device_signature"
    }
}

public actor SignalClient {
    public nonisolated let events: AsyncStream<SignalEvent>

    private struct Incoming: Decodable {
        let type: String
        let accountID: String?
        let deviceID: String?
        let protocolVersion: UInt16?
        let serverNonce: String?
        let expiresAtEpochMillis: Int64?
        let serverSupportedProtocolVersions: [UInt16]?
        let connectionID: String?
        let clientSupportedProtocolVersionsHash: String?
        let clientCapabilitiesHash: String?
        let devices: [SignalOnlineDevice]?
        let sessionID: UUID?
        let state: String?
        let status: String?
        let eventID: String?
        let code: String?
        let message: String?

        private enum CodingKeys: String, CodingKey {
            case type
            case accountID = "account_id"
            case deviceID = "device_id"
            case protocolVersion = "protocol_version"
            case serverNonce = "server_nonce"
            case expiresAtEpochMillis = "expires_at_epoch_millis"
            case serverSupportedProtocolVersions = "server_supported_protocol_versions"
            case connectionID = "connection_id"
            case clientSupportedProtocolVersionsHash = "client_supported_protocol_versions_hash"
            case clientCapabilitiesHash = "client_capabilities_hash"
            case devices
            case sessionID = "session_id"
            case state
            case status
            case eventID = "event_id"
            case code
            case message
        }
    }

    private struct EmptyPayload: Encodable {}

    private let configuration: ServiceConfiguration
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let continuation: AsyncStream<SignalEvent>.Continuation
    private var connectionLoop: Task<Void, Never>?
    private var socket: URLSessionWebSocketTask?
    private var stopped = true
    private var expectedAccountID: String?
    private var expectedDeviceID: String?
    private var expectedProtocolVersion: UInt16?
    private var expectedServerVersions: [UInt16]?
    private var expectedVersionHash: String?
    private var expectedCapabilitiesHash: String?

    public init(configuration: ServiceConfiguration) {
        self.configuration = configuration
        session = PinnedSignalSession.make(fingerprint: configuration.serverPublicKeyFingerprint)
        encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        decoder = JSONDecoder()

        var captured: AsyncStream<SignalEvent>.Continuation!
        events = AsyncStream { captured = $0 }
        continuation = captured
    }

    deinit {
        connectionLoop?.cancel()
        socket?.cancel(with: .goingAway, reason: nil)
        continuation.finish()
    }

    public func start(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities,
        accessTokenProvider: @escaping @Sendable () async throws -> String
    ) throws {
        stop()
        let identity = try identityStore.loadOrCreate()
        guard !accountID.isEmpty,
              identity.publicKeyID != nil,
              identity.publicKeyVersion > 0 else {
            throw APIClientError.authenticationRequired
        }
        stopped = false
        connectionLoop = Task {
            await runConnectionLoop(
                accountID: accountID,
                identityStore: identityStore,
                capabilities: capabilities,
                accessTokenProvider: accessTokenProvider
            )
        }
    }

    public func stop() {
        stopped = true
        connectionLoop?.cancel()
        connectionLoop = nil
        socket?.cancel(with: .normalClosure, reason: nil)
        socket = nil
    }

    public func requestOnlineDevices() async throws {
        try await send(type: "list_online_devices", payload: EmptyPayload())
    }

    private func runConnectionLoop(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities,
        accessTokenProvider: @escaping @Sendable () async throws -> String
    ) async {
        var retryDelay: UInt64 = 1
        while !Task.isCancelled, !stopped {
            do {
                continuation.yield(.connecting)
                let accessToken = try await accessTokenProvider()
                try await connect(accessToken: accessToken)
                retryDelay = 1
                try await receiveLoop(accountID: accountID, identityStore: identityStore, capabilities: capabilities)
            } catch {
                if Task.isCancelled || stopped { return }
                continuation.yield(.disconnected(error.localizedDescription))
                try? await Task.sleep(nanoseconds: retryDelay * 1_000_000_000)
                retryDelay = min(retryDelay * 2, 30)
            }
        }
    }

    private func connect(accessToken: String) async throws {
        expectedAccountID = nil
        expectedDeviceID = nil
        expectedProtocolVersion = nil
        expectedServerVersions = nil
        expectedVersionHash = nil
        expectedCapabilitiesHash = nil
        var request = URLRequest(url: configuration.signalURL)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.setValue(
            ProtocolConstants.supportedVersions.map(String.init).joined(separator: ","),
            forHTTPHeaderField: "X-Rctl-Protocol-Versions"
        )
        request.setValue(
            String(ProtocolConstants.minimumVersion),
            forHTTPHeaderField: "X-Rctl-Min-Protocol-Version"
        )
        let task = session.webSocketTask(with: request)
        socket = task
        task.resume()
    }

    private func receiveLoop(
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        guard let socket else { throw APIClientError.transport("Signal 连接不存在") }
        while !Task.isCancelled, !stopped {
            let message = try await socket.receive()
            let data: Data
            switch message {
            case let .data(value): data = value
            case let .string(value): data = Data(value.utf8)
            @unknown default: continue
            }
            let incoming = try decoder.decode(Incoming.self, from: data)
            try await handle(incoming, accountID: accountID, identityStore: identityStore, capabilities: capabilities)
        }
    }

    private func handle(
        _ incoming: Incoming,
        accountID: String,
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        switch incoming.type {
        case "hello_challenge":
            let identity = try identityStore.loadOrCreate()
            guard incoming.accountID == accountID,
                  incoming.deviceID == nil || incoming.deviceID == identity.deviceID,
                  let protocolVersion = incoming.protocolVersion,
                  ProtocolConstants.supportedVersions.contains(protocolVersion),
                  let serverVersions = incoming.serverSupportedProtocolVersions,
                  serverVersions.contains(protocolVersion),
                  let expiresAt = incoming.expiresAtEpochMillis,
                  expiresAt > Date.now.epochMillis,
                  let encodedServerNonce = incoming.serverNonce,
                  let serverNonce = Data(base64URLEncoded: encodedServerNonce),
                  serverNonce.count == 32 else {
                throw APIClientError.transport("Signal 握手上下文不匹配")
            }
            try await sendHelloResponse(
                accountID: accountID,
                protocolVersion: protocolVersion,
                serverNonce: serverNonce,
                serverSupportedVersions: serverVersions,
                identityStore: identityStore,
                capabilities: capabilities
            )
        case "hello_ok":
            guard incoming.accountID == expectedAccountID,
                  incoming.deviceID == expectedDeviceID,
                  incoming.protocolVersion == expectedProtocolVersion,
                  incoming.clientSupportedProtocolVersionsHash == expectedVersionHash,
                  incoming.clientCapabilitiesHash == expectedCapabilitiesHash,
                  normalizedVersions(incoming.serverSupportedProtocolVersions) == expectedServerVersions,
                  let connectionID = incoming.connectionID else {
                throw APIClientError.transport("Signal 握手回显校验失败")
            }
            continuation.yield(.authenticated(connectionID: connectionID))
            try await requestOnlineDevices()
        case "online_devices":
            continuation.yield(.onlineDevices(incoming.devices ?? []))
        case "connection_state", "session_accept_ack", "session_close_ack", "session_cancel_ack", "session_reject_ack":
            if let sessionID = incoming.sessionID, let state = incoming.status ?? incoming.state {
                continuation.yield(.sessionState(sessionID: sessionID, state: state, eventID: incoming.eventID))
            }
        case "auth_failed":
            stopped = true
            continuation.yield(.authenticationFailed(incoming.message ?? "Signal 身份验证失败"))
            throw APIClientError.authenticationRequired
        case "error":
            throw APIClientError.server(
                code: incoming.code ?? "signal_error",
                message: incoming.message ?? "Signal 返回错误",
                status: 0
            )
        default:
            break
        }
    }

    private func sendHelloResponse(
        accountID: String,
        protocolVersion: UInt16,
        serverNonce: Data,
        serverSupportedVersions: [UInt16],
        identityStore: DeviceIdentityStore,
        capabilities: ClientCapabilities
    ) async throws {
        let identity = try identityStore.loadOrCreate()
        guard let publicKeyID = identity.publicKeyID, identity.publicKeyVersion > 0 else {
            throw APIClientError.authenticationRequired
        }
        let clientNonce = try Self.randomBytes(count: 32)
        guard let timestamp = UInt64(exactly: Date.now.epochMillis) else {
            throw APIClientError.transport("系统时间无效")
        }
        let supportedVersions = Array(Set(ProtocolConstants.supportedVersions)).sorted()
        let versionsHash = try SignalHandshakeCanonical.protocolVersionsHash(
            versions: supportedVersions,
            minimumVersion: ProtocolConstants.minimumVersion
        )
        let capabilitiesHash = try capabilities.canonicalHash()
        let signedCanonical = try SignalHandshakeCanonical.helloSignatureInput(
            serverNonce: serverNonce,
            clientNonce: clientNonce,
            accountID: accountID,
            deviceID: identity.deviceID,
            protocolVersion: protocolVersion,
            timestamp: timestamp,
            versionsHash: versionsHash,
            capabilitiesHash: capabilitiesHash
        )
        let signature = try identityStore.sign(digest: Data(SHA256.hash(data: signedCanonical)))
        expectedAccountID = accountID
        expectedDeviceID = identity.deviceID
        expectedProtocolVersion = protocolVersion
        expectedServerVersions = normalizedVersions(serverSupportedVersions)
        expectedVersionHash = versionsHash.lowercaseHexString
        expectedCapabilitiesHash = capabilitiesHash.lowercaseHexString

        let response = SignalHelloResponse(
            accountID: accountID,
            deviceID: identity.deviceID,
            clientNonce: clientNonce.base64URLEncodedString(),
            timestamp: timestamp,
            clientSupportedProtocolVersions: supportedVersions,
            clientMinProtocolVersion: ProtocolConstants.minimumVersion,
            publicKeyID: publicKeyID,
            publicKeyVersion: identity.publicKeyVersion,
            clientSupportedProtocolVersionsHash: versionsHash.lowercaseHexString,
            clientCapabilities: capabilities,
            clientCapabilitiesHash: capabilitiesHash.lowercaseHexString,
            deviceSignature: signature.base64URLEncodedString()
        )
        try await send(type: "hello_response", payload: response)
    }

    private func send<T: Encodable>(type: String, payload: T) async throws {
        guard let socket else { throw APIClientError.transport("Signal 尚未连接") }
        let payloadData = try encoder.encode(payload)
        guard var object = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw APIClientError.invalidResponse
        }
        object["type"] = type
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard let text = String(data: data, encoding: .utf8) else {
            throw APIClientError.invalidResponse
        }
        try await socket.send(.string(text))
    }

    private func normalizedVersions(_ versions: [UInt16]?) -> [UInt16]? {
        versions.map { Array(Set($0)).sorted() }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw APIClientError.transport("无法生成 Signal 握手随机数")
        }
        return Data(bytes)
    }
}

private final class PinnedSignalSession: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let fingerprint: String?
    private init(fingerprint: String?) { self.fingerprint = fingerprint }

    static func make(fingerprint: String?) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = true
        return URLSession(
            configuration: configuration,
            delegate: PinnedSignalSession(fingerprint: fingerprint),
            delegateQueue: nil
        )
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        guard SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        guard let fingerprint else {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        guard let key = SecTrustCopyKey(trust),
              let data = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if actual == fingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
