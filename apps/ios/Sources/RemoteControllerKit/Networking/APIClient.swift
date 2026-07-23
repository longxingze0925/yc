import CryptoKit
import Foundation
import Security

public protocol RemoteAPI: Sendable {
    func health() async throws
    func login(_ request: LoginRequest) async throws -> LoginChallenge
    func finishLogin(
        challenge: LoginChallenge,
        factor: String?,
        code: String?
    ) async throws -> LoginResponse
    func refresh(using refreshToken: String) async throws -> LoginResponse
    func logout() async throws
    func startTOTPEnrollment(
        _ request: TOTPEnrollmentStartRequest,
        authorizationToken: String
    ) async throws -> TOTPEnrollmentStartResponse
    func finishTOTPEnrollment(
        _ request: TOTPEnrollmentFinishRequest,
        idempotencyKey: String,
        authorizationToken: String
    ) async throws -> RecoveryCodeDeliveryEnvelope
    func registerControllerDevice(_ request: DeviceRegistrationRequest) async throws -> DeviceRegistrationResponse
    func listDevices() async throws -> [DeviceSummary]
    func createSession(_ request: SessionCreateRequest) async throws -> SessionCreateResponse
}

public enum APIClientError: LocalizedError, Equatable, Sendable {
    case serviceNotConfigured
    case authenticationRequired
    case invalidResponse
    case server(code: String, message: String, status: Int)
    case transport(String)
    case unsupportedWireContract(String)

    public var errorDescription: String? {
        switch self {
        case .serviceNotConfigured:
            return "请先配置服务地址"
        case .authenticationRequired:
            return "登录状态已失效"
        case .invalidResponse:
            return "服务返回了无法识别的数据"
        case let .server(_, message, _):
            return message
        case let .transport(message):
            return message
        case let .unsupportedWireContract(message):
            return message
        }
    }
}

public protocol DeviceRequestAuthenticating: Sendable {
    func authenticate(
        _ request: inout URLRequest,
        body: Data,
        accountID: String,
        identityStore: DeviceIdentityStore
    ) throws
}

public struct CanonicalDeviceRequestAuthenticator: DeviceRequestAuthenticating {
    public init() {}

    public func authenticate(
        _ request: inout URLRequest,
        body: Data,
        accountID: String,
        identityStore: DeviceIdentityStore
    ) throws {
        guard let method = request.httpMethod?.uppercased(), let url = request.url else {
            throw APIClientError.invalidResponse
        }
        let identity = try identityStore.loadOrCreate()
        let requestID = UUID().uuidString.lowercased()
        let nonce = try Self.randomNonce()
        let timestamp = Date.now.epochMillis
        let bodyHash = try Self.canonicalBodyHash(
            body,
            contentType: request.value(forHTTPHeaderField: "Content-Type")
        )
        let requestTarget = try Self.normalizedRequestTarget(url)
        let canonical = try ProtocolCanonicalEncoder.encode(domain: "rctl-api-input-v1", fields: [
            ("method", ProtocolCanonicalEncoder.string(method)),
            ("path", ProtocolCanonicalEncoder.string(requestTarget)),
            ("body_hash", bodyHash),
            ("request_id", ProtocolCanonicalEncoder.string(requestID)),
            ("device_id", ProtocolCanonicalEncoder.string(identity.deviceID)),
            ("account_id", ProtocolCanonicalEncoder.string(accountID)),
            ("timestamp", ProtocolCanonicalEncoder.integer(timestamp)),
            ("api_nonce", ProtocolCanonicalEncoder.string(nonce))
        ])
        let digest = Data(SHA256.hash(data: canonical))
        let signature = try identityStore.sign(digest: digest)

        // Header names are isolated here until the server exports a shared wire-contract crate.
        request.setValue(requestID, forHTTPHeaderField: "X-Request-Id")
        request.setValue(identity.deviceID, forHTTPHeaderField: "X-Rctl-Device-Id")
        if let publicKeyID = identity.publicKeyID {
            request.setValue(publicKeyID, forHTTPHeaderField: "X-Rctl-Public-Key-Id")
            request.setValue(String(identity.publicKeyVersion), forHTTPHeaderField: "X-Rctl-Public-Key-Version")
        }
        request.setValue(String(timestamp), forHTTPHeaderField: "X-Rctl-Timestamp")
        request.setValue(nonce, forHTTPHeaderField: "X-Rctl-Api-Nonce")
        request.setValue(signature.base64URLEncodedString(), forHTTPHeaderField: "X-Rctl-Device-Signature")
    }

    static func normalizedRequestTarget(_ url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw APIClientError.invalidResponse
        }
        let encodedPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        let path = removeDotSegments(try normalizePercentEncoding(encodedPath, allowed: isPathByte))
        guard let query = components.percentEncodedQuery, !query.isEmpty else { return path }
        guard !query.contains("+") else { throw APIClientError.invalidResponse }

        let pairs = try query.split(separator: "&", omittingEmptySubsequences: false).map { part in
            let pair = String(part)
            guard !pair.isEmpty else { throw APIClientError.invalidResponse }
            let separator = pair.firstIndex(of: "=")
            let key = separator.map { String(pair[..<$0]) } ?? pair
            let value = separator.map { String(pair[pair.index(after: $0)...]) } ?? ""
            guard !key.isEmpty else { throw APIClientError.invalidResponse }
            return (
                try normalizePercentEncoding(key, allowed: isUnreserved),
                try normalizePercentEncoding(value, allowed: isUnreserved),
                separator != nil
            )
        }
        let sorted = pairs.sorted { lhs, rhs in
            let leftKey = Array(lhs.0.utf8)
            let rightKey = Array(rhs.0.utf8)
            if leftKey != rightKey { return leftKey.lexicographicallyPrecedes(rightKey) }
            let leftValue = Array(lhs.1.utf8)
            let rightValue = Array(rhs.1.utf8)
            if leftValue != rightValue { return leftValue.lexicographicallyPrecedes(rightValue) }
            return !lhs.2 && rhs.2
        }
        return path + "?" + sorted.map { $0.2 ? "\($0.0)=\($0.1)" : $0.0 }.joined(separator: "&")
    }

    static func canonicalBodyHash(_ body: Data, contentType: String?) throws -> Data {
        guard !body.isEmpty else { return Data(SHA256.hash(data: body)) }
        let mediaType = contentType?
            .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)
            .first?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let canonical = mediaType?.caseInsensitiveCompare("application/json") == .orderedSame
            ? try JSONCanonicalizer.canonicalize(body)
            : body
        return Data(SHA256.hash(data: canonical))
    }

    private static func normalizePercentEncoding(
        _ value: String,
        allowed: (UInt8) -> Bool
    ) throws -> String {
        let bytes = Array(value.utf8)
        guard bytes.allSatisfy({ $0 < 0x80 }) else { throw APIClientError.invalidResponse }
        var output = ""
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 0x25 {
                guard index + 2 < bytes.count,
                      let high = hexNibble(bytes[index + 1]),
                      let low = hexNibble(bytes[index + 2]) else {
                    throw APIClientError.invalidResponse
                }
                let decoded = high << 4 | low
                if isUnreserved(decoded) {
                    output.append(Character(UnicodeScalar(decoded)))
                } else {
                    appendPercentEncoded(decoded, to: &output)
                }
                index += 3
            } else {
                if allowed(byte) {
                    output.append(Character(UnicodeScalar(byte)))
                } else {
                    appendPercentEncoded(byte, to: &output)
                }
                index += 1
            }
        }
        return output
    }

    private static func removeDotSegments(_ path: String) -> String {
        let hasTrailingDirectory = path.hasSuffix("/") || path.hasSuffix("/.") || path.hasSuffix("/..")
        var segments: [Substring] = []
        for segment in path.split(separator: "/", omittingEmptySubsequences: false) {
            if segment == "." { continue }
            if segment == ".." {
                if segments.count > 1 { segments.removeLast() }
                continue
            }
            segments.append(segment)
        }
        if hasTrailingDirectory, segments.last?.isEmpty == false {
            segments.append(Substring())
        }
        let result = segments.map(String.init).joined(separator: "/")
        return result.isEmpty ? "/" : result
    }

    private static func isPathByte(_ byte: UInt8) -> Bool {
        isUnreserved(byte) || [
            0x2F, 0x3A, 0x40, 0x21, 0x24, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x3B, 0x3D
        ].contains(byte)
    }

    private static func isUnreserved(_ byte: UInt8) -> Bool {
        (0x41...0x5A).contains(byte)
            || (0x61...0x7A).contains(byte)
            || (0x30...0x39).contains(byte)
            || [0x2D, 0x2E, 0x5F, 0x7E].contains(byte)
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }

    private static func appendPercentEncoded(_ byte: UInt8, to output: inout String) {
        let digits = Array("0123456789ABCDEF".utf8)
        output.append("%")
        output.append(Character(UnicodeScalar(digits[Int(byte >> 4)])))
        output.append(Character(UnicodeScalar(digits[Int(byte & 0x0F)])))
    }

    private static func randomNonce() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 24)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw APIClientError.transport("无法生成安全请求随机数")
        }
        return Data(bytes).base64URLEncodedString()
    }
}

public actor URLSessionRemoteAPI: RemoteAPI {
    private enum Authentication: Equatable {
        case anonymous
        case account
        case accountAndDevice
        case deviceSignature(accountID: String)
        case bearerToken(String)
    }

    private struct EmptyResponse: Decodable {}
    private struct RefreshRequest: Encodable { let refreshToken: String }
    private struct APIErrorBody: Decodable { let code: String; let message: String }
    private struct DeviceListResponse: Decodable { let devices: [DeviceSummary] }

    private let configuration: ServiceConfiguration
    private let tokenVault: TokenVault
    private let identityStore: DeviceIdentityStore
    private let authenticator: any DeviceRequestAuthenticating
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        configuration: ServiceConfiguration,
        tokenVault: TokenVault,
        identityStore: DeviceIdentityStore,
        authenticator: any DeviceRequestAuthenticating = CanonicalDeviceRequestAuthenticator()
    ) {
        self.configuration = configuration
        self.tokenVault = tokenVault
        self.identityStore = identityStore
        self.authenticator = authenticator
        session = PinnedHTTPSession.make(fingerprint: configuration.serverPublicKeyFingerprint)
        encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        decoder = JSONDecoder()
    }

    public func health() async throws {
        let _: EmptyResponse = try await request(path: "/health", method: "GET", body: Optional<String>.none, auth: .anonymous)
    }

    public func login(_ request: LoginRequest) async throws -> LoginChallenge {
        try await self.request(
            path: "/v1/auth/login",
            method: "POST",
            body: request,
            auth: .anonymous,
            decoderUserInfo: [.loginClientNonce: request.clientNonce]
        )
    }

    public func finishLogin(
        challenge: LoginChallenge,
        factor: String?,
        code: String?
    ) async throws -> LoginResponse {
        try await request(
            path: "/v1/auth/login/finish",
            method: "POST",
            body: try LoginFinishRequest(challenge: challenge, factor: factor, code: code),
            auth: .deviceSignature(accountID: challenge.accountID)
        )
    }

    public func refresh(using refreshToken: String) async throws -> LoginResponse {
        let response: LoginResponse = try await request(
            path: "/v1/auth/refresh",
            method: "POST",
            body: RefreshRequest(refreshToken: refreshToken),
            auth: .anonymous
        )
        guard response.deviceEnrollmentGrant == nil else {
            throw APIClientError.invalidResponse
        }
        return response
    }

    public func logout() async throws {
        let _: EmptyResponse = try await request(path: "/v1/auth/logout", method: "POST", body: Optional<String>.none, auth: .account)
    }

    public func startTOTPEnrollment(
        _ request: TOTPEnrollmentStartRequest,
        authorizationToken: String
    ) async throws -> TOTPEnrollmentStartResponse {
        try await self.request(
            path: "/v1/me/mfa/totp/start",
            method: "POST",
            body: request,
            auth: .bearerToken(authorizationToken)
        )
    }

    public func finishTOTPEnrollment(
        _ request: TOTPEnrollmentFinishRequest,
        idempotencyKey: String,
        authorizationToken: String
    ) async throws -> RecoveryCodeDeliveryEnvelope {
        guard !idempotencyKey.isEmpty,
              idempotencyKey.utf8.count <= 128,
              idempotencyKey.utf8.allSatisfy({ (0x21...0x7E).contains($0) }) else {
            throw APIClientError.invalidResponse
        }
        return try await self.request(
            path: "/v1/me/mfa/totp/finish",
            method: "POST",
            body: request,
            auth: .bearerToken(authorizationToken),
            additionalHeaders: ["Idempotency-Key": idempotencyKey]
        )
    }

    public func registerControllerDevice(_ request: DeviceRegistrationRequest) async throws -> DeviceRegistrationResponse {
        try await self.request(path: "/v1/devices", method: "POST", body: request, auth: .accountAndDevice)
    }

    public func listDevices() async throws -> [DeviceSummary] {
        let response: DeviceListResponse = try await request(path: "/v1/devices", method: "GET", body: Optional<String>.none, auth: .account)
        return response.devices
    }

    public func createSession(_ request: SessionCreateRequest) async throws -> SessionCreateResponse {
        try await self.request(path: "/v1/sessions", method: "POST", body: request, auth: .accountAndDevice)
    }

    private func request<Response: Decodable, Body: Encodable>(
        path: String,
        method: String,
        body: Body?,
        auth: Authentication,
        decoderUserInfo: [CodingUserInfoKey: Any] = [:],
        additionalHeaders: [String: String] = [:]
    ) async throws -> Response {
        guard let url = URL(string: path, relativeTo: configuration.apiBaseURL)?.absoluteURL else {
            throw APIClientError.serviceNotConfigured
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 20
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(String(ProtocolConstants.version), forHTTPHeaderField: "X-Rctl-Protocol-Version")
        additionalHeaders.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }

        let bodyData: Data
        if let body {
            bodyData = try encoder.encode(body)
            request.httpBody = bodyData
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        } else {
            bodyData = Data()
        }

        switch auth {
        case .anonymous:
            break
        case .account, .accountAndDevice:
            guard let tokens = try tokenVault.load() else { throw APIClientError.authenticationRequired }
            request.setValue("Bearer \(tokens.accessToken)", forHTTPHeaderField: "Authorization")
            if auth == .accountAndDevice {
                try authenticator.authenticate(
                    &request,
                    body: bodyData,
                    accountID: tokens.accountID,
                    identityStore: identityStore
                )
            }
        case let .deviceSignature(accountID):
            try authenticator.authenticate(
                &request,
                body: bodyData,
                accountID: accountID,
                identityStore: identityStore
            )
        case let .bearerToken(accessToken):
            guard !accessToken.isEmpty else { throw APIClientError.authenticationRequired }
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }

        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw APIClientError.invalidResponse }
            guard (200..<300).contains(http.statusCode) else {
                let errorBody = try? decoder.decode(APIErrorBody.self, from: data)
                throw APIClientError.server(
                    code: errorBody?.code ?? "http_\(http.statusCode)",
                    message: errorBody?.message ?? "服务请求失败（\(http.statusCode)）",
                    status: http.statusCode
                )
            }
            if Response.self == EmptyResponse.self, data.isEmpty {
                return EmptyResponse() as! Response
            }
            let responseDecoder = JSONDecoder()
            responseDecoder.userInfo = decoderUserInfo
            return try responseDecoder.decode(Response.self, from: data)
        } catch let error as APIClientError {
            throw error
        } catch is DecodingError {
            throw APIClientError.invalidResponse
        } catch {
            throw APIClientError.transport(error.localizedDescription)
        }
    }
}

private final class PinnedHTTPSession: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let fingerprint: String?

    private init(fingerprint: String?) {
        self.fingerprint = fingerprint
    }

    static func make(fingerprint: String?) -> URLSession {
        let delegate = PinnedHTTPSession(fingerprint: fingerprint)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.waitsForConnectivity = true
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
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
              let keyData = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let actual = SHA256.hash(data: keyData).map { String(format: "%02x", $0) }.joined()
        guard actual == fingerprint else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
