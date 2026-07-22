import Foundation

public protocol CredentialProofClient: Sendable {
    func verifyTemporaryCode(
        session: SessionCreateResponse,
        secret: OneTimeSecret,
        api: any RemoteAPI
    ) async throws

    func verifyUnattendedCredential(
        session: SessionCreateResponse,
        secret: OneTimeSecret,
        api: any RemoteAPI
    ) async throws
}

public final class OneTimeSecret: @unchecked Sendable {
    private var bytes: Data
    private let lock = NSLock()

    public init(_ value: String) {
        bytes = Data(value.utf8)
    }

    deinit { wipe() }

    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try bytes.withUnsafeBytes(body)
    }

    public func wipe() {
        lock.lock()
        defer { lock.unlock() }
        bytes.resetBytes(in: 0..<bytes.count)
        bytes.removeAll(keepingCapacity: false)
    }
}

public struct UnavailableCredentialProofClient: CredentialProofClient {
    public init() {}

    public func verifyTemporaryCode(
        session: SessionCreateResponse,
        secret: OneTimeSecret,
        api: any RemoteAPI
    ) async throws {
        secret.wipe()
        throw APIClientError.unsupportedWireContract(
            "OPAQUE 客户端尚未接入，已阻止发送一次性验证码明文"
        )
    }

    public func verifyUnattendedCredential(
        session: SessionCreateResponse,
        secret: OneTimeSecret,
        api: any RemoteAPI
    ) async throws {
        secret.wipe()
        throw APIClientError.unsupportedWireContract(
            "OPAQUE 客户端尚未接入，已阻止发送无人值守凭据明文"
        )
    }
}
