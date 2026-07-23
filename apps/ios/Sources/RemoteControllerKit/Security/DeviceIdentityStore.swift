import CryptoKit
import Foundation
import Security
import UIKit

public struct DeviceIdentity: Equatable, Sendable {
    public let deviceID: String
    public let publicKeyID: String?
    public let publicKeyVersion: UInt32
    public let publicKey: Data
}

public final class DeviceIdentityStore: @unchecked Sendable {
    private enum Key {
        static let deviceID = "device.identity.id.v1"
        static let publicKeyID = "device.identity.public-key-id.v1"
        static let publicKeyVersion = "device.identity.public-key-version.v1"
        static let privateKey = "device.identity.ed25519-private.v1"
    }

    private let store: SecureStoring
    private let lock = NSLock()

    public init(store: SecureStoring) {
        self.store = store
    }

    public func loadOrCreate() throws -> DeviceIdentity {
        lock.lock()
        defer { lock.unlock() }

        let deviceIDData = try store.data(for: Key.deviceID)
        let publicKeyIDData = try store.data(for: Key.publicKeyID)
        let versionData = try store.data(for: Key.publicKeyVersion)
        let privateKeyData = try store.data(for: Key.privateKey)
        let values = [deviceIDData, publicKeyIDData, versionData, privateKeyData]

        if values.allSatisfy({ $0 == nil }) {
            return try createIdentity()
        }
        guard let deviceIDData,
              let privateKeyData,
              let deviceID = String(data: deviceIDData, encoding: .utf8) else {
            throw KeychainError.corruptValue("device identity")
        }
        let publicKeyID: String?
        let version: UInt32
        switch (publicKeyIDData, versionData) {
        case (nil, nil):
            publicKeyID = nil
            version = 0
        case let (.some(publicKeyIDData), .some(versionData)):
            guard let value = String(data: publicKeyIDData, encoding: .utf8),
                  !value.isEmpty,
                  versionData.count == MemoryLayout<UInt32>.size else {
                throw KeychainError.corruptValue("device registration")
            }
            let decodedVersion = versionData.withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self).bigEndian
            }
            guard decodedVersion > 0 else {
                throw KeychainError.corruptValue("device registration")
            }
            publicKeyID = value
            version = decodedVersion
        default:
            throw KeychainError.corruptValue("device registration")
        }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return DeviceIdentity(
            deviceID: deviceID,
            publicKeyID: publicKeyID,
            publicKeyVersion: version,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    public func sign(digest: Data) throws -> Data {
        guard digest.count == 32 else { throw DeviceIdentityError.invalidDigestLength }
        lock.lock()
        defer { lock.unlock() }
        guard let privateKeyData = try store.data(for: Key.privateKey) else {
            throw KeychainError.corruptValue(Key.privateKey)
        }
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
        return try privateKey.signature(for: digest)
    }

    public func loginRequest(email: String, password: String) throws -> LoginRequest {
        let identity = try loadOrCreate()
        var nonce = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
            throw KeychainError.corruptValue("login nonce")
        }
        return LoginRequest(
            email: email,
            password: password,
            identity: identity,
            clientNonce: Data(nonce)
        )
    }

    @MainActor
    public func registration(
        enrollmentGrant: String,
        displayName: String? = nil
    ) throws -> DeviceRegistrationRequest {
        guard !enrollmentGrant.isEmpty else {
            throw KeychainError.corruptValue("device enrollment grant")
        }
        let identity = try loadOrCreate()
        return DeviceRegistrationRequest(
            deviceID: identity.deviceID,
            platform: .ios,
            displayName: displayName ?? UIDevice.current.name,
            osVersion: UIDevice.current.systemVersion,
            arch: Self.currentArchitecture,
            publicKey: identity.publicKey.base64URLEncodedString(),
            roleCapabilities: .iosControllerOnly,
            deviceEnrollmentGrant: enrollmentGrant
        )
    }

    public func updateRegistration(publicKeyID: String, publicKeyVersion: UInt32) throws {
        guard !publicKeyID.isEmpty, publicKeyVersion > 0 else {
            throw KeychainError.corruptValue("device registration")
        }
        lock.lock()
        defer { lock.unlock() }
        guard try store.data(for: Key.privateKey) != nil else {
            throw KeychainError.corruptValue(Key.privateKey)
        }
        var bigEndianVersion = publicKeyVersion.bigEndian
        let versionData = Data(bytes: &bigEndianVersion, count: MemoryLayout<UInt32>.size)
        try store.set(
            Data(publicKeyID.utf8),
            for: Key.publicKeyID,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
        try store.set(
            versionData,
            for: Key.publicKeyVersion,
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
    }

    public func resetAfterConfirmedUnbind() throws {
        lock.lock()
        defer { lock.unlock() }
        try [Key.deviceID, Key.publicKeyID, Key.publicKeyVersion, Key.privateKey].forEach {
            try store.remove($0)
        }
    }

    public static var currentArchitecture: String {
#if arch(arm64)
        return "aarch64"
#else
        return "x86_64"
#endif
    }

    @MainActor
    public static var currentOSVersion: String {
        UIDevice.current.systemVersion
    }

    private func createIdentity() throws -> DeviceIdentity {
        let deviceID = UUID().uuidString.lowercased()
        let privateKey = Curve25519.Signing.PrivateKey()

        try store.set(Data(deviceID.utf8), for: Key.deviceID, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try store.set(privateKey.rawRepresentation, for: Key.privateKey, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

        return DeviceIdentity(
            deviceID: deviceID,
            publicKeyID: nil,
            publicKeyVersion: 0,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }
}

public enum DeviceIdentityError: LocalizedError, Equatable, Sendable {
    case invalidDigestLength

    public var errorDescription: String? {
        "设备签名输入必须是 32 字节 SHA-256 digest"
    }
}
