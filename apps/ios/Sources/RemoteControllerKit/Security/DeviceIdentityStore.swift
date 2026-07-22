import CryptoKit
import Foundation
import Security
import UIKit

public struct DeviceIdentity: Equatable, Sendable {
    public let deviceID: String
    public let publicKeyID: String
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
        guard values.allSatisfy({ $0 != nil }),
              let deviceIDData,
              let publicKeyIDData,
              let versionData,
              let privateKeyData,
              let deviceID = String(data: deviceIDData, encoding: .utf8),
              let publicKeyID = String(data: publicKeyIDData, encoding: .utf8),
              versionData.count == MemoryLayout<UInt32>.size else {
            throw KeychainError.corruptValue("device identity")
        }

        let version = versionData.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }
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

    public func registration(displayName: String? = nil) throws -> DeviceRegistrationRequest {
        let identity = try loadOrCreate()
        return DeviceRegistrationRequest(
            deviceID: identity.deviceID,
            platform: .ios,
            displayName: displayName ?? UIDevice.current.name,
            osVersion: UIDevice.current.systemVersion,
            arch: Self.currentArchitecture,
            publicKey: identity.publicKey.base64EncodedString(),
            roleCapabilities: .iosControllerOnly
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

    public static var currentOSVersion: String {
        UIDevice.current.systemVersion
    }

    private func createIdentity() throws -> DeviceIdentity {
        let deviceID = UUID().uuidString.lowercased()
        let publicKeyID = UUID().uuidString.lowercased()
        let version = UInt32(1)
        var bigEndianVersion = version.bigEndian
        let versionData = Data(bytes: &bigEndianVersion, count: MemoryLayout<UInt32>.size)
        let privateKey = Curve25519.Signing.PrivateKey()

        try store.set(Data(deviceID.utf8), for: Key.deviceID, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try store.set(Data(publicKeyID.utf8), for: Key.publicKeyID, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try store.set(versionData, for: Key.publicKeyVersion, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        try store.set(privateKey.rawRepresentation, for: Key.privateKey, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

        return DeviceIdentity(
            deviceID: deviceID,
            publicKeyID: publicKeyID,
            publicKeyVersion: version,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }
}

public enum DeviceIdentityError: LocalizedError, Equatable {
    case invalidDigestLength

    public var errorDescription: String? {
        "设备签名输入必须是 32 字节 SHA-256 digest"
    }
}
