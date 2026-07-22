import CryptoKit
import Foundation
import Security
import XCTest
@testable import RemoteControllerKit

final class DeviceIdentityStoreTests: XCTestCase {
    func testIdentityIsStableAndSignsDigest() throws {
        let secureStore = MemorySecureStore()
        let identityStore = DeviceIdentityStore(store: secureStore)
        let first = try identityStore.loadOrCreate()
        let second = try identityStore.loadOrCreate()
        let digest = Data(repeating: 0x5a, count: 32)
        let signature = try identityStore.sign(digest: digest)
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: first.publicKey)

        XCTAssertEqual(first, second)
        XCTAssertEqual(first.publicKey.count, 32)
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: digest))
    }

    func testRegistrationIsControllerOnlyAndPersistsServerKeyBinding() throws {
        let secureStore = MemorySecureStore()
        let identityStore = DeviceIdentityStore(store: secureStore)
        let request = try identityStore.registration(displayName: "QA iPhone")

        XCTAssertEqual(request.platform, .ios)
        XCTAssertEqual(request.roleCapabilities, .iosControllerOnly)
        XCTAssertFalse(request.osVersion.isEmpty)

        try identityStore.updateRegistration(publicKeyID: "server-key-1", publicKeyVersion: 3)
        let updated = try identityStore.loadOrCreate()
        XCTAssertEqual(updated.publicKeyID, "server-key-1")
        XCTAssertEqual(updated.publicKeyVersion, 3)
    }

    func testSigningRejectsNonSHA256Input() throws {
        let identityStore = DeviceIdentityStore(store: MemorySecureStore())
        _ = try identityStore.loadOrCreate()
        XCTAssertThrowsError(try identityStore.sign(digest: Data([1, 2, 3]))) { error in
            XCTAssertEqual(error as? DeviceIdentityError, .invalidDigestLength)
        }
    }

    func testPartialIdentityIsRejectedInsteadOfSilentlyRotated() throws {
        let secureStore = MemorySecureStore()
        try secureStore.set(
            Data("device-1".utf8),
            for: "device.identity.id.v1",
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
        let identityStore = DeviceIdentityStore(store: secureStore)
        XCTAssertThrowsError(try identityStore.loadOrCreate()) { error in
            guard case KeychainError.corruptValue(_) = error else {
                return XCTFail("Expected corrupt Keychain identity, got \(error)")
            }
        }
    }
}

private final class MemorySecureStore: SecureStoring, @unchecked Sendable {
    private var values: [String: Data] = [:]
    private let lock = NSLock()

    func data(for key: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    func set(_ data: Data, for key: String, accessibility: CFString) throws {
        lock.lock()
        defer { lock.unlock() }
        values[key] = data
    }

    func remove(_ key: String) throws {
        lock.lock()
        defer { lock.unlock() }
        values.removeValue(forKey: key)
    }
}
