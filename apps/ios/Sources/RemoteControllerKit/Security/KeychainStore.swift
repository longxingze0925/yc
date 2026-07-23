import Foundation
import Security

public protocol SecureStoring: Sendable {
    func data(for key: String) throws -> Data?
    func set(_ data: Data, for key: String, accessibility: CFString) throws
    func remove(_ key: String) throws
}

public final class KeychainStore: SecureStoring, @unchecked Sendable {
    private let service: String

    public init(service: String = "com.remotecontroller.ios") {
        self.service = service
    }

    public func data(for key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.unexpectedStatus(status)
        }
        return data
    }

    public func set(_ data: Data, for key: String, accessibility: CFString) throws {
        let query = baseQuery(for: key)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(updateStatus)
        }

        var insert = query
        attributes.forEach { insert[$0.key] = $0.value }
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.unexpectedStatus(addStatus)
        }
    }

    public func remove(_ key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }
}

public enum KeychainError: LocalizedError, Sendable {
    case unexpectedStatus(OSStatus)
    case corruptValue(String)

    public var errorDescription: String? {
        switch self {
        case let .unexpectedStatus(status):
            return "Keychain 操作失败（\(status)）"
        case let .corruptValue(key):
            return "Keychain 中的 \(key) 数据不完整"
        }
    }
}

public final class TokenVault: @unchecked Sendable {
    private let store: SecureStoring
    private let key = "account.tokens.v1"

    public init(store: SecureStoring) {
        self.store = store
    }

    public func load() throws -> TokenSet? {
        guard let data = try store.data(for: key) else { return nil }
        do {
            return try JSONDecoder().decode(TokenSet.self, from: data)
        } catch {
            throw KeychainError.corruptValue(key)
        }
    }

    public func save(_ tokens: TokenSet) throws {
        let data = try JSONEncoder().encode(tokens)
        try store.set(data, for: key, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }

    public func clear() throws {
        try store.remove(key)
    }
}
