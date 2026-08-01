import Combine
import Foundation

public enum ServiceEnvironment: String, Codable, CaseIterable, Identifiable, Sendable {
    case official
    case privateDeployment = "private"

    public var id: String { rawValue }
}

public struct ServiceConfiguration: Codable, Equatable, Sendable {
    public let environment: ServiceEnvironment
    public let apiBaseURL: URL
    public let signalURL: URL
    public let relayEndpoint: String?
    public let serverPublicKeyFingerprint: String?
    public let organizationName: String?

    private enum CodingKeys: String, CodingKey {
        case environment
        case apiBaseURL
        case signalURL
        case relayEndpoint
        case serverPublicKeyFingerprint
        case organizationName
    }

    public init(
        environment: ServiceEnvironment,
        apiBaseURL: URL,
        signalURL: URL,
        relayEndpoint: String? = nil,
        serverPublicKeyFingerprint: String? = nil,
        organizationName: String? = nil
    ) throws {
        try Self.validateWebURL(apiBaseURL, secureScheme: "https", field: "API")
        try Self.validateWebURL(signalURL, secureScheme: "wss", field: "Signal")

        if environment == .privateDeployment {
            guard let fingerprint = serverPublicKeyFingerprint,
                  Self.normalizedFingerprint(fingerprint) != nil else {
                throw ServiceConfigurationError.invalidServerPublicKeyFingerprint
            }
        }

        self.environment = environment
        self.apiBaseURL = apiBaseURL
        self.signalURL = signalURL
        self.relayEndpoint = relayEndpoint?.nilIfBlank
        self.serverPublicKeyFingerprint = serverPublicKeyFingerprint.flatMap(Self.normalizedFingerprint)
        self.organizationName = organizationName?.nilIfBlank
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(
            environment: values.decode(ServiceEnvironment.self, forKey: .environment),
            apiBaseURL: values.decode(URL.self, forKey: .apiBaseURL),
            signalURL: values.decode(URL.self, forKey: .signalURL),
            relayEndpoint: values.decodeIfPresent(String.self, forKey: .relayEndpoint),
            serverPublicKeyFingerprint: values.decodeIfPresent(
                String.self,
                forKey: .serverPublicKeyFingerprint
            ),
            organizationName: values.decodeIfPresent(String.self, forKey: .organizationName)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(environment, forKey: .environment)
        try values.encode(apiBaseURL, forKey: .apiBaseURL)
        try values.encode(signalURL, forKey: .signalURL)
        try values.encodeIfPresent(relayEndpoint, forKey: .relayEndpoint)
        try values.encodeIfPresent(serverPublicKeyFingerprint, forKey: .serverPublicKeyFingerprint)
        try values.encodeIfPresent(organizationName, forKey: .organizationName)
    }

    public static func deriveSignalURL(from apiURL: URL) throws -> URL {
        guard var components = URLComponents(url: apiURL, resolvingAgainstBaseURL: false) else {
            throw ServiceConfigurationError.invalidURL("Signal")
        }
        components.scheme = apiURL.scheme == "http" ? "ws" : "wss"
        components.path = "/ws"
        components.query = nil
        components.fragment = nil
        guard let url = components.url else {
            throw ServiceConfigurationError.invalidURL("Signal")
        }
        return url
    }

    public static func official(from bundle: Bundle = .main) throws -> ServiceConfiguration {
        let apiValue = (bundle.object(forInfoDictionaryKey: "RCTLOfficialAPIURL") as? String)
            ?? BuildServiceConfiguration.apiURL
        let signalValue = (bundle.object(forInfoDictionaryKey: "RCTLOfficialSignalURL") as? String)
            ?? BuildServiceConfiguration.signalURL
        guard
              let apiURL = URL(string: apiValue),
              let signalURL = URL(string: signalValue) else {
            throw ServiceConfigurationError.officialServiceNotConfigured
        }
        return try ServiceConfiguration(
            environment: .official,
            apiBaseURL: apiURL,
            signalURL: signalURL,
            organizationName: "官方服务"
        )
    }

    public static func normalizedFingerprint(_ value: String) -> String? {
        var normalized = ""
        normalized.reserveCapacity(64)
        for byte in value.lowercased().utf8 {
            switch byte {
            case 48...57, 97...102:
                normalized.append(Character(String(UnicodeScalar(byte))))
            case 9, 10, 13, 32, 45, 58:
                continue
            default:
                return nil
            }
        }
        return normalized.count == 64 ? normalized : nil
    }

    private static func validateWebURL(_ url: URL, secureScheme: String, field: String) throws {
        guard let scheme = url.scheme?.lowercased(),
              url.host != nil,
              url.user == nil,
              url.password == nil else {
            throw ServiceConfigurationError.invalidURL(field)
        }
        if scheme == secureScheme { return }

#if DEBUG
        let insecureScheme = secureScheme == "https" ? "http" : "ws"
        if scheme == insecureScheme,
           let host = url.host?.lowercased(),
           host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return
        }
#endif
        throw ServiceConfigurationError.insecureURL(field)
    }
}

public enum ServiceConfigurationError: LocalizedError, Equatable {
    case officialServiceNotConfigured
    case invalidURL(String)
    case insecureURL(String)
    case invalidServerPublicKeyFingerprint

    public var errorDescription: String? {
        switch self {
        case .officialServiceNotConfigured:
            return "官方服务地址尚未写入构建配置"
        case let .invalidURL(field):
            return "\(field) 服务地址格式无效"
        case let .insecureURL(field):
            return "\(field) 服务必须使用安全连接"
        case .invalidServerPublicKeyFingerprint:
            return "服务器公钥指纹必须是 32 字节 SHA-256 十六进制值"
        }
    }
}

@MainActor
public final class ServiceConfigurationStore: ObservableObject {
    @Published public private(set) var current: ServiceConfiguration?

    private let defaults: UserDefaults
    private let storageKey = "rctl.ios.service-configuration.v1"

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: storageKey) {
            current = try? JSONDecoder().decode(ServiceConfiguration.self, from: data)
        }
    }

    public func save(_ configuration: ServiceConfiguration) throws {
        let data = try JSONEncoder().encode(configuration)
        defaults.set(data, forKey: storageKey)
        current = configuration
    }

    public func clear() {
        defaults.removeObject(forKey: storageKey)
        current = nil
    }
}

private extension String {
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
