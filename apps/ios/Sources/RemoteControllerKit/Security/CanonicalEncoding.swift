import CoreFoundation
import CryptoKit
import Foundation

public enum CanonicalEncodingError: Error, Equatable {
    case fieldTooLarge
    case unsupportedJSONNumber
    case unsupportedJSONValue
    case invalidJSON
    case invalidUUID
    case invalidHashLength
    case invalidNonceLength
}

public enum ProtocolCanonicalEncoder {
    public static func encode(domain: String, fields: [(String, Data?)]) throws -> Data {
        var output = Data()
        try append(name: "domain", value: Data(domain.utf8), to: &output)
        for (name, value) in fields {
            try append(name: name, value: value ?? Data(), to: &output)
        }
        return output
    }

    public static func string(_ value: String) -> Data { Data(value.utf8) }
    public static func bool(_ value: Bool) -> Data { Data([value ? 1 : 0]) }

    public static func integer<T: FixedWidthInteger>(_ value: T) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<T>.size)
    }

    public static func uuid(_ value: String) throws -> Data {
        guard let uuid = UUID(uuidString: value) else { throw CanonicalEncodingError.invalidUUID }
        var bytes = uuid.uuid
        return withUnsafeBytes(of: &bytes) { Data($0) }
    }

    public static func sortedStringArray(_ values: [String]) throws -> Data {
        let sorted = Array(Set(values)).sorted { lhs, rhs in
            lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
        }
        var output = Data()
        for value in sorted {
            let bytes = Data(value.utf8)
            guard bytes.count <= Int(UInt32.max) else { throw CanonicalEncodingError.fieldTooLarge }
            output.append(integer(UInt32(bytes.count)))
            output.append(bytes)
        }
        return output
    }

    private static func append(name: String, value: Data, to output: inout Data) throws {
        let nameData = Data(name.utf8)
        guard nameData.count <= Int(UInt32.max), value.count <= Int(UInt32.max) else {
            throw CanonicalEncodingError.fieldTooLarge
        }
        output.append(integer(UInt32(nameData.count)))
        output.append(nameData)
        output.append(integer(UInt32(value.count)))
        output.append(value)
    }
}

public enum JSONCanonicalizer {
    public static func canonicalize(_ data: Data) throws -> Data {
        try StrictJSONValidator.validate(data)
        let object = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return try render(object)
    }

    private static func render(_ value: Any) throws -> Data {
        if value is NSNull { return Data("null".utf8) }
        if let string = value as? String { return try renderString(string) }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return Data((number.boolValue ? "true" : "false").utf8)
            }
            let double = number.doubleValue
            guard double.isFinite else {
                throw CanonicalEncodingError.unsupportedJSONNumber
            }
            let wrapped = try JSONSerialization.data(
                withJSONObject: [number],
                options: [.withoutEscapingSlashes]
            )
            guard wrapped.count >= 2, wrapped.first == 0x5B, wrapped.last == 0x5D else {
                throw CanonicalEncodingError.unsupportedJSONNumber
            }
            return Data(wrapped.dropFirst().dropLast())
        }
        if let array = value as? [Any] {
            let rendered = try array.map(render)
            return joined(rendered, prefix: "[", separator: ",", suffix: "]")
        }
        if let object = value as? [String: Any] {
            let keys = object.keys.sorted { lhs, rhs in
                lhs.utf16.lexicographicallyPrecedes(rhs.utf16)
            }
            let rendered = try keys.map { key -> Data in
                var item = try renderString(key)
                item.append(Data(":".utf8))
                guard let value = object[key] else { throw CanonicalEncodingError.invalidJSON }
                item.append(try render(value))
                return item
            }
            return joined(rendered, prefix: "{", separator: ",", suffix: "}")
        }
        throw CanonicalEncodingError.unsupportedJSONValue
    }

    private static func renderString(_ value: String) throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: [value], options: [.withoutEscapingSlashes])
        guard data.count >= 2 else { throw CanonicalEncodingError.invalidJSON }
        return Data(data.dropFirst().dropLast())
    }

    private static func joined(_ values: [Data], prefix: Character, separator: Character, suffix: Character) -> Data {
        var output = Data(String(prefix).utf8)
        for (index, value) in values.enumerated() {
            if index > 0 { output.append(Data(String(separator).utf8)) }
            output.append(value)
        }
        output.append(Data(String(suffix).utf8))
        return output
    }
}

private struct StrictJSONValidator {
    private let bytes: [UInt8]
    private var index = 0

    static func validate(_ data: Data) throws {
        var parser = StrictJSONValidator(bytes: Array(data))
        try parser.parseValue()
        parser.skipWhitespace()
        guard parser.index == parser.bytes.count else {
            throw CanonicalEncodingError.invalidJSON
        }
    }

    private mutating func parseValue() throws {
        skipWhitespace()
        guard let byte = current else { throw CanonicalEncodingError.invalidJSON }
        switch byte {
        case 0x7B: try parseObject()
        case 0x5B: try parseArray()
        case 0x22: _ = try parseString()
        case 0x74: try consumeLiteral("true")
        case 0x66: try consumeLiteral("false")
        case 0x6E: try consumeLiteral("null")
        case 0x2D, 0x30...0x39: try parseNumber()
        default: throw CanonicalEncodingError.invalidJSON
        }
    }

    private mutating func parseObject() throws {
        try consume(0x7B)
        skipWhitespace()
        if current == 0x7D {
            index += 1
            return
        }
        var keys = Set<String>()
        while true {
            skipWhitespace()
            let key = try parseString()
            guard keys.insert(key).inserted else { throw CanonicalEncodingError.invalidJSON }
            skipWhitespace()
            try consume(0x3A)
            try parseValue()
            skipWhitespace()
            if current == 0x7D {
                index += 1
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseArray() throws {
        try consume(0x5B)
        skipWhitespace()
        if current == 0x5D {
            index += 1
            return
        }
        while true {
            try parseValue()
            skipWhitespace()
            if current == 0x5D {
                index += 1
                return
            }
            try consume(0x2C)
        }
    }

    private mutating func parseString() throws -> String {
        let start = index
        try consume(0x22)
        while let byte = current {
            if byte == 0x22 {
                index += 1
                let token = Data(bytes[start..<index])
                guard let value = try JSONSerialization.jsonObject(
                    with: token,
                    options: [.fragmentsAllowed]
                ) as? String else {
                    throw CanonicalEncodingError.invalidJSON
                }
                return value
            }
            if byte < 0x20 { throw CanonicalEncodingError.invalidJSON }
            if byte == 0x5C {
                index += 1
                guard let escaped = current else { throw CanonicalEncodingError.invalidJSON }
                if escaped == 0x75 {
                    index += 1
                    guard index + 4 <= bytes.count,
                          bytes[index..<index + 4].allSatisfy({ Self.hexNibble($0) != nil }) else {
                        throw CanonicalEncodingError.invalidJSON
                    }
                    index += 4
                } else {
                    guard [0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74].contains(escaped) else {
                        throw CanonicalEncodingError.invalidJSON
                    }
                    index += 1
                }
            } else {
                index += 1
            }
        }
        throw CanonicalEncodingError.invalidJSON
    }

    private mutating func parseNumber() throws {
        if current == 0x2D { index += 1 }
        guard let first = current else { throw CanonicalEncodingError.invalidJSON }
        if first == 0x30 {
            index += 1
            if current.map(Self.isDigit) == true { throw CanonicalEncodingError.invalidJSON }
        } else {
            guard (0x31...0x39).contains(first) else { throw CanonicalEncodingError.invalidJSON }
            consumeDigits()
        }
        if current == 0x2E {
            index += 1
            guard current.map(Self.isDigit) == true else {
                throw CanonicalEncodingError.invalidJSON
            }
            consumeDigits()
        }
        if current == 0x65 || current == 0x45 {
            index += 1
            if current == 0x2B || current == 0x2D { index += 1 }
            guard current.map(Self.isDigit) == true else {
                throw CanonicalEncodingError.invalidJSON
            }
            consumeDigits()
        }
    }

    private mutating func consumeDigits() {
        while current.map(Self.isDigit) == true { index += 1 }
    }

    private mutating func consumeLiteral(_ literal: String) throws {
        let expected = Array(literal.utf8)
        guard index + expected.count <= bytes.count,
              Array(bytes[index..<index + expected.count]) == expected else {
            throw CanonicalEncodingError.invalidJSON
        }
        index += expected.count
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard current == expected else { throw CanonicalEncodingError.invalidJSON }
        index += 1
    }

    private mutating func skipWhitespace() {
        while current.map({ [0x20, 0x09, 0x0A, 0x0D].contains($0) }) == true {
            index += 1
        }
    }

    private var current: UInt8? {
        index < bytes.count ? bytes[index] : nil
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: byte - 0x30
        case 0x41...0x46: byte - 0x41 + 10
        case 0x61...0x66: byte - 0x61 + 10
        default: nil
        }
    }
}

public extension ClientCapabilities {
    func canonicalData() throws -> Data {
        let encoded = try JSONEncoder().encode(self)
        let canonicalJSON = try JSONCanonicalizer.canonicalize(encoded)
        return try ProtocolCanonicalEncoder.encode(domain: "rctl-client-capabilities-v1", fields: [
            ("client_capabilities", canonicalJSON)
        ])
    }

    func canonicalHash() throws -> Data {
        Data(SHA256.hash(data: try canonicalData()))
    }
}

public enum SignalHandshakeCanonical {
    public static func protocolVersionsHash(versions: [UInt16], minimumVersion: UInt16) throws -> Data {
        let normalized = Array(Set(versions)).sorted()
        var encodedVersions = Data()
        normalized.forEach { encodedVersions.append(ProtocolCanonicalEncoder.integer($0)) }
        let canonical = try ProtocolCanonicalEncoder.encode(domain: "rctl-protocol-versions-v1", fields: [
            ("client_supported_protocol_versions", encodedVersions),
            ("client_min_protocol_version", ProtocolCanonicalEncoder.integer(minimumVersion))
        ])
        return Data(SHA256.hash(data: canonical))
    }

    public static func helloSignatureInput(
        serverNonce: Data,
        clientNonce: Data,
        accountID: String,
        deviceID: String,
        protocolVersion: UInt16,
        timestamp: UInt64,
        versionsHash: Data,
        capabilitiesHash: Data
    ) throws -> Data {
        guard serverNonce.count == 32, clientNonce.count == 32 else {
            throw CanonicalEncodingError.invalidNonceLength
        }
        guard versionsHash.count == 32, capabilitiesHash.count == 32 else {
            throw CanonicalEncodingError.invalidHashLength
        }
        return try ProtocolCanonicalEncoder.encode(domain: "rctl-ws-hello-v1", fields: [
            ("server_nonce", serverNonce),
            ("client_nonce", clientNonce),
            ("account_id", ProtocolCanonicalEncoder.string(accountID)),
            ("device_id", ProtocolCanonicalEncoder.string(deviceID)),
            ("protocol_version", ProtocolCanonicalEncoder.integer(protocolVersion)),
            ("timestamp", ProtocolCanonicalEncoder.integer(timestamp)),
            ("client_supported_protocol_versions_hash", versionsHash),
            ("client_capabilities_hash", capabilitiesHash)
        ])
    }
}

extension Data {
    init?(base64URLEncoded value: String) {
        guard value.utf8.allSatisfy({ byte in
            (65...90).contains(byte)
                || (97...122).contains(byte)
                || (48...57).contains(byte)
                || byte == 45
                || byte == 95
        }) else {
            return nil
        }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    var lowercaseHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
