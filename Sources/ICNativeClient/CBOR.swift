import Foundation

public enum ICCBOR {
    public static let selfDescribeTag: UInt64 = 55_799
    public static let defaultMaximumDepth = 64
    public static let defaultMaximumCollectionCount = 100_000

    public indirect enum Value: Equatable, Sendable {
        case text(String)
        case bytes(Data)
        case unsigned(UInt64)
        case array([Value])
        case map([(Value, Value)])
        case tagged(UInt64, Value)

        public static func == (lhs: Value, rhs: Value) -> Bool {
            switch (lhs, rhs) {
            case (.text(let a), .text(let b)): a == b
            case (.bytes(let a), .bytes(let b)): a == b
            case (.unsigned(let a), .unsigned(let b)): a == b
            case (.array(let a), .array(let b)): a == b
            case (.map(let a), .map(let b)):
                a.elementsEqual(b) { $0.0 == $1.0 && $0.1 == $1.1 }
            case (.tagged(let at, let av), .tagged(let bt, let bv)): at == bt && av == bv
            default: false
            }
        }
    }

    public static func encode(_ value: Value) -> Data {
        var data = Data()
        append(value, to: &data)
        return data
    }

    /// Strictly decodes exactly one supported CBOR value.
    public static func decodeStrict(
        _ data: Data,
        maximumDepth: Int = defaultMaximumDepth,
        maximumCollectionCount: Int = defaultMaximumCollectionCount
    ) throws -> Value {
        guard maximumDepth > 0, maximumCollectionCount > 0 else {
            throw ICClientError.invalidCBOR("invalid decoder limits")
        }
        var reader = Reader(
            data: data,
            maximumDepth: maximumDepth,
            maximumCollectionCount: maximumCollectionCount
        )
        let value = try reader.read(depth: 0)
        guard reader.isAtEnd else { throw ICClientError.invalidCBOR("trailing data") }
        return value
    }

    /// Compatibility helper. Security-sensitive paths use `decodeStrict` directly.
    public static func decode(_ data: Data) -> Value? {
        try? decodeStrict(data)
    }

    public static func queryEnvelope(
        canisterId: Data,
        method: String,
        arg: Data,
        ingressExpiry: UInt64
    ) -> Data {
        let content: Value = .map([
            (.text("request_type"), .text("query")),
            (.text("canister_id"), .bytes(canisterId)),
            (.text("method_name"), .text(method)),
            (.text("arg"), .bytes(arg)),
            (.text("sender"), .bytes(Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(ingressExpiry)),
        ])
        return encode(.tagged(selfDescribeTag, .map([(.text("content"), content)])))
    }

    public static func signedEnvelope(
        content: Value,
        publicKey: Data,
        signature: Data,
        delegation: ICDelegationChain
    ) -> Data {
        let delegations = delegation.delegations.map { signed -> Value in
            var fields: [(Value, Value)] = [
                (.text("pubkey"), .bytes(signed.delegation.publicKey)),
                (.text("expiration"), .unsigned(signed.delegation.expiration)),
            ]
            if let targets = signed.delegation.targets {
                fields.append((.text("targets"), .array(targets.map(Value.bytes))))
            }
            if let permissions = signed.delegation.permissions {
                fields.append((.text("permissions"), .text(permissions.rawValue)))
            }
            return .map([
                (.text("delegation"), .map(fields)),
                (.text("signature"), .bytes(signed.signature)),
            ])
        }
        return encode(.tagged(selfDescribeTag, .map([
            (.text("content"), content),
            (.text("sender_pubkey"), .bytes(publicKey)),
            (.text("sender_sig"), .bytes(signature)),
            (.text("sender_delegation"), .array(delegations)),
        ])))
    }

    public static func mapValue(_ data: Data, key: String) -> Value? {
        guard let value = try? decodeStrict(data) else { return nil }
        return mapValue(value, key: key)
    }

    public static func mapValue(_ value: Value, key: String) -> Value? {
        guard case .map(let values) = unwrapSelfDescribeTag(value) else { return nil }
        return values.first { $0.0 == .text(key) }?.1
    }

    static func requiredMap(_ value: Value, context: String) throws -> [(Value, Value)] {
        guard case .map(let fields) = unwrapSelfDescribeTag(value) else {
            throw ICClientError.invalidResponse(context)
        }
        return fields
    }

    static func requiredValue(_ fields: [(Value, Value)], key: String, context: String) throws -> Value {
        guard let value = fields.first(where: { $0.0 == .text(key) })?.1 else {
            throw ICClientError.invalidResponse("\(context).\(key)")
        }
        return value
    }

    static func optionalValue(_ fields: [(Value, Value)], key: String) -> Value? {
        fields.first(where: { $0.0 == .text(key) })?.1
    }

    static func unwrapSelfDescribeTag(_ value: Value) -> Value {
        if case .tagged(selfDescribeTag, let nested) = value { return nested }
        return value
    }

    private static func append(_ value: Value, to data: inout Data) {
        switch value {
        case .text(let text):
            let bytes = Data(text.utf8)
            appendHeader(3, count: UInt64(bytes.count), to: &data)
            data.append(bytes)
        case .bytes(let bytes):
            appendHeader(2, count: UInt64(bytes.count), to: &data)
            data.append(bytes)
        case .unsigned(let value): appendHeader(0, count: value, to: &data)
        case .array(let values):
            appendHeader(4, count: UInt64(values.count), to: &data)
            values.forEach { append($0, to: &data) }
        case .map(let values):
            appendHeader(5, count: UInt64(values.count), to: &data)
            values.forEach { append($0.0, to: &data); append($0.1, to: &data) }
        case .tagged(let tag, let value):
            appendHeader(6, count: tag, to: &data)
            append(value, to: &data)
        }
    }

    private static func appendHeader(_ major: UInt8, count: UInt64, to data: inout Data) {
        let base = major << 5
        switch count {
        case 0..<24: data.append(base | UInt8(count))
        case 24...UInt64(UInt8.max):
            data.append(base | 24); data.append(UInt8(count))
        case 256...UInt64(UInt16.max):
            data.append(base | 25); data.append(contentsOf: UInt16(count).bigEndianBytes)
        case 65_536...UInt64(UInt32.max):
            data.append(base | 26); data.append(contentsOf: UInt32(count).bigEndianBytes)
        default:
            data.append(base | 27); data.append(contentsOf: count.bigEndianBytes)
        }
    }

    private struct Reader {
        let data: Data
        let maximumDepth: Int
        let maximumCollectionCount: Int
        var index = 0

        var isAtEnd: Bool { index == data.count }

        mutating func read(depth: Int) throws -> Value {
            guard depth < maximumDepth else { throw ICClientError.invalidCBOR("maximum nesting depth exceeded") }
            let first = try readByte()
            let major = first >> 5
            let info = first & 0x1f
            if info == 31 {
                return try readIndefinite(major: major, depth: depth)
            }
            let count = try readCount(info)
            switch major {
            case 0: return .unsigned(count)
            case 2:
                return .bytes(try readData(count))
            case 3:
                let bytes = try readData(count)
                guard let text = String(data: bytes, encoding: .utf8) else { throw ICClientError.invalidCBOR("invalid UTF-8") }
                return .text(text)
            case 4:
                let size = try checkedCollectionCount(count)
                var values: [Value] = []
                values.reserveCapacity(size)
                for _ in 0..<size { values.append(try read(depth: depth + 1)) }
                return .array(values)
            case 5:
                let size = try checkedCollectionCount(count)
                var values: [(Value, Value)] = []
                values.reserveCapacity(size)
                var canonicalKeys = Set<Data>()
                canonicalKeys.reserveCapacity(size)
                for _ in 0..<size {
                    let key = try read(depth: depth + 1)
                    guard canonicalKeys.insert(ICCBOR.encode(key)).inserted else {
                        throw ICClientError.invalidCBOR("duplicate map key")
                    }
                    values.append((key, try read(depth: depth + 1)))
                }
                return .map(values)
            case 6:
                guard count == selfDescribeTag else { throw ICClientError.invalidCBOR("unsupported semantic tag \(count)") }
                return .tagged(count, try read(depth: depth + 1))
            default:
                throw ICClientError.invalidCBOR("unsupported CBOR major type \(major)")
            }
        }

        private mutating func readIndefinite(major: UInt8, depth: Int) throws -> Value {
            switch major {
            case 2:
                return .bytes(try readIndefiniteStringChunks(major: major))
            case 3:
                let bytes = try readIndefiniteStringChunks(major: major)
                guard let text = String(data: bytes, encoding: .utf8) else {
                    throw ICClientError.invalidCBOR("invalid UTF-8")
                }
                return .text(text)
            case 4:
                var values: [Value] = []
                while !consumeBreakIfPresent() {
                    guard values.count < maximumCollectionCount else {
                        throw ICClientError.invalidCBOR("collection limit exceeded")
                    }
                    values.append(try read(depth: depth + 1))
                }
                return .array(values)
            case 5:
                var values: [(Value, Value)] = []
                var canonicalKeys = Set<Data>()
                while !consumeBreakIfPresent() {
                    guard values.count < maximumCollectionCount else {
                        throw ICClientError.invalidCBOR("collection limit exceeded")
                    }
                    let key = try read(depth: depth + 1)
                    guard canonicalKeys.insert(ICCBOR.encode(key)).inserted else {
                        throw ICClientError.invalidCBOR("duplicate map key")
                    }
                    values.append((key, try read(depth: depth + 1)))
                }
                return .map(values)
            default:
                throw ICClientError.invalidCBOR("indefinite-length value has an unsupported major type \(major)")
            }
        }

        private mutating func readIndefiniteStringChunks(major: UInt8) throws -> Data {
            var bytes = Data()
            var chunkCount = 0
            while !consumeBreakIfPresent() {
                guard chunkCount < maximumCollectionCount else {
                    throw ICClientError.invalidCBOR("collection limit exceeded")
                }
                let first = try readByte()
                let chunkMajor = first >> 5
                let info = first & 0x1f
                guard chunkMajor == major, info != 31 else {
                    throw ICClientError.invalidCBOR("invalid indefinite-length string chunk")
                }
                let chunk = try readData(readCount(info))
                if major == 3, String(data: chunk, encoding: .utf8) == nil {
                    throw ICClientError.invalidCBOR("invalid UTF-8")
                }
                bytes.append(chunk)
                chunkCount += 1
            }
            return bytes
        }

        private mutating func consumeBreakIfPresent() -> Bool {
            guard index < data.count,
                  data[data.index(data.startIndex, offsetBy: index)] == 0xff else {
                return false
            }
            index += 1
            return true
        }

        private mutating func readCount(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0..<24: return UInt64(info)
            case 24:
                let value = UInt64(try readByte())
                guard value >= 24 else { throw ICClientError.invalidCBOR("non-canonical integer") }
                return value
            case 25:
                let value = try readInteger(byteCount: 2)
                guard value > UInt8.max else { throw ICClientError.invalidCBOR("non-canonical integer") }
                return value
            case 26:
                let value = try readInteger(byteCount: 4)
                guard value > UInt16.max else { throw ICClientError.invalidCBOR("non-canonical integer") }
                return value
            case 27:
                let value = try readInteger(byteCount: 8)
                guard value > UInt32.max else { throw ICClientError.invalidCBOR("non-canonical integer") }
                return value
            default: throw ICClientError.invalidCBOR("invalid additional information")
            }
        }

        private func checkedCollectionCount(_ count: UInt64) throws -> Int {
            guard count <= UInt64(maximumCollectionCount), count <= UInt64(Int.max) else {
                throw ICClientError.invalidCBOR("collection limit exceeded")
            }
            return Int(count)
        }

        private mutating func readByte() throws -> UInt8 {
            guard index < data.count else { throw ICClientError.invalidCBOR("unexpected end of input") }
            defer { index += 1 }
            return data[data.index(data.startIndex, offsetBy: index)]
        }

        private mutating func readInteger(byteCount: Int) throws -> UInt64 {
            guard byteCount <= data.count - index else { throw ICClientError.invalidCBOR("unexpected end of integer") }
            var result: UInt64 = 0
            for _ in 0..<byteCount { result = (result << 8) | UInt64(try readByte()) }
            return result
        }

        private mutating func readData(_ count: UInt64) throws -> Data {
            guard count <= UInt64(Int.max) else { throw ICClientError.invalidCBOR("byte string is too large") }
            let length = Int(count)
            guard length <= data.count - index else { throw ICClientError.invalidCBOR("unexpected end of byte string") }
            let start = data.index(data.startIndex, offsetBy: index)
            let end = data.index(start, offsetBy: length)
            index += length
            return Data(data[start..<end])
        }
    }
}
