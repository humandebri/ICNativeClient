// Minimal CBOR support for IC request envelopes and boundary-node responses.
// This intentionally supports only the CBOR shapes used by IC query/call/read_state.

import Foundation

public enum ICCBOR {
    public indirect enum Value: Equatable, Sendable {
        case text(String)
        case bytes(Data)
        case unsigned(UInt64)
        case array([Value])
        case map([(Value, Value)])
        case tagged(UInt64, Value)

        public static func == (lhs: Value, rhs: Value) -> Bool {
            switch (lhs, rhs) {
            case (.text(let left), .text(let right)):
                return left == right
            case (.bytes(let left), .bytes(let right)):
                return left == right
            case (.unsigned(let left), .unsigned(let right)):
                return left == right
            case (.array(let left), .array(let right)):
                return left == right
            case (.map(let left), .map(let right)):
                return left.elementsEqual(right) { $0.0 == $1.0 && $0.1 == $1.1 }
            case (.tagged(let leftTag, let leftValue), .tagged(let rightTag, let rightValue)):
                return leftTag == rightTag && leftValue == rightValue
            default:
                return false
            }
        }
    }

    public static func encode(_ value: Value) -> Data {
        var data = Data()
        append(value, to: &data)
        return data
    }

    public static func decode(_ data: Data) -> Value? {
        var reader = Reader(data: data)
        return reader.read()
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
        return encode(.map([(.text("content"), content)]))
    }

    public static func signedEnvelope(
        content: Value,
        publicKey: Data,
        signature: Data,
        delegation: ICDelegationChain
    ) -> Data {
        let cborDelegations = delegation.delegations.map { signed -> Value in
            var delegationMap: [(Value, Value)] = [
                (.text("pubkey"), .bytes(signed.delegation.publicKey)),
                (.text("expiration"), .unsigned(signed.delegation.expiration)),
            ]
            if let targets = signed.delegation.targets {
                delegationMap.append((.text("targets"), .array(targets.map(Value.bytes))))
            }
            return .map([
                (.text("delegation"), .map(delegationMap)),
                (.text("signature"), .bytes(signed.signature)),
            ])
        }
        return encode(.map([
            (.text("content"), content),
            (.text("sender_pubkey"), .bytes(publicKey)),
            (.text("sender_sig"), .bytes(signature)),
            (.text("sender_delegation"), .array(cborDelegations)),
        ]))
    }

    public static func decodeReplyArg(_ data: Data) -> Data? {
        var reader = Reader(data: data)
        let value = reader.read()
        let untagged = unwrapTag(value)
        guard case .map(let top)? = untagged else { return nil }
        for (key, value) in top {
            if key == .text("reply"), case .map(let reply) = value {
                for (replyKey, replyValue) in reply where replyKey == .text("arg") {
                    if case .bytes(let arg) = replyValue {
                        return arg
                    }
                }
            }
        }
        return nil
    }

    public static func decodeRejectMessage(_ data: Data) -> String? {
        guard case .map(let top)? = unwrapTag(decode(data)),
              top.contains(where: { $0.0 == .text("status") && $0.1 == .text("rejected") }) else {
            return nil
        }
        for (key, value) in top where key == .text("reject_message") {
            switch value {
            case .text(let message):
                return message
            case .bytes(let data):
                return String(data: data, encoding: .utf8)
            default:
                return nil
            }
        }
        return "IC request rejected."
    }

    public static func certificateStatusArg(from readStateData: Data, requestId: Data) throws -> Result<Data?, Error>? {
        guard case .bytes(let certificateData)? = mapValue(readStateData, key: "certificate"),
              case .map(let certificate)? = unwrapTag(decode(certificateData)),
              let tree = certificate.first(where: { $0.0 == .text("tree") })?.1 else {
            throw ICClientError.invalidResponse("read_state certificate")
        }
        // This mirrors the extracted app behavior: read_state is trusted
        // as an update-completion signal and BLS certificate verification is not
        // performed here. Callers that need certified reads must add verification.
        return certificateStatusArg(fromCertificateTree: tree, requestId: requestId)
    }

    public static func certificateStatusArg(fromCertificateTree tree: Value, requestId: Data) -> Result<Data?, Error>? {
        guard case .array = tree else {
            return nil
        }

        let statusPath = [Data("request_status".utf8), requestId, Data("status".utf8)]
        guard let statusData = lookup(statusPath, in: tree),
              let status = String(data: statusData, encoding: .utf8) else {
            return .success(nil)
        }
        switch status {
        case "replied":
            let replyPath = [Data("request_status".utf8), requestId, Data("reply".utf8)]
            return .success(lookup(replyPath, in: tree))
        case "received", "processing", "unknown":
            return .success(nil)
        case "rejected":
            let messagePath = [Data("request_status".utf8), requestId, Data("reject_message".utf8)]
            let message = lookup(messagePath, in: tree).flatMap { String(data: $0, encoding: .utf8) } ?? "IC update rejected."
            return .failure(ICClientError.rejected(message))
        default:
            return .failure(ICClientError.invalidResponse("read_state request status"))
        }
    }

    public static func mapValue(_ data: Data, key: String) -> Value? {
        guard let value = decode(data) else { return nil }
        return mapValue(value, key: key)
    }

    public static func mapValue(_ value: Value, key: String) -> Value? {
        guard case .map(let values) = unwrapTag(value) else { return nil }
        return values.first { $0.0 == .text(key) }?.1
    }

    public static func lookup(_ path: [Data], in tree: Value) -> Data? {
        switch tree {
        case .tagged(_, let value):
            return lookup(path, in: value)
        case .array(let values):
            guard let nodeType = values.first else { return nil }
            switch nodeType {
            case .unsigned(1):
                guard values.count == 3 else { return nil }
                return lookup(path, in: values[1]) ?? lookup(path, in: values[2])
            case .unsigned(2):
                guard values.count == 3, case .bytes(let label) = values[1], path.first == label else { return nil }
                return lookup(Array(path.dropFirst()), in: values[2])
            case .unsigned(3):
                guard path.isEmpty, values.count == 2, case .bytes(let data) = values[1] else { return nil }
                return data
            default:
                return nil
            }
        default:
            return nil
        }
    }

    private static func unwrapTag(_ value: Value?) -> Value? {
        guard case .tagged(_, let nested)? = value else {
            return value
        }
        return unwrapTag(nested)
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
        case .unsigned(let value):
            appendHeader(0, count: value, to: &data)
        case .array(let values):
            appendHeader(4, count: UInt64(values.count), to: &data)
            values.forEach { append($0, to: &data) }
        case .map(let values):
            appendHeader(5, count: UInt64(values.count), to: &data)
            values.forEach {
                append($0.0, to: &data)
                append($0.1, to: &data)
            }
        case .tagged(let tag, let value):
            appendHeader(6, count: tag, to: &data)
            append(value, to: &data)
        }
    }

    private static func appendHeader(_ major: UInt8, count: UInt64, to data: inout Data) {
        let base = major << 5
        switch count {
        case 0..<24:
            data.append(base | UInt8(count))
        case 24...UInt64(UInt8.max):
            data.append(base | 24)
            data.append(UInt8(count))
        case 256...UInt64(UInt16.max):
            data.append(base | 25)
            data.append(contentsOf: UInt16(count).bigEndianBytes)
        case 65_536...UInt64(UInt32.max):
            data.append(base | 26)
            data.append(contentsOf: UInt32(count).bigEndianBytes)
        default:
            data.append(base | 27)
            data.append(contentsOf: count.bigEndianBytes)
        }
    }

    private struct Reader {
        var data: Data
        var index = 0

        mutating func read() -> Value? {
            guard index < data.count else { return nil }
            let first = data[data.index(data.startIndex, offsetBy: index)]
            index += 1
            let major = first >> 5
            let info = first & 0x1f
            if info == 31 {
                return readIndefinite(major: major)
            }
            guard let count = readCount(info) else { return nil }
            switch major {
            case 0:
                return .unsigned(count)
            case 2:
                guard count <= UInt64(Int.max) else { return nil }
                guard let bytes = readData(Int(count)) else { return nil }
                return .bytes(bytes)
            case 3:
                guard count <= UInt64(Int.max) else { return nil }
                guard let bytes = readData(Int(count)), let text = String(data: bytes, encoding: .utf8) else { return nil }
                return .text(text)
            case 4:
                var values: [Value] = []
                for _ in 0..<count {
                    guard let value = read() else { return nil }
                    values.append(value)
                }
                return .array(values)
            case 5:
                var values: [(Value, Value)] = []
                for _ in 0..<count {
                    guard let key = read(), let value = read() else { return nil }
                    values.append((key, value))
                }
                return .map(values)
            case 6:
                guard let value = read() else { return nil }
                return .tagged(count, value)
            default:
                return nil
            }
        }

        private mutating func readIndefinite(major: UInt8) -> Value? {
            switch major {
            case 4:
                var values: [Value] = []
                while !isBreak() {
                    guard let value = read() else { return nil }
                    values.append(value)
                }
                index += 1
                return .array(values)
            case 5:
                var values: [(Value, Value)] = []
                while !isBreak() {
                    guard let key = read(), let value = read() else { return nil }
                    values.append((key, value))
                }
                index += 1
                return .map(values)
            default:
                return nil
            }
        }

        private func isBreak() -> Bool {
            index < data.count && data[data.index(data.startIndex, offsetBy: index)] == 0xff
        }

        private mutating func readCount(_ info: UInt8) -> UInt64? {
            switch info {
            case 0..<24:
                return UInt64(info)
            case 24:
                guard let value = readUInt8() else { return nil }
                return UInt64(value)
            case 25:
                return readInteger(byteCount: 2)
            case 26:
                return readInteger(byteCount: 4)
            case 27:
                return readInteger(byteCount: 8)
            default:
                return nil
            }
        }

        private mutating func readUInt8() -> UInt8? {
            guard index < data.count else { return nil }
            defer { index += 1 }
            return data[data.index(data.startIndex, offsetBy: index)]
        }

        private mutating func readInteger(byteCount: Int) -> UInt64? {
            guard index + byteCount <= data.count else { return nil }
            var value: UInt64 = 0
            let start = data.index(data.startIndex, offsetBy: index)
            let end = data.index(start, offsetBy: byteCount)
            for byte in data[start..<end] {
                value = (value << 8) | UInt64(byte)
            }
            index += byteCount
            return value
        }

        private mutating func readData(_ count: Int) -> Data? {
            guard index + count <= data.count else { return nil }
            let start = data.index(data.startIndex, offsetBy: index)
            let end = data.index(start, offsetBy: count)
            defer { index += count }
            return Data(data[start..<end])
        }
    }
}
