import Foundation

public indirect enum CandidType: Hashable, Sendable {
    case null, bool, nat, int
    case nat8, nat16, nat32, nat64
    case int8, int16, int32, int64
    case float32, float64, text, principal
    case optional(CandidType)
    case vector(CandidType)
    case record([CandidField])
    case variant([CandidField])
    /// Binds `id` within `body`. Produced by the decoder for recursive wire types.
    case recursive(id: UInt32, body: CandidType)
    /// Refers to the nearest enclosing recursive binding with the same ID.
    case reference(UInt32)
}

public struct CandidField: Hashable, Sendable {
    public let id: UInt32
    public let type: CandidType

    public init(id: UInt32, type: CandidType) {
        self.id = id
        self.type = type
    }

    public init(_ name: String, type: CandidType) {
        self.init(id: Candid.fieldID(name), type: type)
    }
}

public struct CandidNat: Hashable, Sendable {
    public let decimal: String

    public init(_ decimal: String) throws {
        guard decimal.utf8.count <= Candid.maximumIntegerDecimalDigits, Self.isCanonical(decimal) else {
            throw ICClientError.invalidCandid("nat is not a canonical unsigned decimal: \(decimal)")
        }
        self.decimal = decimal
    }

    private static func isCanonical(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }) else { return false }
        return value == "0" || value.first != "0"
    }
}

public struct CandidInt: Hashable, Sendable {
    public let decimal: String

    public init(_ decimal: String) throws {
        let magnitude = decimal.first == "-" ? String(decimal.dropFirst()) : decimal
        guard magnitude.utf8.count <= Candid.maximumIntegerDecimalDigits,
              !magnitude.isEmpty,
              magnitude.utf8.allSatisfy({ (48...57).contains($0) }),
              magnitude == "0" || magnitude.first != "0",
              decimal != "-0" else {
            throw ICClientError.invalidCandid("int is not a canonical signed decimal: \(decimal)")
        }
        self.decimal = decimal
    }
}

public struct CandidPrincipal: Hashable, Sendable {
    public let text: String

    public init(_ text: String) throws {
        guard let bytes = ICPrincipal.parse(text) else {
            throw ICClientError.invalidCandid("invalid principal: \(text)")
        }
        self.text = ICPrincipal.text(from: bytes)
    }

    var bytes: Data { ICPrincipal.parse(text)! }
}

public struct CandidVariant: Equatable, Sendable {
    public let fields: [CandidField]
    public let tag: UInt32
    public let value: CandidValue

    public init(fields: [CandidField], tag: UInt32, value: CandidValue) throws {
        self.fields = try Candid.normalized(fields, context: "variant")
        guard self.fields.contains(where: { $0.id == tag }) else {
            throw ICClientError.invalidCandid("variant tag \(tag) is not declared")
        }
        self.tag = tag
        self.value = value
    }

    public init(fields: [CandidField], tag: String, value: CandidValue) throws {
        try self.init(fields: fields, tag: Candid.fieldID(tag), value: value)
    }
}

public indirect enum CandidValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case nat(CandidNat)
    case int(CandidInt)
    case nat8(UInt8), nat16(UInt16), nat32(UInt32), nat64(UInt64)
    case int8(Int8), int16(Int16), int32(Int32), int64(Int64)
    case float32(Float), float64(Double)
    case text(String)
    case blob(Data)
    case principal(CandidPrincipal)
    case optional(CandidType, CandidValue?)
    case vector(CandidType, [CandidValue])
    case record([CandidField], [UInt32: CandidValue])
    case variant(CandidVariant)
}

public struct CandidTypedValue: Equatable, Sendable {
    public let type: CandidType
    public let value: CandidValue

    public init(type: CandidType, value: CandidValue) throws {
        try Candid.validate(value, as: type, context: "value")
        self.type = try Candid.normalized(type)
        self.value = try Candid.normalized(value)
    }

    public init<T: CandidConvertible>(_ value: T) throws {
        try self.init(type: T.candidType, value: value.candidValue)
    }
}

public struct CandidArguments: Equatable, Sendable {
    public let values: [CandidTypedValue]

    public init(_ values: [CandidTypedValue] = []) {
        self.values = values
    }

    public init<T: CandidConvertible>(_ value: T) throws {
        self.values = [try CandidTypedValue(value)]
    }

    public func encode() throws -> Data {
        try CandidEncoder().encode(self)
    }
}

public struct CandidReply: Equatable, Sendable {
    public let values: [CandidTypedValue]

    public init(values: [CandidTypedValue]) {
        self.values = values
    }

    public func decode<T: CandidConvertible>(_ type: T.Type = T.self, at index: Int = 0) throws -> T {
        guard values.indices.contains(index) else {
            throw ICClientError.invalidCandid("reply value \(index) is missing")
        }
        do {
            return try T(candidValue: values[index].value)
        } catch {
            throw Candid.contextual(error, "reply value \(index)")
        }
    }

    public func decode<A: CandidConvertible, B: CandidConvertible>(
        _ first: A.Type = A.self,
        _ second: B.Type = B.self
    ) throws -> (A, B) {
        (try decode(first, at: 0), try decode(second, at: 1))
    }
}

public protocol CandidConvertible: Sendable {
    static var candidType: CandidType { get }
    init(candidValue: CandidValue) throws
    var candidValue: CandidValue { get }
}

public struct CandidNull: CandidConvertible, Equatable, Hashable, Sendable {
    public static let candidType: CandidType = .null

    public init() {}

    public init(candidValue: CandidValue) throws {
        guard case .null = candidValue else {
            throw ICClientError.invalidCandid("expected null")
        }
    }

    public var candidValue: CandidValue { .null }
}

public struct CandidRecord: Sendable {
    public let fields: [UInt32: CandidValue]

    public init(_ value: CandidValue) throws {
        guard case .record(_, let fields) = value else {
            throw ICClientError.invalidCandid("expected record")
        }
        self.fields = fields
    }

    public func required<T: CandidConvertible>(_ name: String, as type: T.Type = T.self) throws -> T {
        try required(id: Candid.fieldID(name), as: type)
    }

    public func required<T: CandidConvertible>(id: UInt32, as type: T.Type = T.self) throws -> T {
        guard let value = fields[id] else {
            throw ICClientError.invalidCandid("record field \(id) is missing")
        }
        do {
            return try T(candidValue: value)
        } catch {
            throw Candid.contextual(error, "record field \(id)")
        }
    }

    public func optional<T: CandidConvertible>(_ name: String, as type: T.Type = T.self) throws -> T? {
        try optional(id: Candid.fieldID(name), as: type)
    }

    public func optional<T: CandidConvertible>(id: UInt32, as type: T.Type = T.self) throws -> T? {
        guard let value = fields[id] else { return nil }
        do {
            return try T(candidValue: value)
        } catch {
            throw Candid.contextual(error, "record field \(id)")
        }
    }
}

public enum Candid {
    static let maximumIntegerDecimalDigits = 10_000
    static let maximumCollectionElements = 1_000_000

    public static func fieldID(_ name: String) -> UInt32 {
        name.utf8.reduce(UInt32(0)) { $0 &* 223 &+ UInt32($1) }
    }

    static func normalized(_ type: CandidType) throws -> CandidType {
        switch type {
        case .optional(let child): return .optional(try normalized(child))
        case .vector(let child): return .vector(try normalized(child))
        case .record(let fields): return .record(try normalized(fields, context: "record"))
        case .variant(let fields): return .variant(try normalized(fields, context: "variant"))
        case .recursive(let id, let body): return .recursive(id: id, body: try normalized(body))
        case .reference: return type
        default: return type
        }
    }

    static func normalized(_ fields: [CandidField], context: String) throws -> [CandidField] {
        guard fields.count <= maximumCollectionElements else {
            throw ICClientError.invalidCandid("\(context) fields exceed limit")
        }
        let result = try fields.map { CandidField(id: $0.id, type: try normalized($0.type)) }
            .sorted { $0.id < $1.id }
        for pair in zip(result, result.dropFirst()) where pair.0.id == pair.1.id {
            throw ICClientError.invalidCandid("duplicate \(context) field ID \(pair.0.id)")
        }
        return result
    }

    static func normalized(_ value: CandidValue) throws -> CandidValue {
        switch value {
        case .optional(let type, let item):
            return .optional(try normalized(type), try item.map(normalized))
        case .vector(let type, let items):
            return .vector(try normalized(type), try items.map(normalized))
        case .record(let fields, let values):
            let fields = try normalized(fields, context: "record")
            var result: [UInt32: CandidValue] = [:]
            for (id, value) in values { result[id] = try normalized(value) }
            return .record(fields, result)
        case .variant(let variant):
            return .variant(try CandidVariant(
                fields: variant.fields,
                tag: variant.tag,
                value: normalized(variant.value)
            ))
        default:
            return value
        }
    }

    static func validate(_ value: CandidValue, as type: CandidType, context: String) throws {
        try validate(value, as: type, context: context, bindings: [:], depth: 0)
    }

    private static func validate(
        _ value: CandidValue,
        as type: CandidType,
        context: String,
        bindings: [UInt32: CandidType],
        depth: Int
    ) throws {
        guard depth <= 100 else { throw ICClientError.invalidCandid("\(context): value nesting exceeds limit") }
        let type = try normalized(type)
        switch (type, value) {
        case (.null, .null), (.bool, .bool), (.nat, .nat), (.int, .int),
             (.nat8, .nat8), (.nat16, .nat16), (.nat32, .nat32), (.nat64, .nat64),
             (.int8, .int8), (.int16, .int16), (.int32, .int32), (.int64, .int64),
             (.float32, .float32), (.float64, .float64), (.text, .text),
             (.principal, .principal), (.vector(.nat8), .blob):
            return
        case (.optional(let expected), .optional(let declared, let item)):
            guard try normalized(declared) == expected else { break }
            if let item { try validate(item, as: expected, context: context, bindings: bindings, depth: depth + 1) }
            return
        case (.vector(let expected), .vector(let declared, let items)):
            guard try normalized(declared) == expected else { break }
            guard items.count <= maximumCollectionElements else {
                throw ICClientError.invalidCandid("\(context): vector exceeds limit")
            }
            for (index, item) in items.enumerated() {
                try validate(item, as: expected, context: "\(context) vector element \(index)", bindings: bindings, depth: depth + 1)
            }
            return
        case (.record(let expected), .record(let declared, let values)):
            let actual = try normalized(declared, context: "record")
            guard actual == expected else { break }
            let expectedIDs = Set(expected.map(\.id))
            guard Set(values.keys) == expectedIDs else {
                throw ICClientError.invalidCandid("\(context): record values do not match declared fields")
            }
            for field in expected {
                try validate(values[field.id]!, as: field.type, context: "\(context) record field \(field.id)", bindings: bindings, depth: depth + 1)
            }
            return
        case (.variant(let expected), .variant(let variant)):
            guard variant.fields == expected,
                  let field = expected.first(where: { $0.id == variant.tag }) else { break }
            try validate(variant.value, as: field.type, context: "\(context) variant tag \(variant.tag)", bindings: bindings, depth: depth + 1)
            return
        case (.recursive(let id, let body), _):
            var nestedBindings = bindings
            nestedBindings[id] = body
            try validate(value, as: body, context: context, bindings: nestedBindings, depth: depth)
            return
        case (.reference(let id), _):
            guard let body = bindings[id] else {
                throw ICClientError.invalidCandid("\(context): unbound recursive type reference \(id)")
            }
            try validate(value, as: body, context: context, bindings: bindings, depth: depth + 1)
            return
        default:
            break
        }
        throw ICClientError.invalidCandid("\(context): value does not match declared type \(type)")
    }

    static func contextual(_ error: Error, _ context: String) -> ICClientError {
        if case ICClientError.invalidCandid(let message) = error {
            return .invalidCandid("\(context): \(message)")
        }
        return .invalidCandid("\(context): \(error.localizedDescription)")
    }
}

extension Bool: CandidConvertible {
    public static let candidType: CandidType = .bool
    public init(candidValue: CandidValue) throws {
        guard case .bool(let value) = candidValue else { throw ICClientError.invalidCandid("expected bool") }
        self = value
    }
    public var candidValue: CandidValue { .bool(self) }
}

extension String: CandidConvertible {
    public static let candidType: CandidType = .text
    public init(candidValue: CandidValue) throws {
        guard case .text(let value) = candidValue else { throw ICClientError.invalidCandid("expected text") }
        self = value
    }
    public var candidValue: CandidValue { .text(self) }
}

extension Data: CandidConvertible {
    public static let candidType: CandidType = .vector(.nat8)
    public init(candidValue: CandidValue) throws {
        if case .blob(let value) = candidValue { self = value; return }
        if case .vector(.nat8, let values) = candidValue {
            self = try Data(values.map {
                guard case .nat8(let byte) = $0 else { throw ICClientError.invalidCandid("blob contains a non-nat8 value") }
                return byte
            })
            return
        }
        throw ICClientError.invalidCandid("expected blob")
    }
    public var candidValue: CandidValue { .blob(self) }
}

extension CandidNat: CandidConvertible {
    public static let candidType: CandidType = .nat
    public init(candidValue: CandidValue) throws {
        guard case .nat(let value) = candidValue else { throw ICClientError.invalidCandid("expected nat") }
        self = value
    }
    public var candidValue: CandidValue { .nat(self) }
}

extension CandidInt: CandidConvertible {
    public static let candidType: CandidType = .int
    public init(candidValue: CandidValue) throws {
        guard case .int(let value) = candidValue else { throw ICClientError.invalidCandid("expected int") }
        self = value
    }
    public var candidValue: CandidValue { .int(self) }
}

extension CandidPrincipal: CandidConvertible {
    public static let candidType: CandidType = .principal
    public init(candidValue: CandidValue) throws {
        guard case .principal(let value) = candidValue else { throw ICClientError.invalidCandid("expected principal") }
        self = value
    }
    public var candidValue: CandidValue { .principal(self) }
}

private protocol CandidFixedInteger: FixedWidthInteger, CandidConvertible {
    static func makeValue(_ value: Self) -> CandidValue
    static func extract(_ value: CandidValue) -> Self?
}

extension CandidFixedInteger {
    public init(candidValue: CandidValue) throws {
        guard let value = Self.extract(candidValue) else {
            throw ICClientError.invalidCandid("expected \(Self.candidType)")
        }
        self = value
    }
    public var candidValue: CandidValue { Self.makeValue(self) }
}

extension UInt8: CandidFixedInteger { public static let candidType: CandidType = .nat8; fileprivate static func makeValue(_ value: UInt8) -> CandidValue { .nat8(value) }; fileprivate static func extract(_ v: CandidValue) -> UInt8? { if case .nat8(let x) = v { x } else { nil } } }
extension UInt16: CandidFixedInteger { public static let candidType: CandidType = .nat16; fileprivate static func makeValue(_ value: UInt16) -> CandidValue { .nat16(value) }; fileprivate static func extract(_ v: CandidValue) -> UInt16? { if case .nat16(let x) = v { x } else { nil } } }
extension UInt32: CandidFixedInteger { public static let candidType: CandidType = .nat32; fileprivate static func makeValue(_ value: UInt32) -> CandidValue { .nat32(value) }; fileprivate static func extract(_ v: CandidValue) -> UInt32? { if case .nat32(let x) = v { x } else { nil } } }
extension UInt64: CandidFixedInteger { public static let candidType: CandidType = .nat64; fileprivate static func makeValue(_ value: UInt64) -> CandidValue { .nat64(value) }; fileprivate static func extract(_ v: CandidValue) -> UInt64? { if case .nat64(let x) = v { x } else { nil } } }
extension Int8: CandidFixedInteger { public static let candidType: CandidType = .int8; fileprivate static func makeValue(_ value: Int8) -> CandidValue { .int8(value) }; fileprivate static func extract(_ v: CandidValue) -> Int8? { if case .int8(let x) = v { x } else { nil } } }
extension Int16: CandidFixedInteger { public static let candidType: CandidType = .int16; fileprivate static func makeValue(_ value: Int16) -> CandidValue { .int16(value) }; fileprivate static func extract(_ v: CandidValue) -> Int16? { if case .int16(let x) = v { x } else { nil } } }
extension Int32: CandidFixedInteger { public static let candidType: CandidType = .int32; fileprivate static func makeValue(_ value: Int32) -> CandidValue { .int32(value) }; fileprivate static func extract(_ v: CandidValue) -> Int32? { if case .int32(let x) = v { x } else { nil } } }
extension Int64: CandidFixedInteger { public static let candidType: CandidType = .int64; fileprivate static func makeValue(_ value: Int64) -> CandidValue { .int64(value) }; fileprivate static func extract(_ v: CandidValue) -> Int64? { if case .int64(let x) = v { x } else { nil } } }

extension UInt: CandidConvertible {
    public static let candidType: CandidType = .nat64
    public init(candidValue: CandidValue) throws { self = UInt(try UInt64(candidValue: candidValue)) }
    public var candidValue: CandidValue { .nat64(UInt64(self)) }
}

extension Int: CandidConvertible {
    public static let candidType: CandidType = .int64
    public init(candidValue: CandidValue) throws { self = Int(try Int64(candidValue: candidValue)) }
    public var candidValue: CandidValue { .int64(Int64(self)) }
}

extension Float: CandidConvertible {
    public static let candidType: CandidType = .float32
    public init(candidValue: CandidValue) throws {
        guard case .float32(let value) = candidValue else { throw ICClientError.invalidCandid("expected float32") }
        self = value
    }
    public var candidValue: CandidValue { .float32(self) }
}

extension Double: CandidConvertible {
    public static let candidType: CandidType = .float64
    public init(candidValue: CandidValue) throws {
        guard case .float64(let value) = candidValue else { throw ICClientError.invalidCandid("expected float64") }
        self = value
    }
    public var candidValue: CandidValue { .float64(self) }
}

extension Optional: CandidConvertible where Wrapped: CandidConvertible {
    public static var candidType: CandidType { .optional(Wrapped.candidType) }
    public init(candidValue: CandidValue) throws {
        guard case .optional(let type, let value) = candidValue,
              try Candid.normalized(type) == Candid.normalized(Wrapped.candidType) else {
            throw ICClientError.invalidCandid("expected opt \(Wrapped.candidType)")
        }
        self = try value.map(Wrapped.init(candidValue:))
    }
    public var candidValue: CandidValue { .optional(Wrapped.candidType, self?.candidValue) }
}

extension Array: CandidConvertible where Element: CandidConvertible {
    public static var candidType: CandidType { .vector(Element.candidType) }
    public init(candidValue: CandidValue) throws {
        if case .blob(let bytes) = candidValue, Element.self == UInt8.self {
            self = bytes.map { $0 as! Element }
            return
        }
        guard case .vector(let type, let values) = candidValue,
              try Candid.normalized(type) == Candid.normalized(Element.candidType) else {
            throw ICClientError.invalidCandid("expected vec \(Element.candidType)")
        }
        self = try values.enumerated().map { index, value in
            do { return try Element(candidValue: value) }
            catch { throw Candid.contextual(error, "vector element \(index)") }
        }
    }
    public var candidValue: CandidValue { .vector(Element.candidType, map(\.candidValue)) }
}
