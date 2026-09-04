import Foundation

public struct CandidEncoder: Sendable {
    public init() {}

    public func encode(_ arguments: CandidArguments) throws -> Data {
        try Binary.checkCollection(arguments.values.count)
        let values = try arguments.values.map {
            try CandidTypedValue(type: Candid.normalized($0.type), value: $0.value)
        }
        var tableBuilder = EncoderTypeTable()
        let references = try values.map { try tableBuilder.reference(for: $0.type, bindings: [:], depth: 0) }
        let table = try tableBuilder.finalized()

        var output = Data("DIDL".utf8)
        Binary.appendULEB(UInt64(table.count), to: &output)
        for definition in table { definition.append(to: &output) }
        Binary.appendULEB(UInt64(values.count), to: &output)
        for reference in references { Binary.appendSLEB(reference, to: &output) }
        for (index, value) in values.enumerated() {
            do { try append(value.value, as: value.type, to: &output, depth: 0, bindings: [:]) }
            catch { throw Candid.contextual(error, "argument \(index)") }
        }
        return output
    }

    private func append(
        _ value: CandidValue,
        as type: CandidType,
        to output: inout Data,
        depth: Int,
        bindings: [UInt32: CandidType]
    ) throws {
        guard depth <= CandidLimits.maximumDepth else { throw ICClientError.invalidCandid("value nesting exceeds limit") }
        switch (type, value) {
        case (.null, .null): break
        case (.bool, .bool(let value)): output.append(value ? 1 : 0)
        case (.nat, .nat(let value)): output.append(contentsOf: BigLEB.unsigned(value.decimal))
        case (.int, .int(let value)): output.append(contentsOf: BigLEB.signed(value.decimal))
        case (.nat8, .nat8(let value)): output.append(value)
        case (.nat16, .nat16(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.nat32, .nat32(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.nat64, .nat64(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.int8, .int8(let value)): output.append(UInt8(bitPattern: value))
        case (.int16, .int16(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.int32, .int32(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.int64, .int64(let value)): Binary.appendLittleEndian(value, to: &output)
        case (.float32, .float32(let value)): Binary.appendLittleEndian(value.bitPattern, to: &output)
        case (.float64, .float64(let value)): Binary.appendLittleEndian(value.bitPattern, to: &output)
        case (.text, .text(let value)):
            let bytes = Data(value.utf8)
            try Binary.checkCollection(bytes.count)
            Binary.appendULEB(UInt64(bytes.count), to: &output)
            output.append(bytes)
        case (.principal, .principal(let value)):
            output.append(1)
            Binary.appendULEB(UInt64(value.bytes.count), to: &output)
            output.append(value.bytes)
        case (.vector(.nat8), .blob(let value)):
            try Binary.checkCollection(value.count)
            Binary.appendULEB(UInt64(value.count), to: &output)
            output.append(value)
        case (.optional(let child), .optional(_, let value)):
            if let value {
                output.append(1)
                try append(value, as: child, to: &output, depth: depth + 1, bindings: bindings)
            } else {
                output.append(0)
            }
        case (.vector(let child), .vector(_, let values)):
            try Binary.checkCollection(values.count)
            Binary.appendULEB(UInt64(values.count), to: &output)
            for value in values { try append(value, as: child, to: &output, depth: depth + 1, bindings: bindings) }
        case (.record(let fields), .record(_, let values)):
            for field in fields { try append(values[field.id]!, as: field.type, to: &output, depth: depth + 1, bindings: bindings) }
        case (.variant(let fields), .variant(let variant)):
            guard let index = fields.firstIndex(where: { $0.id == variant.tag }) else {
                throw ICClientError.invalidCandid("variant tag \(variant.tag) is not declared")
            }
            Binary.appendULEB(UInt64(index), to: &output)
            try append(variant.value, as: fields[index].type, to: &output, depth: depth + 1, bindings: bindings)
        case (.recursive(let id, let body), _):
            var nestedBindings = bindings
            nestedBindings[id] = body
            try append(value, as: body, to: &output, depth: depth, bindings: nestedBindings)
        case (.reference(let id), _):
            guard let body = bindings[id] else {
                throw ICClientError.invalidCandid("unbound recursive type reference \(id)")
            }
            try append(value, as: body, to: &output, depth: depth + 1, bindings: bindings)
        default:
            throw ICClientError.invalidCandid("value does not match declared type")
        }
    }
}

private enum EncoderDefinition {
    case optional(Int64), vector(Int64)
    case record([(UInt32, Int64)]), variant([(UInt32, Int64)])

    func append(to output: inout Data) {
        switch self {
        case .optional(let child):
            Binary.appendSLEB(-18, to: &output)
            Binary.appendSLEB(child, to: &output)
        case .vector(let child):
            Binary.appendSLEB(-19, to: &output)
            Binary.appendSLEB(child, to: &output)
        case .record(let fields), .variant(let fields):
            if case .record = self { Binary.appendSLEB(-20, to: &output) }
            else { Binary.appendSLEB(-21, to: &output) }
            Binary.appendULEB(UInt64(fields.count), to: &output)
            for (id, type) in fields {
                Binary.appendULEB(UInt64(id), to: &output)
                Binary.appendSLEB(type, to: &output)
            }
        }
    }
}

private struct EncoderTypeTable {
    private var definitions: [EncoderDefinition?] = []
    private var structuralIndices: [CandidType: Int] = [:]

    mutating func reference(
        for rawType: CandidType,
        bindings: [UInt32: Int],
        depth: Int
    ) throws -> Int64 {
        guard depth <= CandidLimits.maximumDepth else {
            throw ICClientError.invalidCandid("type nesting exceeds limit")
        }
        let type = try Candid.normalized(rawType)
        if let primitive = type.primitiveCode { return primitive }
        if case .reference(let id) = type {
            guard let index = bindings[id] else {
                throw ICClientError.invalidCandid("unbound recursive type reference \(id)")
            }
            return Int64(index)
        }
        if let existing = structuralIndices[type] { return Int64(existing) }

        let index = try reserve()
        if type.freeRecursiveReferences.isEmpty { structuralIndices[type] = index }
        if case .recursive(let id, let body) = type {
            structuralIndices[type] = index
            var nestedBindings = bindings
            nestedBindings[id] = index
            definitions[index] = try definition(for: body, bindings: nestedBindings, depth: depth)
        } else {
            definitions[index] = try definition(for: type, bindings: bindings, depth: depth)
        }
        return Int64(index)
    }

    func finalized() throws -> [EncoderDefinition] {
        try definitions.enumerated().map { index, definition in
            guard let definition else {
                throw ICClientError.invalidCandid("incomplete recursive type definition at index \(index)")
            }
            return definition
        }
    }

    private mutating func reserve() throws -> Int {
        guard definitions.count < CandidLimits.maximumTypeTableEntries else {
            throw ICClientError.invalidCandid("type table exceeds limit")
        }
        definitions.append(nil)
        return definitions.count - 1
    }

    private mutating func definition(
        for type: CandidType,
        bindings: [UInt32: Int],
        depth: Int
    ) throws -> EncoderDefinition {
        switch type {
        case .optional(let child):
            return .optional(try reference(for: child, bindings: bindings, depth: depth + 1))
        case .vector(let child):
            return .vector(try reference(for: child, bindings: bindings, depth: depth + 1))
        case .record(let fields):
            return .record(try fields.map {
                ($0.id, try reference(for: $0.type, bindings: bindings, depth: depth + 1))
            })
        case .variant(let fields):
            return .variant(try fields.map {
                ($0.id, try reference(for: $0.type, bindings: bindings, depth: depth + 1))
            })
        case .recursive:
            throw ICClientError.invalidCandid("recursive binding must contain a composite type")
        case .reference(let id):
            throw ICClientError.invalidCandid("recursive reference \(id) cannot define a type-table entry")
        default:
            throw ICClientError.invalidCandid("primitive type cannot define a type-table entry")
        }
    }
}

public struct CandidDecoder: Sendable {
    public init() {}

    public func decode(_ data: Data) throws -> CandidReply {
        var reader = Binary.Reader(data)
        guard try reader.readData(count: 4) == Data("DIDL".utf8) else {
            throw ICClientError.invalidCandid("missing DIDL header")
        }
        let tableCount = try reader.readCount(context: "type table")
        guard tableCount <= CandidLimits.maximumTypeTableEntries else {
            throw ICClientError.invalidCandid("type table exceeds limit")
        }
        var wireTable: [WireType] = []
        wireTable.reserveCapacity(tableCount)
        for index in 0..<tableCount {
            wireTable.append(try readDefinition(from: &reader, index: index))
        }
        try validateReferences(in: wireTable)
        var cache: [Int: CandidType] = [:]
        let valueCount = try reader.readCount(context: "value list")
        try Binary.checkCollection(valueCount)
        var references: [Int64] = []
        references.reserveCapacity(valueCount)
        for _ in 0..<valueCount { references.append(try reader.readSLEB64()) }

        let types = try references.map { try resolve($0, table: wireTable, cache: &cache, stack: [], depth: 0) }
        var values: [CandidTypedValue] = []
        values.reserveCapacity(types.count)
        for (index, type) in types.enumerated() {
            do {
                let value = try readValue(of: type, from: &reader, depth: 0)
                values.append(try CandidTypedValue(type: type, value: value))
            } catch {
                throw Candid.contextual(error, "reply value \(index)")
            }
        }
        guard reader.isAtEnd else { throw ICClientError.invalidCandid("trailing bytes after value list") }
        return CandidReply(values: values)
    }

    private func readDefinition(from reader: inout Binary.Reader, index: Int) throws -> WireType {
        switch try reader.readSLEB64() {
        case -18: return .optional(try reader.readSLEB64())
        case -19: return .vector(try reader.readSLEB64())
        case -20: return .record(try readFields(from: &reader, context: "record type \(index)"))
        case -21: return .variant(try readFields(from: &reader, context: "variant type \(index)"))
        default: throw ICClientError.invalidCandid("invalid type-table constructor at index \(index)")
        }
    }

    private func readFields(from reader: inout Binary.Reader, context: String) throws -> [(UInt32, Int64)] {
        let count = try reader.readCount(context: context)
        try Binary.checkCollection(count)
        var fields: [(UInt32, Int64)] = []
        fields.reserveCapacity(count)
        var previous: UInt32?
        for _ in 0..<count {
            let rawID = try reader.readULEB64()
            guard rawID <= UInt64(UInt32.max) else { throw ICClientError.invalidCandid("\(context) field ID exceeds uint32") }
            let id = UInt32(rawID)
            if let previous, id <= previous { throw ICClientError.invalidCandid("\(context) field IDs are not strictly ascending") }
            fields.append((id, try reader.readSLEB64()))
            previous = id
        }
        return fields
    }

    private func validateReferences(in table: [WireType]) throws {
        for definition in table {
            for reference in definition.references {
                if reference < 0 {
                    guard CandidType(primitiveCode: reference) != nil else {
                        throw ICClientError.invalidCandid("unknown primitive type code \(reference)")
                    }
                } else if reference > Int64(Int.max) || !table.indices.contains(Int(reference)) {
                    throw ICClientError.invalidCandid("type reference \(reference) is out of range")
                }
            }
        }
    }

    private func resolve(
        _ reference: Int64,
        table: [WireType],
        cache: inout [Int: CandidType],
        stack: Set<Int>,
        depth: Int
    ) throws -> CandidType {
        guard depth <= CandidLimits.maximumDepth else { throw ICClientError.invalidCandid("type nesting exceeds limit") }
        if reference < 0 {
            guard let type = CandidType(primitiveCode: reference) else {
                throw ICClientError.invalidCandid("unknown primitive type code \(reference)")
            }
            return type
        }
        guard reference <= Int64(Int.max), table.indices.contains(Int(reference)) else {
            throw ICClientError.invalidCandid("type reference \(reference) is out of range")
        }
        let index = Int(reference)
        if stack.contains(index) {
            return .reference(UInt32(index))
        }
        if let cached = cache[index] { return cached }
        var nextStack = stack
        nextStack.insert(index)
        let result: CandidType
        switch table[index] {
        case .optional(let child):
            result = .optional(try resolve(child, table: table, cache: &cache, stack: nextStack, depth: depth + 1))
        case .vector(let child):
            result = .vector(try resolve(child, table: table, cache: &cache, stack: nextStack, depth: depth + 1))
        case .record(let fields):
            result = .record(try fields.map { CandidField(id: $0.0, type: try resolve($0.1, table: table, cache: &cache, stack: nextStack, depth: depth + 1)) })
        case .variant(let fields):
            result = .variant(try fields.map { CandidField(id: $0.0, type: try resolve($0.1, table: table, cache: &cache, stack: nextStack, depth: depth + 1)) })
        }
        let resolved: CandidType
        if result.freeRecursiveReferences.contains(UInt32(index)) {
            resolved = .recursive(id: UInt32(index), body: result)
        } else {
            resolved = result
        }
        if resolved.freeRecursiveReferences.isEmpty { cache[index] = resolved }
        return resolved
    }

    private func readValue(
        of type: CandidType,
        from reader: inout Binary.Reader,
        depth: Int,
        bindings: [UInt32: CandidType] = [:]
    ) throws -> CandidValue {
        guard depth <= CandidLimits.maximumDepth else { throw ICClientError.invalidCandid("value nesting exceeds limit") }
        switch type {
        case .null: return .null
        case .bool:
            let byte = try reader.readByte()
            guard byte <= 1 else { throw ICClientError.invalidCandid("bool must be 0 or 1") }
            return .bool(byte == 1)
        case .nat: return .nat(try CandidNat(BigLEB.decodeUnsigned(try reader.readLEBBytes())))
        case .int: return .int(try CandidInt(BigLEB.decodeSigned(try reader.readLEBBytes())))
        case .nat8: return .nat8(try reader.readByte())
        case .nat16: return .nat16(try reader.readLittleEndian())
        case .nat32: return .nat32(try reader.readLittleEndian())
        case .nat64: return .nat64(try reader.readLittleEndian())
        case .int8: return .int8(Int8(bitPattern: try reader.readByte()))
        case .int16: return .int16(try reader.readLittleEndian())
        case .int32: return .int32(try reader.readLittleEndian())
        case .int64: return .int64(try reader.readLittleEndian())
        case .float32: return .float32(Float(bitPattern: try reader.readLittleEndian()))
        case .float64: return .float64(Double(bitPattern: try reader.readLittleEndian()))
        case .text:
            let bytes = try reader.readData(count: reader.readCount(context: "text"))
            guard let text = String(data: bytes, encoding: .utf8) else { throw ICClientError.invalidCandid("text is not UTF-8") }
            return .text(text)
        case .principal:
            guard try reader.readByte() == 1 else { throw ICClientError.invalidCandid("principal reference marker must be 1") }
            let bytes = try reader.readData(count: reader.readCount(context: "principal"))
            guard bytes.count <= 29 else { throw ICClientError.invalidCandid("principal exceeds 29 bytes") }
            return .principal(try CandidPrincipal(ICPrincipal.text(from: bytes)))
        case .optional(let child):
            let marker = try reader.readByte()
            guard marker <= 1 else { throw ICClientError.invalidCandid("optional marker must be 0 or 1") }
            return .optional(child, marker == 0 ? nil : try readValue(of: child, from: &reader, depth: depth + 1, bindings: bindings))
        case .vector(.nat8):
            return .blob(try reader.readData(count: reader.readCount(context: "blob")))
        case .vector(let child):
            let count = try reader.readCount(context: "vector")
            var values: [CandidValue] = []
            values.reserveCapacity(count)
            for index in 0..<count {
                do { values.append(try readValue(of: child, from: &reader, depth: depth + 1, bindings: bindings)) }
                catch { throw Candid.contextual(error, "vector element \(index)") }
            }
            return .vector(child, values)
        case .record(let fields):
            var values: [UInt32: CandidValue] = [:]
            for field in fields {
                do { values[field.id] = try readValue(of: field.type, from: &reader, depth: depth + 1, bindings: bindings) }
                catch { throw Candid.contextual(error, "record field \(field.id)") }
            }
            return .record(fields, values)
        case .variant(let fields):
            let index = try reader.readCount(context: "variant index")
            guard fields.indices.contains(index) else { throw ICClientError.invalidCandid("variant index \(index) is out of range") }
            let field = fields[index]
            do {
                return .variant(try CandidVariant(
                    fields: fields,
                    tag: field.id,
                    value: readValue(of: field.type, from: &reader, depth: depth + 1, bindings: bindings)
                ))
            } catch {
                throw Candid.contextual(error, "variant tag \(field.id)")
            }
        case .recursive(let id, let body):
            var nestedBindings = bindings
            nestedBindings[id] = body
            return try readValue(of: body, from: &reader, depth: depth, bindings: nestedBindings)
        case .reference(let id):
            guard let body = bindings[id] else {
                throw ICClientError.invalidCandid("unbound recursive type reference \(id)")
            }
            return try readValue(of: body, from: &reader, depth: depth + 1, bindings: bindings)
        }
    }
}

private indirect enum WireType {
    case optional(Int64), vector(Int64)
    case record([(UInt32, Int64)]), variant([(UInt32, Int64)])
}

private extension WireType {
    var references: [Int64] {
        switch self {
        case .optional(let reference), .vector(let reference): return [reference]
        case .record(let fields), .variant(let fields): return fields.map(\.1)
        }
    }
}

private enum CandidLimits {
    static let maximumDepth = 100
    static let maximumTypeTableEntries = 10_000
    static let maximumCollectionElements = Candid.maximumCollectionElements
    static let maximumLEBBytes = 5_000
}

private extension CandidType {
    init?(primitiveCode: Int64) {
        switch primitiveCode {
        case -1: self = .null; case -2: self = .bool; case -3: self = .nat; case -4: self = .int
        case -5: self = .nat8; case -6: self = .nat16; case -7: self = .nat32; case -8: self = .nat64
        case -9: self = .int8; case -10: self = .int16; case -11: self = .int32; case -12: self = .int64
        case -13: self = .float32; case -14: self = .float64; case -15: self = .text; case -24: self = .principal
        default: return nil
        }
    }

    var primitiveCode: Int64? {
        switch self {
        case .null: -1; case .bool: -2; case .nat: -3; case .int: -4
        case .nat8: -5; case .nat16: -6; case .nat32: -7; case .nat64: -8
        case .int8: -9; case .int16: -10; case .int32: -11; case .int64: -12
        case .float32: -13; case .float64: -14; case .text: -15; case .principal: -24
        default: nil
        }
    }

    var isRecord: Bool { if case .record = self { true } else { false } }

    var freeRecursiveReferences: Set<UInt32> {
        switch self {
        case .optional(let child), .vector(let child):
            return child.freeRecursiveReferences
        case .record(let fields), .variant(let fields):
            return fields.reduce(into: Set<UInt32>()) { $0.formUnion($1.type.freeRecursiveReferences) }
        case .recursive(let id, let body):
            return body.freeRecursiveReferences.subtracting([id])
        case .reference(let id):
            return [id]
        default:
            return []
        }
    }
}

private enum Binary {
    static func checkCollection(_ count: Int) throws {
        guard count <= CandidLimits.maximumCollectionElements else {
            throw ICClientError.invalidCandid("collection exceeds limit")
        }
    }

    static func appendULEB(_ input: UInt64, to output: inout Data) {
        var value = input
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            output.append(byte)
        } while value != 0
    }

    static func appendSLEB(_ input: Int64, to output: inout Data) {
        var value = input
        while true {
            var byte = UInt8(truncatingIfNeeded: value) & 0x7f
            value >>= 7
            let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0)
            if !done { byte |= 0x80 }
            output.append(byte)
            if done { return }
        }
    }

    static func appendLittleEndian<T: FixedWidthInteger>(_ input: T, to output: inout Data) {
        var value = input.littleEndian
        withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
    }

    struct Reader {
        let data: Data
        var offset = 0
        var isAtEnd: Bool { offset == data.count }

        init(_ data: Data) { self.data = data }

        mutating func readByte() throws -> UInt8 {
            guard offset < data.count else { throw ICClientError.invalidCandid("unexpected end of input") }
            defer { offset += 1 }
            return data[offset]
        }

        mutating func readData(count: Int) throws -> Data {
            guard count >= 0, count <= CandidLimits.maximumCollectionElements,
                  offset <= data.count - count else { throw ICClientError.invalidCandid("truncated or oversized value") }
            defer { offset += count }
            return data.subdata(in: offset..<(offset + count))
        }

        mutating func readLEBBytes() throws -> [UInt8] {
            var bytes: [UInt8] = []
            repeat {
                guard bytes.count < CandidLimits.maximumLEBBytes else { throw ICClientError.invalidCandid("LEB128 exceeds limit") }
                let byte = try readByte()
                bytes.append(byte)
                if byte & 0x80 == 0 { return bytes }
            } while true
        }

        mutating func readULEB64() throws -> UInt64 {
            let bytes = try readLEBBytes()
            var value: UInt64 = 0
            for (index, byte) in bytes.enumerated() {
                guard index < 10, index < 9 || byte & 0x7e == 0 else { throw ICClientError.invalidCandid("ULEB128 overflows uint64") }
                value |= UInt64(byte & 0x7f) << (7 * index)
            }
            var canonical = Data(); Binary.appendULEB(value, to: &canonical)
            guard Array(canonical) == bytes else { throw ICClientError.invalidCandid("non-canonical ULEB128") }
            return value
        }

        mutating func readSLEB64() throws -> Int64 {
            let bytes = try readLEBBytes()
            guard bytes.count <= 10 else { throw ICClientError.invalidCandid("SLEB128 overflows int64") }
            var value: Int64 = 0
            for (index, byte) in bytes.enumerated() where index < 9 {
                value |= Int64(byte & 0x7f) << (7 * index)
            }
            if bytes.count == 10 {
                let last = bytes[9] & 0x7f
                guard last == 0 || last == 0x7f else { throw ICClientError.invalidCandid("SLEB128 overflows int64") }
                if last == 0x7f { value |= Int64.min }
            } else if let last = bytes.last, last & 0x40 != 0 {
                value |= -1 << (7 * bytes.count)
            }
            var canonical = Data(); Binary.appendSLEB(value, to: &canonical)
            guard Array(canonical) == bytes else { throw ICClientError.invalidCandid("non-canonical SLEB128") }
            return value
        }

        mutating func readCount(context: String) throws -> Int {
            let value = try readULEB64()
            guard value <= UInt64(CandidLimits.maximumCollectionElements) else {
                throw ICClientError.invalidCandid("\(context) exceeds limit")
            }
            return Int(value)
        }

        mutating func readLittleEndian<T: FixedWidthInteger>() throws -> T {
            let bytes = try readData(count: MemoryLayout<T>.size)
            return bytes.withUnsafeBytes { raw in
                var bits: T.Magnitude = 0
                for (index, byte) in raw.enumerated() { bits |= T.Magnitude(byte) << (8 * index) }
                return T(truncatingIfNeeded: bits)
            }
        }
    }
}

private struct BigUnsigned: Equatable, Comparable {
    private static let base: UInt64 = 1_000_000_000
    var limbs: [UInt32]

    init(decimal: String) {
        limbs = [0]
        for character in decimal {
            multiply(by: 10)
            add(UInt32(character.wholeNumberValue!))
        }
        normalize()
    }

    init(_ value: UInt32 = 0) { limbs = [value] }
    var isZero: Bool { limbs.count == 1 && limbs[0] == 0 }

    static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.limbs.count != rhs.limbs.count { return lhs.limbs.count < rhs.limbs.count }
        for index in lhs.limbs.indices.reversed() where lhs.limbs[index] != rhs.limbs[index] {
            return lhs.limbs[index] < rhs.limbs[index]
        }
        return false
    }

    mutating func add(_ value: UInt32) {
        var carry = UInt64(value), index = 0
        while carry != 0 {
            if index == limbs.count { limbs.append(0) }
            let sum = UInt64(limbs[index]) + carry
            limbs[index] = UInt32(sum % Self.base)
            carry = sum / Self.base
            index += 1
        }
    }

    mutating func multiply(by value: UInt32) {
        var carry: UInt64 = 0
        for index in limbs.indices {
            let product = UInt64(limbs[index]) * UInt64(value) + carry
            limbs[index] = UInt32(product % Self.base)
            carry = product / Self.base
        }
        if carry != 0 { limbs.append(UInt32(carry)) }
        normalize()
    }

    mutating func divide(by value: UInt32) -> UInt32 {
        var remainder: UInt64 = 0
        for index in limbs.indices.reversed() {
            let current = remainder * Self.base + UInt64(limbs[index])
            limbs[index] = UInt32(current / UInt64(value))
            remainder = current % UInt64(value)
        }
        normalize()
        return UInt32(remainder)
    }

    mutating func subtract(_ other: Self) {
        var borrow: Int64 = 0
        for index in limbs.indices {
            let rhs = index < other.limbs.count ? Int64(other.limbs[index]) : 0
            var value = Int64(limbs[index]) - rhs - borrow
            if value < 0 { value += Int64(Self.base); borrow = 1 } else { borrow = 0 }
            limbs[index] = UInt32(value)
        }
        normalize()
    }

    var decimal: String {
        var result = String(limbs.last!)
        for limb in limbs.dropLast().reversed() {
            result += String(repeating: "0", count: 9 - String(limb).count) + String(limb)
        }
        return result
    }

    private mutating func normalize() {
        while limbs.count > 1 && limbs.last == 0 { limbs.removeLast() }
    }
}

private enum BigLEB {
    static func unsigned(_ decimal: String) -> [UInt8] {
        var number = BigUnsigned(decimal: decimal)
        var bytes: [UInt8] = []
        repeat {
            let remainder = UInt8(number.divide(by: 128))
            bytes.append(remainder | (number.isZero ? 0 : 0x80))
        } while !number.isZero
        return bytes
    }

    static func signed(_ decimal: String) -> [UInt8] {
        guard decimal.first == "-" else {
            var bytes = unsigned(decimal)
            if bytes.last! & 0x40 != 0 { bytes[bytes.count - 1] |= 0x80; bytes.append(0) }
            return bytes
        }
        var magnitude = BigUnsigned(decimal: String(decimal.dropFirst()))
        var bytes: [UInt8] = []
        while true {
            let remainder = magnitude.divide(by: 128)
            if remainder != 0 { magnitude.add(1) }
            var byte = UInt8(remainder == 0 ? 0 : 128 - remainder)
            let done = magnitude == BigUnsigned(1) && byte & 0x40 != 0
            if !done { byte |= 0x80 }
            bytes.append(byte)
            if done { return bytes }
        }
    }

    static func decodeUnsigned(_ bytes: [UInt8]) throws -> String {
        var value = BigUnsigned()
        for byte in bytes.reversed() { value.multiply(by: 128); value.add(UInt32(byte & 0x7f)) }
        guard unsigned(value.decimal) == bytes else { throw ICClientError.invalidCandid("non-canonical unsigned LEB128") }
        return value.decimal
    }

    static func decodeSigned(_ bytes: [UInt8]) throws -> String {
        var unsignedValue = BigUnsigned()
        for byte in bytes.reversed() { unsignedValue.multiply(by: 128); unsignedValue.add(UInt32(byte & 0x7f)) }
        let negative = bytes.last! & 0x40 != 0
        let decimal: String
        if negative {
            var power = BigUnsigned(1)
            for _ in bytes { power.multiply(by: 128) }
            guard power >= unsignedValue else { throw ICClientError.invalidCandid("invalid signed LEB128") }
            power.subtract(unsignedValue)
            decimal = "-" + power.decimal
        } else {
            decimal = unsignedValue.decimal
        }
        guard signed(decimal) == bytes else { throw ICClientError.invalidCandid("non-canonical signed LEB128") }
        return decimal
    }
}
