import Foundation
import XCTest
@testable import ICNativeClient

final class CandidTests: XCTestCase {
    func testEmptyAndMultipleValueBoundaries() throws {
        let emptyFixture = data("4449444c0000")
        XCTAssertEqual(try CandidArguments().encode(), emptyFixture)
        XCTAssertEqual(try CandidDecoder().decode(emptyFixture).values, [])

        let reply = try CandidDecoder().decode(CandidArguments([
            try CandidTypedValue("one"),
            try CandidTypedValue(UInt64(2)),
        ]).encode())
        let values: (String, UInt64) = try reply.decode(String.self, UInt64.self)
        XCTAssertEqual(values.0, "one")
        XCTAssertEqual(values.1, 2)
        XCTAssertEqual(Candid.fieldID("name"), 1_224_700_491)
    }

    func testReplyDecodingUsesCandidTupleAndNumericSubtyping() throws {
        let reply = CandidReply(values: [
            try typed(.nat, .nat(CandidNat("42"))),
            try CandidTypedValue("ignored"),
        ])
        XCTAssertEqual(try reply.decode(CandidInt.self).decimal, "42")
        XCTAssertNil(try reply.decode(UInt64?.self, at: 2))
        XCTAssertEqual(try reply.decode(CandidNull.self, at: 2), CandidNull())
        XCTAssertThrowsError(try reply.decode(String.self, at: 2))

        XCTAssertThrowsError(try CandidReply(values: [CandidTypedValue(UInt8(1))]).decode(UInt16.self))
        XCTAssertNil(try CandidReply(values: [CandidTypedValue("not a nat")]).decode(UInt64?.self))
        XCTAssertNil(try CandidReply(values: [CandidTypedValue(Optional("not a nat"))]).decode(UInt64?.self))
    }

    func testReplyDecodingNormalizesExpectedVariantFieldOrder() throws {
        let fields = [
            CandidField(id: 1, type: .text),
            CandidField(id: 2, type: .null),
        ]
        let value = try CandidTypedValue(
            type: .variant(fields),
            value: .variant(CandidVariant(fields: fields, tag: 1, value: .text("ok")))
        )

        XCTAssertEqual(
            try CandidReply(values: [value]).decode(UnsortedVariant.self),
            .text("ok")
        )
    }

    func testRecordProjectionFillsMissingNullableFieldsAroundRetainedFields() throws {
        struct Record: CandidConvertible {
            static var candidType: CandidType { .record([
                CandidField(id: 8, type: .optional(.text)),
                CandidField(id: 6, type: .nat64),
                CandidField(id: 4, type: .null),
                CandidField(id: 3, type: .optional(.text)),
                CandidField(id: 2, type: .nat64),
            ]) }
            let candidValue: CandidValue
            init(candidValue: CandidValue) { self.candidValue = candidValue }
        }
        let fields = [CandidField(id: 6, type: .nat64), CandidField(id: 1, type: .bool), CandidField(id: 2, type: .nat64)]
        let value = try CandidTypedValue(type: .record(fields), value: .record(fields, [
            6: .nat64(60), 1: .bool(true), 2: .nat64(20),
        ]))
        let result = try CandidReply(values: [value]).decode(Record.self)
        guard case .record(_, let values) = result.candidValue else { return XCTFail("expected record") }
        XCTAssertEqual(values, [2: .nat64(20), 3: .optional(.text, nil), 4: .null, 6: .nat64(60), 8: .optional(.text, nil)])
    }

    func testCandidNullConvertible() throws {
        let encoded = try CandidArguments(CandidNull()).encode()
        XCTAssertEqual(encoded, data("4449444c00017f"))
        XCTAssertEqual(try CandidDecoder().decode(encoded).decode(CandidNull.self), CandidNull())
        XCTAssertThrowsError(try CandidNull(candidValue: .bool(false))) { error in
            guard case ICClientError.invalidCandid = error else { return XCTFail("expected invalid Candid") }
        }
    }

    func testDidcPrimitiveArbitraryIntegerBlobAndEmptyCompositeFixtures() throws {
        try assertFixture(
            "4449444c00047c7c7c7cff00800140bf7f",
            values: [
                typed(.int, .int(try CandidInt("127"))),
                typed(.int, .int(try CandidInt("128"))),
                typed(.int, .int(try CandidInt("-64"))),
                typed(.int, .int(try CandidInt("-65"))),
            ]
        )
        try assertFixture(
            "4449444c016d7b0100020102",
            values: [typed(.vector(.nat8), .blob(Data([1, 2])))]
        )
        try assertFixture(
            "4449444c026e716d7a0200010000",
            values: [
                typed(.optional(.text), .optional(.text, nil)),
                typed(.vector(.nat16), .vector(.nat16, [])),
            ]
        )

        let huge = "12345678901234567890123456789012345678901234567890"
        let hugeNegative = "-" + huge
        try assertFixture(
            "4449444c00027d7cd295fcf1ecb2fce3f8f5d1b382aaa89ef8d5a69bf6cf9c04aeea838e93cd839c878aaeccfdd5d7e187aad9e489b0e37b",
            values: [
                typed(.nat, .nat(try CandidNat(huge))),
                typed(.int, .int(try CandidInt(hugeNegative))),
            ]
        )

        let fixedValues: [CandidTypedValue] = [
            try CandidTypedValue(UInt8.max), try CandidTypedValue(UInt16.max),
            try CandidTypedValue(UInt32.max), try CandidTypedValue(UInt64.max),
            try CandidTypedValue(Int8.min), try CandidTypedValue(Int16.min),
            try CandidTypedValue(Int32.min), try CandidTypedValue(Int64.min),
            try CandidTypedValue(Float.pi), try CandidTypedValue(Double.pi),
        ]
        XCTAssertEqual(
            try CandidDecoder().decode(CandidArguments(fixedValues).encode()),
            CandidReply(values: fixedValues)
        )
    }

    func testDidcRecordVariantPrincipalAndSharedTypeFixtures() throws {
        let recordFields = [CandidField("name", type: .text), CandidField("age", type: .nat8)]
        let recordValues: [UInt32: CandidValue] = [
            Candid.fieldID("name"): .text("Ada"),
            Candid.fieldID("age"): .nat8(42),
        ]
        let ok = CandidField("ok", type: .text)
        try assertFixture(
            "4449444c026c02bfe9a7027bcbe4fdc704716b019cc201710200012a034164610003796573",
            values: [
                typed(.record(recordFields), .record(recordFields, recordValues)),
                typed(.variant([ok]), .variant(try CandidVariant(fields: [ok], tag: "ok", value: .text("yes")))),
            ]
        )

        let variantFields = [CandidField("err", type: .nat), CandidField("ok", type: .text)]
        try assertFixture(
            "4449444c016b029cc20171e58eb4027d01000003796573",
            values: [typed(
                .variant(variantFields),
                .variant(try CandidVariant(fields: variantFields, tag: "ok", value: .text("yes")))
            )]
        )

        let sharedFields = [CandidField("left", type: .vector(.text)), CandidField("right", type: .vector(.text))]
        try assertFixture(
            "4449444c026c028790c0bd0401dc9790cb0e016d71010000010178",
            values: [typed(.record(sharedFields), .record(sharedFields, [
                Candid.fieldID("left"): .vector(.text, []),
                Candid.fieldID("right"): .vector(.text, [.text("x")]),
            ]))]
        )

        let principal = try CandidPrincipal("aaaaa-aa")
        XCTAssertEqual(try CandidPrincipal("AAAAA-AA").text, "aaaaa-aa")
        let reply = try CandidDecoder().decode(CandidArguments([typed(.principal, .principal(principal))]).encode())
        XCTAssertEqual(reply.values.first?.value, .principal(principal))
    }

    func testConvertibleArraysAndDecodeErrorContext() throws {
        let list: [UInt16] = [0, 42, .max]
        XCTAssertEqual(
            try CandidDecoder().decode(CandidArguments(list).encode()).decode([UInt16].self),
            list
        )
        let bytes: [UInt8] = [0, 1, 127, 255]
        XCTAssertEqual(
            try CandidDecoder().decode(CandidArguments(bytes).encode()).decode([UInt8].self),
            bytes
        )
        XCTAssertThrowsError(try CandidReply(values: [CandidTypedValue(UInt8(42))]).decode(String.self)) { error in
            XCTAssertTrue(String(describing: error).contains("reply value 0"))
        }
        XCTAssertThrowsError(try CandidRecord(.record([], [:])).required("missing", as: String.self)) { error in
            XCTAssertTrue(String(describing: error).contains(String(Candid.fieldID("missing"))))
        }

    }

    func testDecodesFiniteValuesWithRecursiveWireTypes() throws {
        let nilFixture = data("4449444c026e016c02a0d2aca8047d90eddae70400010000")
        let nilList = try CandidDecoder().decode(nilFixture)
        guard case .optional(_, nil) = nilList.values.first?.value else {
            return XCTFail("expected an empty recursive list")
        }
        XCTAssertEqual(try CandidEncoder().encode(CandidArguments(nilList.values)), nilFixture)

        let oneItemFixture = data("4449444c026e016c02a0d2aca8047d90eddae704000100010100")
        let oneItemList = try CandidDecoder().decode(oneItemFixture)
        guard case .optional(_, let item?) = oneItemList.values.first?.value else {
            return XCTFail("expected a recursive list item")
        }
        let record = try CandidRecord(item)
        XCTAssertEqual(try record.required("head", as: CandidNat.self).decimal, "1")
        let tail: CandidValue? = record.fields[Candid.fieldID("tail")]
        guard case .optional(_, nil) = tail else { return XCTFail("expected an empty tail") }
        XCTAssertEqual(try CandidEncoder().encode(CandidArguments(oneItemList.values)), oneItemFixture)
    }

    func testRejectsMalformedReferenceFieldVariantAndLimits() throws {
        for hex in [
            "5849444c0000",             // malformed header
            "4449444c000100",           // type reference outside an empty table
            "4449444c016c02017b017b00", // duplicate record field ID
            "4449444c016c02027b017b00", // descending record field ID
            "4449444c016b01017f010001", // variant index out of range
            "4449444c00017e02",         // invalid bool
            "4449444c00016800",         // invalid principal marker
            "4449444c000001",           // trailing byte
        ] {
            XCTAssertThrowsError(try CandidDecoder().decode(data(hex)), "accepted malformed fixture \(hex)")
        }

        let fields = [CandidField(id: 1, type: .text), CandidField(id: 1, type: .nat)]
        XCTAssertThrowsError(try CandidTypedValue(type: .record(fields), value: .record(fields, [1: .text("x")])))
        XCTAssertThrowsError(try CandidTypedValue(type: .vector(.text), value: .vector(.text, [.nat8(1)])))

        var oversized = Data("DIDL".utf8)
        oversized.append(contentsOf: [0x81, 0x80, 0x80, 0x80, 0x01])
        XCTAssertThrowsError(try CandidDecoder().decode(oversized))

        var deepType = CandidType.text
        var deepValue = CandidValue.text("x")
        for _ in 0...CandidLimitsForTests.maximumDepth {
            deepValue = .optional(deepType, deepValue)
            deepType = .optional(deepType)
        }
        XCTAssertThrowsError(try CandidArguments([CandidTypedValue(type: deepType, value: deepValue)]).encode())

        XCTAssertThrowsError(try CandidNat(String(repeating: "1", count: 10_001)))
        XCTAssertThrowsError(try CandidInt(String(repeating: "1", count: 10_001)))

        XCTAssertThrowsError(try CandidDecoder().decode(data("4449444c016c01017e010002"))) { error in
            XCTAssertTrue(String(describing: error).contains("record field 1"))
        }
        XCTAssertThrowsError(try CandidDecoder().decode(data("4449444c016b01017e01000002"))) { error in
            XCTAssertTrue(String(describing: error).contains("variant tag 1"))
        }
    }

    func testDecodesDataSlicesAndRejectsTruncatedSlices() throws {
        let encoded = try CandidArguments("hello").encode()
        let framed = Data([0xaa, 0xbb]) + encoded + Data([0xcc])
        let slice = framed.dropFirst(2).dropLast()
        XCTAssertEqual(try CandidDecoder().decode(slice).decode(String.self), "hello")
        XCTAssertThrowsError(try CandidDecoder().decode(slice.dropLast()))
        XCTAssertThrowsError(try CandidDecoder().decode(slice.prefix(3)))
    }

    func testAcceptsPaddedLEB128AndReencodesCanonically() throws {
        // Cross-checked with candid 0.10.35. Padding is allowed on the wire.
        let fixtures = [
            ("4449444c80008000", "4449444c0000"),
            ("4449444c0001fd7f8000", "4449444c00017d00"),
            ("4449444c00017d8100", "4449444c00017d01"),
            ("4449444c00017cff7f", "4449444c00017c7f"),
            ("4449444c00017c8000", "4449444c00017c00"),
            ("4449444c016c0180007f018000", "4449444c016c01007f0100"),
            ("4449444c000171810061", "4449444c0001710161"),
        ]
        for (padded, canonical) in fixtures {
            let reply = try CandidDecoder().decode(data(padded))
            XCTAssertEqual(try CandidArguments(reply.values).encode(), data(canonical))
        }
        for hex in [
            "4449444c80", // Unterminated structural integer.
            "4449444c00017d80", // Unterminated nat.
            "4449444c" + String(repeating: "80", count: 9) + "02", // UInt64 overflow.
            "4449444c0001" + String(repeating: "80", count: 9) + "01", // Int64 overflow.
            "4449444c" + String(repeating: "80", count: 10) + "00", // Structural length limit.
            "4449444c00017d" + String(repeating: "80", count: 5_000) + "00",
        ] {
            XCTAssertThrowsError(try CandidDecoder().decode(data(hex)))
        }
        for value in [Int64.min, Int64.max] {
            let reply = try CandidDecoder().decode(CandidArguments(CandidInt(String(value))).encode())
            XCTAssertEqual(try reply.decode(CandidInt.self).decimal, String(value))
        }
        XCTAssertEqual(
            try CandidDecoder().decode(CandidArguments(CandidNat(String(UInt64.max))).encode()).decode(CandidNat.self).decimal,
            String(UInt64.max)
        )
    }

    func testDecodingBudgetStopsSharedTypeExpansion() throws {
        XCTAssertNoThrow(try CandidDecoder().decode(sharedTypeFixture(depth: 10)))
        XCTAssertThrowsError(try CandidDecoder().decode(sharedTypeFixture(depth: 40))) { error in
            XCTAssertTrue(String(describing: error).contains("decoding work limit exceeded"))
        }
    }

    func testDecodingBudgetIsSharedAcrossReplyValues() throws {
        // Each smaller reply fits; resetting the budget per value must not let their combined work through.
        func nulls(_ count: UInt64) -> Data {
            Data("DIDL".utf8) + Data([0]) + ICRequestID.leb128(count)
                + Data(repeating: 0x7f, count: Int(count))
        }
        XCTAssertEqual(try CandidDecoder().decode(nulls(10), budget: CandidDecodingBudget(maximumWork: 100)).values.count, 10)
        XCTAssertThrowsError(try CandidDecoder().decode(nulls(20), budget: CandidDecodingBudget(maximumWork: 100))) { error in
            XCTAssertTrue(String(describing: error).contains("decoding work limit exceeded"))
        }
        let blob = Data(repeating: 0x55, count: 1_000_000)
        XCTAssertEqual(try CandidDecoder().decode(CandidArguments(blob).encode()).decode(Data.self), blob)
    }

    func testCachedTypesStillEnforceDepthLimit() throws {
        func nestedTypes(_ count: Int) -> Data {
            func reference(_ value: Int) -> Data {
                value < 64 ? Data([UInt8(value)]) : Data([UInt8(value) | 0x80, 0])
            }
            var bytes = Data("DIDL".utf8) + ICRequestID.leb128(UInt64(count))
            for index in 0..<count {
                bytes.append(0x6e)
                bytes.append(index == 0 ? Data([0x7f]) : reference(index - 1))
            }
            bytes.append(ICRequestID.leb128(UInt64(count)))
            for index in 0..<count { bytes.append(reference(index)) }
            bytes.append(Data(repeating: 0, count: count))
            return bytes
        }
        XCTAssertNoThrow(try CandidDecoder().decode(nestedTypes(100)))
        XCTAssertThrowsError(try CandidDecoder().decode(nestedTypes(101))) { error in
            XCTAssertTrue(String(describing: error).contains("type nesting exceeds limit"))
        }
    }

    private func sharedTypeFixture(depth: Int) -> Data {
        var bytes = Data("DIDL".utf8)
        bytes.append(contentsOf: [UInt8(depth + 2), 0x6e, 1])
        for index in 1...depth {
            bytes.append(contentsOf: [0x6c, 2, 0, UInt8(index + 1), 1, UInt8(index + 1)])
        }
        bytes.append(contentsOf: [0x6c, 0, 1, 0, 0])
        return bytes
    }

    private func typed(_ type: CandidType, _ value: CandidValue) throws -> CandidTypedValue {
        try CandidTypedValue(type: type, value: value)
    }

    private func assertFixture(_ hex: String, values: [CandidTypedValue]) throws {
        let fixture = data(hex)
        let encoded = try CandidEncoder().encode(CandidArguments(values))
        let encodedHex = encoded.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(encoded, fixture, "encoded: \(encodedHex)")
        XCTAssertEqual(try CandidDecoder().decode(fixture), CandidReply(values: values))
    }

    private func data(_ hex: String) -> Data {
        Data(stride(from: 0, to: hex.count, by: 2).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
        })
    }
}

private enum CandidLimitsForTests {
    static let maximumDepth = 100
}

private enum UnsortedVariant: CandidConvertible, Equatable {
    case text(String)
    case empty

    static let candidType = CandidType.variant([
        CandidField(id: 2, type: .null),
        CandidField(id: 1, type: .text),
    ])

    init(candidValue: CandidValue) throws {
        guard case .variant(let variant) = candidValue else {
            throw ICClientError.invalidCandid("expected variant")
        }
        switch variant.tag {
        case 1:
            self = .text(try String(candidValue: variant.value))
        case 2:
            self = .empty
        default:
            throw ICClientError.invalidCandid("unexpected variant tag")
        }
    }

    var candidValue: CandidValue {
        switch self {
        case .text(let value):
            return .variant(try! CandidVariant(fields: Self.fields, tag: 1, value: .text(value)))
        case .empty:
            return .variant(try! CandidVariant(fields: Self.fields, tag: 2, value: .null))
        }
    }

    private static let fields = [
        CandidField(id: 1, type: .text),
        CandidField(id: 2, type: .null),
    ]
}
