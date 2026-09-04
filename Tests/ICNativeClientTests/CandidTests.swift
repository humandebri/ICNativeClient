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

    func testCandidNullConvertibleAndVariantPayload() throws {
        let null = CandidNull()
        try assertFixture(
            "4449444c00017f",
            values: [try CandidTypedValue(null)]
        )

        let reply = try CandidDecoder().decode(CandidArguments(null).encode())
        XCTAssertEqual(try reply.decode(CandidNull.self), null)
        XCTAssertThrowsError(try CandidNull(candidValue: .bool(false))) { error in
            XCTAssertEqual(error as? ICClientError, .invalidCandid("expected null"))
        }

        let fields = [
            CandidField("ok", type: .null),
            CandidField("err", type: .text),
        ]
        let value = try CandidTypedValue(
            type: .variant(fields),
            value: .variant(try CandidVariant(fields: fields, tag: "ok", value: .null))
        )
        let variantReply = try CandidDecoder().decode(CandidArguments([value]).encode())
        guard case .variant(let variant) = variantReply.values.first?.value else {
            return XCTFail("expected a variant")
        }
        XCTAssertEqual(variant.tag, Candid.fieldID("ok"))
        XCTAssertEqual(variant.value, .null)
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

    func testConvertibleRecordOptionalArrayAndReplyContext() throws {
        let person = Person(name: "Ada", age: 42, nickname: nil)
        let roundTrip = try CandidDecoder().decode(CandidArguments(person).encode())
        XCTAssertEqual(try roundTrip.decode(Person.self), person)

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
        XCTAssertThrowsError(try roundTrip.decode(String.self)) { error in
            XCTAssertTrue(String(describing: error).contains("reply value 0"))
        }
        XCTAssertThrowsError(try CandidRecord(person.candidValue).required("missing", as: String.self)) { error in
            XCTAssertTrue(String(describing: error).contains(String(Candid.fieldID("missing"))))
        }

        let extra = CandidField("future", type: .bool)
        let recordWithUnknownField = CandidValue.record(Person.fields + [extra], [
            Candid.fieldID("name"): .text("Ada"),
            Candid.fieldID("age"): .nat8(42),
            Candid.fieldID("nickname"): .optional(.text, nil),
            extra.id: .bool(true),
        ])
        XCTAssertEqual(try Person(candidValue: recordWithUnknownField), person)

        let recordMissingAge = CandidValue.record(Person.fields, [
            Candid.fieldID("name"): .text("Ada"),
            Candid.fieldID("nickname"): .optional(.text, nil),
        ])
        XCTAssertThrowsError(try Person(candidValue: recordMissingAge))
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

    func testRejectsMalformedCanonicalReferenceFieldVariantAndLimits() throws {
        for hex in [
            "5849444c0000",             // malformed header
            "4449444c00017d8000",       // non-canonical nat zero
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

private struct Person: CandidConvertible, Equatable {
    let name: String
    let age: UInt8
    let nickname: String?

    static let fields = [
        CandidField("name", type: String.candidType),
        CandidField("age", type: UInt8.candidType),
        CandidField("nickname", type: Optional<String>.candidType),
    ]
    static let candidType = CandidType.record(fields)

    init(name: String, age: UInt8, nickname: String?) {
        self.name = name
        self.age = age
        self.nickname = nickname
    }

    init(candidValue: CandidValue) throws {
        let record = try CandidRecord(candidValue)
        name = try record.required("name")
        age = try record.required("age")
        nickname = try record.required("nickname")
    }

    var candidValue: CandidValue {
        .record(Self.fields, [
            Candid.fieldID("name"): name.candidValue,
            Candid.fieldID("age"): age.candidValue,
            Candid.fieldID("nickname"): nickname.candidValue,
        ])
    }
}
