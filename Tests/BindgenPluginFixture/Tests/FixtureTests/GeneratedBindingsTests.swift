@testable import Fixture
import ICNativeClient
import XCTest

final class GeneratedBindingsTests: XCTestCase {
    func testGeneratedRecordAndVariantRoundTrip() throws {
        let entry = FixtureEntry(id: 42, label: "generated")
        let entryReply = try CandidDecoder().decode(CandidArguments(entry).encode())
        let decodedEntry = try entryReply.decode(FixtureEntry.self)
        XCTAssertEqual(decodedEntry.id, 42)
        XCTAssertEqual(decodedEntry.label, "generated")

        let result = FixtureStoreResult.err(value: "rejected")
        let resultReply = try CandidDecoder().decode(CandidArguments(result).encode())
        guard case .err(let message) = try resultReply.decode(FixtureStoreResult.self) else {
            return XCTFail("expected err variant")
        }
        XCTAssertEqual(message, "rejected")

        let chain = FixtureChain.next(value: .end)
        let chainReply = try CandidDecoder().decode(CandidArguments(chain).encode())
        guard case .next(let next) = try chainReply.decode(FixtureChain.self) else {
            return XCTFail("expected next variant")
        }
        guard case .some(.end) = next else {
            return XCTFail("expected recursive end variant")
        }
    }

    func testContainerDeclarationsAreValidatedWhenEmpty() throws {
        let optionalTextID = Candid.fieldID("optional_text")
        let textsID = Candid.fieldID("texts")
        let fields = [
            CandidField(id: optionalTextID, type: .optional(.text)),
            CandidField(id: textsID, type: .vector(.text)),
        ]

        XCTAssertThrowsError(try FixtureContainers(candidValue: .record(fields, [
            optionalTextID: .optional(.nat64, nil),
            textsID: .vector(.text, []),
        ])))
        XCTAssertThrowsError(try FixtureContainers(candidValue: .record(fields, [
            optionalTextID: .optional(.text, nil),
            textsID: .vector(.nat64, []),
        ])))
    }

    func testGeneratedDecoderAcceptsDirectionalRecordVectorOptionalAndRecursiveSubtypes() throws {
        let id = Candid.fieldID("id")
        let label = Candid.fieldID("label")
        let future = Candid.fieldID("future")
        let expandedEntryFields = [
            CandidField(id: id, type: .nat64),
            CandidField(id: label, type: .text),
            CandidField(id: future, type: .bool),
        ]
        let expandedEntry = CandidValue.record(expandedEntryFields, [
            id: .nat64(42),
            label: .text("compatible"),
            future: .bool(true),
        ])
        let entry = try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(type: .record(expandedEntryFields), value: expandedEntry),
            as: FixtureEntry.self,
            context: "record"
        )
        XCTAssertEqual(entry.id, 42)
        XCTAssertEqual(entry.label, "compatible")

        let vector = try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(
                type: .vector(.record(expandedEntryFields)),
                value: .vector(.record(expandedEntryFields), [expandedEntry])
            ),
            as: [FixtureEntry].self,
            context: "vector"
        )
        XCTAssertEqual(vector.map(\.label), ["compatible"])

        let optional = try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(type: .record(expandedEntryFields), value: expandedEntry),
            as: FixtureEntry?.self,
            context: "optional"
        )
        XCTAssertEqual(optional?.id, 42)

        let recursiveID: UInt32 = 99
        let recursiveFields = [
            CandidField(id: Candid.fieldID("value"), type: .text),
            CandidField(id: Candid.fieldID("next"), type: .optional(.reference(recursiveID))),
            CandidField(id: future, type: .bool),
        ]
        let recursiveValue = CandidValue.record(recursiveFields, [
            Candid.fieldID("value"): .text("root"),
            Candid.fieldID("next"): .optional(.reference(recursiveID), nil),
            future: .bool(true),
        ])
        let recursive = try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(
                type: .recursive(id: recursiveID, body: .record(recursiveFields)),
                value: recursiveValue
            ),
            as: FixtureRecursiveRecord.self,
            context: "recursive record"
        )
        XCTAssertEqual(recursive.value, "root")
        XCTAssertNil(recursive.next)
    }

    func testGeneratedDecoderSupportsNumericAndOptionalCandidSubtypes() throws {
        XCTAssertEqual(
            try SelfCanister._ICBindgenSupport.decode(
                CandidTypedValue(type: .nat64, value: .nat64(42)),
                as: CandidInt.self,
                context: "numeric"
            ).decimal,
            "42"
        )
        XCTAssertEqual(
            try SelfCanister._ICBindgenSupport.decode(
                CandidTypedValue(type: .nat8, value: .nat8(42)),
                as: UInt64?.self,
                context: "optional numeric"
            ),
            42
        )
        XCTAssertNil(try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(type: .text, value: .text("not a nat")),
            as: UInt64?.self,
            context: "optional fallback"
        ))
        XCTAssertNil(try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(type: .optional(.text), value: .optional(.text, .text("not a nat"))),
            as: UInt64?.self,
            context: "optional nested fallback"
        ))
    }

    func testGeneratedDecoderRejectsVariantExpansionChangesAndMissingRequiredRecordFields() throws {
        let expandedVariantFields = [
            CandidField(id: Candid.fieldID("ok"), type: .null),
            CandidField(id: Candid.fieldID("err"), type: .text),
            CandidField(id: Candid.fieldID("future"), type: .null),
        ]
        XCTAssertThrowsError(try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(
                type: .variant(expandedVariantFields),
                value: .variant(try CandidVariant(
                    fields: expandedVariantFields,
                    tag: Candid.fieldID("ok"),
                    value: .null
                ))
            ),
            as: FixtureStoreResult.self,
            context: "expanded variant"
        ))

        let changedVariantFields = [
            CandidField(id: Candid.fieldID("ok"), type: .null),
            CandidField(id: Candid.fieldID("err"), type: .nat64),
        ]
        XCTAssertThrowsError(try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(
                type: .variant(changedVariantFields),
                value: .variant(try CandidVariant(
                    fields: changedVariantFields,
                    tag: Candid.fieldID("err"),
                    value: .nat64(1)
                ))
            ),
            as: FixtureStoreResult.self,
            context: "changed variant payload"
        ))

        let missingID = Candid.fieldID("id")
        let labelID = Candid.fieldID("label")
        let missingRequiredFields = [CandidField(id: labelID, type: .text)]
        XCTAssertThrowsError(try SelfCanister._ICBindgenSupport.decode(
            CandidTypedValue(
                type: .record(missingRequiredFields),
                value: .record(missingRequiredFields, [labelID: .text("missing")])
            ),
            as: FixtureEntry.self,
            context: "missing record field \(missingID)"
        ))
    }

    func testRecursiveTypedDecodeIgnoresBinderIDsButRejectsDifferentShapes() throws {
        let endID = Candid.fieldID("end")
        let nextID = Candid.fieldID("next")
        let matchingFields = [
            CandidField(id: endID, type: .null),
            CandidField(id: nextID, type: .optional(.reference(77))),
        ]
        let matching = try CandidTypedValue(
            type: .recursive(id: 77, body: .variant(matchingFields)),
            value: .variant(CandidVariant(fields: matchingFields, tag: endID, value: .null))
        )
        guard case .end = try SelfCanister._ICBindgenSupport.decode(
            matching,
            as: FixtureChain.self,
            context: "test"
        ) else {
            return XCTFail("expected recursive end variant")
        }

        let differentFields = [
            CandidField(id: endID, type: .null),
            CandidField(id: nextID, type: .optional(.text)),
        ]
        let different = try CandidTypedValue(
            type: .recursive(id: 88, body: .variant(differentFields)),
            value: .variant(CandidVariant(fields: differentFields, tag: endID, value: .null))
        )
        XCTAssertThrowsError(
            try SelfCanister._ICBindgenSupport.decode(
                different,
                as: FixtureChain.self,
                context: "test"
            )
        )
    }
}
