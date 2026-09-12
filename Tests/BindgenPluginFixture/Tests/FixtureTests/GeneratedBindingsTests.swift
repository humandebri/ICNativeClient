@testable import Fixture
import ICNativeClient
import XCTest

final class GeneratedBindingsTests: XCTestCase {
    private func decode<T: CandidConvertible>(
        _ typedValue: CandidTypedValue,
        as type: T.Type
    ) throws -> T {
        try CandidReply(values: [typedValue]).decode(type)
    }

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
        let entry = try decode(
            CandidTypedValue(type: .record(expandedEntryFields), value: expandedEntry),
            as: FixtureEntry.self
        )
        XCTAssertEqual(entry.id, 42)
        XCTAssertEqual(entry.label, "compatible")

        let vector = try decode(
            CandidTypedValue(
                type: .vector(.record(expandedEntryFields)),
                value: .vector(.record(expandedEntryFields), [expandedEntry])
            ),
            as: [FixtureEntry].self
        )
        XCTAssertEqual(vector.map(\.label), ["compatible"])

        let optional = try decode(
            CandidTypedValue(type: .record(expandedEntryFields), value: expandedEntry),
            as: FixtureEntry?.self
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
        let recursive = try decode(
            CandidTypedValue(
                type: .recursive(id: recursiveID, body: .record(recursiveFields)),
                value: recursiveValue
            ),
            as: FixtureRecursiveRecord.self
        )
        XCTAssertEqual(recursive.value, "root")
        XCTAssertNil(recursive.next)
    }

    func testGeneratedDecoderRejectsVariantExpansionChangesAndMissingRequiredRecordFields() throws {
        let expandedVariantFields = [
            CandidField(id: Candid.fieldID("ok"), type: .null),
            CandidField(id: Candid.fieldID("err"), type: .text),
            CandidField(id: Candid.fieldID("future"), type: .null),
        ]
        XCTAssertThrowsError(try decode(
            CandidTypedValue(
                type: .variant(expandedVariantFields),
                value: .variant(try CandidVariant(
                    fields: expandedVariantFields,
                    tag: Candid.fieldID("ok"),
                    value: .null
                ))
            ),
            as: FixtureStoreResult.self
        ))

        let changedVariantFields = [
            CandidField(id: Candid.fieldID("ok"), type: .null),
            CandidField(id: Candid.fieldID("err"), type: .nat64),
        ]
        XCTAssertThrowsError(try decode(
            CandidTypedValue(
                type: .variant(changedVariantFields),
                value: .variant(try CandidVariant(
                    fields: changedVariantFields,
                    tag: Candid.fieldID("err"),
                    value: .nat64(1)
                ))
            ),
            as: FixtureStoreResult.self
        ))

        let labelID = Candid.fieldID("label")
        let missingRequiredFields = [CandidField(id: labelID, type: .text)]
        XCTAssertThrowsError(try decode(
            CandidTypedValue(
                type: .record(missingRequiredFields),
                value: .record(missingRequiredFields, [labelID: .text("missing")])
            ),
            as: FixtureEntry.self
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
        guard case .end = try decode(
            matching,
            as: FixtureChain.self
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
            try decode(
                different,
                as: FixtureChain.self
            )
        )
    }
}
