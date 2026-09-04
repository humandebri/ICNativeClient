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
