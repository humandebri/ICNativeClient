import Foundation

enum CandidSubtype {
    static func project(
        _ value: CandidValue,
        actual: CandidType,
        expected: CandidType,
        actualBindings: [UInt32: CandidType] = [:],
        expectedBindings: [UInt32: CandidType] = [:],
        bindings: [UInt32: UInt32] = [:],
        reverseBindings: [UInt32: UInt32] = [:]
    ) throws -> CandidValue? {
        switch (actual, expected) {
        case let (.recursive(actualID, actualBody), .recursive(expectedID, expectedBody)):
            if let bound = bindings[actualID], bound != expectedID { return nil }
            if let bound = reverseBindings[expectedID], bound != actualID { return nil }
            var nestedActualBindings = actualBindings
            var nestedExpectedBindings = expectedBindings
            var nestedBindings = bindings
            var nestedReverseBindings = reverseBindings
            nestedActualBindings[actualID] = actualBody
            nestedExpectedBindings[expectedID] = expectedBody
            nestedBindings[actualID] = expectedID
            nestedReverseBindings[expectedID] = actualID
            return try project(
                value,
                actual: actualBody,
                expected: expectedBody,
                actualBindings: nestedActualBindings,
                expectedBindings: nestedExpectedBindings,
                bindings: nestedBindings,
                reverseBindings: nestedReverseBindings
            )
        case let (.recursive(actualID, actualBody), _):
            var nestedActualBindings = actualBindings
            nestedActualBindings[actualID] = actualBody
            return try project(
                value,
                actual: actualBody,
                expected: expected,
                actualBindings: nestedActualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (_, .recursive(expectedID, expectedBody)):
            var nestedExpectedBindings = expectedBindings
            nestedExpectedBindings[expectedID] = expectedBody
            return try project(
                value,
                actual: actual,
                expected: expectedBody,
                actualBindings: actualBindings,
                expectedBindings: nestedExpectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (.reference(actualID), .reference(expectedID)):
            guard bindings[actualID] == expectedID,
                  reverseBindings[expectedID] == actualID,
                  let actualBody = actualBindings[actualID],
                  let expectedBody = expectedBindings[expectedID] else { return nil }
            return try project(
                value,
                actual: actualBody,
                expected: expectedBody,
                actualBindings: actualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (.reference(actualID), _):
            guard let actualBody = actualBindings[actualID] else { return nil }
            return try project(
                value,
                actual: actualBody,
                expected: expected,
                actualBindings: actualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (_, .reference(expectedID)):
            guard let expectedBody = expectedBindings[expectedID] else { return nil }
            return try project(
                value,
                actual: actual,
                expected: expectedBody,
                actualBindings: actualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (.optional(actualChild), .optional(expectedChild)):
            guard case .optional(_, let item) = value else { return nil }
            guard let item else { return .optional(expectedChild, nil) }
            guard let projected = try project(
                item,
                actual: actualChild,
                expected: expectedChild,
                actualBindings: actualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            ) else {
                return .optional(expectedChild, nil)
            }
            return .optional(expectedChild, projected)
        case let (_, .optional(expectedChild)):
            if case .null = value { return .optional(expectedChild, nil) }
            guard let projected = try project(
                value,
                actual: actual,
                expected: expectedChild,
                actualBindings: actualBindings,
                expectedBindings: expectedBindings,
                bindings: bindings,
                reverseBindings: reverseBindings
            ) else {
                // Candid's special opt rule decodes an incompatible value as null.
                return .optional(expectedChild, nil)
            }
            return .optional(expectedChild, projected)
        case let (.vector(actualChild), .vector(expectedChild)):
            if case .blob = value, actualChild == .nat8, expectedChild == .nat8 { return value }
            guard case .vector(_, let items) = value else { return nil }
            var projected: [CandidValue] = []
            projected.reserveCapacity(items.count)
            for item in items {
                guard let projectedItem = try project(
                    item,
                    actual: actualChild,
                    expected: expectedChild,
                    actualBindings: actualBindings,
                    expectedBindings: expectedBindings,
                    bindings: bindings,
                    reverseBindings: reverseBindings
                ) else { return nil }
                projected.append(projectedItem)
            }
            return .vector(expectedChild, projected)
        case let (.record(actualFields), .record(expectedFields)):
            guard case .record(_, let values) = value else { return nil }
            var projected: [UInt32: CandidValue] = [:]
            for expectedField in expectedFields {
                if let actualField = actualFields.first(where: { $0.id == expectedField.id }),
                   let actualValue = values[expectedField.id] {
                    guard let projectedValue = try project(
                        actualValue,
                        actual: actualField.type,
                        expected: expectedField.type,
                        actualBindings: actualBindings,
                        expectedBindings: expectedBindings,
                        bindings: bindings,
                        reverseBindings: reverseBindings
                    ) else { return nil }
                    projected[expectedField.id] = projectedValue
                } else if case .optional(let child) = expectedField.type {
                    projected[expectedField.id] = .optional(child, nil)
                } else if case .null = expectedField.type {
                    projected[expectedField.id] = .null
                } else {
                    return nil
                }
            }
            return .record(expectedFields, projected)
        case let (.variant(actualFields), .variant(expectedFields)):
            // Generated Swift enums cannot represent added cases or changed payload declarations.
            guard typesEquivalent(actual, expected, bindings: bindings, reverseBindings: reverseBindings),
                  case .variant(let variant) = value,
                  let actualField = actualFields.first(where: { $0.id == variant.tag }),
                  let expectedField = expectedFields.first(where: { $0.id == variant.tag }),
                  let projected = try project(
                      variant.value,
                      actual: actualField.type,
                      expected: expectedField.type,
                      actualBindings: actualBindings,
                      expectedBindings: expectedBindings,
                      bindings: bindings,
                      reverseBindings: reverseBindings
                  ) else { return nil }
            return .variant(try CandidVariant(fields: expectedFields, tag: variant.tag, value: projected))
        default:
            return try projectPrimitive(value, actual: actual, expected: expected)
        }
    }

    private static func projectPrimitive(
        _ value: CandidValue,
        actual: CandidType,
        expected: CandidType
    ) throws -> CandidValue? {
        if actual == expected { return value }
        guard case .nat(let natural) = value, actual == .nat, expected == .int else { return nil }
        return .int(try CandidInt(natural.decimal))
    }

    private static func typesEquivalent(
        _ lhs: CandidType,
        _ rhs: CandidType,
        bindings: [UInt32: UInt32],
        reverseBindings: [UInt32: UInt32]
    ) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null), (.bool, .bool), (.nat, .nat), (.int, .int),
             (.nat8, .nat8), (.nat16, .nat16), (.nat32, .nat32), (.nat64, .nat64),
             (.int8, .int8), (.int16, .int16), (.int32, .int32), (.int64, .int64),
             (.float32, .float32), (.float64, .float64), (.text, .text),
             (.principal, .principal):
            return true
        case let (.optional(lhsChild), .optional(rhsChild)),
             let (.vector(lhsChild), .vector(rhsChild)):
            return typesEquivalent(
                lhsChild,
                rhsChild,
                bindings: bindings,
                reverseBindings: reverseBindings
            )
        case let (.record(lhsFields), .record(rhsFields)),
             let (.variant(lhsFields), .variant(rhsFields)):
            guard lhsFields.count == rhsFields.count else { return false }
            return zip(lhsFields, rhsFields).allSatisfy { lhsField, rhsField in
                lhsField.id == rhsField.id && typesEquivalent(
                    lhsField.type,
                    rhsField.type,
                    bindings: bindings,
                    reverseBindings: reverseBindings
                )
            }
        case let (.recursive(lhsID, lhsBody), .recursive(rhsID, rhsBody)):
            if let existing = bindings[lhsID], existing != rhsID { return false }
            if let existing = reverseBindings[rhsID], existing != lhsID { return false }
            var nestedBindings = bindings
            var nestedReverseBindings = reverseBindings
            nestedBindings[lhsID] = rhsID
            nestedReverseBindings[rhsID] = lhsID
            return typesEquivalent(
                lhsBody,
                rhsBody,
                bindings: nestedBindings,
                reverseBindings: nestedReverseBindings
            )
        case let (.reference(lhsID), .reference(rhsID)):
            return bindings[lhsID] == rhsID && reverseBindings[rhsID] == lhsID
        default:
            return false
        }
    }
}
