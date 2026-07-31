// Error surface for reusable Internet Computer request,
// identity, and encoding primitives.

import Foundation
import Security

public enum ICClientError: Error, LocalizedError, Equatable {
    case invalidCanisterId
    case invalidIdentity(String)
    case invalidPayload
    case authorizationFailed(String)
    case authorizationTimedOut
    case expiredDelegation
    case emptyResponse
    case invalidResponse(String)
    case backendUnavailable(String)
    case rejected(String)
    case pollTimeout
    case keychainFailure(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidCanisterId:
            return "Invalid canister id."
        case .invalidIdentity(let message):
            return message
        case .invalidPayload:
            return "Internet Identity returned an invalid payload."
        case .authorizationFailed(let message):
            return message
        case .authorizationTimedOut:
            return "Internet Identity authorization timed out. Please try again."
        case .expiredDelegation:
            return "Internet Identity delegation expired."
        case .emptyResponse:
            return "The canister returned no response."
        case .invalidResponse(let context):
            return "The canister response could not be decoded: \(context)."
        case .backendUnavailable(let context):
            return "IC boundary node is unavailable. (\(context))"
        case .rejected(let message):
            return message
        case .pollTimeout:
            return "IC update polling timed out."
        case .keychainFailure(let status):
            return "Keychain operation failed: \(status)."
        }
    }
}
