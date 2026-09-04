// Error surface for reusable Internet Computer request,
// identity, and encoding primitives.

import Foundation
import Security

public struct ICReject: Error, Equatable, Sendable {
    public let code: UInt64
    public let message: String
    public let errorCode: String?
    public let isCertified: Bool

    public init(code: UInt64, message: String, errorCode: String? = nil, isCertified: Bool) {
        self.code = code
        self.message = message
        self.errorCode = errorCode
        self.isCertified = isCertified
    }
}

public enum ICClientError: Error, LocalizedError, Equatable {
    case invalidCanisterId
    case invalidConfiguration(String)
    case invalidIdentity(String)
    case invalidPayload
    case authorizationFailed(String)
    case expiredDelegation
    case emptyResponse
    case invalidResponse(String)
    case invalidCBOR(String)
    case responseTooLarge(limit: Int)
    case certificateVerificationFailed(String)
    case querySignatureVerificationFailed(String)
    case backendUnavailable(String)
    case rejected(ICReject)
    case requestDoneWithoutReply
    case pollTimeout
    case keychainFailure(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .invalidCanisterId:
            return "Invalid canister id."
        case .invalidConfiguration(let message):
            return message
        case .invalidIdentity(let message):
            return message
        case .invalidPayload:
            return "Internet Identity returned an invalid payload."
        case .authorizationFailed(let message):
            return message
        case .expiredDelegation:
            return "Internet Identity delegation expired."
        case .emptyResponse:
            return "The canister returned no response."
        case .invalidResponse(let context):
            return "The canister response could not be decoded: \(context)."
        case .invalidCBOR(let context):
            return "Invalid CBOR: \(context)."
        case .responseTooLarge(let limit):
            return "The IC response exceeded the \(limit)-byte limit."
        case .certificateVerificationFailed(let context):
            return "IC certificate verification failed: \(context)."
        case .querySignatureVerificationFailed(let context):
            return "IC query signature verification failed: \(context)."
        case .backendUnavailable(let context):
            return "IC boundary node is unavailable. (\(context))"
        case .rejected(let reject):
            let suffix = reject.errorCode.map { " (\($0))" } ?? ""
            return "IC reject \(reject.code): \(reject.message)\(suffix)"
        case .requestDoneWithoutReply:
            return "The IC request is done, but its reply is no longer available."
        case .pollTimeout:
            return "IC update polling timed out."
        case .keychainFailure(let status):
            return "Keychain operation failed: \(status)."
        }
    }
}
