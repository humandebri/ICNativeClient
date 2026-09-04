import CryptoKit
import Foundation
import Security

final class ICRC167PendingRequest {
    let requestID: String
    let state: String
    let privateKey: Curve25519.Signing.PrivateKey
    let requestedAt: Date
    let maxTimeToLiveNanoseconds: UInt64
    let requestedTargets: [String]?
    private(set) var isConsumed = false

    init(
        requestID: String,
        state: String,
        privateKey: Curve25519.Signing.PrivateKey,
        requestedAt: Date,
        maxTimeToLiveNanoseconds: UInt64,
        requestedTargets: [String]? = nil
    ) {
        self.requestID = requestID
        self.state = state
        self.privateKey = privateKey
        self.requestedAt = requestedAt
        self.maxTimeToLiveNanoseconds = maxTimeToLiveNanoseconds
        self.requestedTargets = requestedTargets
    }

    func consume() throws {
        guard !isConsumed else {
            throw ICClientError.invalidPayload
        }
        isConsumed = true
    }
}

enum ICRC167Codec {
    static let defaultMaxTimeToLiveNanoseconds = ICClientConfiguration.defaultDelegationTTLNanoseconds
    static let callbackPath = "/ios-auth-callback"
    static let clockSkewNanoseconds: UInt64 = 300_000_000_000
    static let ed25519DERPrefix = Data([
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ])

    static func makePendingRequest(
        maxTimeToLiveNanoseconds: UInt64 = defaultMaxTimeToLiveNanoseconds,
        targets: [String]? = nil,
        requestedAt: Date = Date()
    ) throws -> ICRC167PendingRequest {
        let options = try ICAuthenticationOptions(
            maxTimeToLiveNanoseconds: maxTimeToLiveNanoseconds,
            targets: targets
        )
        return ICRC167PendingRequest(
            requestID: try randomToken(byteCount: 16),
            state: try randomToken(byteCount: 32),
            privateKey: Curve25519.Signing.PrivateKey(),
            requestedAt: requestedAt,
            maxTimeToLiveNanoseconds: maxTimeToLiveNanoseconds,
            requestedTargets: options.targets
        )
    }

    static func authorizationURL(
        configuration: ICClientConfiguration,
        callbackURL: URL,
        pendingRequest: ICRC167PendingRequest
    ) throws -> URL {
        try validateInternetIdentityURL(configuration.internetIdentityURL)
        try validateCallbackURL(callbackURL)
        guard let configuredCanister = ICPrincipal.parse(configuration.canisterId) else {
            throw ICClientError.invalidCanisterId
        }
        if let targets = pendingRequest.requestedTargets,
           !targets.compactMap(ICPrincipal.parse).contains(configuredCanister) {
            throw ICClientError.invalidConfiguration(
                "Authentication targets must include the configured canister ID."
            )
        }

        let publicKey = derPublicKey(from: pendingRequest.privateKey.publicKey.rawRepresentation)
        let request = JSONRPCRequest(
            jsonrpc: "2.0",
            id: pendingRequest.requestID,
            method: "icrc34_delegation",
            params: DelegationRequestParameters(
                publicKey: publicKey.base64EncodedString(),
                maxTimeToLive: String(pendingRequest.maxTimeToLiveNanoseconds),
                icrc95DerivationOrigin: configuration.derivationOrigin,
                targets: pendingRequest.requestedTargets
            )
        )
        let message: Data
        do {
            message = try JSONEncoder().encode(request)
        } catch {
            throw ICClientError.invalidPayload
        }
        guard let messageString = String(data: message, encoding: .utf8),
              var components = URLComponents(
                  url: configuration.internetIdentityURL,
                  resolvingAgainstBaseURL: false
              ) else {
            throw ICClientError.invalidConfiguration("Internet Identity URL is invalid.")
        }
        components.percentEncodedFragment = formEncoded([
            ("message", messageString),
            ("callback", callbackURL.absoluteString),
            ("state", pendingRequest.state),
        ])
        guard let url = components.url else {
            throw ICClientError.invalidConfiguration("Internet Identity URL could not be constructed.")
        }
        return url
    }

    static func session(
        from callbackURL: URL,
        expectedCallbackURL: URL,
        pendingRequest: ICRC167PendingRequest,
        configuration: ICClientConfiguration,
        now: Date = Date()
    ) throws -> ICAuthSession {
        try pendingRequest.consume()
        try validateReturnedCallbackURL(callbackURL, expected: expectedCallbackURL)

        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let fragment = components.percentEncodedFragment else {
            throw ICClientError.invalidPayload
        }
        let values = try parseFormEncoded(fragment)
        guard values.count == 2,
              let state = values["state"],
              let message = values["message"],
              state == pendingRequest.state,
              let messageData = message.data(using: .utf8) else {
            throw ICClientError.invalidPayload
        }

        let response: JSONRPCResponse
        do {
            try validateResponseSchema(messageData)
            response = try JSONDecoder().decode(JSONRPCResponse.self, from: messageData)
        } catch {
            throw ICClientError.invalidPayload
        }
        guard response.jsonrpc == "2.0", response.id == pendingRequest.requestID else {
            throw ICClientError.invalidPayload
        }
        switch (response.result, response.error) {
        case (.some(let result), nil):
            let sessionPublicKey = derPublicKey(from: pendingRequest.privateKey.publicKey.rawRepresentation)
            let chain = try delegationChain(from: result)
            try ICIdentityValidation.validateDelegationChain(
                chain,
                expectedSessionPublicKey: sessionPublicKey,
                canisterId: configuration.canisterId,
                requestedAt: pendingRequest.requestedAt,
                maxTimeToLiveNanoseconds: pendingRequest.maxTimeToLiveNanoseconds,
                permission: nil,
                trustRoot: configuration.trustRoot,
                now: now
            )
            try validateRequestedTargetScope(
                chain,
                requestedTargets: pendingRequest.requestedTargets
            )
            let principal = ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(chain.publicKey))
            return ICAuthSession(
                storage: ICStoredAuthSession(
                    formatVersion: ICAuthSession.currentFormatVersion,
                    principal: principal,
                    canisterId: configuration.canisterId,
                    internetIdentityURL: configuration.internetIdentityURL.absoluteString,
                    derivationOrigin: configuration.derivationOrigin,
                    sessionPublicKey: sessionPublicKey,
                    sessionPrivateKey: pendingRequest.privateKey.rawRepresentation,
                    delegation: chain,
                    requestedAt: pendingRequest.requestedAt,
                    maxTimeToLiveNanoseconds: pendingRequest.maxTimeToLiveNanoseconds
                )
            )
        case (nil, .some(let error)):
            throw ICClientError.authorizationFailed(error.message)
        default:
            throw ICClientError.invalidPayload
        }
    }

    static func derPublicKey(from rawPublicKey: Data) -> Data {
        ed25519DERPrefix + rawPublicKey
    }

    static func validateInternetIdentityURL(_ url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host != nil,
              components.user == nil,
              components.password == nil,
              components.percentEncodedPath == "/authorize",
              components.percentEncodedFragment == nil else {
            throw ICClientError.invalidConfiguration(
                "Internet Identity URL must be an HTTPS /authorize URL without credentials or a fragment."
            )
        }

        if components.host?.lowercased() == "id.ai", let queryItems = components.queryItems {
            guard queryItems.count == 1,
                  queryItems[0].name == "openid",
                  (queryItems[0].value == "https://appleid.apple.com" ||
                    queryItems[0].value == "https://accounts.google.com") else {
                throw ICClientError.invalidConfiguration("The id.ai OpenID provider query is not supported.")
            }
        }
    }

    static func validateCallbackURL(_ url: URL) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == "https",
              components.host != nil,
              components.user == nil,
              components.password == nil,
              !components.percentEncodedPath.isEmpty,
              components.percentEncodedPath.hasPrefix("/"),
              !components.percentEncodedPath.hasPrefix("//"),
              components.percentEncodedQuery == nil,
              components.percentEncodedFragment == nil else {
            throw ICClientError.invalidConfiguration(
                "Callback URL must be an HTTPS URL with an explicit path and without credentials, query, or fragment."
            )
        }
    }

    static func validateReturnedCallbackURL(_ url: URL, expected: URL) throws {
        try validateCallbackURL(expected)
        guard let actual = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let wanted = URLComponents(url: expected, resolvingAgainstBaseURL: false),
              actual.scheme?.lowercased() == wanted.scheme?.lowercased(),
              actual.host?.lowercased() == wanted.host?.lowercased(),
              normalizedPort(actual) == normalizedPort(wanted),
              actual.percentEncodedPath == wanted.percentEncodedPath,
              actual.user == nil,
              actual.password == nil,
              actual.percentEncodedQuery == nil,
              actual.percentEncodedFragment != nil else {
            throw ICClientError.invalidPayload
        }
    }

    static func parseFormEncoded(_ encoded: String) throws -> [String: String] {
        guard !encoded.isEmpty else {
            throw ICClientError.invalidPayload
        }
        var values: [String: String] = [:]
        for field in encoded.split(separator: "&", omittingEmptySubsequences: false) {
            let pair = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2,
                  let name = decodeFormComponent(String(pair[0])),
                  let value = decodeFormComponent(String(pair[1])),
                  !name.isEmpty,
                  values[name] == nil else {
                throw ICClientError.invalidPayload
            }
            values[name] = value
        }
        return values
    }

    private static func delegationChain(from result: DelegationResult) throws -> ICDelegationChain {
        let publicKey = try strictBase64Decoded(result.publicKey)
        guard !result.signerDelegation.isEmpty else {
            throw ICClientError.invalidPayload
        }
        let delegations = try result.signerDelegation.map { signed -> ICDelegationChain.SignedDelegation in
            let delegatedPublicKey = try strictBase64Decoded(signed.delegation.pubkey)
            let signature = try strictBase64Decoded(signed.signature)
            let expiration = try decimalUInt64(signed.delegation.expiration)
            let targets = try signed.delegation.targets?.map { target -> Data in
                guard let principal = ICPrincipal.parse(target) else {
                    throw ICClientError.invalidPayload
                }
                return principal
            }
            let permissions: ICDelegationPermission?
            if let raw = signed.delegation.permissions {
                guard let parsed = ICDelegationPermission(rawValue: raw) else { throw ICClientError.invalidPayload }
                permissions = parsed
            } else {
                permissions = nil
            }
            return ICDelegationChain.SignedDelegation(
                delegation: .init(
                    publicKey: delegatedPublicKey,
                    expiration: expiration,
                    targets: targets,
                    permissions: permissions
                ),
                signature: signature
            )
        }
        return ICDelegationChain(publicKey: publicKey, delegations: delegations)
    }

    private static func validateRequestedTargetScope(
        _ chain: ICDelegationChain,
        requestedTargets: [String]?
    ) throws {
        guard let requestedTargets else { return }
        let requested = Set(try requestedTargets.map { target -> Data in
            guard let principal = ICPrincipal.parse(target) else { throw ICClientError.invalidPayload }
            return principal
        })
        var effectiveTargets: Set<Data>?
        for delegation in chain.delegations.compactMap(\.delegation.targets) {
            let targets = Set(delegation)
            effectiveTargets = effectiveTargets.map { $0.intersection(targets) } ?? targets
        }
        guard let effectiveTargets,
              !effectiveTargets.isEmpty,
              effectiveTargets.isSubset(of: requested) else {
            throw ICClientError.invalidPayload
        }
    }

    private static func validateResponseSchema(_ data: Data) throws {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ICClientError.invalidPayload
        }
        let hasResult = root["result"] != nil
        let hasError = root["error"] != nil
        guard Set(root.keys) == Set(["jsonrpc", "id", hasResult ? "result" : "error"]),
              hasResult != hasError,
              root["jsonrpc"] is String,
              root["id"] is String else {
            throw ICClientError.invalidPayload
        }
        if hasResult {
            guard let result = root["result"] as? [String: Any],
                  Set(result.keys) == Set(["publicKey", "signerDelegation"]),
                  result["publicKey"] is String,
                  let signedDelegations = result["signerDelegation"] as? [[String: Any]],
                  !signedDelegations.isEmpty else {
                throw ICClientError.invalidPayload
            }
            for signed in signedDelegations {
                guard Set(signed.keys) == Set(["delegation", "signature"]),
                      signed["signature"] is String,
                      let delegation = signed["delegation"] as? [String: Any] else {
                    throw ICClientError.invalidPayload
                }
                let allowed = Set(["pubkey", "expiration", "targets", "permissions"])
                guard Set(delegation.keys).isSubset(of: allowed),
                      delegation["pubkey"] is String,
                      delegation["expiration"] is String,
                      delegation["targets"].map({ $0 is [String] }) ?? true,
                      delegation["permissions"].map({ $0 is String }) ?? true else {
                    throw ICClientError.invalidPayload
                }
            }
        } else {
            guard let error = root["error"] as? [String: Any],
                  Set(error.keys) == Set(["code", "message"]),
                  error["code"] is NSNumber,
                  error["message"] is String else {
                throw ICClientError.invalidPayload
            }
        }
    }

    private static func normalizedPort(_ components: URLComponents) -> Int? {
        if let port = components.port { return port }
        return components.scheme?.lowercased() == "https" ? 443 : nil
    }

    private static func strictBase64Decoded(_ value: String) throws -> Data {
        guard !value.isEmpty,
              value.utf8.count.isMultiple(of: 4),
              value.range(of: #"^[A-Za-z0-9+/]+={0,2}$"#, options: .regularExpression) != nil,
              let data = Data(base64Encoded: value),
              data.base64EncodedString() == value else {
            throw ICClientError.invalidPayload
        }
        return data
    }

    private static func decimalUInt64(_ value: String) throws -> UInt64 {
        guard value.utf8.count <= 20,
              value.range(of: #"^[0-9]+$"#, options: .regularExpression) != nil,
              let number = UInt64(value) else {
            throw ICClientError.invalidPayload
        }
        return number
    }

    private static func nanosecondsSinceEpoch(_ date: Date) throws -> UInt64 {
        let seconds = date.timeIntervalSince1970
        guard seconds >= 0, seconds <= Double(UInt64.max) / 1_000_000_000 else {
            throw ICClientError.invalidPayload
        }
        return UInt64(seconds * 1_000_000_000)
    }

    private static func randomToken(byteCount: Int) throws -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw ICClientError.authorizationFailed("Secure random generation failed.")
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func formEncoded(_ fields: [(String, String)]) -> String {
        fields.map { formEncodeComponent($0.0) + "=" + formEncodeComponent($0.1) }
            .joined(separator: "&")
    }

    private static func formEncodeComponent(_ value: String) -> String {
        value.utf8.map { byte -> String in
            switch byte {
            case 0x41...0x5a, 0x61...0x7a, 0x30...0x39, 0x2a, 0x2d, 0x2e, 0x5f:
                return String(UnicodeScalar(byte))
            case 0x20:
                return "+"
            default:
                return String(format: "%%%02X", byte)
            }
        }.joined()
    }

    private static func decodeFormComponent(_ value: String) -> String? {
        value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }
}

private struct JSONRPCRequest: Encodable {
    let jsonrpc: String
    let id: String
    let method: String
    let params: DelegationRequestParameters
}

private struct DelegationRequestParameters: Encodable {
    let publicKey: String
    let maxTimeToLive: String
    let icrc95DerivationOrigin: String
    let targets: [String]?
}

private struct JSONRPCResponse: Decodable {
    let jsonrpc: String
    let id: String
    let result: DelegationResult?
    let error: JSONRPCError?
}

private struct JSONRPCError: Decodable {
    let code: Int
    let message: String
}

private struct DelegationResult: Decodable {
    let publicKey: String
    let signerDelegation: [SignedDelegationResult]
}

private struct SignedDelegationResult: Decodable {
    let delegation: DelegationResultValue
    let signature: String
}

private struct DelegationResultValue: Decodable {
    let pubkey: String
    let expiration: String
    let targets: [String]?
    let permissions: String?
}
