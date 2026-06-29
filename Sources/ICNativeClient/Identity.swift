// Internet Identity delegation-session types and validation logic for iOS clients.
// Signature verification is intentionally left to IC replicas; this validates
// session key binding, target restrictions, and expiration before signing calls.

import CryptoKit
import Foundation
import Security

public struct ICAuthSession: Codable, Equatable, Sendable {
    public let principal: String
    public let canisterId: String
    public let identityProvider: String
    public let derivationOrigin: String
    public let sessionPublicKey: Data
    public let sessionPrivateKey: Data
    public let delegation: ICDelegationChain
    public let createdAt: Date

    public init(
        principal: String,
        canisterId: String,
        identityProvider: String,
        derivationOrigin: String,
        sessionPublicKey: Data,
        sessionPrivateKey: Data,
        delegation: ICDelegationChain,
        createdAt: Date = Date()
    ) {
        self.principal = principal
        self.canisterId = canisterId
        self.identityProvider = identityProvider
        self.derivationOrigin = derivationOrigin
        self.sessionPublicKey = sessionPublicKey
        self.sessionPrivateKey = sessionPrivateKey
        self.delegation = delegation
        self.createdAt = createdAt
    }
}

public struct ICDelegationChain: Codable, Equatable, Sendable {
    public struct SignedDelegation: Codable, Equatable, Sendable {
        public struct Delegation: Codable, Equatable, Sendable {
            public let publicKey: Data
            public let expiration: UInt64
            public let targets: [Data]?

            public init(publicKey: Data, expiration: UInt64, targets: [Data]?) {
                self.publicKey = publicKey
                self.expiration = expiration
                self.targets = targets
            }
        }

        public let delegation: Delegation
        public let signature: Data

        public init(delegation: Delegation, signature: Data) {
            self.delegation = delegation
            self.signature = signature
        }
    }

    public let publicKey: Data
    public let delegations: [SignedDelegation]

    public init(publicKey: Data, delegations: [SignedDelegation]) {
        self.publicKey = publicKey
        self.delegations = delegations
    }
}

public final class ICIdentityStore {
    public static let keychainAccessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

    private let configuration: ICClientConfiguration
    private let service: String
    private let account: String

    public init(
        configuration: ICClientConfiguration,
        service: String,
        account: String = "internet-identity-session"
    ) {
        self.configuration = configuration
        self.service = service
        self.account = account
    }

    public func load() -> ICAuthSession? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        guard let session = try? JSONDecoder().decode(ICAuthSession.self, from: data) else {
            clear()
            return nil
        }
        do {
            try ICIdentityBridge.validateSession(session, configuration: configuration)
            return session
        } catch {
            clear()
            return nil
        }
    }

    public func save(_ session: ICAuthSession) throws {
        try ICIdentityBridge.validateSession(session, configuration: configuration)
        let data = try JSONEncoder().encode(session)
        clear()
        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = Self.keychainAccessibility
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            throw ICClientError.keychainFailure(status)
        }
    }

    public func clear() {
        SecItemDelete(baseQuery() as CFDictionary)
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

public enum ICIdentityBridge {
    public static let maxTimeToLiveNanos = "2592000000000000"
    public static let ed25519DERPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

    public static func makeSession(
        from payload: String,
        privateKey: Curve25519.Signing.PrivateKey,
        configuration: ICClientConfiguration
    ) throws -> ICAuthSession {
        guard let data = payload.data(using: .utf8) else {
            throw ICClientError.invalidPayload
        }
        let response: InternetIdentityResponse
        do {
            response = try JSONDecoder().decode(InternetIdentityResponse.self, from: data)
        } catch {
            throw ICClientError.invalidPayload
        }
        if response.kind == "authorize-client-failure" {
            throw ICClientError.authorizationFailed(response.text ?? response.message ?? "Internet Identity authorization failed.")
        }
        guard response.kind == "authorize-client-success" else {
            throw ICClientError.invalidPayload
        }

        let sessionPublicKey = derPublicKey(from: privateKey.publicKey.rawRepresentation)
        let chain = try response.delegationChain()
        try validate(chain, expectedSessionPublicKey: sessionPublicKey, canisterId: configuration.canisterId)
        let principal = ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(chain.publicKey))
        return ICAuthSession(
            principal: principal,
            canisterId: configuration.canisterId,
            identityProvider: configuration.identityProvider.absoluteString,
            derivationOrigin: configuration.derivationOrigin,
            sessionPublicKey: sessionPublicKey,
            sessionPrivateKey: privateKey.rawRepresentation,
            delegation: chain,
            createdAt: Date()
        )
    }

    public static func authorizeClientRequest(publicKey: Data) -> Data {
        let request = AuthorizeClientRequest(
            kind: "authorize-client",
            sessionPublicKey: Array(publicKey),
            maxTimeToLive: maxTimeToLiveNanos
        )
        return (try? JSONEncoder().encode(request)) ?? Data("{}".utf8)
    }

    public static func derPublicKey(from rawPublicKey: Data) -> Data {
        ed25519DERPrefix + rawPublicKey
    }

    public static func validateSession(
        _ session: ICAuthSession,
        configuration: ICClientConfiguration,
        requestCanisterId: String? = nil
    ) throws {
        guard session.canisterId == configuration.canisterId,
              session.identityProvider == configuration.identityProvider.absoluteString,
              session.derivationOrigin == configuration.derivationOrigin else {
            throw ICClientError.invalidPayload
        }
        try validate(
            session.delegation,
            expectedSessionPublicKey: session.sessionPublicKey,
            canisterId: requestCanisterId ?? configuration.canisterId
        )
    }

    static func validate(
        _ chain: ICDelegationChain,
        expectedSessionPublicKey: Data?,
        canisterId: String
    ) throws {
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        guard let canister = ICPrincipal.parse(canisterId) else {
            throw ICClientError.invalidPayload
        }
        guard chain.delegations.last?.delegation.publicKey == expectedSessionPublicKey else {
            throw ICClientError.invalidPayload
        }
        for signed in chain.delegations {
            guard signed.delegation.expiration > now else {
                throw ICClientError.expiredDelegation
            }
            if let targets = signed.delegation.targets, !targets.contains(canister) {
                throw ICClientError.invalidPayload
            }
        }
    }
}

private struct AuthorizeClientRequest: Encodable {
    let kind: String
    let sessionPublicKey: [UInt8]
    let maxTimeToLive: String
}

private struct InternetIdentityResponse: Decodable {
    let kind: String
    let text: String?
    let message: String?
    let userPublicKey: BytesValue?
    let publicKey: BytesValue?
    let delegation: DelegationContainer?
    let delegations: [SignedDelegationPayload]?

    func delegationChain() throws -> ICDelegationChain {
        let chainObject = delegation ?? DelegationContainer(
            userPublicKey: userPublicKey,
            publicKey: publicKey,
            delegations: delegations
        )
        guard let publicKey = chainObject.userPublicKey?.data ?? chainObject.publicKey?.data,
              let rawDelegations = chainObject.delegations else {
            throw ICClientError.invalidPayload
        }
        let signedDelegations = try rawDelegations.map { raw -> ICDelegationChain.SignedDelegation in
            guard let publicKey = raw.delegation.publicKey.data,
                  let expiration = raw.delegation.expiration.value,
                  let signature = raw.signature.data else {
                throw ICClientError.invalidPayload
            }
            let targets = try raw.delegation.targets?.map { target -> Data in
                guard let data = target.data else {
                    throw ICClientError.invalidPayload
                }
                return data
            }
            return ICDelegationChain.SignedDelegation(
                delegation: .init(publicKey: publicKey, expiration: expiration, targets: targets),
                signature: signature
            )
        }
        guard !signedDelegations.isEmpty else {
            throw ICClientError.invalidPayload
        }
        return ICDelegationChain(publicKey: publicKey, delegations: signedDelegations)
    }
}

private struct DelegationContainer: Decodable {
    let userPublicKey: BytesValue?
    let publicKey: BytesValue?
    let delegations: [SignedDelegationPayload]?
}

private struct SignedDelegationPayload: Decodable {
    let delegation: DelegationPayload
    let signature: BytesValue
}

private struct DelegationPayload: Decodable {
    let publicKey: BytesValue
    let expiration: UInt64Value
    let targets: [BytesValue]?

    enum CodingKeys: String, CodingKey {
        case publicKey = "pubkey"
        case expiration
        case targets
    }
}

private struct BytesValue: Decodable {
    let data: Data?

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let hex = try? container.decode(String.self) {
            data = Data(icHex: hex)
            return
        }
        if let bytes = try? container.decode([UInt8].self) {
            data = Data(bytes)
            return
        }
        data = nil
    }
}

private struct UInt64Value: Decodable {
    let value: UInt64?

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let text = try? container.decode(String.self) {
            if text.hasPrefix("0x") {
                value = UInt64(text.dropFirst(2), radix: 16)
            } else {
                value = UInt64(text, radix: 10)
            }
            return
        }
        value = try? container.decode(UInt64.self)
    }
}
