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
            try ICIdentitySession.validateSession(session, configuration: configuration)
            return session
        } catch {
            clear()
            return nil
        }
    }

    public func save(_ session: ICAuthSession) throws {
        try ICIdentitySession.validateSession(session, configuration: configuration)
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

public enum ICIdentitySession {
    public static let maxTimeToLiveNanos = "2592000000000000"
    public static let ed25519DERPrefix = Data([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

    public static func makeSession(
        privateKey: Curve25519.Signing.PrivateKey,
        delegation: ICDelegationChain,
        configuration: ICClientConfiguration,
        createdAt: Date = Date()
    ) throws -> ICAuthSession {
        let sessionPublicKey = derPublicKey(from: privateKey.publicKey.rawRepresentation)
        try validate(delegation, expectedSessionPublicKey: sessionPublicKey, canisterId: configuration.canisterId)
        let principal = ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(delegation.publicKey))
        return ICAuthSession(
            principal: principal,
            canisterId: configuration.canisterId,
            identityProvider: configuration.identityProvider.absoluteString,
            derivationOrigin: configuration.derivationOrigin,
            sessionPublicKey: sessionPublicKey,
            sessionPrivateKey: privateKey.rawRepresentation,
            delegation: delegation,
            createdAt: createdAt
        )
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
