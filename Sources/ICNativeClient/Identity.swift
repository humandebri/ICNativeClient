import CryptoKit
import Foundation
import Security

public struct ICAuthSession: Equatable, Sendable {
    public static let currentFormatVersion = 3

    public var formatVersion: Int { storage.formatVersion }
    public var principal: String { storage.principal }
    public var canisterId: String { storage.canisterId }
    public var internetIdentityURL: String { storage.internetIdentityURL }
    public var derivationOrigin: String { storage.derivationOrigin }
    public var sessionPublicKey: Data { storage.sessionPublicKey }
    public var delegation: ICDelegationChain { storage.delegation }
    public var requestedAt: Date { storage.requestedAt }
    public var maxTimeToLiveNanoseconds: UInt64 { storage.maxTimeToLiveNanoseconds }

    let storage: ICStoredAuthSession
    var sessionPrivateKey: Data { storage.sessionPrivateKey }

    init(storage: ICStoredAuthSession) {
        self.storage = storage
    }
}

struct ICStoredAuthSession: Codable, Equatable, Sendable {
    let formatVersion: Int
    let principal: String
    let canisterId: String
    let internetIdentityURL: String
    let derivationOrigin: String
    let sessionPublicKey: Data
    let sessionPrivateKey: Data
    let delegation: ICDelegationChain
    let requestedAt: Date
    let maxTimeToLiveNanoseconds: UInt64
}

public enum ICDelegationPermission: String, Codable, Equatable, Sendable {
    case queries
    case all
}

public struct ICDelegationChain: Codable, Equatable, Sendable {
    public struct SignedDelegation: Codable, Equatable, Sendable {
        public struct Delegation: Codable, Equatable, Sendable {
            public let publicKey: Data
            public let expiration: UInt64
            public let targets: [Data]?
            public let permissions: ICDelegationPermission?

            public init(
                publicKey: Data,
                expiration: UInt64,
                targets: [Data]?,
                permissions: ICDelegationPermission? = nil
            ) {
                self.publicKey = publicKey
                self.expiration = expiration
                self.targets = targets
                self.permissions = permissions
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

protocol ICKeychainAccess: Sendable {
    func copyMatching(_ query: CFDictionary, result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    func update(_ query: CFDictionary, attributes: CFDictionary) -> OSStatus
    func add(_ attributes: CFDictionary) -> OSStatus
    func delete(_ query: CFDictionary) -> OSStatus
}

struct ICSystemKeychain: ICKeychainAccess {
    func copyMatching(_ query: CFDictionary, result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        SecItemCopyMatching(query, result)
    }
    func update(_ query: CFDictionary, attributes: CFDictionary) -> OSStatus { SecItemUpdate(query, attributes) }
    func add(_ attributes: CFDictionary) -> OSStatus { SecItemAdd(attributes, nil) }
    func delete(_ query: CFDictionary) -> OSStatus { SecItemDelete(query) }
}

public final class ICIdentityStore {
    public static var keychainAccessibility: CFString { kSecAttrAccessibleWhenUnlockedThisDeviceOnly }

    private let configuration: ICClientConfiguration
    private let service: String
    private let account: String
    private let accessGroup: String?
    private let keychain: any ICKeychainAccess

    public convenience init(
        configuration: ICClientConfiguration,
        service: String,
        account: String = "internet-identity-session",
        accessGroup: String? = nil
    ) {
        self.init(
            configuration: configuration,
            service: service,
            account: account,
            accessGroup: accessGroup,
            keychain: ICSystemKeychain()
        )
    }

    init(
        configuration: ICClientConfiguration,
        service: String,
        account: String,
        accessGroup: String? = nil,
        keychain: any ICKeychainAccess
    ) {
        self.configuration = configuration
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
        self.keychain = keychain
    }

    public func load() throws -> ICAuthSession? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = keychain.copyMatching(query as CFDictionary, result: &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw ICClientError.keychainFailure(status) }
        guard let data = result as? Data else { throw ICClientError.invalidIdentity("Stored session is not data.") }
        let stored: ICStoredAuthSession
        do {
            stored = try JSONDecoder().decode(ICStoredAuthSession.self, from: data)
        } catch {
            // A malformed item is still a registered credential. Preserve it for
            // diagnosis/recovery and distinguish it from an absent credential.
            throw ICClientError.invalidIdentity("Stored session could not be decoded.")
        }
        let session = ICAuthSession(storage: stored)
        try ICIdentityValidation.validateSession(session, configuration: configuration)
        return session
    }

    public func save(_ session: ICAuthSession) throws {
        try ICIdentityValidation.validateSession(session, configuration: configuration)
        let data = try JSONEncoder().encode(session.storage)
        let updates: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: Self.keychainAccessibility,
        ]
        var status = keychain.update(baseQuery() as CFDictionary, attributes: updates as CFDictionary)
        if status == errSecItemNotFound {
            var item = baseQuery()
            updates.forEach { item[$0.key] = $0.value }
            status = keychain.add(item as CFDictionary)
            if status == errSecDuplicateItem {
                status = keychain.update(baseQuery() as CFDictionary, attributes: updates as CFDictionary)
            }
        }
        guard status == errSecSuccess else { throw ICClientError.keychainFailure(status) }
    }

    public func clear() throws {
        let status = keychain.delete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ICClientError.keychainFailure(status)
        }
    }

    private func baseQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

enum ICRequestPermission {
    case query
    case call
    case readState
}

enum ICIdentityValidation {
    static let maximumDelegationDepth = 20
    static let maximumTargetsPerDelegation = 1_000

    static func validateSession(
        _ session: ICAuthSession,
        configuration: ICClientConfiguration,
        requestCanisterId: String? = nil,
        permission: ICRequestPermission? = nil,
        now: Date = Date()
    ) throws {
        guard session.storage.formatVersion == ICAuthSession.currentFormatVersion,
              session.canisterId == configuration.canisterId,
              session.internetIdentityURL == configuration.internetIdentityURL.absoluteString,
              session.derivationOrigin == configuration.derivationOrigin,
              session.maxTimeToLiveNanoseconds > 0,
              session.maxTimeToLiveNanoseconds <= ICClientConfiguration.maximumDelegationTTLNanoseconds,
              session.principal == ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(session.delegation.publicKey)) else {
            throw ICClientError.invalidPayload
        }

        let privateKey: Curve25519.Signing.PrivateKey
        do { privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: session.sessionPrivateKey) }
        catch { throw ICClientError.invalidPayload }
        guard ICRC167Codec.derPublicKey(from: privateKey.publicKey.rawRepresentation) == session.sessionPublicKey else {
            throw ICClientError.invalidPayload
        }

        try validateDelegationChain(
            session.delegation,
            expectedSessionPublicKey: session.sessionPublicKey,
            canisterId: requestCanisterId ?? configuration.canisterId,
            requestedAt: session.requestedAt,
            maxTimeToLiveNanoseconds: session.maxTimeToLiveNanoseconds,
            permission: permission,
            trustRoot: configuration.trustRoot,
            now: now
        )
    }

    static func validateDelegationChain(
        _ chain: ICDelegationChain,
        expectedSessionPublicKey: Data,
        canisterId: String,
        requestedAt: Date,
        maxTimeToLiveNanoseconds: UInt64,
        permission: ICRequestPermission?,
        trustRoot: ICTrustRoot,
        now: Date
    ) throws {
        guard !chain.publicKey.isEmpty,
              !chain.delegations.isEmpty,
              chain.delegations.count <= maximumDelegationDepth,
              chain.delegations.last?.delegation.publicKey == expectedSessionPublicKey,
              let canister = ICPrincipal.parse(canisterId),
              maxTimeToLiveNanoseconds > 0,
              maxTimeToLiveNanoseconds <= ICClientConfiguration.maximumDelegationTTLNanoseconds else {
            throw ICClientError.invalidPayload
        }
        let nowNS = try nanosecondsSinceEpoch(now)
        let requestedAtNS = try nanosecondsSinceEpoch(requestedAt)
        let (latestRequest, requestOverflow) = nowNS.addingReportingOverflow(ICRC167Codec.clockSkewNanoseconds)
        guard !requestOverflow, requestedAtNS <= latestRequest else { throw ICClientError.invalidPayload }

        var signerKey = chain.publicKey
        var observedKeys = Set<Data>([signerKey])
        var earliestExpiration = UInt64.max
        for signed in chain.delegations {
            let delegation = signed.delegation
            guard !delegation.publicKey.isEmpty,
                  !signed.signature.isEmpty,
                  observedKeys.insert(delegation.publicKey).inserted else {
                throw ICClientError.invalidPayload
            }
            guard delegation.expiration > nowNS else { throw ICClientError.expiredDelegation }
            earliestExpiration = min(earliestExpiration, delegation.expiration)
            if let targets = delegation.targets {
                guard !targets.isEmpty,
                      targets.count <= maximumTargetsPerDelegation,
                      Set(targets).count == targets.count,
                      targets.allSatisfy({ $0.count <= 29 }),
                      targets.contains(canister) else { throw ICClientError.invalidPayload }
            }
            if delegation.permissions == .queries, permission == .call { throw ICClientError.invalidIdentity("Delegation does not permit update calls.") }
            let payload = delegationSignable(delegation)
            try verify(signature: signed.signature, payload: payload, signerDERKey: signerKey, trustRoot: trustRoot, now: now)
            signerKey = delegation.publicKey
        }

        let (requestedExpiry, ttlOverflow) = requestedAtNS.addingReportingOverflow(maxTimeToLiveNanoseconds)
        let (maximumExpiry, skewOverflow) = requestedExpiry.addingReportingOverflow(ICRC167Codec.clockSkewNanoseconds)
        guard !ttlOverflow, !skewOverflow, earliestExpiration <= maximumExpiry else { throw ICClientError.invalidPayload }
    }

    private static func delegationSignable(_ delegation: ICDelegationChain.SignedDelegation.Delegation) -> Data {
        var fields: [(ICCBOR.Value, ICCBOR.Value)] = [
            (.text("pubkey"), .bytes(delegation.publicKey)),
            (.text("expiration"), .unsigned(delegation.expiration)),
        ]
        if let targets = delegation.targets { fields.append((.text("targets"), .array(targets.map(ICCBOR.Value.bytes)))) }
        if let permissions = delegation.permissions { fields.append((.text("permissions"), .text(permissions.rawValue))) }
        return Data([0x1a]) + Data("ic-request-auth-delegation".utf8) + ICRequestID.hash(of: .map(fields))
    }

    private static func verify(
        signature: Data,
        payload: Data,
        signerDERKey: Data,
        trustRoot: ICTrustRoot,
        now: Date
    ) throws {
        let spki = try ICDERSubjectPublicKeyInfo(data: signerDERKey)
        switch spki.algorithmOID {
        case ICDERSubjectPublicKeyInfo.ed25519OID:
            guard spki.parametersOID == nil,
                  spki.key.count == 32,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: spki.key),
                  key.isValidSignature(signature, for: payload) else { throw ICClientError.invalidIdentity("Broken Ed25519 delegation signature.") }
        case ICDERSubjectPublicKeyInfo.ecPublicKeyOID:
            guard spki.parametersOID == ICDERSubjectPublicKeyInfo.prime256v1OID,
                  spki.key.count == 65,
                  spki.key.first == 0x04,
                  signature.count == 64,
                  let key = try? P256.Signing.PublicKey(x963Representation: spki.key),
                  let p256Signature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
                  key.isValidSignature(p256Signature, for: payload) else {
                throw ICClientError.invalidIdentity("Broken P-256 delegation signature.")
            }
        case ICDERSubjectPublicKeyInfo.canisterSignatureOID:
            guard spki.parametersOID == nil,
                  let length = spki.key.first.map(Int.init),
                  length <= 29,
                  spki.key.count >= 1 + length else { throw ICClientError.invalidPayload }
            let canister = spki.key.subdata(in: 1..<(1 + length))
            let seed = spki.key.dropFirst(1 + length)
            try ICCertificateVerifier.verifyCanisterSignature(
                payload: payload,
                signatureData: signature,
                signingCanisterID: canister,
                seed: Data(seed),
                trustRoot: trustRoot,
                now: now
            )
        default:
            throw ICClientError.invalidIdentity("Unsupported delegation signing algorithm.")
        }
    }

    private static func nanosecondsSinceEpoch(_ date: Date) throws -> UInt64 {
        let seconds = date.timeIntervalSince1970
        guard seconds >= 0, seconds <= Double(UInt64.max) / 1_000_000_000 else { throw ICClientError.invalidPayload }
        return UInt64(seconds * 1_000_000_000)
    }
}

private struct ICDERSubjectPublicKeyInfo {
    static let ed25519OID = Data([0x2b, 0x65, 0x70])
    static let ecPublicKeyOID = Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
    static let prime256v1OID = Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
    static let canisterSignatureOID = Data([0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02])

    let algorithmOID: Data
    let parametersOID: Data?
    let key: Data

    init(data: Data) throws {
        var outer = ICDERReader(data: data)
        var sequence = try outer.readConstructed(tag: 0x30)
        guard outer.isAtEnd else { throw ICClientError.invalidPayload }
        var algorithm = try sequence.readConstructed(tag: 0x30)
        algorithmOID = try algorithm.readValue(tag: 0x06)
        parametersOID = algorithm.isAtEnd ? nil : try algorithm.readValue(tag: 0x06)
        guard algorithm.isAtEnd else { throw ICClientError.invalidPayload }
        let bitString = try sequence.readValue(tag: 0x03)
        guard sequence.isAtEnd, bitString.first == 0 else { throw ICClientError.invalidPayload }
        key = Data(bitString.dropFirst())
    }
}

private struct ICDERReader {
    let data: Data
    var index = 0
    var isAtEnd: Bool { index == data.count }

    mutating func readConstructed(tag: UInt8) throws -> ICDERReader {
        ICDERReader(data: try readValue(tag: tag))
    }

    mutating func readValue(tag: UInt8) throws -> Data {
        guard index < data.count, data[index] == tag else { throw ICClientError.invalidPayload }
        index += 1
        let length = try readLength()
        guard length <= data.count - index else { throw ICClientError.invalidPayload }
        defer { index += length }
        return data.subdata(in: index..<(index + length))
    }

    private mutating func readLength() throws -> Int {
        guard index < data.count else { throw ICClientError.invalidPayload }
        let first = data[index]
        index += 1
        if first < 0x80 { return Int(first) }
        let count = Int(first & 0x7f)
        guard count > 0, count <= 4, count <= data.count - index else { throw ICClientError.invalidPayload }
        var length = 0
        for _ in 0..<count { length = (length << 8) | Int(data[index]); index += 1 }
        guard length >= 0x80 else { throw ICClientError.invalidPayload }
        return length
    }
}
