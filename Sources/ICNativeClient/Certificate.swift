import CBlst
import CryptoKit
import Foundation

struct ICCertificate: Sendable {
    struct Delegation: Sendable {
        let subnetID: Data
        let certificate: Data
    }

    let tree: ICHashTree
    let signature: Data
    let delegation: Delegation?

    init(cbor data: Data) throws {
        let value = try ICCBOR.decodeStrict(data)
        let fields = try ICCBOR.requiredMap(value, context: "certificate")
        guard case .bytes(let signature) = try ICCBOR.requiredValue(fields, key: "signature", context: "certificate"),
              signature.count == 48 else {
            throw ICClientError.invalidResponse("certificate.signature")
        }
        self.tree = try ICHashTree(value: ICCBOR.requiredValue(fields, key: "tree", context: "certificate"))
        self.signature = signature
        if let delegationValue = ICCBOR.optionalValue(fields, key: "delegation") {
            let delegationFields = try ICCBOR.requiredMap(delegationValue, context: "certificate.delegation")
            guard case .bytes(let subnetID) = try ICCBOR.requiredValue(delegationFields, key: "subnet_id", context: "certificate.delegation"),
                  case .bytes(let nestedCertificate) = try ICCBOR.requiredValue(delegationFields, key: "certificate", context: "certificate.delegation"),
                  !subnetID.isEmpty else {
                throw ICClientError.invalidResponse("certificate.delegation")
            }
            self.delegation = Delegation(subnetID: subnetID, certificate: nestedCertificate)
        } else {
            self.delegation = nil
        }
    }
}

indirect enum ICHashTree: Sendable {
    enum Lookup: Equatable {
        case absent
        case unknown
        case found(Data)
        case error
    }

    case empty
    case fork(ICHashTree, ICHashTree)
    case labeled(Data, ICHashTree)
    case leaf(Data)
    case pruned(Data)

    init(value: ICCBOR.Value) throws {
        guard case .array(let fields) = value,
              case .unsigned(let kind)? = fields.first else {
            throw ICClientError.invalidResponse("certificate hash tree")
        }
        switch kind {
        case 0 where fields.count == 1:
            self = .empty
        case 1 where fields.count == 3:
            self = .fork(try ICHashTree(value: fields[1]), try ICHashTree(value: fields[2]))
        case 2 where fields.count == 3:
            guard case .bytes(let label) = fields[1] else { throw ICClientError.invalidResponse("hash tree label") }
            self = .labeled(label, try ICHashTree(value: fields[2]))
        case 3 where fields.count == 2:
            guard case .bytes(let value) = fields[1] else { throw ICClientError.invalidResponse("hash tree leaf") }
            self = .leaf(value)
        case 4 where fields.count == 2:
            guard case .bytes(let digest) = fields[1], digest.count == 32 else { throw ICClientError.invalidResponse("hash tree pruned digest") }
            self = .pruned(digest)
        default:
            throw ICClientError.invalidResponse("certificate hash tree node")
        }
    }

    var digest: Data {
        switch self {
        case .empty: Self.hash(domain: "ic-hashtree-empty", values: [])
        case .fork(let left, let right): Self.hash(domain: "ic-hashtree-fork", values: [left.digest, right.digest])
        case .labeled(let label, let tree): Self.hash(domain: "ic-hashtree-labeled", values: [label, tree.digest])
        case .leaf(let value): Self.hash(domain: "ic-hashtree-leaf", values: [value])
        case .pruned(let digest): digest
        }
    }

    func lookup(_ path: [Data]) -> Lookup {
        if path.isEmpty {
            if case .leaf(let value) = self { return .found(value) }
            if case .pruned = self { return .unknown }
            return .error
        }
        switch self {
        case .empty, .leaf: return .absent
        case .pruned: return .unknown
        case .labeled(let label, let child):
            return label == path[0] ? child.lookup(Array(path.dropFirst())) : .absent
        case .fork(let left, let right):
            return Self.merge(left.lookup(path), right.lookup(path))
        }
    }

    func subtree(_ path: [Data]) -> ICHashTree? {
        guard let first = path.first else { return self }
        switch self {
        case .fork(let left, let right): return left.subtree(path) ?? right.subtree(path)
        case .labeled(let label, let child) where label == first: return child.subtree(Array(path.dropFirst()))
        default: return nil
        }
    }

    func labeledLeaves(prefix: [Data] = []) -> [([Data], Data)] {
        switch self {
        case .fork(let left, let right): return left.labeledLeaves(prefix: prefix) + right.labeledLeaves(prefix: prefix)
        case .labeled(let label, let child): return child.labeledLeaves(prefix: prefix + [label])
        case .leaf(let value): return [(prefix, value)]
        case .empty, .pruned: return []
        }
    }

    private static func merge(_ left: Lookup, _ right: Lookup) -> Lookup {
        switch (left, right) {
        case (.error, _), (_, .error), (.found, .found): .error
        case (.found(let value), _), (_, .found(let value)): .found(value)
        case (.unknown, _), (_, .unknown): .unknown
        default: .absent
        }
    }

    private static func hash(domain: String, values: [Data]) -> Data {
        var input = Data([UInt8(domain.utf8.count)])
        input.append(Data(domain.utf8))
        values.forEach { input.append($0) }
        return Data(SHA256.hash(data: input))
    }
}

enum ICCertificateStatus: Equatable {
    case absent
    case pending
    case replied(Data)
    case rejected(ICReject)
    case done
}

struct ICVerifiedSubnet: Sendable {
    let id: Data
    let nodeKeys: [Data: Data]
    let canisterRanges: [(Data, Data)]
}

enum ICCertificateVerifier {
    static let permittedTimeDriftNanoseconds: UInt64 = 300_000_000_000
    private static let blsDERPrefix = Data([
        0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06,
        0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61, 0x00,
    ])
    private static let stateRootDomain = Data([0x0d]) + Data("ic-state-root".utf8)
    private static let blsCipherSuite = Data("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".utf8)

    static func validateRootKey(_ der: Data) throws {
        _ = try rawBLSKey(from: der)
    }

    static func verify(
        certificateData: Data,
        effectiveCanisterID: Data,
        trustRoot: ICTrustRoot,
        now: Date = Date()
    ) throws -> ICCertificate {
        let certificate = try verifyCryptographically(
            certificateData: certificateData,
            effectiveCanisterID: effectiveCanisterID,
            trustRoot: trustRoot
        )
        try verifyTime(certificate, now: now)
        return certificate
    }

    private static func verifyCryptographically(
        certificateData: Data,
        effectiveCanisterID: Data,
        trustRoot: ICTrustRoot
    ) throws -> ICCertificate {
        let certificate = try ICCertificate(cbor: certificateData)
        let key = try verificationKey(
            for: certificate,
            effectiveCanisterID: effectiveCanisterID,
            rootKey: trustRoot.derEncodedPublicKey
        )
        try verifySignature(certificate, derKey: key)
        return certificate
    }

    static func status(in certificate: ICCertificate, requestID: Data) throws -> ICCertificateStatus {
        let base = [Data("request_status".utf8), requestID]
        switch certificate.tree.lookup(base + [Data("status".utf8)]) {
        case .absent: return .absent
        case .unknown: throw ICClientError.certificateVerificationFailed("request status is not proven")
        case .error: throw ICClientError.invalidResponse("request status tree")
        case .found(let bytes):
            guard let status = String(data: bytes, encoding: .utf8) else { throw ICClientError.invalidResponse("request status UTF-8") }
            switch status {
            case "received", "processing": return .pending
            case "done": return .done
            case "replied":
                guard case .found(let reply) = certificate.tree.lookup(base + [Data("reply".utf8)]) else {
                    throw ICClientError.invalidResponse("certified reply")
                }
                return .replied(reply)
            case "rejected":
                let code = try requiredLEB128(certificate.tree, path: base + [Data("reject_code".utf8)])
                let message = try requiredText(certificate.tree, path: base + [Data("reject_message".utf8)])
                let errorCode: String?
                switch certificate.tree.lookup(base + [Data("error_code".utf8)]) {
                case .found(let value):
                    guard let text = String(data: value, encoding: .utf8) else {
                        throw ICClientError.invalidResponse("certified reject error_code UTF-8")
                    }
                    errorCode = text
                case .absent: errorCode = nil
                default: throw ICClientError.invalidResponse("certified reject error_code")
                }
                return .rejected(ICReject(code: code, message: message, errorCode: errorCode, isCertified: true))
            default: throw ICClientError.invalidResponse("unknown request status \(status)")
            }
        }
    }

    static func subnet(
        from certificate: ICCertificate,
        effectiveCanisterID: Data
    ) throws -> ICVerifiedSubnet {
        let subnetID: Data
        let authorityTree: ICHashTree
        if let delegation = certificate.delegation {
            subnetID = delegation.subnetID
            authorityTree = try ICCertificate(cbor: delegation.certificate).tree
        } else {
            // Root-subnet responses expose their subnet entry in their own certified tree.
            let candidates = certificate.tree.labeledLeaves().compactMap { path, _ -> Data? in
                path.count >= 3 && path[0] == Data("subnet".utf8) ? path[1] : nil
            }
            guard let only = Set(candidates).first, Set(candidates).count == 1 else {
                throw ICClientError.certificateVerificationFailed("subnet identity is unavailable")
            }
            subnetID = only
            authorityTree = certificate.tree
        }
        let ranges = try canisterRanges(in: authorityTree, subnetID: subnetID)
        guard contains(effectiveCanisterID, in: ranges) else {
            throw ICClientError.certificateVerificationFailed("canister is outside the certified subnet range")
        }
        guard let subnetTree = certificate.tree.subtree([Data("subnet".utf8), subnetID]),
              let nodeTree = subnetTree.subtree([Data("node".utf8)]) else {
            throw ICClientError.certificateVerificationFailed("certified node keys are unavailable")
        }
        var nodeKeys: [Data: Data] = [:]
        for (path, key) in nodeTree.labeledLeaves() where path.count == 2 && path[1] == Data("public_key".utf8) {
            guard nodeKeys[path[0]] == nil else { throw ICClientError.invalidResponse("duplicate certified node key") }
            try validateEd25519DERKey(key)
            nodeKeys[path[0]] = key
        }
        guard !nodeKeys.isEmpty else { throw ICClientError.certificateVerificationFailed("certified node-key set is empty") }
        return ICVerifiedSubnet(id: subnetID, nodeKeys: nodeKeys, canisterRanges: ranges)
    }

    static func verifyCanisterSignature(
        payload: Data,
        signatureData: Data,
        signingCanisterID: Data,
        seed: Data,
        trustRoot: ICTrustRoot,
        now: Date
    ) throws {
        let fields = try ICCBOR.requiredMap(
            ICCBOR.decodeStrict(signatureData),
            context: "canister signature"
        )
        guard case .bytes(let certificateData) = try ICCBOR.requiredValue(
            fields,
            key: "certificate",
            context: "canister signature"
        ) else { throw ICClientError.invalidPayload }
        let signatureTree = try ICHashTree(
            value: ICCBOR.requiredValue(fields, key: "tree", context: "canister signature")
        )
        // Delegation expiration, not this embedded witness certificate's timestamp,
        // defines session freshness. Rechecking its timestamp would invalidate every
        // persisted II session after five minutes.
        let certificate = try verifyCryptographically(
            certificateData: certificateData,
            effectiveCanisterID: signingCanisterID,
            trustRoot: trustRoot
        )
        guard case .found(let certifiedData) = certificate.tree.lookup([
            Data("canister".utf8), signingCanisterID, Data("certified_data".utf8),
        ]), certifiedData == signatureTree.digest else {
            throw ICClientError.invalidIdentity("Canister signature certified_data mismatch.")
        }
        let seedHash = Data(SHA256.hash(data: seed))
        let payloadHash = Data(SHA256.hash(data: payload))
        guard case .found(let leaf) = signatureTree.lookup([
            Data("sig".utf8), seedHash, payloadHash,
        ]), leaf.isEmpty else {
            throw ICClientError.invalidIdentity("Canister signature witness mismatch.")
        }
    }

    private static func verificationKey(
        for certificate: ICCertificate,
        effectiveCanisterID: Data,
        rootKey: Data
    ) throws -> Data {
        guard let delegation = certificate.delegation else { return rootKey }
        let rootCertificate = try ICCertificate(cbor: delegation.certificate)
        guard case nil = rootCertificate.delegation else {
            throw ICClientError.certificateVerificationFailed("nested subnet delegation")
        }
        try verifySignature(rootCertificate, derKey: rootKey)
        let ranges = try canisterRanges(in: rootCertificate.tree, subnetID: delegation.subnetID)
        guard contains(effectiveCanisterID, in: ranges) else {
            throw ICClientError.certificateVerificationFailed("effective canister is outside delegated ranges")
        }
        switch rootCertificate.tree.lookup([Data("subnet".utf8), delegation.subnetID, Data("public_key".utf8)]) {
        case .found(let key): try validateRootKey(key); return key
        default: throw ICClientError.certificateVerificationFailed("delegated subnet key is not proven")
        }
    }

    private static func verifySignature(_ certificate: ICCertificate, derKey: Data) throws {
        let rawKey = try rawBLSKey(from: derKey)
        let message = stateRootDomain + certificate.tree.digest
        guard ICBLS.verify(signature: certificate.signature, message: message, publicKey: rawKey, dst: blsCipherSuite) else {
            throw ICClientError.certificateVerificationFailed("BLS signature")
        }
    }

    private static func verifyTime(_ certificate: ICCertificate, now: Date) throws {
        let timestamp = try requiredLEB128(certificate.tree, path: [Data("time".utf8)])
        guard now.timeIntervalSince1970 >= 0 else { throw ICClientError.certificateVerificationFailed("system clock") }
        let nowNS = UInt64(now.timeIntervalSince1970 * 1_000_000_000)
        let lower = nowNS > permittedTimeDriftNanoseconds ? nowNS - permittedTimeDriftNanoseconds : 0
        let (upper, overflow) = nowNS.addingReportingOverflow(permittedTimeDriftNanoseconds)
        guard timestamp >= lower, !overflow, timestamp <= upper else {
            throw ICClientError.certificateVerificationFailed("certificate time is outside the ±5 minute window")
        }
    }

    private static func canisterRanges(in tree: ICHashTree, subnetID: Data) throws -> [(Data, Data)] {
        let legacy = tree.lookup([Data("subnet".utf8), subnetID, Data("canister_ranges".utf8)])
        var encodedLeaves: [Data] = []
        if case .found(let value) = legacy {
            encodedLeaves = [value]
        } else if let sharded = tree.subtree([Data("canister_ranges".utf8), subnetID]) {
            encodedLeaves = sharded.labeledLeaves().map(\.1)
        }
        guard !encodedLeaves.isEmpty else { throw ICClientError.certificateVerificationFailed("canister ranges are not proven") }
        var ranges: [(Data, Data)] = []
        for encoded in encodedLeaves {
            let decoded = ICCBOR.unwrapSelfDescribeTag(try ICCBOR.decodeStrict(encoded))
            guard case .array(let entries) = decoded else { throw ICClientError.invalidResponse("canister ranges") }
            for entry in entries {
                guard case .array(let pair) = entry, pair.count == 2,
                      case .bytes(let low) = pair[0], case .bytes(let high) = pair[1],
                      low.count <= 29, high.count <= 29,
                      !high.lexicographicallyPrecedes(low) else {
                    throw ICClientError.invalidResponse("canister range entry")
                }
                ranges.append((low, high))
            }
        }
        guard !ranges.isEmpty else { throw ICClientError.certificateVerificationFailed("canister range set is empty") }
        return ranges
    }

    private static func contains(_ principal: Data, in ranges: [(Data, Data)]) -> Bool {
        ranges.contains { !principal.lexicographicallyPrecedes($0.0) && !($0.1.lexicographicallyPrecedes(principal)) }
    }

    private static func requiredText(_ tree: ICHashTree, path: [Data]) throws -> String {
        guard case .found(let bytes) = tree.lookup(path), let text = String(data: bytes, encoding: .utf8) else {
            throw ICClientError.invalidResponse("certified text value")
        }
        return text
    }

    private static func requiredLEB128(_ tree: ICHashTree, path: [Data]) throws -> UInt64 {
        guard case .found(let bytes) = tree.lookup(path) else { throw ICClientError.invalidResponse("certified integer") }
        return try decodeUnsignedLEB128(bytes)
    }

    static func decodeUnsignedLEB128(_ data: Data) throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        for (index, byte) in data.enumerated() {
            let value = UInt64(byte & 0x7f)
            guard shift < 64, value <= (UInt64.max >> shift) else { throw ICClientError.invalidResponse("LEB128 overflow") }
            result |= value << shift
            if byte & 0x80 == 0 {
                guard index == data.count - 1, index == 0 || value != 0 else { throw ICClientError.invalidResponse("non-canonical LEB128") }
                return result
            }
            shift += 7
        }
        throw ICClientError.invalidResponse("unterminated LEB128")
    }

    static func validateEd25519DERKey(_ key: Data) throws {
        guard key.count == 44, key.prefix(12) == ICRC167Codec.ed25519DERPrefix else {
            throw ICClientError.certificateVerificationFailed("invalid Ed25519 DER key")
        }
    }

    private static func rawBLSKey(from der: Data) throws -> Data {
        guard der.count == blsDERPrefix.count + 96, der.prefix(blsDERPrefix.count) == blsDERPrefix else {
            throw ICClientError.invalidConfiguration("Trust root must be a 133-byte IC BLS DER public key.")
        }
        return der.dropFirst(blsDERPrefix.count)
    }
}

enum ICBLS {
    static func verify(signature: Data, message: Data, publicKey: Data, dst: Data) -> Bool {
        guard signature.count == 48, publicKey.count == 96 else { return false }
        var pk = blst_p2_affine()
        var sig = blst_p1_affine()
        let pkResult = publicKey.withUnsafeBytes { bytes in
            blst_p2_uncompress(&pk, bytes.bindMemory(to: UInt8.self).baseAddress)
        }
        guard pkResult == BLST_SUCCESS else { return false }
        let sigResult = signature.withUnsafeBytes { bytes in
            blst_p1_uncompress(&sig, bytes.bindMemory(to: UInt8.self).baseAddress)
        }
        guard sigResult == BLST_SUCCESS else { return false }
        return message.withUnsafeBytes { messageBytes in
            dst.withUnsafeBytes { dstBytes in
                blst_core_verify_pk_in_g2(
                    &pk,
                    &sig,
                    true,
                    messageBytes.bindMemory(to: UInt8.self).baseAddress,
                    message.count,
                    dstBytes.bindMemory(to: UInt8.self).baseAddress,
                    dst.count,
                    nil,
                    0
                ) == BLST_SUCCESS
            }
        }
    }
}
