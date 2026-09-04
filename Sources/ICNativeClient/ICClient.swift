import CryptoKit
import Foundation

public final class ICClient: @unchecked Sendable {
    private let session: URLSession
    private let sleep: @Sendable (Duration) async throws -> Void
    private let subnetCache = ICSubnetCache()
    public let configuration: ICClientConfiguration

    public convenience init(configuration: ICClientConfiguration, session: URLSession = .shared) {
        self.init(configuration: configuration, session: session) { duration in
            try await Task.sleep(for: duration)
        }
    }

    init(
        configuration: ICClientConfiguration,
        session: URLSession,
        sleep: @escaping @Sendable (Duration) async throws -> Void
    ) {
        self.configuration = configuration
        self.session = session
        self.sleep = sleep
    }

    public func apiURL(
        for requestType: String,
        canisterId: String? = nil,
        version: ICClientAPIVersion? = nil
    ) throws -> URL {
        try configuration.apiURL(for: requestType, canisterId: canisterId, version: version)
    }

    /// Performs a query and verifies every returned node signature against certified subnet keys.
    public func queryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> Data {
        let target = canisterId ?? configuration.canisterId
        let (response, requestID) = try await performQuery(method: method, arg: arg, canisterId: target, identity: identity)
        var subnet = try await verifiedSubnet(for: target, identity: identity, forceRefresh: false)
        do {
            try verify(response: response, requestID: requestID, subnet: subnet)
        } catch {
            subnet = try await verifiedSubnet(for: target, identity: identity, forceRefresh: true)
            try verify(response: response, requestID: requestID, subnet: subnet)
        }
        return try response.result()
    }

    /// Explicit opt-out for callers that accept an unauthenticated query response.
    public func unsafeQueryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> Data {
        let target = canisterId ?? configuration.canisterId
        let (response, _) = try await performQuery(method: method, arg: arg, canisterId: target, identity: identity)
        return try response.result()
    }

    /// Performs a verified query with Candid arguments and decodes the returned DIDL value list.
    public func queryCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> CandidReply {
        let bytes = try arguments.encode()
        let reply = try await queryRaw(method: method, arg: bytes, canisterId: canisterId, identity: identity)
        return try CandidDecoder().decode(reply)
    }

    public func query<Output: CandidConvertible>(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        identity: ICAuthSession? = nil,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        let reply = try await queryCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            identity: identity
        )
        guard reply.values.count == 1 else {
            throw ICClientError.invalidCandid("typed query expected one reply value, received \(reply.values.count)")
        }
        return try reply.decode(outputType)
    }

    public func query<Input: CandidConvertible, Output: CandidConvertible>(
        method: String,
        argument: Input,
        canisterId: String? = nil,
        identity: ICAuthSession? = nil,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await query(
            method: method,
            arguments: CandidArguments(argument),
            canisterId: canisterId,
            identity: identity,
            as: outputType
        )
    }

    public func callRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> Data {
        let targetText = canisterId ?? configuration.canisterId
        let effectiveText = effectiveCanisterId ?? targetText
        guard let target = ICPrincipal.parse(targetText), let effective = ICPrincipal.parse(effectiveText) else {
            throw ICClientError.invalidCanisterId
        }
        // Delegation targets constrain the content canister, while certificate ranges constrain routing.
        try validateIdentityForRequest(identity, requestCanisterId: targetText, permission: .call)
        let content = requestContent(type: "call", canister: target, method: method, arg: arg, identity: identity)
        let requestID = ICRequestID.hash(of: content)
        let envelope = try Self.signedEnvelope(content: content, identity: identity)
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "call", canisterId: effectiveText, version: .v4),
            operation: "update \(method)"
        )
        if response.statusCode == 404 {
            return try await callRawV2(
                envelope: envelope,
                requestID: requestID,
                method: method,
                effectiveText: effectiveText,
                effective: effective,
                identity: identity
            )
        }
        guard response.statusCode == 200 || response.statusCode == 202 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("update \(method)", data: data, response: response))
        }
        if response.statusCode == 202 || data.isEmpty {
            return try await poll(requestId: requestID, canisterId: effectiveText, identity: identity)
        }
        let fields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(data), context: "v4 call response")
        guard case .text(let status) = try ICCBOR.requiredValue(fields, key: "status", context: "v4 call response") else {
            throw ICClientError.invalidResponse("v4 call status")
        }
        switch status {
        case "replied":
            guard case .bytes(let certificateData) = try ICCBOR.requiredValue(fields, key: "certificate", context: "v4 call response") else {
                throw ICClientError.invalidResponse("v4 call certificate")
            }
            let certificate = try ICCertificateVerifier.verify(
                certificateData: certificateData,
                effectiveCanisterID: effective,
                trustRoot: configuration.trustRoot
            )
            return try await resolve(status: ICCertificateVerifier.status(in: certificate, requestID: requestID), pollIfPending: true, requestID: requestID, effectiveText: effectiveText, identity: identity)
        case "non_replicated_rejection":
            throw ICClientError.rejected(try parseReject(fields, certified: false, context: "v4 rejection"))
        default:
            throw ICClientError.invalidResponse("unsupported v4 call status \(status)")
        }
    }

    /// Performs an update with Candid arguments using the same verified path as `callRaw`.
    public func callCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> CandidReply {
        let bytes = try arguments.encode()
        let reply = try await callRaw(
            method: method,
            arg: bytes,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity
        )
        return try CandidDecoder().decode(reply)
    }

    public func call<Output: CandidConvertible>(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        let reply = try await callCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity
        )
        guard reply.values.count == 1 else {
            throw ICClientError.invalidCandid("typed call expected one reply value, received \(reply.values.count)")
        }
        return try reply.decode(outputType)
    }

    public func call<Input: CandidConvertible, Output: CandidConvertible>(
        method: String,
        argument: Input,
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await call(
            method: method,
            arguments: CandidArguments(argument),
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            as: outputType
        )
    }

    public func poll(
        requestId: Data,
        canisterId: String? = nil,
        identity: ICAuthSession,
        attempts: Int? = nil
    ) async throws -> Data {
        let effectiveText = canisterId ?? configuration.canisterId
        let maximumAttempts = attempts ?? configuration.network.maximumPollingAttempts
        guard requestId.count == 32, let effective = ICPrincipal.parse(effectiveText), maximumAttempts > 0 else {
            throw ICClientError.invalidConfiguration("Poll requires a 32-byte request ID and at least one attempt.")
        }
        try validateIdentityForRequest(identity, requestCanisterId: effectiveText, permission: .readState)
        let url = try apiURL(for: "read_state", canisterId: effectiveText)
        for _ in 0..<maximumAttempts {
            try await sleep(configuration.network.pollingInterval)
            let content = readStateContent(
                paths: [[Data("request_status".utf8), requestId]],
                identity: identity
            )
            let envelope = try Self.signedEnvelope(content: content, identity: identity)
            let (data, response) = try await postCBOR(envelope, to: url, operation: "read_state")
            guard response.statusCode == 200 else {
                throw ICClientError.backendUnavailable(Self.httpFailureContext("read_state", data: data, response: response))
            }
            let certificateData = try decodeReadStateCertificate(data)
            let certificate = try ICCertificateVerifier.verify(
                certificateData: certificateData,
                effectiveCanisterID: effective,
                trustRoot: configuration.trustRoot
            )
            switch try ICCertificateVerifier.status(in: certificate, requestID: requestId) {
            case .replied(let reply): return reply
            case .rejected(let reject): throw ICClientError.rejected(reject)
            case .done: throw ICClientError.requestDoneWithoutReply
            case .absent, .pending: continue
            }
        }
        throw ICClientError.pollTimeout
    }

    public func validateIdentity(_ identity: ICAuthSession, requestCanisterId: String) throws {
        try validateIdentityForRequest(identity, requestCanisterId: requestCanisterId, permission: nil)
    }

    private func validateIdentityForRequest(
        _ identity: ICAuthSession,
        requestCanisterId: String,
        permission: ICRequestPermission?
    ) throws {
        do {
            try ICIdentityValidation.validateSession(
                identity,
                configuration: configuration,
                requestCanisterId: requestCanisterId,
                permission: permission
            )
        } catch ICClientError.invalidPayload {
            throw ICClientError.invalidIdentity("Internet Identity session is not valid for this canister.")
        }
    }

    public static func signedEnvelope(content: ICCBOR.Value, identity: ICAuthSession) throws -> Data {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: identity.sessionPrivateKey)
        let challenge = Data([0x0a]) + Data("ic-request".utf8) + ICRequestID.hash(of: content)
        let signature = try privateKey.signature(for: challenge)
        return ICCBOR.signedEnvelope(
            content: content,
            publicKey: identity.delegation.publicKey,
            signature: signature,
            delegation: identity.delegation
        )
    }

    private func performQuery(
        method: String,
        arg: Data,
        canisterId: String,
        identity: ICAuthSession?
    ) async throws -> (ICQueryResponse, Data) {
        guard let canister = ICPrincipal.parse(canisterId), !method.isEmpty else {
            throw ICClientError.invalidCanisterId
        }
        let content: ICCBOR.Value
        if let identity {
            try validateIdentityForRequest(identity, requestCanisterId: canisterId, permission: .query)
            content = requestContent(type: "query", canister: canister, method: method, arg: arg, identity: identity)
        } else {
            content = anonymousRequestContent(type: "query", canister: canister, method: method, arg: arg)
        }
        let envelope = try envelope(content: content, identity: identity)
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "query", canisterId: canisterId),
            operation: "query \(method)"
        )
        guard response.statusCode == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("query \(method)", data: data, response: response))
        }
        return (try ICQueryResponse(cbor: data), ICRequestID.hash(of: content))
    }

    private func verifiedSubnet(
        for canisterText: String,
        identity: ICAuthSession?,
        forceRefresh: Bool
    ) async throws -> ICVerifiedSubnet {
        guard let canister = ICPrincipal.parse(canisterText) else { throw ICClientError.invalidCanisterId }
        if !forceRefresh, let cached = await subnetCache.value(for: canister) { return cached }
        let content = readStateContent(paths: [[Data("subnet".utf8)]], identity: identity)
        let request = try envelope(content: content, identity: identity)
        let (data, response) = try await postCBOR(
            request,
            to: apiURL(for: "read_state", canisterId: canisterText),
            operation: "certified subnet keys"
        )
        guard response.statusCode == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("certified subnet keys", data: data, response: response))
        }
        let certificate = try ICCertificateVerifier.verify(
            certificateData: decodeReadStateCertificate(data),
            effectiveCanisterID: canister,
            trustRoot: configuration.trustRoot
        )
        let subnet = try ICCertificateVerifier.subnet(from: certificate, effectiveCanisterID: canister)
        await subnetCache.insert(subnet)
        return subnet
    }

    private func verify(response: ICQueryResponse, requestID: Data, subnet: ICVerifiedSubnet) throws {
        guard !response.signatures.isEmpty, response.signatures.count <= subnet.nodeKeys.count else {
            throw ICClientError.querySignatureVerificationFailed("missing or excessive signatures")
        }
        let now = Date().timeIntervalSince1970
        for signature in response.signatures {
            let timestampSeconds = Double(signature.timestamp) / 1_000_000_000
            guard abs(now - timestampSeconds) <= 300 else {
                throw ICClientError.querySignatureVerificationFailed("signature timestamp is outside the ±5 minute window")
            }
            guard let derKey = subnet.nodeKeys[signature.identity] else {
                throw ICClientError.querySignatureVerificationFailed("signing node is not certified for the subnet")
            }
            try ICCertificateVerifier.validateEd25519DERKey(derKey)
            let rawKey = derKey.dropFirst(ICRC167Codec.ed25519DERPrefix.count)
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
            guard key.isValidSignature(signature.signature, for: response.signable(requestID: requestID, timestamp: signature.timestamp)) else {
                throw ICClientError.querySignatureVerificationFailed("invalid Ed25519 node signature")
            }
        }
    }

    private func requestContent(
        type: String,
        canister: Data,
        method: String,
        arg: Data,
        identity: ICAuthSession
    ) -> ICCBOR.Value {
        .map([
            (.text("request_type"), .text(type)),
            (.text("canister_id"), .bytes(canister)),
            (.text("method_name"), .text(method)),
            (.text("arg"), .bytes(arg)),
            (.text("sender"), .bytes(ICPrincipal.selfAuthenticatingPublicKey(identity.delegation.publicKey))),
            (.text("ingress_expiry"), .unsigned(Self.ingressExpiry())),
        ])
    }

    private func anonymousRequestContent(type: String, canister: Data, method: String, arg: Data) -> ICCBOR.Value {
        .map([
            (.text("request_type"), .text(type)),
            (.text("canister_id"), .bytes(canister)),
            (.text("method_name"), .text(method)),
            (.text("arg"), .bytes(arg)),
            (.text("sender"), .bytes(Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(Self.ingressExpiry())),
        ])
    }

    private func readStateContent(paths: [[Data]], identity: ICAuthSession?) -> ICCBOR.Value {
        .map([
            (.text("request_type"), .text("read_state")),
            (.text("paths"), .array(paths.map { .array($0.map(ICCBOR.Value.bytes)) })),
            (.text("sender"), .bytes(identity.map { ICPrincipal.selfAuthenticatingPublicKey($0.delegation.publicKey) } ?? Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(Self.ingressExpiry())),
        ])
    }

    private func envelope(content: ICCBOR.Value, identity: ICAuthSession?) throws -> Data {
        if let identity { return try Self.signedEnvelope(content: content, identity: identity) }
        return ICCBOR.encode(.tagged(ICCBOR.selfDescribeTag, .map([(.text("content"), content)])))
    }

    private static func ingressExpiry() -> UInt64 {
        UInt64((Date().timeIntervalSince1970 + 300) * 1_000_000_000)
    }

    private func callRawV2(
        envelope: Data,
        requestID: Data,
        method: String,
        effectiveText: String,
        effective: Data,
        identity: ICAuthSession
    ) async throws -> Data {
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "call", canisterId: effectiveText, version: .v2),
            operation: "update \(method)"
        )
        guard response.statusCode == 200 || response.statusCode == 202 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("update \(method)", data: data, response: response))
        }
        if response.statusCode == 200 {
            let fields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(data), context: "v2 call rejection")
            throw ICClientError.rejected(try parseReject(fields, certified: false, context: "v2 rejection"))
        }
        _ = effective
        return try await poll(requestId: requestID, canisterId: effectiveText, identity: identity)
    }

    private func resolve(
        status: ICCertificateStatus,
        pollIfPending: Bool,
        requestID: Data,
        effectiveText: String,
        identity: ICAuthSession
    ) async throws -> Data {
        switch status {
        case .replied(let data): return data
        case .rejected(let reject): throw ICClientError.rejected(reject)
        case .done: throw ICClientError.requestDoneWithoutReply
        case .absent, .pending:
            guard pollIfPending else { throw ICClientError.emptyResponse }
            return try await poll(requestId: requestID, canisterId: effectiveText, identity: identity)
        }
    }

    private func decodeReadStateCertificate(_ data: Data) throws -> Data {
        let fields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(data), context: "read_state response")
        guard case .bytes(let certificate) = try ICCBOR.requiredValue(fields, key: "certificate", context: "read_state response") else {
            throw ICClientError.invalidResponse("read_state certificate")
        }
        return certificate
    }

    private func parseReject(
        _ fields: [(ICCBOR.Value, ICCBOR.Value)],
        certified: Bool,
        context: String
    ) throws -> ICReject {
        guard case .unsigned(let code) = try ICCBOR.requiredValue(fields, key: "reject_code", context: context),
              case .text(let message) = try ICCBOR.requiredValue(fields, key: "reject_message", context: context) else {
            throw ICClientError.invalidResponse(context)
        }
        let errorCode: String?
        if let value = ICCBOR.optionalValue(fields, key: "error_code") {
            guard case .text(let text) = value else { throw ICClientError.invalidResponse("\(context).error_code") }
            errorCode = text
        } else { errorCode = nil }
        return ICReject(code: code, message: message, errorCode: errorCode, isCertified: certified)
    }

    private func postCBOR(_ body: Data, to url: URL, operation: String) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.network.requestTimeout
        request.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw ICClientError.invalidResponse("non-HTTP response") }
            if let length = http.value(forHTTPHeaderField: "Content-Length").flatMap(Int.init),
               length > configuration.maximumResponseBytes {
                throw ICClientError.responseTooLarge(limit: configuration.maximumResponseBytes)
            }
            var data = Data()
            data.reserveCapacity(min(configuration.maximumResponseBytes, 64 * 1_024))
            for try await byte in bytes {
                guard data.count < configuration.maximumResponseBytes else {
                    throw ICClientError.responseTooLarge(limit: configuration.maximumResponseBytes)
                }
                data.append(byte)
            }
            return (data, http)
        } catch let error as ICClientError {
            throw error
        } catch let error as URLError {
            guard error.code != .cancelled else { throw error }
            throw ICClientError.backendUnavailable("\(operation): \(Self.urlErrorContext(error))")
        }
    }

    private static func httpFailureContext(_ operation: String, data: Data, response: HTTPURLResponse) -> String {
        guard let body = responseBodyDetail(data) else { return "\(operation) HTTP \(response.statusCode)" }
        return "\(operation) HTTP \(response.statusCode): \(body)"
    }

    private static func responseBodyDetail(_ data: Data) -> String? {
        guard !data.isEmpty, let text = String(data: data.prefix(1_000), encoding: .utf8) else { return nil }
        let normalized = text.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        let lower = normalized.lowercased()
        guard !["<!doctype html", "<html", "<head", "<body"].contains(where: lower.contains) else { return nil }
        return String(normalized.prefix(240))
    }

    private static func urlErrorContext(_ error: URLError) -> String {
        switch error.code {
        case .cannotFindHost, .cannotConnectToHost: "cannot connect to host"
        case .networkConnectionLost: "network connection lost"
        case .notConnectedToInternet: "not connected to the internet"
        case .timedOut: "request timed out"
        default: error.localizedDescription
        }
    }
}

struct ICQueryResponse {
    struct NodeSignature {
        let identity: Data
        let signature: Data
        let timestamp: UInt64
    }
    enum Payload {
        case replied(Data)
        case rejected(ICReject)
    }
    let payload: Payload
    let signatures: [NodeSignature]

    init(cbor data: Data) throws {
        let fields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(data), context: "query response")
        guard case .text(let status) = try ICCBOR.requiredValue(fields, key: "status", context: "query response"),
              case .array(let signatureValues) = try ICCBOR.requiredValue(fields, key: "signatures", context: "query response") else {
            throw ICClientError.invalidResponse("query response schema")
        }
        signatures = try signatureValues.map { value in
            let fields = try ICCBOR.requiredMap(value, context: "query signature")
            guard case .bytes(let identity) = try ICCBOR.requiredValue(fields, key: "identity", context: "query signature"),
                  case .bytes(let signature) = try ICCBOR.requiredValue(fields, key: "signature", context: "query signature"),
                  case .unsigned(let timestamp) = try ICCBOR.requiredValue(fields, key: "timestamp", context: "query signature"),
                  !identity.isEmpty, signature.count == 64 else {
                throw ICClientError.invalidResponse("query signature schema")
            }
            return NodeSignature(identity: identity, signature: signature, timestamp: timestamp)
        }
        switch status {
        case "replied":
            let reply = try ICCBOR.requiredMap(ICCBOR.requiredValue(fields, key: "reply", context: "query response"), context: "query reply")
            guard case .bytes(let arg) = try ICCBOR.requiredValue(reply, key: "arg", context: "query reply") else {
                throw ICClientError.invalidResponse("query reply arg")
            }
            payload = .replied(arg)
        case "rejected":
            guard case .unsigned(let code) = try ICCBOR.requiredValue(fields, key: "reject_code", context: "query reject"),
                  case .text(let message) = try ICCBOR.requiredValue(fields, key: "reject_message", context: "query reject") else {
                throw ICClientError.invalidResponse("query reject")
            }
            let errorCode: String?
            if let value = ICCBOR.optionalValue(fields, key: "error_code") {
                guard case .text(let text) = value else { throw ICClientError.invalidResponse("query reject error_code") }
                errorCode = text
            } else { errorCode = nil }
            payload = .rejected(ICReject(code: code, message: message, errorCode: errorCode, isCertified: false))
        default: throw ICClientError.invalidResponse("unknown query status")
        }
    }

    func result() throws -> Data {
        switch payload {
        case .replied(let data): data
        case .rejected(let reject): throw ICClientError.rejected(reject)
        }
    }

    func signable(requestID: Data, timestamp: UInt64) -> Data {
        var fields: [(ICCBOR.Value, ICCBOR.Value)]
        switch payload {
        case .replied(let arg):
            fields = [
                (.text("status"), .text("replied")),
                (.text("reply"), .map([(.text("arg"), .bytes(arg))])),
                (.text("request_id"), .bytes(requestID)),
                (.text("timestamp"), .unsigned(timestamp)),
            ]
        case .rejected(let reject):
            fields = [
                (.text("status"), .text("rejected")),
                (.text("reject_code"), .unsigned(reject.code)),
                (.text("reject_message"), .text(reject.message)),
                (.text("request_id"), .bytes(requestID)),
                (.text("timestamp"), .unsigned(timestamp)),
            ]
            if let errorCode = reject.errorCode { fields.append((.text("error_code"), .text(errorCode))) }
        }
        return Data([0x0b]) + Data("ic-response".utf8) + ICRequestID.hash(of: .map(fields))
    }
}

private actor ICSubnetCache {
    private struct Entry { let subnet: ICVerifiedSubnet; let expiresAt: Date }
    private var entries: [Data: Entry] = [:]

    func value(for canister: Data, now: Date = Date()) -> ICVerifiedSubnet? {
        entries = entries.filter { $0.value.expiresAt > now }
        return entries.values.first { entry in
            entry.subnet.canisterRanges.contains {
                !canister.lexicographicallyPrecedes($0.0) && !$0.1.lexicographicallyPrecedes(canister)
            }
        }?.subnet
    }

    func insert(_ subnet: ICVerifiedSubnet, now: Date = Date()) {
        entries[subnet.id] = Entry(subnet: subnet, expiresAt: now.addingTimeInterval(3_600))
    }
}
