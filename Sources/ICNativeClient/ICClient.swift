import CryptoKit
import Foundation

public enum ICRequestStatus: Equatable, Sendable {
    case absent
    case received
    case processing
    case replied(Data)
    case rejected(ICReject)
    case done
}

public struct ICRequestOptions: Equatable, Sendable {
    public static let maximumNonceBytes = 32
    public static let maximumIngressTTL: TimeInterval = 300
    public static let `default` = ICRequestOptions()

    public let ingressExpiry: Date?
    public let nonce: Data?

    public init(ingressExpiry: Date? = nil, nonce: Data? = nil) {
        self.ingressExpiry = ingressExpiry
        self.nonce = nonce
    }
}

public struct ICSignedQuery: Codable, Equatable, Sendable {
    public let requestID: Data
    public let canisterId: String
    public let effectiveCanisterId: String
    public let delegationTargetCanisterId: String
    public let method: String
    public let ingressExpiry: Date
    public let envelope: Data

    init(
        requestID: Data,
        canisterId: String,
        effectiveCanisterId: String,
        delegationTargetCanisterId: String,
        method: String,
        ingressExpiry: Date,
        envelope: Data
    ) {
        self.requestID = requestID
        self.canisterId = canisterId
        self.effectiveCanisterId = effectiveCanisterId
        self.delegationTargetCanisterId = delegationTargetCanisterId
        self.method = method
        self.ingressExpiry = ingressExpiry
        self.envelope = envelope
    }
}

public struct ICSignedUpdate: Codable, Equatable, Sendable {
    public let requestID: Data
    public let canisterId: String
    public let effectiveCanisterId: String
    public let method: String
    public let ingressExpiry: Date
    public let envelope: Data

    init(
        requestID: Data,
        canisterId: String,
        effectiveCanisterId: String,
        method: String,
        ingressExpiry: Date,
        envelope: Data
    ) {
        self.requestID = requestID
        self.canisterId = canisterId
        self.effectiveCanisterId = effectiveCanisterId
        self.method = method
        self.ingressExpiry = ingressExpiry
        self.envelope = envelope
    }
}

public struct ICUpdateSubmission: Equatable, Sendable {
    public let requestID: Data
    public let effectiveCanisterId: String

    let initialStatus: ICCertificateStatus
    let sender: Data

    init(
        requestID: Data,
        effectiveCanisterId: String,
        initialStatus: ICCertificateStatus,
        sender: Data
    ) {
        self.requestID = requestID
        self.effectiveCanisterId = effectiveCanisterId
        self.initialStatus = initialStatus
        self.sender = sender
    }
}

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
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> Data {
        try await queryRaw(
            method: method,
            arg: arg,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: .default
        )
    }

    /// Performs a query with per-request expiry and nonce options.
    public func queryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        options: ICRequestOptions
    ) async throws -> Data {
        if let identity {
            return try await querySigned(signQuery(
                method: method,
                arg: arg,
                canisterId: canisterId,
                effectiveCanisterId: effectiveCanisterId,
                delegationTargetCanisterId: delegationTargetCanisterId,
                identity: identity,
                options: options
            ))
        }
        let requestText = canisterId ?? configuration.canisterId
        let effectiveText = effectiveCanisterId ?? requestText
        // Delegation targets constrain the signed content canister, while certificate ranges constrain routing.
        let (response, requestID) = try await performQuery(
            method: method,
            arg: arg,
            requestCanisterId: requestText,
            effectiveCanisterId: effectiveText,
            delegationTargetCanisterId: delegationTargetCanisterId ?? requestText,
            identity: nil,
            options: options
        )
        var subnet = try await verifiedSubnet(for: effectiveText, forceRefresh: false)
        do {
            try verify(response: response, requestID: requestID, subnet: subnet)
        } catch {
            subnet = try await verifiedSubnet(for: effectiveText, forceRefresh: true)
            try verify(response: response, requestID: requestID, subnet: subnet)
        }
        return try response.result()
    }

    /// Explicit opt-out for callers that accept an unauthenticated query response.
    public func unsafeQueryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> Data {
        try await unsafeQueryRaw(
            method: method,
            arg: arg,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: .default
        )
    }

    /// Explicit opt-out with per-request expiry and nonce options.
    public func unsafeQueryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        options: ICRequestOptions
    ) async throws -> Data {
        if let identity {
            return try await unsafeQuerySigned(signQuery(
                method: method,
                arg: arg,
                canisterId: canisterId,
                effectiveCanisterId: effectiveCanisterId,
                delegationTargetCanisterId: delegationTargetCanisterId,
                identity: identity,
                options: options
            ))
        }
        let requestText = canisterId ?? configuration.canisterId
        let effectiveText = effectiveCanisterId ?? requestText
        let (response, _) = try await performQuery(
            method: method,
            arg: arg,
            requestCanisterId: requestText,
            effectiveCanisterId: effectiveText,
            delegationTargetCanisterId: delegationTargetCanisterId ?? requestText,
            identity: nil,
            options: options
        )
        return try response.result()
    }

    /// Performs a verified query with Candid arguments and decodes the returned DIDL value list.
    public func queryCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> CandidReply {
        try await queryCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: .default
        )
    }

    /// Performs a verified Candid query with per-request options.
    public func queryCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        options: ICRequestOptions
    ) async throws -> CandidReply {
        let bytes = try arguments.encode()
        let reply = try await queryRaw(
            method: method,
            arg: bytes,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: options
        )
        return try CandidDecoder().decode(reply)
    }

    public func query<Output: CandidConvertible>(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await query(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: .default,
            as: outputType
        )
    }

    public func query<Output: CandidConvertible>(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        options: ICRequestOptions,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        let reply = try await queryCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: options
        )
        return try reply.decode(outputType)
    }

    public func query<Input: CandidConvertible, Output: CandidConvertible>(
        method: String,
        argument: Input,
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await query(
            method: method,
            argument: argument,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: .default,
            as: outputType
        )
    }

    public func query<Input: CandidConvertible, Output: CandidConvertible>(
        method: String,
        argument: Input,
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession? = nil,
        options: ICRequestOptions,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await query(
            method: method,
            arguments: CandidArguments(argument),
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            delegationTargetCanisterId: delegationTargetCanisterId,
            identity: identity,
            options: options,
            as: outputType
        )
    }

    /// Creates a reusable, fully signed query envelope without sending it.
    public func signQuery(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        delegationTargetCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions = .default
    ) throws -> ICSignedQuery {
        let requestText = canisterId ?? configuration.canisterId
        let effectiveText = effectiveCanisterId ?? requestText
        let delegationTargetText = delegationTargetCanisterId ?? requestText
        guard let canister = ICPrincipal.parse(requestText),
              ICPrincipal.parse(effectiveText) != nil,
              !method.isEmpty else {
            throw ICClientError.invalidCanisterId
        }
        try validateIdentityForRequest(
            identity,
            requestCanisterId: delegationTargetText,
            permission: .query
        )
        let (expiry, expiryNanoseconds) = try resolvedIngressExpiry(options, identity: identity)
        let content = requestContent(
            type: "query",
            canister: canister,
            method: method,
            arg: arg,
            identity: identity,
            ingressExpiry: expiryNanoseconds,
            nonce: options.nonce
        )
        return ICSignedQuery(
            requestID: ICRequestID.hash(of: content),
            canisterId: requestText,
            effectiveCanisterId: effectiveText,
            delegationTargetCanisterId: delegationTargetText,
            method: method,
            ingressExpiry: expiry,
            envelope: try Self.signedEnvelope(content: content, identity: identity)
        )
    }

    /// Sends a stored signed query and verifies its node signatures.
    public func querySigned(_ request: ICSignedQuery) async throws -> Data {
        let response = try await performSignedQuery(request)
        var subnet = try await verifiedSubnet(for: request.effectiveCanisterId, forceRefresh: false)
        do {
            try verify(response: response, requestID: request.requestID, subnet: subnet)
        } catch {
            subnet = try await verifiedSubnet(for: request.effectiveCanisterId, forceRefresh: true)
            try verify(response: response, requestID: request.requestID, subnet: subnet)
        }
        return try response.result()
    }

    /// Explicitly sends a stored signed query without authenticating its response.
    public func unsafeQuerySigned(_ request: ICSignedQuery) async throws -> Data {
        let response = try await performSignedQuery(request)
        return try response.result()
    }

    public func callRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> Data {
        try await callRaw(
            method: method,
            arg: arg,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: .default
        )
    }

    public func callRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions
    ) async throws -> Data {
        let submission = try await submitRaw(
            method: method,
            arg: arg,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options
        )
        return try await completeRaw(submission, identity: identity)
    }

    /// Submits an update and returns its ingress request ID before polling for completion.
    public func submitRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions = .default
    ) async throws -> ICUpdateSubmission {
        try await submitSigned(signUpdate(
            method: method,
            arg: arg,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options
        ))
    }

    /// Creates a reusable, fully signed update envelope without sending it.
    public func signUpdate(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions = .default
    ) throws -> ICSignedUpdate {
        let targetText = canisterId ?? configuration.canisterId
        let effectiveText = effectiveCanisterId ?? targetText
        guard let target = ICPrincipal.parse(targetText),
              ICPrincipal.parse(effectiveText) != nil,
              !method.isEmpty else {
            throw ICClientError.invalidCanisterId
        }
        try validateIdentityForRequest(identity, requestCanisterId: targetText, permission: .call)
        let (expiry, expiryNanoseconds) = try resolvedIngressExpiry(options, identity: identity)
        let content = requestContent(
            type: "call",
            canister: target,
            method: method,
            arg: arg,
            identity: identity,
            ingressExpiry: expiryNanoseconds,
            nonce: options.nonce
        )
        let requestID = ICRequestID.hash(of: content)
        let envelope = try Self.signedEnvelope(content: content, identity: identity)
        return ICSignedUpdate(
            requestID: requestID,
            canisterId: targetText,
            effectiveCanisterId: effectiveText,
            method: method,
            ingressExpiry: expiry,
            envelope: envelope
        )
    }

    /// Sends a stored signed update and returns before polling for completion.
    public func submitSigned(_ request: ICSignedUpdate) async throws -> ICUpdateSubmission {
        let content = try validateSignedRequest(
            envelope: request.envelope,
            requestID: request.requestID,
            canisterId: request.canisterId,
            effectiveCanisterId: request.effectiveCanisterId,
            method: request.method,
            ingressExpiry: request.ingressExpiry,
            expectedType: "call",
            authorizationCanisterId: request.canisterId
        )
        guard case .bytes(let sender) = try ICCBOR.requiredValue(
            try ICCBOR.requiredMap(content, context: "signed update content"),
            key: "sender",
            context: "signed update content"
        ), let effective = ICPrincipal.parse(request.effectiveCanisterId) else {
            throw ICClientError.invalidIdentity("Signed update metadata does not match its envelope.")
        }
        let (data, response) = try await postCBOR(
            request.envelope,
            to: apiURL(for: "call", canisterId: request.effectiveCanisterId, version: .v4),
            operation: "update \(request.method)"
        )
        if response.statusCode == 404 {
            return try await submitRawV2(
                envelope: request.envelope,
                requestID: request.requestID,
                method: request.method,
                effectiveText: request.effectiveCanisterId,
                sender: sender
            )
        }
        guard response.statusCode == 200 || response.statusCode == 202 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("update \(request.method)", data: data, response: response))
        }
        if response.statusCode == 202 || data.isEmpty {
            return updateSubmission(
                requestID: request.requestID,
                effectiveCanisterId: request.effectiveCanisterId,
                status: .pending,
                sender: sender
            )
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
            return updateSubmission(
                requestID: request.requestID,
                effectiveCanisterId: request.effectiveCanisterId,
                status: try ICCertificateVerifier.status(in: certificate, requestID: request.requestID),
                sender: sender
            )
        case "non_replicated_rejection":
            throw ICClientError.rejected(try parseReject(fields, context: "v4 rejection"))
        default:
            throw ICClientError.invalidResponse("unsupported v4 call status \(status)")
        }
    }

    /// Resolves a previously submitted update, polling only when its initial response was pending.
    public func completeRaw(
        _ submission: ICUpdateSubmission,
        identity: ICAuthSession
    ) async throws -> Data {
        try validateSubmissionIdentity(submission, identity: identity)
        return try await resolve(
            status: submission.initialStatus,
            requestID: submission.requestID,
            effectiveText: submission.effectiveCanisterId,
            identity: identity
        )
    }

    /// Performs an update with Candid arguments using the same verified path as `callRaw`.
    public func callCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> CandidReply {
        try await callCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: .default
        )
    }

    /// Performs a Candid update with per-request options.
    public func callCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions
    ) async throws -> CandidReply {
        let bytes = try arguments.encode()
        let reply = try await callRaw(
            method: method,
            arg: bytes,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options
        )
        return try CandidDecoder().decode(reply)
    }

    /// Encodes and submits a Candid update without waiting for its final reply.
    public func submitCandid(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions = .default
    ) async throws -> ICUpdateSubmission {
        try await submitRaw(
            method: method,
            arg: arguments.encode(),
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options
        )
    }

    /// Resolves and decodes a previously submitted Candid update.
    public func completeCandid(
        _ submission: ICUpdateSubmission,
        identity: ICAuthSession
    ) async throws -> CandidReply {
        let reply = try await completeRaw(submission, identity: identity)
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
        try await call(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: .default,
            as: outputType
        )
    }

    public func call<Output: CandidConvertible>(
        method: String,
        arguments: CandidArguments = CandidArguments(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        let reply = try await callCandid(
            method: method,
            arguments: arguments,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options
        )
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
            argument: argument,
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: .default,
            as: outputType
        )
    }

    public func call<Input: CandidConvertible, Output: CandidConvertible>(
        method: String,
        argument: Input,
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession,
        options: ICRequestOptions,
        as outputType: Output.Type = Output.self
    ) async throws -> Output {
        try await call(
            method: method,
            arguments: CandidArguments(argument),
            canisterId: canisterId,
            effectiveCanisterId: effectiveCanisterId,
            identity: identity,
            options: options,
            as: outputType
        )
    }

    /// Reads one certified status for an ingress request without waiting or retrying.
    public func requestStatus(
        requestID: Data,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> ICRequestStatus {
        let effectiveText = effectiveCanisterId ?? configuration.canisterId
        guard requestID.count == 32, let effective = ICPrincipal.parse(effectiveText) else {
            throw ICClientError.invalidConfiguration("Request status requires a 32-byte request ID and valid effective canister ID.")
        }
        try validateIdentityForRequest(identity, requestCanisterId: effectiveText, permission: .readState)
        let (_, expiryNanoseconds) = try resolvedIngressExpiry(.default, identity: identity)
        let content = readStateContent(
            paths: [[Data("request_status".utf8), requestID]],
            identity: identity,
            ingressExpiry: expiryNanoseconds
        )
        let envelope = try Self.signedEnvelope(content: content, identity: identity)
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "read_state", canisterId: effectiveText),
            operation: "read_state"
        )
        guard response.statusCode == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("read_state", data: data, response: response))
        }
        let certificate = try ICCertificateVerifier.verify(
            certificateData: decodeReadStateCertificate(data),
            effectiveCanisterID: effective,
            trustRoot: configuration.trustRoot
        )
        return Self.publicStatus(try ICCertificateVerifier.status(in: certificate, requestID: requestID))
    }

    /// Returns a submission's retained certified result, or performs one status request when it was accepted as pending.
    public func requestStatus(
        for submission: ICUpdateSubmission,
        identity: ICAuthSession
    ) async throws -> ICRequestStatus {
        try validateSubmissionIdentity(submission, identity: identity)
        if submission.initialStatus != .pending {
            return Self.publicStatus(submission.initialStatus)
        }
        return try await requestStatus(
            requestID: submission.requestID,
            effectiveCanisterId: submission.effectiveCanisterId,
            identity: identity
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
        guard requestId.count == 32, ICPrincipal.parse(effectiveText) != nil, maximumAttempts > 0 else {
            throw ICClientError.invalidConfiguration("Poll requires a 32-byte request ID and at least one attempt.")
        }
        for _ in 0..<maximumAttempts {
            try await sleep(configuration.network.pollingInterval)
            switch try await requestStatus(requestID: requestId, effectiveCanisterId: effectiveText, identity: identity) {
            case .replied(let reply): return reply
            case .rejected(let reject): throw ICClientError.rejected(reject)
            case .done: throw ICClientError.requestDoneWithoutReply
            case .absent, .received, .processing: continue
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

    private func validateSubmissionIdentity(_ submission: ICUpdateSubmission, identity: ICAuthSession) throws {
        let sender = ICPrincipal.selfAuthenticatingPublicKey(identity.delegation.publicKey)
        guard sender == submission.sender else {
            throw ICClientError.invalidIdentity("Update submission belongs to a different identity.")
        }
    }

    private static func publicStatus(_ status: ICCertificateStatus) -> ICRequestStatus {
        switch status {
        case .absent, .pending: return .absent
        case .received: return .received
        case .processing: return .processing
        case .replied(let data): return .replied(data)
        case .rejected(let reject): return .rejected(reject)
        case .done: return .done
        }
    }

    private func resolvedIngressExpiry(
        _ options: ICRequestOptions,
        identity: ICAuthSession?
    ) throws -> (Date, UInt64) {
        if let nonce = options.nonce,
           nonce.isEmpty || nonce.count > ICRequestOptions.maximumNonceBytes {
            throw ICClientError.invalidConfiguration("Request nonce must contain between 1 and 32 bytes.")
        }
        let now = Date()
        let expiry = options.ingressExpiry ?? now.addingTimeInterval(ICRequestOptions.maximumIngressTTL)
        let interval = expiry.timeIntervalSince1970
        guard interval.isFinite, expiry > now,
              expiry.timeIntervalSince(now) <= ICRequestOptions.maximumIngressTTL else {
            throw ICClientError.invalidConfiguration("Ingress expiry must be in the future and no more than 5 minutes away.")
        }
        let scaled = interval * 1_000_000_000
        guard scaled >= 0, scaled < Double(UInt64.max) else {
            throw ICClientError.invalidConfiguration("Ingress expiry is outside the supported range.")
        }
        let nanoseconds = UInt64(scaled)
        if let parentExpiry = identity?.delegation.delegations.map(\.delegation.expiration).min(),
           nanoseconds > parentExpiry {
            throw ICClientError.invalidIdentity("Ingress expiry exceeds the session delegation expiration.")
        }
        return (Date(timeIntervalSince1970: Double(nanoseconds) / 1_000_000_000), nanoseconds)
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
        requestCanisterId: String,
        effectiveCanisterId: String,
        delegationTargetCanisterId: String,
        identity: ICAuthSession?,
        options: ICRequestOptions
    ) async throws -> (ICQueryResponse, Data) {
        guard let canister = ICPrincipal.parse(requestCanisterId),
              ICPrincipal.parse(effectiveCanisterId) != nil,
              !method.isEmpty else {
            throw ICClientError.invalidCanisterId
        }
        let content: ICCBOR.Value
        let (_, expiryNanoseconds) = try resolvedIngressExpiry(options, identity: identity)
        if let identity {
            try validateIdentityForRequest(identity, requestCanisterId: delegationTargetCanisterId, permission: .query)
            content = requestContent(
                type: "query", canister: canister, method: method, arg: arg, identity: identity,
                ingressExpiry: expiryNanoseconds, nonce: options.nonce
            )
        } else {
            content = anonymousRequestContent(
                type: "query", canister: canister, method: method, arg: arg,
                ingressExpiry: expiryNanoseconds, nonce: options.nonce
            )
        }
        let envelope = try envelope(content: content, identity: identity)
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "query", canisterId: effectiveCanisterId),
            operation: "query \(method)"
        )
        guard response.statusCode == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("query \(method)", data: data, response: response))
        }
        return (try ICQueryResponse(cbor: data), ICRequestID.hash(of: content))
    }

    private func performSignedQuery(_ request: ICSignedQuery) async throws -> ICQueryResponse {
        _ = try validateSignedRequest(
            envelope: request.envelope,
            requestID: request.requestID,
            canisterId: request.canisterId,
            effectiveCanisterId: request.effectiveCanisterId,
            method: request.method,
            ingressExpiry: request.ingressExpiry,
            expectedType: "query",
            authorizationCanisterId: request.delegationTargetCanisterId
        )
        let (data, response) = try await postCBOR(
            request.envelope,
            to: apiURL(for: "query", canisterId: request.effectiveCanisterId),
            operation: "query \(request.method)"
        )
        guard response.statusCode == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("query \(request.method)", data: data, response: response))
        }
        return try ICQueryResponse(cbor: data)
    }

    private func validateSignedRequest(
        envelope: Data,
        requestID: Data,
        canisterId: String,
        effectiveCanisterId: String,
        method: String,
        ingressExpiry: Date,
        expectedType: String,
        authorizationCanisterId: String
    ) throws -> ICCBOR.Value {
        guard requestID.count == 32,
              let canister = ICPrincipal.parse(canisterId),
              ICPrincipal.parse(effectiveCanisterId) != nil,
              ICPrincipal.parse(authorizationCanisterId) != nil,
              !method.isEmpty,
              ingressExpiry > Date(),
              ingressExpiry.timeIntervalSinceNow <= ICRequestOptions.maximumIngressTTL else {
            throw ICClientError.invalidConfiguration("Signed request metadata is invalid or expired.")
        }
        let envelopeFields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(envelope), context: "signed request envelope")
        let content = try ICCBOR.requiredValue(envelopeFields, key: "content", context: "signed request envelope")
        let fields = try ICCBOR.requiredMap(content, context: "signed request content")
        guard case .text(let requestType) = try ICCBOR.requiredValue(fields, key: "request_type", context: "signed request content"),
              requestType == expectedType,
              case .bytes(let contentCanister) = try ICCBOR.requiredValue(fields, key: "canister_id", context: "signed request content"),
              contentCanister == canister,
              case .text(let contentMethod) = try ICCBOR.requiredValue(fields, key: "method_name", context: "signed request content"),
              contentMethod == method,
              case .unsigned(let contentExpiry) = try ICCBOR.requiredValue(fields, key: "ingress_expiry", context: "signed request content"),
              Date(timeIntervalSince1970: Double(contentExpiry) / 1_000_000_000) == ingressExpiry,
              ICRequestID.hash(of: content) == requestID,
              case .bytes(let sender) = try ICCBOR.requiredValue(fields, key: "sender", context: "signed request content"),
              case .bytes(let senderPublicKey) = try ICCBOR.requiredValue(envelopeFields, key: "sender_pubkey", context: "signed request envelope"),
              sender == ICPrincipal.selfAuthenticatingPublicKey(senderPublicKey),
              case .bytes(let senderSignature) = try ICCBOR.requiredValue(envelopeFields, key: "sender_sig", context: "signed request envelope") else {
            throw ICClientError.invalidIdentity("Signed request metadata does not match its envelope.")
        }
        if let nonce = ICCBOR.optionalValue(fields, key: "nonce") {
            guard case .bytes(let bytes) = nonce,
                  !bytes.isEmpty, bytes.count <= ICRequestOptions.maximumNonceBytes else {
                throw ICClientError.invalidConfiguration("Signed request nonce is invalid.")
            }
        }
        let chain = try delegationChain(from: envelopeFields, publicKey: senderPublicKey)
        let leafKey = try ICIdentityValidation.validateEnvelopeDelegationChain(
            chain,
            canisterId: authorizationCanisterId,
            permission: expectedType == "query" ? .query : .call,
            requestExpiration: contentExpiry,
            trustRoot: configuration.trustRoot
        )
        try Self.verifyEnvelopeSignature(senderSignature, requestID: requestID, derPublicKey: leafKey)
        return content
    }

    private func delegationChain(
        from envelopeFields: [(ICCBOR.Value, ICCBOR.Value)],
        publicKey: Data
    ) throws -> ICDelegationChain {
        guard case .array(let values) = try ICCBOR.requiredValue(
            envelopeFields, key: "sender_delegation", context: "signed request envelope"
        ) else {
            throw ICClientError.invalidIdentity("Signed request delegation chain is invalid.")
        }
        let signed = try values.map { value -> ICDelegationChain.SignedDelegation in
            let fields = try ICCBOR.requiredMap(value, context: "signed request delegation")
            let delegationValue = try ICCBOR.requiredValue(fields, key: "delegation", context: "signed request delegation")
            let delegationFields = try ICCBOR.requiredMap(delegationValue, context: "signed request delegation")
            guard case .bytes(let key) = try ICCBOR.requiredValue(delegationFields, key: "pubkey", context: "signed request delegation"),
                  case .unsigned(let expiration) = try ICCBOR.requiredValue(delegationFields, key: "expiration", context: "signed request delegation"),
                  case .bytes(let signature) = try ICCBOR.requiredValue(fields, key: "signature", context: "signed request delegation") else {
                throw ICClientError.invalidIdentity("Signed request delegation chain is invalid.")
            }
            let targets: [Data]?
            if let value = ICCBOR.optionalValue(delegationFields, key: "targets") {
                guard case .array(let items) = value else { throw ICClientError.invalidIdentity("Signed request targets are invalid.") }
                targets = try items.map {
                    guard case .bytes(let target) = $0 else { throw ICClientError.invalidIdentity("Signed request target is invalid.") }
                    return target
                }
            } else { targets = nil }
            let permissions: ICDelegationPermission?
            if let value = ICCBOR.optionalValue(delegationFields, key: "permissions") {
                guard case .text(let raw) = value, let parsed = ICDelegationPermission(rawValue: raw) else {
                    throw ICClientError.invalidIdentity("Signed request permissions are invalid.")
                }
                permissions = parsed
            } else { permissions = nil }
            return ICDelegationChain.SignedDelegation(
                delegation: .init(publicKey: key, expiration: expiration, targets: targets, permissions: permissions),
                signature: signature
            )
        }
        return ICDelegationChain(publicKey: publicKey, delegations: signed)
    }

    private static func verifyEnvelopeSignature(_ signature: Data, requestID: Data, derPublicKey: Data) throws {
        let challenge = Data([0x0a]) + Data("ic-request".utf8) + requestID
        do {
            try ICCertificateVerifier.validateEd25519DERKey(derPublicKey)
            let raw = derPublicKey.dropFirst(ICRC167Codec.ed25519DERPrefix.count)
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
            guard key.isValidSignature(signature, for: challenge) else { throw ICClientError.invalidIdentity("Signed request signature is invalid.") }
        } catch let error as ICClientError {
            throw error
        } catch {
            throw ICClientError.invalidIdentity("Signed request signature is invalid.")
        }
    }

    private func verifiedSubnet(
        for canisterText: String,
        forceRefresh: Bool
    ) async throws -> ICVerifiedSubnet {
        guard let canister = ICPrincipal.parse(canisterText) else { throw ICClientError.invalidCanisterId }
        if !forceRefresh, let cached = await subnetCache.value(for: canister) { return cached }
        let content = readStateContent(paths: [[Data("subnet".utf8)]], identity: nil)
        let request = try envelope(content: content, identity: nil)
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
        let subnet = try ICCertificateVerifier.subnet(
            from: certificate,
            effectiveCanisterID: canister,
            trustRoot: configuration.trustRoot
        )
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
        identity: ICAuthSession,
        ingressExpiry: UInt64,
        nonce: Data?
    ) -> ICCBOR.Value {
        var fields: [(ICCBOR.Value, ICCBOR.Value)] = [
            (.text("request_type"), .text(type)),
            (.text("canister_id"), .bytes(canister)),
            (.text("method_name"), .text(method)),
            (.text("arg"), .bytes(arg)),
            (.text("sender"), .bytes(ICPrincipal.selfAuthenticatingPublicKey(identity.delegation.publicKey))),
            (.text("ingress_expiry"), .unsigned(ingressExpiry)),
        ]
        if let nonce { fields.append((.text("nonce"), .bytes(nonce))) }
        return .map(fields)
    }

    private func anonymousRequestContent(
        type: String,
        canister: Data,
        method: String,
        arg: Data,
        ingressExpiry: UInt64,
        nonce: Data?
    ) -> ICCBOR.Value {
        var fields: [(ICCBOR.Value, ICCBOR.Value)] = [
            (.text("request_type"), .text(type)),
            (.text("canister_id"), .bytes(canister)),
            (.text("method_name"), .text(method)),
            (.text("arg"), .bytes(arg)),
            (.text("sender"), .bytes(Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(ingressExpiry)),
        ]
        if let nonce { fields.append((.text("nonce"), .bytes(nonce))) }
        return .map(fields)
    }

    private func readStateContent(
        paths: [[Data]],
        identity: ICAuthSession?,
        ingressExpiry: UInt64? = nil
    ) -> ICCBOR.Value {
        .map([
            (.text("request_type"), .text("read_state")),
            (.text("paths"), .array(paths.map { .array($0.map(ICCBOR.Value.bytes)) })),
            (.text("sender"), .bytes(identity.map { ICPrincipal.selfAuthenticatingPublicKey($0.delegation.publicKey) } ?? Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(ingressExpiry ?? Self.ingressExpiry())),
        ])
    }

    private func envelope(content: ICCBOR.Value, identity: ICAuthSession?) throws -> Data {
        if let identity { return try Self.signedEnvelope(content: content, identity: identity) }
        return ICCBOR.encode(.tagged(ICCBOR.selfDescribeTag, .map([(.text("content"), content)])))
    }

    private static func ingressExpiry() -> UInt64 {
        UInt64((Date().timeIntervalSince1970 + ICRequestOptions.maximumIngressTTL) * 1_000_000_000)
    }

    private func submitRawV2(
        envelope: Data,
        requestID: Data,
        method: String,
        effectiveText: String,
        sender: Data
    ) async throws -> ICUpdateSubmission {
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
            throw ICClientError.rejected(try parseReject(fields, context: "v2 rejection"))
        }
        return updateSubmission(
            requestID: requestID,
            effectiveCanisterId: effectiveText,
            status: .pending,
            sender: sender
        )
    }

    private func updateSubmission(
        requestID: Data,
        effectiveCanisterId: String,
        status: ICCertificateStatus,
        sender: Data
    ) -> ICUpdateSubmission {
        ICUpdateSubmission(
            requestID: requestID,
            effectiveCanisterId: effectiveCanisterId,
            initialStatus: status,
            sender: sender
        )
    }

    private func resolve(
        status: ICCertificateStatus,
        requestID: Data,
        effectiveText: String,
        identity: ICAuthSession
    ) async throws -> Data {
        switch status {
        case .replied(let data): return data
        case .rejected(let reject): throw ICClientError.rejected(reject)
        case .done: throw ICClientError.requestDoneWithoutReply
        case .absent, .pending, .received, .processing:
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
        return ICReject(code: code, message: message, errorCode: errorCode, isCertified: false)
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
