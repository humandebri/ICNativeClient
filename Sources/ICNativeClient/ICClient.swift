// Raw Internet Computer HTTP API client for iOS. It builds unsigned query
// envelopes, signed query/call/read_state envelopes, and returns raw reply args.

import CryptoKit
import Foundation

public final class ICClient {
    private static let requestTimeout: TimeInterval = 20
    private let session: URLSession
    public let configuration: ICClientConfiguration

    public init(configuration: ICClientConfiguration, session: URLSession = .shared) {
        self.configuration = configuration
        self.session = session
    }

    public func apiURL(
        for requestType: String,
        canisterId: String? = nil,
        version: ICClientAPIVersion? = nil
    ) -> URL {
        configuration.apiURL(for: requestType, canisterId: canisterId, version: version)
    }

    public func queryRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        identity: ICAuthSession? = nil
    ) async throws -> Data {
        let requestCanisterId = canisterId ?? configuration.canisterId
        guard let canister = ICPrincipal.parse(requestCanisterId) else {
            throw ICClientError.invalidCanisterId
        }
        let envelope: Data
        if let identity {
            try validateIdentity(identity, requestCanisterId: requestCanisterId)
            let content = requestContent(type: "query", canister: canister, method: method, arg: arg, identity: identity)
            envelope = try Self.signedEnvelope(content: content, identity: identity)
        } else {
            envelope = ICCBOR.queryEnvelope(
                canisterId: canister,
                method: method,
                arg: arg,
                ingressExpiry: Self.ingressExpiry()
            )
        }
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "query", canisterId: requestCanisterId),
            operation: "query \(method)"
        )
        guard let status = (response as? HTTPURLResponse)?.statusCode, status == 200 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("query \(method)", data: data, response: response))
        }
        // Query signatures are not verified yet. This matches the current app
        // behavior while moving the HTTP endpoint to the IC v3 API shape.
        guard let arg = ICCBOR.decodeReplyArg(data) else {
            if let message = ICCBOR.decodeRejectMessage(data) {
                throw ICClientError.rejected(message)
            }
            throw ICClientError.emptyResponse
        }
        return arg
    }

    public func callRaw(
        method: String,
        arg: Data = Data(),
        canisterId: String? = nil,
        effectiveCanisterId: String? = nil,
        identity: ICAuthSession
    ) async throws -> Data {
        let targetCanisterId = canisterId ?? configuration.canisterId
        let effectiveId = effectiveCanisterId ?? targetCanisterId
        guard let canister = ICPrincipal.parse(targetCanisterId),
              ICPrincipal.parse(effectiveId) != nil else {
            throw ICClientError.invalidCanisterId
        }
        try validateIdentity(identity, requestCanisterId: effectiveId)
        let content = requestContent(type: "call", canister: canister, method: method, arg: arg, identity: identity)
        let requestId = ICRequestID.hash(of: content)
        let envelope = try Self.signedEnvelope(content: content, identity: identity)
        let v4URL = apiURL(for: "call", canisterId: effectiveId, version: .v4)
        let (data, response) = try await postCBOR(
            envelope,
            to: v4URL,
            operation: "update \(method)"
        )
        if let status = (response as? HTTPURLResponse)?.statusCode,
           status == 404 {
            return try await callRawV2(
                envelope: envelope,
                requestId: requestId,
                method: method,
                effectiveId: effectiveId,
                identity: identity
            )
        }
        return try await handleCallResponse(
            data: data,
            response: response,
            requestId: requestId,
            method: method,
            effectiveId: effectiveId,
            identity: identity
        )
    }

    private func callRawV2(
        envelope: Data,
        requestId: Data,
        method: String,
        effectiveId: String,
        identity: ICAuthSession
    ) async throws -> Data {
        let (data, response) = try await postCBOR(
            envelope,
            to: apiURL(for: "call", canisterId: effectiveId, version: .v2),
            operation: "update \(method)"
        )
        return try await handleCallResponse(
            data: data,
            response: response,
            requestId: requestId,
            method: method,
            effectiveId: effectiveId,
            identity: identity
        )
    }

    private func handleCallResponse(
        data: Data,
        response: URLResponse,
        requestId: Data,
        method: String,
        effectiveId: String,
        identity: ICAuthSession
    ) async throws -> Data {
        guard let status = (response as? HTTPURLResponse)?.statusCode, status == 200 || status == 202 else {
            throw ICClientError.backendUnavailable(Self.httpFailureContext("update \(method)", data: data, response: response))
        }
        if let arg = ICCBOR.decodeReplyArg(data) {
            return arg
        }
        if let message = ICCBOR.decodeRejectMessage(data) {
            throw ICClientError.rejected(message)
        }
        if !data.isEmpty {
            let result = try ICCBOR.certificateStatusArg(from: data, requestId: requestId)
            if let reply = try result?.get() {
                return reply
            }
        }
        return try await poll(requestId: requestId, canisterId: effectiveId, identity: identity)
    }

    public func poll(
        requestId: Data,
        canisterId: String? = nil,
        identity: ICAuthSession,
        attempts: Int = 30
    ) async throws -> Data {
        let requestCanisterId = canisterId ?? configuration.canisterId
        guard ICPrincipal.parse(requestCanisterId) != nil else {
            throw ICClientError.invalidCanisterId
        }
        try validateIdentity(identity, requestCanisterId: requestCanisterId)
        let url = apiURL(for: "read_state", canisterId: requestCanisterId)
        for _ in 0..<attempts {
            try await Task.sleep(nanoseconds: 1_000_000_000)
            let content: ICCBOR.Value = .map([
                (.text("request_type"), .text("read_state")),
                (.text("paths"), .array([.array([.bytes(Data("request_status".utf8)), .bytes(requestId)])])),
                (.text("sender"), .bytes(ICPrincipal.selfAuthenticatingPublicKey(identity.delegation.publicKey))),
                (.text("ingress_expiry"), .unsigned(Self.ingressExpiry())),
            ])
            let envelope = try Self.signedEnvelope(content: content, identity: identity)
            let (data, response) = try await postCBOR(envelope, to: url, operation: "read_state")
            guard let status = (response as? HTTPURLResponse)?.statusCode, status == 200 else {
                throw ICClientError.backendUnavailable(Self.httpFailureContext("read_state", data: data, response: response))
            }
            // read_state certificates are parsed but not cryptographically verified yet.
            if let result = try ICCBOR.certificateStatusArg(from: data, requestId: requestId) {
                if let reply = try result.get() {
                    return reply
                }
            }
        }
        throw ICClientError.pollTimeout
    }

    public func validateIdentity(_ identity: ICAuthSession, requestCanisterId: String) throws {
        do {
            try ICIdentityBridge.validateSession(identity, configuration: configuration, requestCanisterId: requestCanisterId)
        } catch ICClientError.invalidPayload {
            throw ICClientError.invalidIdentity("Internet Identity session is not valid for this canister.")
        } catch {
            throw error
        }
    }

    public static func signedEnvelope(content: ICCBOR.Value, identity: ICAuthSession) throws -> Data {
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: identity.sessionPrivateKey)
        let requestId = ICRequestID.hash(of: content)
        let challenge = Data([0x0a]) + Data("ic-request".utf8) + requestId
        let signature = try privateKey.signature(for: challenge)
        return ICCBOR.signedEnvelope(
            content: content,
            publicKey: identity.delegation.publicKey,
            signature: signature,
            delegation: identity.delegation
        )
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

    private static func ingressExpiry() -> UInt64 {
        UInt64((Date().timeIntervalSince1970 + 300) * 1_000_000_000)
    }

    private func postCBOR(_ body: Data, to url: URL, operation: String) async throws -> (Data, URLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = Self.requestTimeout
        request.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        do {
            return try await session.data(for: request)
        } catch let error as URLError {
            guard error.code != .cancelled else { throw error }
            throw ICClientError.backendUnavailable("\(operation): \(Self.urlErrorContext(error))")
        }
    }

    private static func httpFailureContext(_ operation: String, data: Data, response: URLResponse) -> String {
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard let body = responseBodyDetail(data) else {
            return "\(operation) HTTP \(status)"
        }
        return "\(operation) HTTP \(status): \(body)"
    }

    private static func responseBodyDetail(_ data: Data) -> String? {
        guard !data.isEmpty,
              let text = String(data: data.prefix(1_000), encoding: .utf8) else {
            return nil
        }
        let normalized = text
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        let lowercased = normalized.lowercased()
        if lowercased.contains("<!doctype html") ||
            lowercased.contains("<html") ||
            lowercased.contains("<head") ||
            lowercased.contains("<body") {
            return nil
        }
        return String(normalized.prefix(240))
    }

    private static func urlErrorContext(_ error: URLError) -> String {
        switch error.code {
        case .cannotFindHost, .cannotConnectToHost:
            return "cannot connect to host"
        case .networkConnectionLost:
            return "network connection lost"
        case .notConnectedToInternet:
            return "not connected to the internet"
        case .timedOut:
            return "request timed out"
        default:
            return error.localizedDescription
        }
    }
}
