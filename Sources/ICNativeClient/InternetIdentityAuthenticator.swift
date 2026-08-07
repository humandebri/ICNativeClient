// iOS Internet Identity authenticator using the ICRC-167 browser URL transport.

#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import CryptoKit
import Foundation
import UIKit

@available(iOS 17.4, *)
public final class ICInternetIdentityAuthenticator: NSObject, ASWebAuthenticationPresentationContextProviding {
    public nonisolated static let callbackPath = "/ios-auth-callback"
    public nonisolated static let defaultAuthorizationTimeout: Duration = .seconds(330)

    private let configuration: ICClientConfiguration
    private let callbackDomain: String
    @MainActor private var activeAttempt: AuthorizationAttempt?

    public init(configuration: ICClientConfiguration, callbackDomain: String) {
        self.configuration = configuration
        self.callbackDomain = callbackDomain
    }

    @MainActor
    public func authenticate(
        timeout: Duration = ICInternetIdentityAuthenticator.defaultAuthorizationTimeout,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> ICAuthSession {
        guard timeout > .zero else {
            throw ICClientError.authorizationFailed("Internet Identity authorization timeout must be positive.")
        }
        guard activeAttempt == nil else {
            throw ICClientError.authorizationFailed("Internet Identity authorization is already in progress.")
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        let state = UUID().uuidString
        let requestID = UUID().uuidString
        let url = try Self.authorizationURL(
            callbackDomain: callbackDomain,
            configuration: configuration,
            state: state,
            requestID: requestID,
            privateKey: privateKey
        )

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }

                let attempt = AuthorizationAttempt(continuation: continuation)
                let session = ASWebAuthenticationSession(
                    url: url,
                    callback: Self.callbackMatcher(callbackDomain: callbackDomain)
                ) { [weak self, weak attempt] callbackURL, error in
                    Task { @MainActor in
                        guard let self, let attempt else { return }
                        if let error {
                            self.finish(attempt, with: .failure(error))
                            return
                        }
                        guard let callbackURL else {
                            self.finish(attempt, with: .failure(ICClientError.invalidPayload))
                            return
                        }
                        do {
                            let authSession = try Self.session(
                                from: callbackURL,
                                callbackDomain: self.callbackDomain,
                                expectedState: state,
                                expectedRequestID: requestID,
                                privateKey: privateKey,
                                configuration: self.configuration
                            )
                            self.finish(attempt, with: .success(authSession))
                        } catch {
                            self.finish(attempt, with: .failure(error))
                        }
                    }
                }
                attempt.session = session
                session.presentationContextProvider = self
                session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
                activeAttempt = attempt
                attempt.timeoutTask = Task { [weak self, weak attempt] in
                    do {
                        try await Task.sleep(for: timeout)
                    } catch {
                        return
                    }
                    guard let self, let attempt else { return }
                    self.finish(attempt, with: .failure(ICClientError.authorizationTimedOut), cancelSession: true)
                }
                if !session.start() {
                    finish(
                        attempt,
                        with: .failure(ICClientError.authorizationFailed("Internet Identity could not start."))
                    )
                }
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                guard let self, let attempt = self.activeAttempt else { return }
                self.finish(attempt, with: .failure(CancellationError()), cancelSession: true)
            }
        }
    }

    public static func authorizationURL(
        callbackDomain: String,
        configuration: ICClientConfiguration,
        state: String,
        requestID: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) throws -> URL {
        guard !state.isEmpty, !requestID.isEmpty else {
            throw ICClientError.invalidPayload
        }
        var provider = URLComponents(url: configuration.identityProvider, resolvingAgainstBaseURL: false)
        guard provider?.scheme == "https",
              provider?.host != nil,
              provider?.fragment == nil,
              provider?.user == nil,
              provider?.password == nil else {
            throw ICClientError.invalidPayload
        }

        let request = DelegationRequest(
            id: requestID,
            params: .init(
                publicKey: ICIdentitySession
                    .derPublicKey(from: privateKey.publicKey.rawRepresentation)
                    .base64EncodedString(),
                maxTimeToLive: ICIdentitySession.maxTimeToLiveNanos,
                derivationOrigin: configuration.derivationOrigin
            )
        )
        let message = String(decoding: try JSONEncoder().encode(request), as: UTF8.self)
        var fragment = URLComponents()
        fragment.queryItems = [
            URLQueryItem(name: "message", value: message),
            URLQueryItem(name: "callback", value: callbackURL(callbackDomain: callbackDomain).absoluteString),
            URLQueryItem(name: "state", value: state),
        ]
        guard let encodedFragment = fragment.percentEncodedQuery else {
            throw ICClientError.invalidPayload
        }
        provider?.percentEncodedFragment = encodedFragment
        guard let url = provider?.url else {
            throw ICClientError.invalidPayload
        }
        return url
    }

    public static func callbackURL(callbackDomain: String) -> URL {
        URL(string: "https://\(callbackDomain)\(callbackPath)")!
    }

    public static func callbackMatcher(callbackDomain: String) -> ASWebAuthenticationSession.Callback {
        .https(host: callbackDomain, path: callbackPath)
    }

    public static func session(
        from callbackURL: URL,
        callbackDomain: String,
        expectedState: String,
        expectedRequestID: String,
        privateKey: Curve25519.Signing.PrivateKey,
        configuration: ICClientConfiguration,
        now: Date = Date()
    ) throws -> ICAuthSession {
        guard callbackURL.scheme == "https",
              callbackURL.host == callbackDomain,
              callbackURL.port == nil,
              callbackURL.user == nil,
              callbackURL.password == nil,
              callbackURL.path == callbackPath,
              callbackURL.query == nil,
              let fragment = callbackURL.fragment else {
            throw ICClientError.invalidPayload
        }
        let values = try fragmentValues(fragment)
        guard Set(values.keys) == ["message", "state"],
              values["state"] == expectedState,
              let message = values["message"],
              let data = message.data(using: .utf8) else {
            throw ICClientError.invalidPayload
        }

        let response: DelegationResponse
        do {
            response = try JSONDecoder().decode(DelegationResponse.self, from: data)
        } catch {
            throw ICClientError.invalidPayload
        }
        guard response.jsonrpc == "2.0", response.id == expectedRequestID else {
            throw ICClientError.invalidPayload
        }
        if let error = response.error {
            throw ICClientError.authorizationFailed(error.message)
        }
        guard let result = response.result,
              let userPublicKey = Data(base64Encoded: result.publicKey),
              !result.signerDelegation.isEmpty else {
            throw ICClientError.invalidPayload
        }

        let delegations = try result.signerDelegation.map { signed in
            guard let publicKey = Data(base64Encoded: signed.delegation.publicKey),
                  let signature = Data(base64Encoded: signed.signature),
                  let expiration = UInt64(signed.delegation.expiration) else {
                throw ICClientError.invalidPayload
            }
            let targets = try signed.delegation.targets?.map { target in
                guard let principal = ICPrincipal.parse(target) else {
                    throw ICClientError.invalidPayload
                }
                return principal
            }
            return ICDelegationChain.SignedDelegation(
                delegation: .init(
                    publicKey: publicKey,
                    expiration: expiration,
                    targets: targets
                ),
                signature: signature
            )
        }
        let chain = ICDelegationChain(publicKey: userPublicKey, delegations: delegations)
        try validateRequestedLifetime(chain, now: now)
        return try ICIdentitySession.makeSession(
            privateKey: privateKey,
            delegation: chain,
            configuration: configuration,
            createdAt: now
        )
    }

    private static func validateRequestedLifetime(_ chain: ICDelegationChain, now: Date) throws {
        guard let earliestExpiration = chain.delegations.map(\.delegation.expiration).min(),
              let requestedTTL = UInt64(ICIdentitySession.maxTimeToLiveNanos) else {
            throw ICClientError.invalidPayload
        }
        let nowNanos = UInt64(now.timeIntervalSince1970 * 1_000_000_000)
        let clockSkewNanos: UInt64 = 5 * 60 * 1_000_000_000
        guard earliestExpiration <= nowNanos + requestedTTL + clockSkewNanos else {
            throw ICClientError.invalidPayload
        }
    }

    private static func fragmentValues(_ fragment: String) throws -> [String: String] {
        var components = URLComponents()
        components.percentEncodedQuery = fragment
        var values: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard let value = item.value, values[item.name] == nil else {
                throw ICClientError.invalidPayload
            }
            values[item.name] = value
        }
        return values
    }

    @MainActor
    private func finish(
        _ attempt: AuthorizationAttempt,
        with result: Result<ICAuthSession, Error>,
        cancelSession: Bool = false
    ) {
        guard activeAttempt === attempt, let continuation = attempt.continuation else { return }
        activeAttempt = nil
        attempt.continuation = nil
        attempt.timeoutTask?.cancel()
        attempt.timeoutTask = nil
        if cancelSession {
            attempt.session?.cancel()
        }
        attempt.session = nil
        continuation.resume(with: result)
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }

    private final class AuthorizationAttempt {
        var continuation: CheckedContinuation<ICAuthSession, Error>?
        var session: ASWebAuthenticationSession?
        var timeoutTask: Task<Void, Never>?

        init(continuation: CheckedContinuation<ICAuthSession, Error>) {
            self.continuation = continuation
        }
    }
}

private struct DelegationRequest: Encodable {
    let jsonrpc = "2.0"
    let id: String
    let method = "icrc34_delegation"
    let params: Params

    struct Params: Encodable {
        let publicKey: String
        let maxTimeToLive: String
        let derivationOrigin: String

        enum CodingKeys: String, CodingKey {
            case publicKey, maxTimeToLive
            case derivationOrigin = "icrc95DerivationOrigin"
        }
    }
}

private struct DelegationResponse: Decodable {
    let jsonrpc: String
    let id: String
    let result: Result?
    let error: RPCError?

    struct Result: Decodable {
        let publicKey: String
        let signerDelegation: [SignedDelegation]
    }

    struct SignedDelegation: Decodable {
        let delegation: Delegation
        let signature: String
    }

    struct Delegation: Decodable {
        let publicKey: String
        let expiration: String
        let targets: [String]?

        enum CodingKeys: String, CodingKey {
            case publicKey = "pubkey"
            case expiration, targets
        }
    }

    struct RPCError: Decodable {
        let code: Int
        let message: String
    }
}
#endif
