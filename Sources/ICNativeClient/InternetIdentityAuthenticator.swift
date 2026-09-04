// Direct ICRC-167 Internet Identity authentication for native iOS clients.

#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import Foundation
import UIKit

@available(iOS 17.4, *)
public final class ICInternetIdentityAuthenticator: NSObject, ASWebAuthenticationPresentationContextProviding {
    public nonisolated static let defaultAuthorizationTimeout: Duration = .seconds(330)
    public static let callbackPath = ICRC167Codec.callbackPath
    public static let defaultMaxTimeToLiveNanoseconds = ICRC167Codec.defaultMaxTimeToLiveNanoseconds

    private let configuration: ICClientConfiguration
    private let callbackURL: URL
    private let maxTimeToLiveNanoseconds: UInt64
    @MainActor private var activeAttempt: AuthorizationAttempt?

    public init(
        configuration: ICClientConfiguration,
        callbackURL: URL,
        maxTimeToLiveNanoseconds: UInt64? = nil
    ) throws {
        try ICRC167Codec.validateInternetIdentityURL(configuration.internetIdentityURL)
        try ICRC167Codec.validateCallbackURL(callbackURL)
        let lifetime = maxTimeToLiveNanoseconds ?? configuration.delegationTTLNanoseconds
        guard lifetime > 0,
              lifetime <= ICClientConfiguration.maximumDelegationTTLNanoseconds else {
            throw ICClientError.invalidConfiguration("Internet Identity delegation lifetime must not exceed 30 days.")
        }
        self.configuration = configuration
        self.callbackURL = callbackURL
        self.maxTimeToLiveNanoseconds = lifetime
    }

    public convenience init(
        configuration: ICClientConfiguration,
        callbackDomain: String,
        callbackPath: String,
        maxTimeToLiveNanoseconds: UInt64? = nil
    ) throws {
        try self.init(
            configuration: configuration,
            callbackURL: Self.callbackURL(callbackDomain: callbackDomain, callbackPath: callbackPath),
            maxTimeToLiveNanoseconds: maxTimeToLiveNanoseconds
        )
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
            throw ICClientError.authorizationFailed("Internet Identity authentication is already in progress.")
        }

        let pendingRequest = try ICRC167Codec.makePendingRequest(
            maxTimeToLiveNanoseconds: maxTimeToLiveNanoseconds
        )
        let authorizationURL = try ICRC167Codec.authorizationURL(
            configuration: configuration,
            callbackURL: callbackURL,
            pendingRequest: pendingRequest
        )
        guard let callbackHost = callbackURL.host else {
            throw ICClientError.invalidConfiguration("Callback URL has no host.")
        }
        let callback = ASWebAuthenticationSession.Callback.https(
            host: callbackHost,
            path: callbackURL.path
        )

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }

                let attempt = AuthorizationAttempt(continuation: continuation)
                let session = ASWebAuthenticationSession(
                    url: authorizationURL,
                    callback: callback
                ) { [weak self, weak attempt] returnedURL, error in
                    Task { @MainActor in
                        guard let self, let attempt else { return }
                        if let error {
                            self.finish(attempt, with: .failure(error))
                            return
                        }
                        guard let returnedURL else {
                            self.finish(attempt, with: .failure(ICClientError.invalidPayload))
                            return
                        }
                        do {
                            let authenticatedSession = try ICRC167Codec.session(
                                from: returnedURL,
                                expectedCallbackURL: self.callbackURL,
                                pendingRequest: pendingRequest,
                                configuration: self.configuration
                            )
                            self.finish(attempt, with: .success(authenticatedSession))
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

    public static func callbackURL(callbackDomain: String, callbackPath: String) throws -> URL {
        guard !callbackDomain.isEmpty,
              callbackPath.hasPrefix("/"),
              !callbackPath.hasPrefix("//") else {
            throw ICClientError.invalidConfiguration("Callback domain and explicit callback path are required.")
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = callbackDomain
        components.path = callbackPath
        guard let url = components.url,
              url.host?.lowercased() == callbackDomain.lowercased(),
              url.path == callbackPath else {
            throw ICClientError.invalidConfiguration("Callback URL could not be constructed.")
        }
        try ICRC167Codec.validateCallbackURL(url)
        return url
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

    @MainActor
    private final class AuthorizationAttempt {
        var continuation: CheckedContinuation<ICAuthSession, Error>?
        var session: ASWebAuthenticationSession?
        var timeoutTask: Task<Void, Never>?

        init(continuation: CheckedContinuation<ICAuthSession, Error>) {
            self.continuation = continuation
        }
    }
}
#endif
