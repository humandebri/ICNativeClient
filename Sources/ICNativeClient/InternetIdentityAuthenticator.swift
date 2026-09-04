// Direct ICRC-167 Internet Identity authentication for native iOS clients.

#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import Foundation
import UIKit

@available(iOS 17.4, *)
public final class ICInternetIdentityAuthenticator: NSObject, ASWebAuthenticationPresentationContextProviding {
    public static let callbackPath = ICRC167Codec.callbackPath
    public static let defaultMaxTimeToLiveNanoseconds = ICRC167Codec.defaultMaxTimeToLiveNanoseconds

    private let configuration: ICClientConfiguration
    private let callbackURL: URL
    private let maxTimeToLiveNanoseconds: UInt64
    private var activeSession: ASWebAuthenticationSession?

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

    @MainActor
    public func authenticate() async throws -> ICAuthSession {
        guard activeSession == nil else {
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

        return try await withCheckedThrowingContinuation { continuation in
            var didComplete = false
            let finish: @MainActor (Result<ICAuthSession, Error>) -> Void = { result in
                guard !didComplete else { return }
                didComplete = true
                self.activeSession = nil
                continuation.resume(with: result)
            }
            let session = ASWebAuthenticationSession(
                url: authorizationURL,
                callback: callback
            ) { callbackURL, error in
                Task { @MainActor in
                    if let error {
                        finish(.failure(error))
                        return
                    }
                    guard let callbackURL else {
                        finish(.failure(ICClientError.invalidPayload))
                        return
                    }
                    do {
                        let authenticatedSession = try ICRC167Codec.session(
                            from: callbackURL,
                            expectedCallbackURL: self.callbackURL,
                            pendingRequest: pendingRequest,
                            configuration: self.configuration
                        )
                        finish(.success(authenticatedSession))
                    } catch {
                        finish(.failure(error))
                    }
                }
            }
            session.presentationContextProvider = self
            activeSession = session
            if !session.start() {
                finish(.failure(ICClientError.authorizationFailed("Internet Identity could not start.")))
            }
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}
#endif
