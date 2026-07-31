// iOS Internet Identity authenticator. It opens a configured native-auth bridge
// with ASWebAuthenticationSession and converts the callback payload to a session.

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
    private let authOrigin: URL
    private let callbackDomain: String
    @MainActor private var activeAttempt: AuthorizationAttempt?

    public init(configuration: ICClientConfiguration, authOrigin: URL, callbackDomain: String) {
        self.configuration = configuration
        self.authOrigin = authOrigin
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
        let url = Self.authorizationURL(
            authOrigin: authOrigin,
            callbackDomain: callbackDomain,
            configuration: configuration,
            state: state,
            privateKey: privateKey
        )
        let callback = Self.callbackMatcher(callbackDomain: callbackDomain)

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: CancellationError())
                    return
                }

                let attempt = AuthorizationAttempt(continuation: continuation)
                let session = ASWebAuthenticationSession(url: url, callback: callback) { [weak self, weak attempt] callbackURL, error in
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
                            let session = try Self.session(
                                from: callbackURL,
                                expectedState: state,
                                privateKey: privateKey,
                                configuration: self.configuration
                            )
                            self.finish(attempt, with: .success(session))
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

    public static func authorizationURL(
        authOrigin: URL,
        callbackDomain: String,
        configuration: ICClientConfiguration,
        state: String,
        privateKey: Curve25519.Signing.PrivateKey
    ) -> URL {
        let sessionPublicKey = ICIdentityBridge.derPublicKey(from: privateKey.publicKey.rawRepresentation)
        let queryItems = [
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "callback", value: callbackURL(callbackDomain: callbackDomain).absoluteString),
            URLQueryItem(name: "sessionPublicKey", value: base64URLEncoded(sessionPublicKey)),
            URLQueryItem(name: "maxTimeToLive", value: ICIdentityBridge.maxTimeToLiveNanos),
            URLQueryItem(name: "identityProvider", value: configuration.identityProvider.absoluteString),
        ]
        var components = URLComponents()
        components.queryItems = queryItems
        let query = components.percentEncodedQuery ?? ""
        let origin = authOrigin.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return URL(string: "\(origin)/#/native-auth?\(query)")!
    }

    public static func callbackURL(callbackDomain: String) -> URL {
        URL(string: "https://\(callbackDomain)\(callbackPath)")!
    }

    public static func callbackMatcher(callbackDomain: String) -> ASWebAuthenticationSession.Callback {
        .https(host: callbackDomain, path: callbackPath)
    }

    public static func session(
        from callbackURL: URL,
        expectedState: String,
        privateKey: Curve25519.Signing.PrivateKey,
        configuration: ICClientConfiguration
    ) throws -> ICAuthSession {
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false) else {
            throw ICClientError.invalidPayload
        }
        let values = try callbackQueryValues(from: components)
        guard values["state"] == expectedState else {
            throw ICClientError.invalidPayload
        }
        if let encodedError = values["error"] {
            let message = String(data: try base64URLDecoded(encodedError), encoding: .utf8) ?? "Internet Identity authorization failed."
            throw ICClientError.authorizationFailed(message)
        }
        guard let encodedResult = values["result"],
              let payload = String(data: try base64URLDecoded(encodedResult), encoding: .utf8) else {
            throw ICClientError.invalidPayload
        }
        return try ICIdentityBridge.makeSession(from: payload, privateKey: privateKey, configuration: configuration)
    }

    public static func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func base64URLDecoded(_ value: String) throws -> Data {
        let base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64 + padding) else {
            throw ICClientError.invalidPayload
        }
        return data
    }

    private static func callbackQueryValues(from components: URLComponents) throws -> [String: String] {
        var values: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard let value = item.value else { continue }
            guard values[item.name] == nil else {
                throw ICClientError.invalidPayload
            }
            values[item.name] = value
        }
        return values
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
#endif
