// iOS Internet Identity authenticator. It opens a configured native-auth bridge
// with ASWebAuthenticationSession and converts the callback payload to a session.

#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import CryptoKit
import Foundation
import UIKit

@available(iOS 17.4, *)
public final class ICInternetIdentityAuthenticator: NSObject, ASWebAuthenticationPresentationContextProviding {
    public static let callbackPath = "/ios-auth-callback"

    private let configuration: ICClientConfiguration
    private let authOrigin: URL
    private let callbackDomain: String
    private var activeSession: ASWebAuthenticationSession?

    public init(configuration: ICClientConfiguration, authOrigin: URL, callbackDomain: String) {
        self.configuration = configuration
        self.authOrigin = authOrigin
        self.callbackDomain = callbackDomain
    }

    @MainActor
    public func authenticate() async throws -> ICAuthSession {
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

        return try await withCheckedThrowingContinuation { continuation in
            var didComplete = false
            let finish: @MainActor (Result<ICAuthSession, Error>) -> Void = { result in
                guard !didComplete else { return }
                didComplete = true
                self.activeSession = nil
                switch result {
                case .success(let session):
                    continuation.resume(returning: session)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
            let session = ASWebAuthenticationSession(url: url, callback: callback) { callbackURL, error in
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
                        let session = try Self.session(
                            from: callbackURL,
                            expectedState: state,
                            privateKey: privateKey,
                            configuration: self.configuration
                        )
                        finish(.success(session))
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
}
#endif
