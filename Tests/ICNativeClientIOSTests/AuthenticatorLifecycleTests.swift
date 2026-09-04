#if canImport(AuthenticationServices) && canImport(UIKit)
import AuthenticationServices
import Foundation
import UIKit
import XCTest
@testable import ICNativeClient

@MainActor
@available(iOS 17.4, *)
final class AuthenticatorLifecycleTests: XCTestCase {
    func testCanonicalCallbackAndTimeoutAPI() throws {
        XCTAssertEqual(ICInternetIdentityAuthenticator.defaultAuthorizationTimeout, .seconds(330))
        let config = try configuration()
        XCTAssertNoThrow(try ICInternetIdentityAuthenticator(
            configuration: config,
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ))
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator(
            configuration: config,
            callbackURL: URL(string: "https://app.example.com/native-auth-callback")!
        ))
    }

    func testTimeoutCancelsSessionAndAppliesBrowserPreference() async throws {
        var createdSession: MockWebAuthenticationSession?
        let authenticator = try ICInternetIdentityAuthenticator(
            configuration: try configuration(),
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ) { _, _, completion in
            let session = MockWebAuthenticationSession(completion: completion)
            createdSession = session
            return session
        }

        do {
            _ = try await authenticator.authenticate(
                timeout: .milliseconds(10),
                prefersEphemeralWebBrowserSession: true
            )
            XCTFail("Expected authorization timeout.")
        } catch {
            XCTAssertEqual(error as? ICClientError, .authorizationTimedOut)
        }
        XCTAssertEqual(createdSession?.prefersEphemeralWebBrowserSession, true)
        XCTAssertEqual(createdSession?.cancelCount, 1)
    }

    func testAlreadyCancelledTaskDoesNotCreateBrowserSession() async throws {
        var factoryCallCount = 0
        let authenticator = try ICInternetIdentityAuthenticator(
            configuration: try configuration(),
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ) { _, _, completion in
            factoryCallCount += 1
            return MockWebAuthenticationSession(completion: completion)
        }

        let task = Task { @MainActor in
            while !Task.isCancelled { await Task.yield() }
            return try await authenticator.authenticate()
        }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("Expected cancellation.")
        } catch is CancellationError { }
        XCTAssertEqual(factoryCallCount, 0)
    }

    func testBrowserSessionIsSharedByDefault() async throws {
        var createdSession: MockWebAuthenticationSession?
        let authenticator = try ICInternetIdentityAuthenticator(
            configuration: try configuration(),
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ) { _, _, completion in
            let session = MockWebAuthenticationSession(completion: completion)
            session.startResult = false
            createdSession = session
            return session
        }

        do {
            _ = try await authenticator.authenticate()
            XCTFail("Expected start failure.")
        } catch {
            XCTAssertEqual(
                error as? ICClientError,
                .authorizationFailed("Internet Identity could not start.")
            )
        }
        XCTAssertEqual(createdSession?.prefersEphemeralWebBrowserSession, false)
    }

    func testCancellationImmediatelyBeforeStartCancelsSessionOnce() async throws {
        var task: Task<ICAuthSession, Error>?
        var createdSession: MockWebAuthenticationSession?
        let authenticator = try ICInternetIdentityAuthenticator(
            configuration: try configuration(),
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ) { _, _, completion in
            let session = MockWebAuthenticationSession(completion: completion)
            session.onBrowserPreferenceSet = { task?.cancel() }
            createdSession = session
            return session
        }

        task = Task { @MainActor in try await authenticator.authenticate() }
        do {
            _ = try await task?.value
            XCTFail("Expected cancellation.")
        } catch is CancellationError { }
        XCTAssertEqual(createdSession?.cancelCount, 1)
        XCTAssertEqual(createdSession?.startCount, 0)
    }

    func testDuplicateCompletionResumesOnlyOnce() async throws {
        let authenticator = try ICInternetIdentityAuthenticator(
            configuration: try configuration(),
            callbackURL: URL(string: "https://app.example.com/ios-auth-callback")!
        ) { _, _, completion in
            let session = MockWebAuthenticationSession(completion: completion)
            session.onStart = {
                completion(nil, nil)
                completion(nil, nil)
            }
            return session
        }

        do {
            _ = try await authenticator.authenticate()
            XCTFail("Expected invalid payload.")
        } catch {
            XCTAssertEqual(error as? ICClientError, .invalidPayload)
        }
    }

    private func configuration() throws -> ICClientConfiguration {
        try ICClientConfiguration(
            canisterId: "bkyz2-fmaaa-aaaaa-qaaaq-cai",
            derivationOrigin: "https://example.com"
        )
    }
}

@MainActor
@available(iOS 17.4, *)
private final class MockWebAuthenticationSession: ICWebAuthenticationSession {
    var presentationContextProvider: (any ASWebAuthenticationPresentationContextProviding)?
    var prefersEphemeralWebBrowserSession = false {
        didSet { onBrowserPreferenceSet?() }
    }
    var onBrowserPreferenceSet: (() -> Void)?
    var onStart: (() -> Void)?
    var startResult = true
    private(set) var cancelCount = 0
    private(set) var startCount = 0
    private let completion: (URL?, Error?) -> Void

    init(completion: @escaping (URL?, Error?) -> Void) {
        self.completion = completion
    }

    func start() -> Bool {
        startCount += 1
        onStart?()
        return startResult
    }

    func cancel() {
        cancelCount += 1
    }
}
#endif
