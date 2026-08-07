// Package-level regression tests for the extracted native IC client.
// These lock the reusable primitives without depending on app targets.

import CryptoKit
import XCTest
import ICNativeClient

final class ICNativeClientTests: XCTestCase {
    func testAuthorizationTimedOutDescriptionIsRetryable() {
        XCTAssertEqual(
            ICClientError.authorizationTimedOut.errorDescription,
            "Internet Identity authorization timed out. Please try again."
        )
    }

#if canImport(UIKit)
    @available(iOS 17.4, *)
    func testAuthorizationURLUsesICRC167DelegationRequest() throws {
        XCTAssertEqual(
            ICInternetIdentityAuthenticator.defaultAuthorizationTimeout,
            .seconds(330)
        )

        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let url = try ICInternetIdentityAuthenticator.authorizationURL(
            callbackDomain: "wiki.kinic.xyz",
            configuration: configuration,
            state: "expected-state",
            requestID: "request-1",
            privateKey: privateKey
        )
        let fragment = try XCTUnwrap(url.fragment)
        var queryComponents = URLComponents()
        queryComponents.percentEncodedQuery = fragment
        let values = Dictionary(
            uniqueKeysWithValues: (queryComponents.queryItems ?? []).compactMap { item in
                item.value.map { (item.name, $0) }
            }
        )

        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "id.ai")
        XCTAssertEqual(url.path, "/authorize")
        XCTAssertEqual(values["state"], "expected-state")
        XCTAssertEqual(values["callback"], "https://wiki.kinic.xyz/ios-auth-callback")
        let message = try XCTUnwrap(values["message"]?.data(using: .utf8))
        let request = try XCTUnwrap(JSONSerialization.jsonObject(with: message) as? [String: Any])
        let params = try XCTUnwrap(request["params"] as? [String: Any])
        XCTAssertEqual(request["jsonrpc"] as? String, "2.0")
        XCTAssertEqual(request["id"] as? String, "request-1")
        XCTAssertEqual(request["method"] as? String, "icrc34_delegation")
        XCTAssertEqual(params["maxTimeToLive"] as? String, ICIdentitySession.maxTimeToLiveNanos)
        XCTAssertEqual(params["icrc95DerivationOrigin"] as? String, configuration.derivationOrigin)
        XCTAssertEqual(
            Data(base64Encoded: try XCTUnwrap(params["publicKey"] as? String)),
            ICIdentitySession.derPublicKey(from: privateKey.publicKey.rawRepresentation)
        )
    }

    @available(iOS 17.4, *)
    func testCallbackBuildsTwoHopDelegationSession() throws {
        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let callbackURL = try makeICRC167CallbackURL(
            state: "expected-state",
            message: delegationResponse(
                requestID: "request-1",
                sessionPrivateKey: privateKey,
                delegationCount: 2
            )
        )

        let session = try ICInternetIdentityAuthenticator.session(
            from: callbackURL,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: configuration
        )

        XCTAssertEqual(session.canisterId, configuration.canisterId)
        XCTAssertEqual(session.identityProvider, configuration.identityProvider.absoluteString)
        XCTAssertEqual(session.delegation.delegations.count, 2)
        XCTAssertEqual(session.delegation.delegations.last?.delegation.publicKey, session.sessionPublicKey)
    }

    @available(iOS 17.4, *)
    func testCallbackRejectsMismatchedStateAndRequestID() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let callbackURL = try makeICRC167CallbackURL(
            state: "unexpected-state",
            message: delegationResponse(requestID: "unexpected-request", sessionPrivateKey: privateKey)
        )

        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: callbackURL,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        )) { error in
            XCTAssertEqual(error as? ICClientError, .invalidPayload)
        }
    }

    @available(iOS 17.4, *)
    func testCallbackRejectsDuplicateFragmentItems() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let callbackURL = try makeCallbackURL(
            fragmentItems: [
                URLQueryItem(name: "message", value: delegationResponse(requestID: "request-1", sessionPrivateKey: privateKey)),
                URLQueryItem(name: "state", value: "expected-state"),
                URLQueryItem(name: "state", value: "expected-state"),
            ]
        )

        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: callbackURL,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        )) { error in
            XCTAssertEqual(error as? ICClientError, .invalidPayload)
        }
    }

    @available(iOS 17.4, *)
    func testCallbackSurfacesRPCError() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let callbackURL = try makeICRC167CallbackURL(
            state: "expected-state",
            message: #"{"jsonrpc":"2.0","id":"request-1","error":{"code":1000,"message":"denied"}}"#
        )

        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: callbackURL,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        )) { error in
            XCTAssertEqual(error as? ICClientError, .authorizationFailed("denied"))
        }
    }

    @available(iOS 17.4, *)
    func testCallbackRejectsInvalidBase64AndExcessiveLifetime() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let invalidBase64 = try makeICRC167CallbackURL(
            state: "expected-state",
            message: delegationResponse(
                requestID: "request-1",
                sessionPrivateKey: privateKey,
                rootPublicKey: "***"
            )
        )
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: invalidBase64,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        ))

        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let excessiveExpiration = UInt64((now.timeIntervalSince1970 + 31 * 24 * 60 * 60) * 1_000_000_000)
        let excessiveLifetime = try makeICRC167CallbackURL(
            state: "expected-state",
            message: delegationResponse(
                requestID: "request-1",
                sessionPrivateKey: privateKey,
                expiration: excessiveExpiration
            )
        )
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: excessiveLifetime,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration(),
            now: now
        ))
    }

    @available(iOS 17.4, *)
    func testCallbackRejectsWrongLeafAndTargetScope() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let wrongLeaf = try makeICRC167CallbackURL(
            state: "expected-state",
            message: delegationResponse(
                requestID: "request-1",
                sessionPrivateKey: privateKey,
                leafPublicKey: ICIdentitySession.derPublicKey(from: otherKey.publicKey.rawRepresentation)
            )
        )
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: wrongLeaf,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        ))

        let wrongTarget = try makeICRC167CallbackURL(
            state: "expected-state",
            message: delegationResponse(
                requestID: "request-1",
                sessionPrivateKey: privateKey,
                targets: ["aaaaa-aa"]
            )
        )
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.session(
            from: wrongTarget,
            callbackDomain: "wiki.kinic.xyz",
            expectedState: "expected-state",
            expectedRequestID: "request-1",
            privateKey: privateKey,
            configuration: testConfiguration()
        ))
    }

    private func makeICRC167CallbackURL(state: String, message: String) throws -> URL {
        try makeCallbackURL(
            fragmentItems: [
                URLQueryItem(name: "message", value: message),
                URLQueryItem(name: "state", value: state),
            ]
        )
    }

    private func delegationResponse(
        requestID: String,
        sessionPrivateKey: Curve25519.Signing.PrivateKey,
        rootPublicKey: String? = nil,
        leafPublicKey: Data? = nil,
        delegationCount: Int = 1,
        expiration: UInt64 = UInt64((Date().timeIntervalSince1970 + 3600) * 1_000_000_000),
        targets: [String]? = nil
    ) -> String {
        let sessionKey = leafPublicKey ?? ICIdentitySession.derPublicKey(from: sessionPrivateKey.publicKey.rawRepresentation)
        let rootKey = ICIdentitySession.derPublicKey(from: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let intermediateKey = ICIdentitySession.derPublicKey(from: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let delegatedKeys = delegationCount == 2 ? [intermediateKey, sessionKey] : [sessionKey]
        let signedDelegations: [[String: Any]] = delegatedKeys.map { delegatedKey in
            var delegation: [String: Any] = [
                "pubkey": delegatedKey.base64EncodedString(),
                "expiration": String(expiration),
            ]
            if let targets {
                delegation["targets"] = targets
            }
            return [
                "delegation": delegation,
                "signature": Data(repeating: 7, count: 64).base64EncodedString(),
            ]
        }
        let response: [String: Any] = [
            "jsonrpc": "2.0",
            "id": requestID,
            "result": [
                "publicKey": rootPublicKey ?? rootKey.base64EncodedString(),
                "signerDelegation": signedDelegations,
            ],
        ]
        return String(decoding: try! JSONSerialization.data(withJSONObject: response), as: UTF8.self)
    }

    private func makeCallbackURL(fragmentItems: [URLQueryItem]) throws -> URL {
        var components = URLComponents(
            url: URL(string: "https://wiki.kinic.xyz/ios-auth-callback")!,
            resolvingAgainstBaseURL: false
        )
        var fragment = URLComponents()
        fragment.queryItems = fragmentItems
        components?.percentEncodedFragment = fragment.percentEncodedQuery
        return try XCTUnwrap(components?.url)
    }
#endif

    func testPrincipalRoundTrip() throws {
        let principal = try XCTUnwrap(ICPrincipal.parse("bkyz2-fmaaa-aaaaa-qaaaq-cai"))
        XCTAssertEqual(ICPrincipal.text(from: principal), "bkyz2-fmaaa-aaaaa-qaaaq-cai")
    }

    func testICPAccountIdentifierAcceptsPrincipalOrAccountHex() throws {
        let account = try ICPAccountIdentifier.defaultAccount(for: "2vxsx-fae")

        XCTAssertEqual(account.count, 32)
        XCTAssertEqual(try ICPAccountIdentifier.parse(account.icHexString), account)
        XCTAssertEqual(try ICPAccountIdentifier.parse("2vxsx-fae"), account)
        XCTAssertThrowsError(try ICPAccountIdentifier.parse(String(repeating: "0", count: 64)))
    }

    func testICPAmountParsesAndFormatsE8s() {
        XCTAssertEqual(ICPAmount.parse("1"), 100_000_000)
        XCTAssertEqual(ICPAmount.parse("0.0001"), 10_000)
        XCTAssertEqual(ICPAmount.parse("1.23456789"), 123_456_789)
        XCTAssertNil(ICPAmount.parse("1.123456789"))
        XCTAssertEqual(ICPAmount.format(123_450_000), "1.2345 ICP")
        XCTAssertEqual(ICPAmount.format(100_000_000, units: false), "1")
    }

    func testIdentitySessionBuildsValidatedSession() throws {
        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let target = try XCTUnwrap(ICPrincipal.parse(configuration.canisterId))
        let chain = delegationChain(sessionPrivateKey: privateKey, targets: [target])

        let session = try ICIdentitySession.makeSession(
            privateKey: privateKey,
            delegation: chain,
            configuration: configuration
        )

        XCTAssertEqual(session.canisterId, configuration.canisterId)
        XCTAssertEqual(session.identityProvider, configuration.identityProvider.absoluteString)
        XCTAssertEqual(session.derivationOrigin, configuration.derivationOrigin)
        XCTAssertEqual(session.sessionPublicKey, ICIdentitySession.derPublicKey(from: privateKey.publicKey.rawRepresentation))
        XCTAssertEqual(session.delegation.delegations.count, 1)
    }

    func testIdentitySessionRejectsMismatchedSessionKey() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let chain = delegationChain(
            sessionPrivateKey: privateKey,
            delegatedPublicKey: ICIdentitySession.derPublicKey(from: otherKey.publicKey.rawRepresentation)
        )

        XCTAssertThrowsError(try ICIdentitySession.makeSession(
            privateKey: privateKey,
            delegation: chain,
            configuration: testConfiguration()
        ))
    }

    func testCBORRejectsOversizedByteStringLength() {
        let hugeByteStringHeader = Data([0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

        XCTAssertNil(ICCBOR.decode(hugeByteStringHeader))
    }

    func testSignedEnvelopeContainsDelegationFields() throws {
        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let session = try ICIdentitySession.makeSession(
            privateKey: privateKey,
            delegation: delegationChain(sessionPrivateKey: privateKey),
            configuration: configuration
        )
        let content: ICCBOR.Value = .map([
            (.text("request_type"), .text("query")),
            (.text("canister_id"), .bytes(try XCTUnwrap(ICPrincipal.parse(configuration.canisterId)))),
            (.text("method_name"), .text("status")),
            (.text("arg"), .bytes(Data())),
            (.text("sender"), .bytes(ICPrincipal.selfAuthenticatingPublicKey(session.delegation.publicKey))),
            (.text("ingress_expiry"), .unsigned(1)),
        ])

        let envelope = try ICClient.signedEnvelope(content: content, identity: session)
        let decoded = try XCTUnwrap(ICCBOR.decode(envelope))

        XCTAssertNotNil(ICCBOR.mapValue(decoded, key: "content"))
        XCTAssertNotNil(ICCBOR.mapValue(decoded, key: "sender_pubkey"))
        XCTAssertNotNil(ICCBOR.mapValue(decoded, key: "sender_sig"))
        XCTAssertNotNil(ICCBOR.mapValue(decoded, key: "sender_delegation"))
    }

    func testConfigurationUsesCurrentAPIEndpointVersions() {
        let configuration = testConfiguration()

        XCTAssertEqual(
            configuration.apiURL(for: "query").absoluteString,
            "https://ic0.app/api/v3/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/query"
        )
        XCTAssertEqual(
            configuration.apiURL(for: "read_state").absoluteString,
            "https://ic0.app/api/v3/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/read_state"
        )
        XCTAssertEqual(
            configuration.apiURL(for: "call").absoluteString,
            "https://ic0.app/api/v4/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call"
        )
        XCTAssertEqual(
            configuration.apiURL(for: "call", version: .v2).absoluteString,
            "https://ic0.app/api/v2/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call"
        )
    }

    func testQueryRawUsesV3Endpoint() async throws {
        var capturedPath: String?
        let client = makeStubbedClient { request in
            capturedPath = request.url?.path
            return Self.httpResponse(request, status: 200, body: Self.queryReply(Data("ok".utf8)))
        }

        let response = try await client.queryRaw(method: "status")

        XCTAssertEqual(response, Data("ok".utf8))
        XCTAssertEqual(capturedPath, "/api/v3/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/query")
    }

    func testCallRawUsesV4SyncReply() async throws {
        var capturedPaths: [String] = []
        let client = makeStubbedClient { request in
            capturedPaths.append(request.url?.path ?? "")
            return Self.httpResponse(request, status: 200, body: Self.queryReply(Data("done".utf8)))
        }
        let session = try makeAuthSession()

        let response = try await client.callRaw(method: "update", identity: session)

        XCTAssertEqual(response, Data("done".utf8))
        XCTAssertEqual(capturedPaths, ["/api/v4/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call"])
    }

    func testCallRawFallsBackToV2WhenV4IsNotFound() async throws {
        var capturedPaths: [String] = []
        let client = makeStubbedClient { request in
            let path = request.url?.path ?? ""
            capturedPaths.append(path)
            if path.contains("/api/v4/") {
                return Self.httpResponse(request, status: 404, body: Data())
            }
            return Self.httpResponse(request, status: 200, body: Self.queryReply(Data("done".utf8)))
        }
        let session = try makeAuthSession()

        let response = try await client.callRaw(method: "update", identity: session)

        XCTAssertEqual(response, Data("done".utf8))
        XCTAssertEqual(capturedPaths, [
            "/api/v4/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call",
            "/api/v2/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call",
        ])
    }

    func testCallRawSurfacesMalformedV4BodyWithoutPolling() async throws {
        var capturedPaths: [String] = []
        let client = makeStubbedClient { request in
            capturedPaths.append(request.url?.path ?? "")
            return Self.httpResponse(request, status: 200, body: Data([0x01]))
        }
        let session = try makeAuthSession()

        do {
            _ = try await client.callRaw(method: "update", identity: session)
            XCTFail("Expected invalidResponse.")
        } catch ICClientError.invalidResponse(let context) {
            XCTAssertEqual(context, "read_state certificate")
        }
        XCTAssertEqual(capturedPaths, ["/api/v4/canister/bkyz2-fmaaa-aaaaa-qaaaq-cai/call"])
    }

    private func testConfiguration() -> ICClientConfiguration {
        ICClientConfiguration(
            canisterId: "bkyz2-fmaaa-aaaaa-qaaaq-cai",
            identityProvider: URL(string: "https://id.ai/authorize")!,
            derivationOrigin: "https://bkyz2-fmaaa-aaaaa-qaaaq-cai.icp0.io"
        )
    }

    private func makeStubbedClient(
        _ handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)
    ) -> ICClient {
        ICNativeURLProtocolStub.requestHandler = handler
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.protocolClasses = [ICNativeURLProtocolStub.self]
        return ICClient(
            configuration: testConfiguration(),
            session: URLSession(configuration: sessionConfiguration)
        )
    }

    private func makeAuthSession() throws -> ICAuthSession {
        let privateKey = Curve25519.Signing.PrivateKey()
        return try ICIdentitySession.makeSession(
            privateKey: privateKey,
            delegation: delegationChain(sessionPrivateKey: privateKey),
            configuration: testConfiguration()
        )
    }

    private static func httpResponse(
        _ request: URLRequest,
        status: Int,
        body: Data
    ) -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(
            url: request.url ?? URL(string: "https://ic0.app")!,
            statusCode: status,
            httpVersion: nil,
            headerFields: nil
        )!
        return (response, body)
    }

    private static func queryReply(_ arg: Data) -> Data {
        ICCBOR.encode(.map([
            (.text("status"), .text("replied")),
            (.text("reply"), .map([(.text("arg"), .bytes(arg))])),
        ]))
    }

    private func delegationChain(
        sessionPrivateKey: Curve25519.Signing.PrivateKey,
        expiration: UInt64 = UInt64((Date().timeIntervalSince1970 + 3600) * 1_000_000_000),
        targets: [Data]? = nil,
        delegatedPublicKey: Data? = nil
    ) -> ICDelegationChain {
        let sessionPublicKey = delegatedPublicKey ?? ICIdentitySession.derPublicKey(from: sessionPrivateKey.publicKey.rawRepresentation)
        let rootPublicKey = ICIdentitySession.derPublicKey(from: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        return ICDelegationChain(
            publicKey: rootPublicKey,
            delegations: [
                .init(
                    delegation: .init(
                        publicKey: sessionPublicKey,
                        expiration: expiration,
                        targets: targets
                    ),
                    signature: Data(repeating: 7, count: 64)
                ),
            ]
        )
    }
}

private final class ICNativeURLProtocolStub: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let requestHandler = Self.requestHandler else {
            client?.urlProtocol(self, didFailWithError: ICClientError.invalidResponse("missing URLProtocol stub"))
            return
        }
        do {
            let (response, data) = try requestHandler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
