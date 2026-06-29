// Package-level regression tests for the extracted native IC client.
// These lock the reusable primitives without depending on app targets.

import CryptoKit
import XCTest
import ICNativeClient

final class ICNativeClientTests: XCTestCase {
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

    func testIdentityPayloadBuildsValidatedSession() throws {
        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let target = try XCTUnwrap(ICPrincipal.parse(configuration.canisterId))
        let payload = identityPayload(sessionPrivateKey: privateKey, targets: [target])

        let session = try ICIdentityBridge.makeSession(
            from: payload,
            privateKey: privateKey,
            configuration: configuration
        )

        XCTAssertEqual(session.canisterId, configuration.canisterId)
        XCTAssertEqual(session.identityProvider, configuration.identityProvider.absoluteString)
        XCTAssertEqual(session.derivationOrigin, configuration.derivationOrigin)
        XCTAssertEqual(session.sessionPublicKey, ICIdentityBridge.derPublicKey(from: privateKey.publicKey.rawRepresentation))
        XCTAssertEqual(session.delegation.delegations.count, 1)
    }

    func testIdentityPayloadRejectsMismatchedSessionKey() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let otherKey = Curve25519.Signing.PrivateKey()
        let payload = identityPayload(
            sessionPrivateKey: privateKey,
            delegatedPublicKey: ICIdentityBridge.derPublicKey(from: otherKey.publicKey.rawRepresentation)
        )

        XCTAssertThrowsError(try ICIdentityBridge.makeSession(
            from: payload,
            privateKey: privateKey,
            configuration: testConfiguration()
        ))
    }

    func testIdentityPayloadRejectsMalformedJSONWithPublicError() {
        XCTAssertThrowsError(try ICIdentityBridge.makeSession(
            from: "{",
            privateKey: Curve25519.Signing.PrivateKey(),
            configuration: testConfiguration()
        )) { error in
            XCTAssertEqual(error as? ICClientError, .invalidPayload)
        }
    }

    func testCBORRejectsOversizedByteStringLength() {
        let hugeByteStringHeader = Data([0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

        XCTAssertNil(ICCBOR.decode(hugeByteStringHeader))
    }

    func testSignedEnvelopeContainsDelegationFields() throws {
        let configuration = testConfiguration()
        let privateKey = Curve25519.Signing.PrivateKey()
        let payload = identityPayload(sessionPrivateKey: privateKey)
        let session = try ICIdentityBridge.makeSession(
            from: payload,
            privateKey: privateKey,
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
            identityProvider: URL(string: "https://id.ai/#authorize")!,
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
        return try ICIdentityBridge.makeSession(
            from: identityPayload(sessionPrivateKey: privateKey),
            privateKey: privateKey,
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

    private func identityPayload(
        sessionPrivateKey: Curve25519.Signing.PrivateKey,
        expiration: UInt64 = UInt64((Date().timeIntervalSince1970 + 3600) * 1_000_000_000),
        targets: [Data]? = nil,
        delegatedPublicKey: Data? = nil
    ) -> String {
        let sessionPublicKey = delegatedPublicKey ?? ICIdentityBridge.derPublicKey(from: sessionPrivateKey.publicKey.rawRepresentation)
        let rootPublicKey = ICIdentityBridge.derPublicKey(from: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let signature = Data(repeating: 7, count: 64)
        let targetJSON = targets.map { values in
            #","targets":[\#(values.map { #""\#($0.icHexString)""# }.joined(separator: ","))]"#
        } ?? ""
        return """
        {"kind":"authorize-client-success","userPublicKey":"\(rootPublicKey.icHexString)","delegations":[{"delegation":{"pubkey":"\(sessionPublicKey.icHexString)","expiration":"\(expiration)"\(targetJSON)},"signature":"\(signature.icHexString)"}]}
        """
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
