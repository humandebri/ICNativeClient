import CBlst
import CryptoKit
import Foundation
import Security
import XCTest
@testable import ICNativeClient

final class ICNativeClientTests: XCTestCase {
    private let canisterText = "bkyz2-fmaaa-aaaaa-qaaaq-cai"
    private let subnetID = Data([0x01, 0x02, 0x03])

    override func tearDown() {
        URLProtocolStub.handler = nil
        super.tearDown()
    }

    func testAuthorizationTimedOutDescriptionIsRetryable() {
        XCTAssertEqual(
            ICClientError.authorizationTimedOut.errorDescription,
            "Internet Identity authorization timed out. Please try again."
        )
    }

#if canImport(UIKit)
    @available(iOS 17.4, *)
    func testAuthenticatorRetainsExplicitCallbackAndTimeoutAPI() throws {
        XCTAssertEqual(ICInternetIdentityAuthenticator.defaultAuthorizationTimeout, .seconds(330))
        XCTAssertEqual(
            try ICInternetIdentityAuthenticator.callbackURL(
                callbackDomain: "app.example.com",
                callbackPath: "/native-auth-callback"
            ).absoluteString,
            "https://app.example.com/native-auth-callback"
        )
        XCTAssertThrowsError(try ICInternetIdentityAuthenticator.callbackURL(
            callbackDomain: "app.example.com",
            callbackPath: "native-auth-callback"
        ))
    }
#endif

    func testConfigurationValidatesInputsAndDefaultsToEightHours() throws {
        let config = try configuration(root: BLSTKey(seed: 1).derPublicKey)
        XCTAssertEqual(config.delegationTTLNanoseconds, 28_800_000_000_000)
        XCTAssertEqual(config.maximumResponseBytes, 10 * 1_024 * 1_024)
        XCTAssertThrowsError(try ICClientConfiguration(
            canisterId: canisterText,
            apiBaseURL: URL(string: "http://ic0.app")!,
            derivationOrigin: "https://example.com"
        ))
        XCTAssertThrowsError(try ICClientConfiguration(
            canisterId: canisterText,
            derivationOrigin: "https://example.com/path"
        ))
        XCTAssertThrowsError(try ICClientConfiguration(
            canisterId: canisterText,
            derivationOrigin: "https://example.com",
            delegationTTLNanoseconds: ICClientConfiguration.maximumDelegationTTLNanoseconds + 1
        ))
        XCTAssertThrowsError(try ICClientConfiguration(
            canisterId: canisterText,
            derivationOrigin: "https://example.com",
            trustRoot: .custom(Data(repeating: 0, count: 133))
        ))
    }

    func testAPIURLIsStructuredAndRejectsArbitraryRequestType() throws {
        let config = try configuration(root: BLSTKey(seed: 2).derPublicKey)
        XCTAssertEqual(
            try config.apiURL(for: "query").path,
            "/api/v3/canister/\(canisterText)/query"
        )
        XCTAssertThrowsError(try config.apiURL(for: "../status"))
    }

    func testPrincipalAmountAndSubaccountInputLimits() throws {
        let principal = try XCTUnwrap(ICPrincipal.parse(canisterText))
        XCTAssertEqual(ICPrincipal.parse(ICPrincipal.text(from: principal)), principal)
        XCTAssertNil(ICPrincipal.parse(String(repeating: "a", count: 64)))
        XCTAssertNil(ICPAmount.parse("１２"))
        XCTAssertEqual(ICPAmount.parse("1.00000001"), 100_000_001)
        XCTAssertThrowsError(try ICPAccountIdentifier.account(for: principal, subaccount: Data(count: 31)))
        XCTAssertEqual(try ICPAccountIdentifier.account(for: principal, subaccount: Data(count: 32)).count, 32)
    }

    func testCBORAddsSelfDescribeTagAndStrictlyRejectsAmbiguity() throws {
        let canister = try XCTUnwrap(ICPrincipal.parse(canisterText))
        let envelope = ICCBOR.queryEnvelope(canisterId: canister, method: "status", arg: Data(), ingressExpiry: 1)
        guard case .tagged(ICCBOR.selfDescribeTag, _) = try ICCBOR.decodeStrict(envelope) else {
            return XCTFail("missing self-described CBOR tag")
        }
        XCTAssertThrowsError(try ICCBOR.decodeStrict(Data([0x01, 0x01])))
        XCTAssertThrowsError(try ICCBOR.decodeStrict(Data([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])))
        XCTAssertThrowsError(try ICCBOR.decodeStrict(Data([0x9f, 0xff])))
        XCTAssertThrowsError(try ICCBOR.decodeStrict(Data([0xd8, 0x01, 0x01])))

        var deep: ICCBOR.Value = .unsigned(1)
        for _ in 0..<65 { deep = .array([deep]) }
        XCTAssertThrowsError(try ICCBOR.decodeStrict(ICCBOR.encode(deep)))
        XCTAssertThrowsError(try ICCBOR.decodeStrict(Data([0x9a, 0x00, 0x01, 0x86, 0xa1])))
    }

    func testRequestIDAndHashTreeVectors() throws {
        XCTAssertEqual(
            ICRequestID.hash(of: .text("hello")).icHexString,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        let tree = try ICHashTree(value: .array([.unsigned(3), .bytes(Data("abc".utf8))]))
        XCTAssertEqual(tree.digest.count, 32)
        XCTAssertEqual(tree.lookup([]), .found(Data("abc".utf8)))
        let publicSpecRequest: ICCBOR.Value = .map([
            (.text("request_type"), .text("call")),
            (.text("sender"), .bytes(Data([0x04]))),
            (.text("ingress_expiry"), .unsigned(1_685_570_400_000_000_000)),
            (.text("canister_id"), .bytes(Data([0, 0, 0, 0, 0, 0, 0x04, 0xd2]))),
            (.text("method_name"), .text("hello")),
            (.text("arg"), .bytes(Data([0x44, 0x49, 0x44, 0x4c, 0x00, 0xfd, 0x2a]))),
        ])
        XCTAssertEqual(
            ICRequestID.hash(of: publicSpecRequest).icHexString,
            "1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101"
        )
    }

    func testBLSCertificateAcceptsValidAndRejectsTamperingWrongRootAndTime() throws {
        let key = BLSTKey(seed: 3)
        let canister = try XCTUnwrap(ICPrincipal.parse(canisterText))
        let now = Date()
        let certificate = try makeCertificate(
            leaves: [([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now)))],
            key: key
        )
        XCTAssertNoThrow(try ICCertificateVerifier.verify(
            certificateData: certificate,
            effectiveCanisterID: canister,
            trustRoot: .custom(key.derPublicKey),
            now: now
        ))
        var tampered = certificate
        tampered[tampered.index(before: tampered.endIndex)] ^= 1
        XCTAssertThrowsError(try ICCertificateVerifier.verify(
            certificateData: tampered,
            effectiveCanisterID: canister,
            trustRoot: .custom(key.derPublicKey),
            now: now
        ))
        XCTAssertThrowsError(try ICCertificateVerifier.verify(
            certificateData: certificate,
            effectiveCanisterID: canister,
            trustRoot: .custom(BLSTKey(seed: 4).derPublicKey),
            now: now
        ))
        XCTAssertThrowsError(try ICCertificateVerifier.verify(
            certificateData: certificate,
            effectiveCanisterID: canister,
            trustRoot: .custom(key.derPublicKey),
            now: now.addingTimeInterval(301)
        ))
        XCTAssertThrowsError(try ICCertificateVerifier.verify(
            certificateData: certificate,
            effectiveCanisterID: canister,
            trustRoot: .custom(key.derPublicKey),
            now: now.addingTimeInterval(-301)
        ))
    }

    func testAgentRSMainnetDelegatedCertificateVector() throws {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "agent_rs_ivg37_time",
            withExtension: "bin",
            subdirectory: "Fixtures"
        ))
        let response = try Data(contentsOf: url)
        let fields = try ICCBOR.requiredMap(ICCBOR.decodeStrict(response), context: "agent-rs response")
        guard case .bytes(let certificateData) = try ICCBOR.requiredValue(fields, key: "certificate", context: "agent-rs response") else {
            return XCTFail("missing certificate")
        }
        let parsed = try ICCertificate(cbor: certificateData)
        guard case .found(let encodedTime) = parsed.tree.lookup([Data("time".utf8)]) else {
            return XCTFail("missing certified time")
        }
        let time = try ICCertificateVerifier.decodeUnsignedLEB128(encodedTime)
        let canister = try XCTUnwrap(ICPrincipal.parse("ivg37-qiaaa-aaaab-aaaga-cai"))
        XCTAssertNoThrow(try ICCertificateVerifier.verify(
            certificateData: certificateData,
            effectiveCanisterID: canister,
            trustRoot: .mainnet,
            now: Date(timeIntervalSince1970: Double(time) / 1_000_000_000)
        ))
    }

    func testSubnetDelegationChecksRangeAndSubnetSignature() throws {
        let root = BLSTKey(seed: 5)
        let subnet = BLSTKey(seed: 6)
        let canister = try XCTUnwrap(ICPrincipal.parse(canisterText))
        let now = Date()
        let valid = try makeDelegatedCertificate(
            mainLeaves: [([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now)))],
            root: root,
            subnet: subnet,
            range: (Data(), Data(repeating: 0xff, count: 29)),
            now: now
        )
        XCTAssertNoThrow(try ICCertificateVerifier.verify(
            certificateData: valid,
            effectiveCanisterID: canister,
            trustRoot: .custom(root.derPublicKey),
            now: now
        ))
        let wrongRange = try makeDelegatedCertificate(
            mainLeaves: [([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now)))],
            root: root,
            subnet: subnet,
            range: (Data([0xff]), Data([0xff, 0xff])),
            now: now
        )
        XCTAssertThrowsError(try ICCertificateVerifier.verify(
            certificateData: wrongRange,
            effectiveCanisterID: canister,
            trustRoot: .custom(root.derPublicKey),
            now: now
        ))
    }

    func testCertifiedStatusBindsRequestIDAndHandlesDoneAndReject() throws {
        let key = BLSTKey(seed: 7)
        let requestID = Data(repeating: 1, count: 32)
        let now = Date()
        let base = [Data("request_status".utf8), requestID]
        let certData = try makeCertificate(leaves: [
            ([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now))),
            (base + [Data("status".utf8)], Data("rejected".utf8)),
            (base + [Data("reject_code".utf8)], ICRequestID.leb128(4)),
            (base + [Data("reject_message".utf8)], Data("denied".utf8)),
            (base + [Data("error_code".utf8)], Data("IC0406".utf8)),
        ], key: key)
        let certificate = try ICCertificateVerifier.verify(
            certificateData: certData,
            effectiveCanisterID: Data(),
            trustRoot: .custom(key.derPublicKey),
            now: now
        )
        XCTAssertEqual(
            try ICCertificateVerifier.status(in: certificate, requestID: requestID),
            .rejected(ICReject(code: 4, message: "denied", errorCode: "IC0406", isCertified: true))
        )
        XCTAssertEqual(try ICCertificateVerifier.status(in: certificate, requestID: Data(repeating: 2, count: 32)), .absent)

        let doneData = try makeCertificate(leaves: [
            ([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now))),
            (base + [Data("status".utf8)], Data("done".utf8)),
        ], key: key)
        let done = try ICCertificateVerifier.verify(
            certificateData: doneData,
            effectiveCanisterID: Data(),
            trustRoot: .custom(key.derPublicKey),
            now: now
        )
        XCTAssertEqual(try ICCertificateVerifier.status(in: done, requestID: requestID), .done)
    }

    func testDelegationValidatesSignaturesBindingTargetsPermissionsAndLimits() throws {
        let bls = BLSTKey(seed: 8)
        let config = try configuration(root: bls.derPublicKey)
        let root = Curve25519.Signing.PrivateKey()
        let session = Curve25519.Signing.PrivateKey()
        let auth = try makeAuthSession(config: config, root: root, session: session, permission: .queries)
        XCTAssertNoThrow(try ICIdentityValidation.validateSession(auth, configuration: config, permission: .query))
        XCTAssertThrowsError(try ICIdentityValidation.validateSession(auth, configuration: config, permission: .call))

        var stored = auth.storage
        let delegation = stored.delegation.delegations[0]
        let broken = ICDelegationChain.SignedDelegation(delegation: delegation.delegation, signature: Data(repeating: 0, count: 64))
        stored = replacing(stored, chain: ICDelegationChain(publicKey: stored.delegation.publicKey, delegations: [broken]))
        XCTAssertThrowsError(try ICIdentityValidation.validateSession(ICAuthSession(storage: stored), configuration: config))

        let excluded = try makeAuthSession(config: config, root: root, session: session, targets: [Data([0x04])])
        XCTAssertThrowsError(try ICIdentityValidation.validateSession(excluded, configuration: config))
    }

    func testTwoHopDelegationAndCycleRejection() throws {
        let config = try configuration(root: BLSTKey(seed: 9).derPublicKey)
        let root = Curve25519.Signing.PrivateKey()
        let intermediate = Curve25519.Signing.PrivateKey()
        let session = Curve25519.Signing.PrivateKey()
        let auth = try makeAuthSession(config: config, root: root, session: session, intermediate: intermediate)
        XCTAssertNoThrow(try ICIdentityValidation.validateSession(auth, configuration: config))

        let expiry = nanoseconds(Date().addingTimeInterval(3_600))
        let rootDER = ICRC167Codec.derPublicKey(from: root.publicKey.rawRepresentation)
        let cycleDelegation = ICDelegationChain.SignedDelegation.Delegation(publicKey: rootDER, expiration: expiry, targets: nil)
        let cycleSignature = try root.signature(for: delegationSignable(cycleDelegation))
        let cycle = ICDelegationChain(publicKey: rootDER, delegations: [.init(delegation: cycleDelegation, signature: cycleSignature)])
        let stored = replacing(auth.storage, chain: cycle, sessionPublicKey: rootDER, privateKey: root.rawRepresentation)
        XCTAssertThrowsError(try ICIdentityValidation.validateSession(ICAuthSession(storage: stored), configuration: config))

        let tooDeep = ICDelegationChain(
            publicKey: rootDER,
            delegations: (0..<21).map { index in
                .init(
                    delegation: .init(
                        publicKey: index == 20 ? auth.sessionPublicKey : Data(repeating: UInt8(index + 1), count: 44),
                        expiration: expiry,
                        targets: nil
                    ),
                    signature: Data(repeating: 1, count: 64)
                )
            }
        )
        XCTAssertThrowsError(try ICIdentityValidation.validateDelegationChain(
            tooDeep,
            expectedSessionPublicKey: auth.sessionPublicKey,
            canisterId: config.canisterId,
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: config.delegationTTLNanoseconds,
            permission: nil,
            trustRoot: config.trustRoot,
            now: Date()
        ))

        let tooManyTargets = ICDelegationChain.SignedDelegation.Delegation(
            publicKey: auth.sessionPublicKey,
            expiration: expiry,
            targets: Array(repeating: try XCTUnwrap(ICPrincipal.parse(config.canisterId)), count: 1_001)
        )
        XCTAssertThrowsError(try ICIdentityValidation.validateDelegationChain(
            ICDelegationChain(publicKey: rootDER, delegations: [.init(delegation: tooManyTargets, signature: Data(repeating: 1, count: 64))]),
            expectedSessionPublicKey: auth.sessionPublicKey,
            canisterId: config.canisterId,
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: config.delegationTTLNanoseconds,
            permission: nil,
            trustRoot: config.trustRoot,
            now: Date()
        ))
    }

    func testCanisterSignedInternetIdentityDelegationIsVerified() throws {
        let root = BLSTKey(seed: 18)
        let config = try configuration(root: root.derPublicKey)
        let signingCanister = try XCTUnwrap(ICPrincipal.parse(canisterText))
        let seed = Data("ii-seed".utf8)
        let canisterKey = canisterSignatureDER(canister: signingCanister, seed: seed)
        let sessionKey = Curve25519.Signing.PrivateKey()
        let sessionDER = ICRC167Codec.derPublicKey(from: sessionKey.publicKey.rawRepresentation)
        let delegation = ICDelegationChain.SignedDelegation.Delegation(
            publicKey: sessionDER,
            expiration: nanoseconds(Date().addingTimeInterval(3_600)),
            targets: [signingCanister]
        )
        let payload = delegationSignable(delegation)
        let signatureTree = hashTree([(
            [Data("sig".utf8), Data(SHA256.hash(data: seed)), Data(SHA256.hash(data: payload))],
            Data()
        )])
        let signatureDigest = try ICHashTree(value: signatureTree).digest
        let certificate = try makeCertificate(leaves: [
            // Canister-signature witness certificates may be older than the
            // replica-response skew window; delegation expiration is the bound.
            ([Data("time".utf8)], ICRequestID.leb128(nanoseconds(Date().addingTimeInterval(-600)))),
            ([Data("canister".utf8), signingCanister, Data("certified_data".utf8)], signatureDigest),
        ], key: root)
        let decodedCertificate = try ICCertificate(cbor: certificate)
        XCTAssertEqual(
            decodedCertificate.tree.lookup([Data("canister".utf8), signingCanister, Data("certified_data".utf8)]),
            .found(signatureDigest)
        )
        XCTAssertEqual(
            try ICCertificate(cbor: certificate).tree.lookup([
                Data("canister".utf8), signingCanister, Data("certified_data".utf8),
            ]),
            .found(signatureDigest)
        )
        let canisterSignature = ICCBOR.encode(.tagged(ICCBOR.selfDescribeTag, .map([
            (.text("certificate"), .bytes(certificate)),
            (.text("tree"), signatureTree),
        ])))
        let chain = ICDelegationChain(
            publicKey: canisterKey,
            delegations: [.init(delegation: delegation, signature: canisterSignature)]
        )
        let session = ICAuthSession(storage: ICStoredAuthSession(
            formatVersion: ICAuthSession.currentFormatVersion,
            principal: ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(canisterKey)),
            canisterId: config.canisterId,
            internetIdentityURL: config.internetIdentityURL.absoluteString,
            derivationOrigin: config.derivationOrigin,
            sessionPublicKey: sessionDER,
            sessionPrivateKey: sessionKey.rawRepresentation,
            delegation: chain,
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: config.delegationTTLNanoseconds
        ))
        XCTAssertNoThrow(try ICIdentityValidation.validateSession(session, configuration: config))

        var tamperedSignature = canisterSignature
        tamperedSignature[tamperedSignature.index(before: tamperedSignature.endIndex)] ^= 1
        let tamperedChain = ICDelegationChain(
            publicKey: canisterKey,
            delegations: [.init(delegation: delegation, signature: tamperedSignature)]
        )
        XCTAssertThrowsError(try ICIdentityValidation.validateSession(
            ICAuthSession(storage: replacing(session.storage, chain: tamperedChain)),
            configuration: config
        ))
    }

    func testICRC167CarriesDerivationOriginAndRejectsStateReplay() throws {
        let config = try configuration(root: BLSTKey(seed: 10).derPublicKey)
        let pending = ICRC167PendingRequest(
            requestID: "request",
            state: "state",
            privateKey: Curve25519.Signing.PrivateKey(),
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: ICClientConfiguration.defaultDelegationTTLNanoseconds
        )
        let callback = URL(string: "https://app.example/ios-auth-callback")!
        let url = try ICRC167Codec.authorizationURL(configuration: config, callbackURL: callback, pendingRequest: pending)
        let fragment = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedFragment)
        let fields = try ICRC167Codec.parseFormEncoded(fragment)
        let message = try XCTUnwrap(fields["message"]?.data(using: .utf8))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: message) as? [String: Any])
        let parameters = try XCTUnwrap(json["params"] as? [String: Any])
        XCTAssertEqual(parameters["icrc95DerivationOrigin"] as? String, config.derivationOrigin)
        XCTAssertEqual(parameters["maxTimeToLive"] as? String, String(ICClientConfiguration.defaultDelegationTTLNanoseconds))
        XCTAssertThrowsError(try ICRC167Codec.parseFormEncoded("state=a&state=b"))
    }

    func testVerifiedQueryFetchesCertifiedKeysCachesThemAndUnsafeQuerySkipsFetch() async throws {
        let root = BLSTKey(seed: 11)
        let node = Curve25519.Signing.PrivateKey()
        let nodeID = Data([0xaa])
        let config = try configuration(root: root.derPublicKey)
        let now = Date()
        let subnetCertificate = try makeSubnetCertificate(root: root, nodeID: nodeID, node: node, now: now)
        let lock = NSLock()
        var readStateCount = 0
        URLProtocolStub.handler = { request in
            let path = request.url?.path ?? ""
            if path.hasSuffix("/read_state") {
                lock.withLock { readStateCount += 1 }
                return response(request, status: 200, body: readStateResponse(subnetCertificate))
            }
            let content = try requestContent(request)
            let requestID = ICRequestID.hash(of: content)
            let arg = Data("ok".utf8)
            let timestamp = self.nanoseconds(Date())
            let unsigned = queryResponse(arg: arg, signatures: [])
            let parsed = try ICQueryResponse(cbor: unsigned)
            let signature = try node.signature(for: parsed.signable(requestID: requestID, timestamp: timestamp))
            return response(request, status: 200, body: queryResponse(
                arg: arg,
                signatures: [(nodeID, signature, timestamp)]
            ))
        }
        let client = client(config)
        let first = try await client.queryRaw(method: "one")
        let second = try await client.queryRaw(method: "two")
        XCTAssertEqual(first, Data("ok".utf8))
        XCTAssertEqual(second, Data("ok".utf8))
        XCTAssertEqual(lock.withLock { readStateCount }, 1)
        let unsafe = try await client.unsafeQueryRaw(method: "unsafe")
        XCTAssertEqual(unsafe, Data("ok".utf8))
        XCTAssertEqual(lock.withLock { readStateCount }, 1)
    }

    func testQueryRejectsTamperedSignatureAndRefreshesOnlyOnce() async throws {
        let root = BLSTKey(seed: 12)
        let node = Curve25519.Signing.PrivateKey()
        let nodeID = Data([0xbb])
        let config = try configuration(root: root.derPublicKey)
        let certificate = try makeSubnetCertificate(root: root, nodeID: nodeID, node: node, now: Date())
        let lock = NSLock()
        var reads = 0
        URLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/read_state") == true {
                lock.withLock { reads += 1 }
                return response(request, status: 200, body: readStateResponse(certificate))
            }
            return response(request, status: 200, body: queryResponse(
                arg: Data("forged".utf8),
                signatures: [(nodeID, Data(repeating: 0, count: 64), self.nanoseconds(Date()))]
            ))
        }
        do {
            _ = try await client(config).queryRaw(method: "tampered")
            XCTFail("expected query signature failure")
        } catch ICClientError.querySignatureVerificationFailed { }
        XCTAssertEqual(lock.withLock { reads }, 2)
    }

    func testV4CertifiedReplyReject202V2RejectAndDone() async throws {
        let root = BLSTKey(seed: 13)
        let config = try configuration(root: root.derPublicKey)
        let identity = try makeAuthSession(config: config)
        let canister = try XCTUnwrap(ICPrincipal.parse(canisterText))

        URLProtocolStub.handler = { request in
            let content = try requestContent(request)
            let requestID = ICRequestID.hash(of: content)
            let now = Date()
            let base = [Data("request_status".utf8), requestID]
            let certificate = try self.makeCertificate(leaves: [
                ([Data("time".utf8)], ICRequestID.leb128(self.nanoseconds(now))),
                (base + [Data("status".utf8)], Data("replied".utf8)),
                (base + [Data("reply".utf8)], Data("done".utf8)),
            ], key: root)
            return response(request, status: 200, body: ICCBOR.encode(.map([
                (.text("status"), .text("replied")),
                (.text("certificate"), .bytes(certificate)),
            ])))
        }
        let reply = try await client(config).callRaw(method: "update", identity: identity)
        XCTAssertEqual(reply, Data("done".utf8))

        URLProtocolStub.handler = { request in response(request, status: 200, body: ICCBOR.encode(.map([
            (.text("status"), .text("non_replicated_rejection")),
            (.text("reject_code"), .unsigned(4)),
            (.text("reject_message"), .text("no")),
            (.text("error_code"), .text("IC0406")),
        ]))) }
        await XCTAssertThrowsErrorAsync(try await client(config).callRaw(method: "reject", identity: identity))

        URLProtocolStub.handler = { request in
            if request.url?.path.contains("/v4/") == true { return response(request, status: 404, body: Data()) }
            return response(request, status: 200, body: ICCBOR.encode(.map([
                (.text("reject_code"), .unsigned(3)),
                (.text("reject_message"), .text("bad destination")),
            ])))
        }
        await XCTAssertThrowsErrorAsync(try await client(config).callRaw(method: "v2", identity: identity))
        _ = canister
    }

    func testV4AcceptedPollsAndSurfacesCertifiedDone() async throws {
        let root = BLSTKey(seed: 25)
        let config = try configuration(root: root.derPublicKey)
        let identity = try makeAuthSession(config: config)
        let lock = NSLock()
        var updateRequestID: Data?
        URLProtocolStub.handler = { request in
            if request.url?.path.hasSuffix("/call") == true {
                let id = ICRequestID.hash(of: try requestContent(request))
                lock.withLock { updateRequestID = id }
                return response(request, status: 202, body: Data())
            }
            let id = try XCTUnwrap(lock.withLock { updateRequestID })
            let base = [Data("request_status".utf8), id]
            let certificate = try self.makeCertificate(leaves: [
                ([Data("time".utf8)], ICRequestID.leb128(self.nanoseconds(Date()))),
                (base + [Data("status".utf8)], Data("done".utf8)),
            ], key: root)
            return response(request, status: 200, body: readStateResponse(certificate))
        }
        await XCTAssertThrowsErrorAsync(
            try await client(config).callRaw(method: "accepted", identity: identity)
        ) { error in
            XCTAssertEqual(error as? ICClientError, .requestDoneWithoutReply)
        }
    }

    func testV2AcceptedPollsAndReturnsCertifiedReply() async throws {
        let root = BLSTKey(seed: 26)
        let config = try configuration(root: root.derPublicKey)
        let identity = try makeAuthSession(config: config)
        let lock = NSLock()
        var updateRequestID: Data?
        URLProtocolStub.handler = { request in
            if request.url?.path.contains("/v4/") == true {
                let id = ICRequestID.hash(of: try requestContent(request))
                lock.withLock { updateRequestID = id }
                return response(request, status: 404, body: Data())
            }
            if request.url?.path.contains("/v2/") == true {
                return response(request, status: 202, body: Data())
            }
            let id = try XCTUnwrap(lock.withLock { updateRequestID })
            let base = [Data("request_status".utf8), id]
            let certificate = try self.makeCertificate(leaves: [
                ([Data("time".utf8)], ICRequestID.leb128(self.nanoseconds(Date()))),
                (base + [Data("status".utf8)], Data("replied".utf8)),
                (base + [Data("reply".utf8)], Data("v2 reply".utf8)),
            ], key: root)
            return response(request, status: 200, body: readStateResponse(certificate))
        }
        let reply = try await client(config).callRaw(method: "accepted-v2", identity: identity)
        XCTAssertEqual(reply, Data("v2 reply".utf8))
    }

    func testResponseLimitStopsBeforeBodyAcceptance() async throws {
        let root = BLSTKey(seed: 14)
        let config = try ICClientConfiguration(
            canisterId: canisterText,
            derivationOrigin: "https://example.com",
            trustRoot: .custom(root.derPublicKey),
            maximumResponseBytes: 32
        )
        URLProtocolStub.handler = { request in
            response(request, status: 200, body: Data(repeating: 0, count: 33))
        }
        await XCTAssertThrowsErrorAsync(try await client(config).unsafeQueryRaw(method: "large")) { error in
            XCTAssertEqual(error as? ICClientError, .responseTooLarge(limit: 32))
        }
    }

    func testPollRejectsInvalidBounds() async throws {
        let config = try configuration(root: BLSTKey(seed: 15).derPublicKey)
        let identity = try makeAuthSession(config: config)
        await XCTAssertThrowsErrorAsync(try await client(config).poll(requestId: Data(count: 31), identity: identity, attempts: 1))
        await XCTAssertThrowsErrorAsync(try await client(config).poll(requestId: Data(count: 32), identity: identity, attempts: 0))
    }

    func testKeychainUpdateFailurePreservesExistingSessionAndLoadErrorsThrow() throws {
        let config = try configuration(root: BLSTKey(seed: 16).derPublicKey)
        let session = try makeAuthSession(config: config)
        let old = Data("old".utf8)
        let keychain = MockKeychain(data: old)
        keychain.updateStatus = errSecInteractionNotAllowed
        let store = ICIdentityStore(configuration: config, service: "test", account: "account", keychain: keychain)
        XCTAssertThrowsError(try store.save(session))
        XCTAssertEqual(keychain.data, old)
        keychain.copyStatus = errSecInteractionNotAllowed
        XCTAssertThrowsError(try store.load())
        keychain.copyStatus = errSecItemNotFound
        XCTAssertNil(try store.load())
    }

    func testBLSVerificationPerformanceIsMeasured() throws {
        let key = BLSTKey(seed: 17)
        let message = Data("benchmark".utf8)
        let signature = key.sign(message)
        let start = ContinuousClock.now
        for _ in 0..<100 {
            XCTAssertTrue(ICBLS.verify(
                signature: signature,
                message: message,
                publicKey: key.publicKey,
                dst: BLSTKey.dst
            ))
        }
        let elapsed = start.duration(to: .now)
        XCTAssertLessThan(elapsed, .seconds(5), "100 BLS verifications took \(elapsed)")
    }

    func testICRC167DefaultRequestUsesEightHourTTLAndFragmentOnly() throws {
        let config = try configuration(root: BLSTKey(seed: 18).derPublicKey)
        let pending = try ICRC167Codec.makePendingRequest(requestedAt: Date())
        let callback = URL(string: "https://app.example/ios-auth-callback")!
        let url = try ICRC167Codec.authorizationURL(configuration: config, callbackURL: callback, pendingRequest: pending)
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let fields = try ICRC167Codec.parseFormEncoded(try XCTUnwrap(components.percentEncodedFragment))
        let request = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(fields["message"]!.utf8)) as? [String: Any])
        let parameters = try XCTUnwrap(request["params"] as? [String: Any])
        XCTAssertEqual(pending.maxTimeToLiveNanoseconds, 28_800_000_000_000)
        XCTAssertEqual(parameters["maxTimeToLive"] as? String, "28800000000000")
        XCTAssertEqual(parameters["icrc95DerivationOrigin"] as? String, config.derivationOrigin)
        XCTAssertNotEqual(pending.requestID, pending.state)
        XCTAssertEqual(fields["callback"], callback.absoluteString)
        XCTAssertFalse(url.absoluteString.contains("native-auth"))
        XCTAssertNil(components.queryItems?.first { ["message", "callback", "state"].contains($0.name) })
    }

    func testICRC167AcceptsSignedOneAndTwoHopResponses() throws {
        let config = try configuration(root: BLSTKey(seed: 19).derPublicKey)
        let one = icrcPending()
        XCTAssertEqual(try parseICRC(try icrcCallback(pending: one), pending: one, config: config).delegation.delegations.count, 1)
        let two = icrcPending()
        let intermediate = Curve25519.Signing.PrivateKey()
        let session = try parseICRC(
            try icrcCallback(pending: two, delegatedKeys: [intermediate, two.privateKey]),
            pending: two,
            config: config
        )
        XCTAssertEqual(session.delegation.delegations.count, 2)
        XCTAssertEqual(session.sessionPublicKey, ICRC167Codec.derPublicKey(from: two.privateKey.publicKey.rawRepresentation))
    }

    func testICRC167CallbackValidatesNormalizedOriginPathPortAndQuery() throws {
        let expected = URL(string: "https://app.example/ios-auth-callback")!
        XCTAssertNoThrow(try ICRC167Codec.validateReturnedCallbackURL(
            URL(string: "https://APP.EXAMPLE:443/ios-auth-callback#message=x&state=y")!,
            expected: expected
        ))
        for raw in [
            "https://evil.example/ios-auth-callback#message=x&state=y",
            "https://app.example:8443/ios-auth-callback#message=x&state=y",
            "https://app.example/other#message=x&state=y",
            "https://app.example/ios-auth-callback?q=1#message=x&state=y",
            "https://user:pass@app.example/ios-auth-callback#message=x&state=y",
        ] {
            XCTAssertThrowsError(try ICRC167Codec.validateReturnedCallbackURL(URL(string: raw)!, expected: expected))
        }
        XCTAssertThrowsError(try ICRC167Codec.validateCallbackURL(URL(string: "https://app.example/ios-auth-callback#old")!))
        XCTAssertNoThrow(try ICRC167Codec.validateCallbackURL(URL(string: "https://app.example/native-auth-callback")!))
        XCTAssertThrowsError(try ICRC167Codec.validateCallbackURL(URL(string: "https://app.example")!))
    }

    func testICRC167RejectsFragmentStateIDSchemaAndReplayFailures() throws {
        XCTAssertThrowsError(try ICRC167Codec.parseFormEncoded("message=a&message=b&state=c"))
        XCTAssertThrowsError(try ICRC167Codec.parseFormEncoded("message=%ZZ&state=c"))
        let config = try configuration(root: BLSTKey(seed: 20).derPublicKey)
        let state = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: state, returnedState: "wrong"), pending: state, config: config))
        let id = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: id, returnedID: "wrong"), pending: id, config: config))
        let extra = icrcPending()
        var object = try icrcSuccessObject(pending: extra)
        object["unexpected"] = true
        XCTAssertThrowsError(try parseICRC(try icrcCallback(object: object, state: extra.state), pending: extra, config: config))
        let replay = icrcPending()
        let response = try icrcCallback(pending: replay)
        _ = try parseICRC(response, pending: replay, config: config)
        XCTAssertThrowsError(try parseICRC(response, pending: replay, config: config))
    }

    func testICRC167SurfacesJSONRPCErrorAndRejectsResultErrorCombination() throws {
        let config = try configuration(root: BLSTKey(seed: 21).derPublicKey)
        let failed = icrcPending()
        let errorURL = try icrcCallback(object: [
            "jsonrpc": "2.0", "id": failed.requestID,
            "error": ["code": 3001, "message": "Action aborted"],
        ], state: failed.state)
        XCTAssertThrowsError(try parseICRC(errorURL, pending: failed, config: config)) {
            XCTAssertEqual($0 as? ICClientError, .authorizationFailed("Action aborted"))
        }
        let both = icrcPending()
        var object = try icrcSuccessObject(pending: both)
        object["error"] = ["code": 1, "message": "bad"]
        XCTAssertThrowsError(try parseICRC(try icrcCallback(object: object, state: both.state), pending: both, config: config))
    }

    func testICRC167RejectsExpirationBase64LeafAndTargetFailures() throws {
        let config = try configuration(root: BLSTKey(seed: 22).derPublicKey)
        let numeric = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(
            pending: numeric,
            expiration: NSNumber(value: nanoseconds(Date().addingTimeInterval(3_600)))
        ), pending: numeric, config: config))
        let expired = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: expired, expiration: "0"), pending: expired, config: config))
        let overTTL = icrcPending(ttl: 3_600_000_000_000)
        XCTAssertThrowsError(try parseICRC(try icrcCallback(
            pending: overTTL,
            expiration: String(nanoseconds(overTTL.requestedAt.addingTimeInterval(7_200)))
        ), pending: overTTL, config: config))
        let base64 = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: base64, rootEncoding: "-w=="), pending: base64, config: config))
        let leaf = icrcPending()
        let other = ICRC167Codec.derPublicKey(from: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: leaf, leafKey: other), pending: leaf, config: config))
        let target = icrcPending()
        XCTAssertThrowsError(try parseICRC(try icrcCallback(pending: target, targets: ["2vxsx-fae"]), pending: target, config: config))
    }

    func testICRC167NarrowTargetAndRootPrincipalArePreserved() throws {
        let config = try configuration(root: BLSTKey(seed: 23).derPublicKey)
        let pending = icrcPending()
        let root = Curve25519.Signing.PrivateKey()
        let session = try parseICRC(
            try icrcCallback(pending: pending, targets: [canisterText], rootKey: root),
            pending: pending,
            config: config
        )
        let rootDER = ICRC167Codec.derPublicKey(from: root.publicKey.rawRepresentation)
        XCTAssertEqual(session.principal, ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(rootDER)))
        XCTAssertEqual(session.storage.formatVersion, ICAuthSession.currentFormatVersion)
        XCTAssertEqual(session.requestedAt, pending.requestedAt)
    }

    func testMalformedKeychainSessionIsPreservedAndRejected() throws {
        let config = try configuration(root: BLSTKey(seed: 24).derPublicKey)
        let keychain = MockKeychain(data: Data(#"{"identityProvider":"https://id.ai/#authorize"}"#.utf8))
        let store = ICIdentityStore(configuration: config, service: "test", account: "legacy", keychain: keychain)
        XCTAssertThrowsError(try store.load())
        XCTAssertNotNil(keychain.data)
    }

    // MARK: Helpers

    private func configuration(root: Data) throws -> ICClientConfiguration {
        try ICClientConfiguration(
            canisterId: canisterText,
            internetIdentityURL: URL(string: "https://id.ai/authorize")!,
            derivationOrigin: "https://example.com",
            trustRoot: .custom(root)
        )
    }

    private func client(_ config: ICClientConfiguration) -> ICClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [URLProtocolStub.self]
        return ICClient(configuration: config, session: URLSession(configuration: configuration))
    }

    private func makeAuthSession(
        config: ICClientConfiguration,
        root: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
        session: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
        intermediate: Curve25519.Signing.PrivateKey? = nil,
        targets: [Data]? = nil,
        permission: ICDelegationPermission? = nil
    ) throws -> ICAuthSession {
        let rootDER = ICRC167Codec.derPublicKey(from: root.publicKey.rawRepresentation)
        let sessionDER = ICRC167Codec.derPublicKey(from: session.publicKey.rawRepresentation)
        let expiry = nanoseconds(Date().addingTimeInterval(3_600))
        var signed: [ICDelegationChain.SignedDelegation] = []
        if let intermediate {
            let intermediateDER = ICRC167Codec.derPublicKey(from: intermediate.publicKey.rawRepresentation)
            let first = ICDelegationChain.SignedDelegation.Delegation(publicKey: intermediateDER, expiration: expiry, targets: targets, permissions: permission)
            signed.append(.init(delegation: first, signature: try root.signature(for: delegationSignable(first))))
            let second = ICDelegationChain.SignedDelegation.Delegation(publicKey: sessionDER, expiration: expiry, targets: targets, permissions: permission)
            signed.append(.init(delegation: second, signature: try intermediate.signature(for: delegationSignable(second))))
        } else {
            let delegation = ICDelegationChain.SignedDelegation.Delegation(publicKey: sessionDER, expiration: expiry, targets: targets, permissions: permission)
            signed.append(.init(delegation: delegation, signature: try root.signature(for: delegationSignable(delegation))))
        }
        let chain = ICDelegationChain(publicKey: rootDER, delegations: signed)
        return ICAuthSession(storage: ICStoredAuthSession(
            formatVersion: ICAuthSession.currentFormatVersion,
            principal: ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(rootDER)),
            canisterId: config.canisterId,
            internetIdentityURL: config.internetIdentityURL.absoluteString,
            derivationOrigin: config.derivationOrigin,
            sessionPublicKey: sessionDER,
            sessionPrivateKey: session.rawRepresentation,
            delegation: chain,
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: config.delegationTTLNanoseconds
        ))
    }

    private func replacing(
        _ stored: ICStoredAuthSession,
        chain: ICDelegationChain,
        sessionPublicKey: Data? = nil,
        privateKey: Data? = nil
    ) -> ICStoredAuthSession {
        ICStoredAuthSession(
            formatVersion: stored.formatVersion,
            principal: ICPrincipal.text(from: ICPrincipal.selfAuthenticatingPublicKey(chain.publicKey)),
            canisterId: stored.canisterId,
            internetIdentityURL: stored.internetIdentityURL,
            derivationOrigin: stored.derivationOrigin,
            sessionPublicKey: sessionPublicKey ?? stored.sessionPublicKey,
            sessionPrivateKey: privateKey ?? stored.sessionPrivateKey,
            delegation: chain,
            requestedAt: stored.requestedAt,
            maxTimeToLiveNanoseconds: stored.maxTimeToLiveNanoseconds
        )
    }

    private func delegationSignable(_ delegation: ICDelegationChain.SignedDelegation.Delegation) -> Data {
        var fields: [(ICCBOR.Value, ICCBOR.Value)] = [
            (.text("pubkey"), .bytes(delegation.publicKey)),
            (.text("expiration"), .unsigned(delegation.expiration)),
        ]
        if let targets = delegation.targets { fields.append((.text("targets"), .array(targets.map(ICCBOR.Value.bytes)))) }
        if let permission = delegation.permissions { fields.append((.text("permissions"), .text(permission.rawValue))) }
        return Data([0x1a]) + Data("ic-request-auth-delegation".utf8) + ICRequestID.hash(of: .map(fields))
    }

    private func icrcPending(ttl: UInt64 = ICRC167Codec.defaultMaxTimeToLiveNanoseconds) -> ICRC167PendingRequest {
        ICRC167PendingRequest(
            requestID: UUID().uuidString,
            state: UUID().uuidString,
            privateKey: Curve25519.Signing.PrivateKey(),
            requestedAt: Date(),
            maxTimeToLiveNanoseconds: ttl
        )
    }

    private func parseICRC(_ url: URL, pending: ICRC167PendingRequest, config: ICClientConfiguration) throws -> ICAuthSession {
        try ICRC167Codec.session(
            from: url,
            expectedCallbackURL: URL(string: "https://app.example/ios-auth-callback")!,
            pendingRequest: pending,
            configuration: config,
            now: pending.requestedAt
        )
    }

    private func icrcCallback(
        pending: ICRC167PendingRequest,
        returnedState: String? = nil,
        returnedID: String? = nil,
        delegatedKeys: [Curve25519.Signing.PrivateKey]? = nil,
        expiration: Any? = nil,
        targets: [String]? = nil,
        rootKey: Curve25519.Signing.PrivateKey? = nil,
        rootEncoding: String? = nil,
        leafKey: Data? = nil
    ) throws -> URL {
        try icrcCallback(object: icrcSuccessObject(
            pending: pending,
            returnedID: returnedID,
            delegatedKeys: delegatedKeys,
            expiration: expiration,
            targets: targets,
            rootKey: rootKey,
            rootEncoding: rootEncoding,
            leafKey: leafKey
        ), state: returnedState ?? pending.state)
    }

    private func icrcSuccessObject(
        pending: ICRC167PendingRequest,
        returnedID: String? = nil,
        delegatedKeys: [Curve25519.Signing.PrivateKey]? = nil,
        expiration: Any? = nil,
        targets: [String]? = nil,
        rootKey: Curve25519.Signing.PrivateKey? = nil,
        rootEncoding: String? = nil,
        leafKey: Data? = nil
    ) throws -> [String: Any] {
        let keys = delegatedKeys ?? [pending.privateKey]
        var publicKeys = keys.map { ICRC167Codec.derPublicKey(from: $0.publicKey.rawRepresentation) }
        if let leafKey { publicKeys[publicKeys.count - 1] = leafKey }
        let root = rootKey ?? Curve25519.Signing.PrivateKey()
        let signers = [root] + keys.dropLast()
        let expirationJSON = expiration ?? String(nanoseconds(pending.requestedAt.addingTimeInterval(3_600)))
        let expirationValue = UInt64(expirationJSON as? String ?? "") ?? 0
        let targetData = targets?.compactMap(ICPrincipal.parse)
        let delegations = try publicKeys.enumerated().map { index, publicKey -> [String: Any] in
            let value = ICDelegationChain.SignedDelegation.Delegation(
                publicKey: publicKey,
                expiration: expirationValue,
                targets: targetData
            )
            var json: [String: Any] = ["pubkey": publicKey.base64EncodedString(), "expiration": expirationJSON]
            if let targets { json["targets"] = targets }
            return [
                "delegation": json,
                "signature": try signers[index].signature(for: delegationSignable(value)).base64EncodedString(),
            ]
        }
        return [
            "jsonrpc": "2.0",
            "id": returnedID ?? pending.requestID,
            "result": [
                "publicKey": rootEncoding ?? ICRC167Codec.derPublicKey(from: root.publicKey.rawRepresentation).base64EncodedString(),
                "signerDelegation": delegations,
            ],
        ]
    }

    private func icrcCallback(object: Any, state: String) throws -> URL {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        var components = URLComponents(url: URL(string: "https://app.example/ios-auth-callback")!, resolvingAgainstBaseURL: false)!
        components.percentEncodedFragment = ICRC167Codec.formEncoded([
            ("message", String(decoding: data, as: UTF8.self)), ("state", state),
        ])
        return try XCTUnwrap(components.url)
    }

    private func canisterSignatureDER(canister: Data, seed: Data) -> Data {
        let raw = Data([UInt8(canister.count)]) + canister + seed
        let oid = derTLV(tag: 0x06, value: Data([0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xb8, 0x43, 0x01, 0x02]))
        let algorithm = derTLV(tag: 0x30, value: oid)
        let bitString = derTLV(tag: 0x03, value: Data([0]) + raw)
        return derTLV(tag: 0x30, value: algorithm + bitString)
    }

    private func derTLV(tag: UInt8, value: Data) -> Data {
        var output = Data([tag])
        if value.count < 0x80 {
            output.append(UInt8(value.count))
        } else if value.count < 0x100 {
            output.append(contentsOf: [0x81, UInt8(value.count)])
        } else {
            output.append(contentsOf: [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xff)])
        }
        output.append(value)
        return output
    }

    private func makeSubnetCertificate(
        root: BLSTKey,
        nodeID: Data,
        node: Curve25519.Signing.PrivateKey,
        now: Date
    ) throws -> Data {
        let ranges = ICCBOR.encode(.array([.array([.bytes(Data()), .bytes(Data(repeating: 0xff, count: 29))])]))
        return try makeCertificate(leaves: [
            ([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now))),
            ([Data("subnet".utf8), subnetID, Data("canister_ranges".utf8)], ranges),
            ([Data("subnet".utf8), subnetID, Data("node".utf8), nodeID, Data("public_key".utf8)], ICRC167Codec.derPublicKey(from: node.publicKey.rawRepresentation)),
        ], key: root)
    }

    private func makeDelegatedCertificate(
        mainLeaves: [([Data], Data)],
        root: BLSTKey,
        subnet: BLSTKey,
        range: (Data, Data),
        now: Date
    ) throws -> Data {
        let ranges = ICCBOR.encode(.array([.array([.bytes(range.0), .bytes(range.1)])]))
        let rootCertificate = try makeCertificate(leaves: [
            ([Data("time".utf8)], ICRequestID.leb128(nanoseconds(now))),
            ([Data("subnet".utf8), subnetID, Data("canister_ranges".utf8)], ranges),
            ([Data("subnet".utf8), subnetID, Data("public_key".utf8)], subnet.derPublicKey),
        ], key: root)
        return try makeCertificate(leaves: mainLeaves, key: subnet, delegation: (subnetID, rootCertificate))
    }

    private func makeCertificate(
        leaves: [([Data], Data)],
        key: BLSTKey,
        delegation: (Data, Data)? = nil
    ) throws -> Data {
        let treeValue = hashTree(leaves)
        let digest = try ICHashTree(value: treeValue).digest
        let signature = key.sign(Data([0x0d]) + Data("ic-state-root".utf8) + digest)
        var fields: [(ICCBOR.Value, ICCBOR.Value)] = [
            (.text("tree"), treeValue),
            (.text("signature"), .bytes(signature)),
        ]
        if let delegation {
            fields.append((.text("delegation"), .map([
                (.text("subnet_id"), .bytes(delegation.0)),
                (.text("certificate"), .bytes(delegation.1)),
            ])))
        }
        return ICCBOR.encode(.tagged(ICCBOR.selfDescribeTag, .map(fields)))
    }

    private func hashTree(_ leaves: [([Data], Data)]) -> ICCBOR.Value {
        precondition(!leaves.isEmpty)
        let groups = Dictionary(grouping: leaves, by: { $0.0[0] })
        let nodes = groups.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }).map { label -> ICCBOR.Value in
            let entries = groups[label]!
            let child: ICCBOR.Value
            if entries.allSatisfy({ $0.0.count == 1 }) {
                precondition(entries.count == 1)
                child = .array([.unsigned(3), .bytes(entries[0].1)])
            } else {
                child = hashTree(entries.map { (Array($0.0.dropFirst()), $0.1) })
            }
            return .array([.unsigned(2), .bytes(label), child])
        }
        return fork(nodes)
    }

    private func fork(_ nodes: [ICCBOR.Value]) -> ICCBOR.Value {
        if nodes.count == 1 { return nodes[0] }
        let midpoint = nodes.count / 2
        return .array([.unsigned(1), fork(Array(nodes[..<midpoint])), fork(Array(nodes[midpoint...] ))])
    }

    private func nanoseconds(_ date: Date) -> UInt64 {
        UInt64(date.timeIntervalSince1970 * 1_000_000_000)
    }
}

private struct BLSTKey {
    static let dst = Data("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".utf8)
    let secret: blst_scalar
    let publicKey: Data
    var derPublicKey: Data {
        Data([
            0x30, 0x81, 0x82, 0x30, 0x1d, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x04, 0x01,
            0x82, 0xdc, 0x7c, 0x05, 0x03, 0x01, 0x02, 0x01, 0x06, 0x0c, 0x2b, 0x06,
            0x01, 0x04, 0x01, 0x82, 0xdc, 0x7c, 0x05, 0x03, 0x02, 0x01, 0x03, 0x61, 0x00,
        ]) + publicKey
    }

    init(seed: UInt8) {
        var secret = blst_scalar()
        let ikm = Data(repeating: seed, count: 32)
        ikm.withUnsafeBytes { bytes in
            blst_keygen(&secret, bytes.bindMemory(to: UInt8.self).baseAddress, ikm.count, nil, 0)
        }
        var point = blst_p2()
        blst_sk_to_pk_in_g2(&point, &secret)
        var compressed = [UInt8](repeating: 0, count: 96)
        blst_p2_compress(&compressed, &point)
        self.secret = secret
        self.publicKey = Data(compressed)
    }

    func sign(_ message: Data) -> Data {
        var hash = blst_p1()
        message.withUnsafeBytes { messageBytes in
            Self.dst.withUnsafeBytes { dstBytes in
                blst_hash_to_g1(
                    &hash,
                    messageBytes.bindMemory(to: UInt8.self).baseAddress,
                    message.count,
                    dstBytes.bindMemory(to: UInt8.self).baseAddress,
                    Self.dst.count,
                    nil,
                    0
                )
            }
        }
        var signature = blst_p1()
        var secret = secret
        blst_sign_pk_in_g2(&signature, &hash, &secret)
        var compressed = [UInt8](repeating: 0, count: 48)
        blst_p1_compress(&compressed, &signature)
        return Data(compressed)
    }
}

private final class URLProtocolStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw ICClientError.invalidResponse("missing stub") }
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() { }
}

private final class MockKeychain: ICKeychainAccess, @unchecked Sendable {
    var data: Data?
    var updateStatus: OSStatus = errSecSuccess
    var copyStatus: OSStatus = errSecSuccess
    init(data: Data?) { self.data = data }
    func copyMatching(_ query: CFDictionary, result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
        guard copyStatus == errSecSuccess else { return copyStatus }
        result?.pointee = data as CFData?
        return data == nil ? errSecItemNotFound : errSecSuccess
    }
    func update(_ query: CFDictionary, attributes: CFDictionary) -> OSStatus {
        guard updateStatus == errSecSuccess else { return updateStatus }
        guard data != nil else { return errSecItemNotFound }
        if let value = attributes as? [String: Any], let newData = value[kSecValueData as String] as? Data { data = newData }
        return errSecSuccess
    }
    func add(_ attributes: CFDictionary) -> OSStatus {
        if data != nil { return errSecDuplicateItem }
        if let value = attributes as? [String: Any] { data = value[kSecValueData as String] as? Data }
        return errSecSuccess
    }
    func delete(_ query: CFDictionary) -> OSStatus { data = nil; return errSecSuccess }
}

private func response(_ request: URLRequest, status: Int, body: Data) -> (HTTPURLResponse, Data) {
    let response = HTTPURLResponse(
        url: request.url ?? URL(string: "https://ic0.app")!,
        statusCode: status,
        httpVersion: nil,
        headerFields: ["Content-Length": String(body.count)]
    )!
    return (response, body)
}

private func requestContent(_ request: URLRequest) throws -> ICCBOR.Value {
    let body: Data
    if let direct = request.httpBody {
        body = direct
    } else if let stream = request.httpBodyStream {
        stream.open()
        defer { stream.close() }
        var collected = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else { throw stream.streamError ?? ICClientError.invalidResponse("request body stream") }
            if count == 0 { break }
            collected.append(buffer, count: count)
        }
        body = collected
    } else {
        throw ICClientError.invalidResponse("missing request body")
    }
    let envelope = try ICCBOR.decodeStrict(body)
    return try XCTUnwrap(ICCBOR.mapValue(envelope, key: "content"))
}

private func queryResponse(
    arg: Data,
    signatures: [(Data, Data, UInt64)]
) -> Data {
    ICCBOR.encode(.map([
        (.text("status"), .text("replied")),
        (.text("reply"), .map([(.text("arg"), .bytes(arg))])),
        (.text("signatures"), .array(signatures.map { identity, signature, timestamp in
            .map([
                (.text("identity"), .bytes(identity)),
                (.text("signature"), .bytes(signature)),
                (.text("timestamp"), .unsigned(timestamp)),
            ])
        })),
    ]))
}

private func readStateResponse(_ certificate: Data) -> Data {
    ICCBOR.encode(.map([(.text("certificate"), .bytes(certificate))]))
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ handler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error", file: file, line: line)
    } catch { handler(error) }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T {
        lock(); defer { unlock() }
        return body()
    }
}
