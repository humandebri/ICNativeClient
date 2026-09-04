# ICNativeClient

ICNativeClient is a Swift package for calling Internet Computer canisters from native Apple applications. Version 0.5.0 adds typed Candid encoding, decoding, and verified calls while retaining the raw transport APIs introduced in 0.4.0.

It includes principal/account helpers, a Candid DIDL codec, explicit Swift model conversion, and raw Candid-byte transport.

## Requirements and installation

- Swift 5.9 or newer
- iOS 17 or newer, or macOS 13 or newer
- Xcode with CryptoKit and Security frameworks

Add the repository as a Swift Package dependency and link the `ICNativeClient` product. The fixed `blst` C sources required for BLS verification are vendored, so consumers do not download a crypto binary.

## Trust and verification model

The following APIs authenticate responses before returning application data:

- `queryRaw`: verifies every query response signature with Ed25519 node keys obtained from a BLS-verified subnet certificate.
- `callRaw`: verifies a v4 synchronous certificate, or polls with verified `read_state` certificates after 202.
- `poll`: verifies the BLS signature, hash tree, subnet delegation, effective-canister range, certificate time, and request ID path.

`unsafeQueryRaw` is the only unverified query API. It is an explicit integrity opt-out and must not be used for balances, authorization, configuration, or other security-relevant results.

Mainnet uses the 133-byte DER BLS root key pinned by the official agent implementation:

```swift
let configuration = try ICClientConfiguration(
    canisterId: "bkyz2-fmaaa-aaaaa-qaaaq-cai",
    derivationOrigin: "https://bkyz2-fmaaa-aaaaa-qaaaq-cai.icp0.io",
    trustRoot: .mainnet
)
```

Local replicas and testnets must receive a root key through `ICTrustRoot.custom` from an independently trusted setup channel:

```swift
let configuration = try ICClientConfiguration(
    canisterId: canisterID,
    apiBaseURL: replicaHTTPSURL,
    derivationOrigin: derivationOrigin,
    trustRoot: .custom(rootKeyDER)
)
```

The package never fetches a mainnet trust root from `/api/v2/status`. A root key obtained from the same untrusted connection as the response would not establish trust.

Certificates and query timestamps are accepted only within five minutes of the local clock. HTTP bodies are streamed and aborted above 10 MiB by default; `maximumResponseBytes` can set a smaller positive limit.

## Query and update calls

Use `CandidConvertible` values for ordinary typed calls. The typed APIs encode arguments, call the existing verified raw transport, and decode the Candid reply:

```swift
let greeting: String = try await client.query(
    method: "greet",
    argument: "Ada"
)

let result: UInt64 = try await client.call(
    method: "increment",
    argument: UInt64(1),
    identity: identity
)
```

`CandidArguments` and `CandidReply` preserve Candid's positional multi-value boundary. Composite values carry their declared type, so an absent optional and an empty vector remain unambiguous:

```swift
let arguments = CandidArguments([
    try CandidTypedValue(type: .optional(.text), value: .optional(.text, nil)),
    try CandidTypedValue(type: .vector(.nat16), value: .vector(.nat16, [])),
])
let reply = try await client.queryCandid(method: "lookup", arguments: arguments)
let (name, count) = try reply.decode(String.self, UInt64.self)
```

Canister-specific records implement `CandidConvertible` explicitly. This keeps the wire schema visible and avoids treating Swift's synthesized `Codable` enum representation as a Candid variant:

```swift
struct User: CandidConvertible {
    let name: String
    let age: UInt8

    static let fields = [
        CandidField("name", type: .text),
        CandidField("age", type: .nat8),
    ]
    static let candidType = CandidType.record(fields)

    init(candidValue: CandidValue) throws {
        let record = try CandidRecord(candidValue)
        name = try record.required("name")
        age = try record.required("age")
    }

    var candidValue: CandidValue {
        .record(Self.fields, [
            Candid.fieldID("name"): name.candidValue,
            Candid.fieldID("age"): age.candidValue,
        ])
    }
}
```

`CandidNat` and `CandidInt` retain canonical decimal strings for arbitrary-precision values. `CandidPrincipal` validates principal text. Variants use `CandidVariant` with the complete declared case list, selected tag, and payload.

Use `CandidNull()` for a typed Candid `null`, including payload-free variant cases such as `variant { ok; err : text }`. It is distinct from an empty Candid record.

`Data` and `[UInt8]` both map to Candid `vec nat8`. Recursive wire types are retained with `CandidType.recursive` and `CandidType.reference`; finite values can be decoded and re-encoded, while the configured nesting limit still rejects excessively deep values.

Use `queryRaw` and `callRaw` when integrating generated bindings or Candid types not represented by this value API. `unsafeQueryRaw` remains the explicit unverified opt-out; there is intentionally no typed unsafe wrapper.

### Raw transport

```swift
let client = ICClient(configuration: configuration)

let queryReply = try await client.queryRaw(
    method: "some_query",
    arg: candidQueryArgument
)

let updateReply = try await client.callRaw(
    method: "some_update",
    arg: candidUpdateArgument,
    identity: identity
)
```

Certified subnet/node keys are cached for one hour. Consecutive queries routed to the same certified subnet reuse the cache and do not perform an additional `read_state`. A missing node key or invalid node signature causes exactly one forced refresh before failure. The included benchmark test currently measures 100 local BLS verifications, so performance regressions remain visible without weakening verification.

Rejects are exposed as `ICClientError.rejected(ICReject)`, including reject code, message, optional error code, and whether the rejection was certified. A certified `done` status is reported as `requestDoneWithoutReply` rather than as an empty reply.

For management-canister calls, `canisterId` remains the content canister ID used for delegation targets, while `effectiveCanisterId` controls HTTP routing and certificate range authorization.

## Internet Identity native authentication

`ICInternetIdentityAuthenticator` uses direct ICRC-167 URL transport on iOS 17.4 or newer. It binds the callback state and JSON-RPC request ID, forwards `derivationOrigin`, validates the session private/public key pair, and verifies every delegation signature, expiration, target, permission, and chain bound.

The default delegation TTL is 8 hours. Callers may explicitly request a longer lifetime up to 30 days.

```swift
guard let callbackURL = URL(string: "https://example.com/ios-auth-callback") else {
    fatalError("Static callback URL is invalid")
}

let authenticator = try ICInternetIdentityAuthenticator(
    configuration: configuration,
    callbackURL: callbackURL
)
let identity = try await authenticator.authenticate(
    timeout: .seconds(330),
    prefersEphemeralWebBrowserSession: false
)
```

Authorization times out after 330 seconds by default and throws `ICClientError.authorizationTimedOut`. Cancelling the calling task cancels the active browser session. The shared browser session remains the default so passkeys and existing Internet Identity sessions are available; use an ephemeral session only for an intentional clean-session flow.

The 0.3.0 domain/path initializer remains available and requires an explicit path:

```swift
let authenticator = try ICInternetIdentityAuthenticator(
    configuration: configuration,
    callbackDomain: "example.com",
    callbackPath: "/ios-auth-callback"
)
```

The callback origin must publish its exact callback declaration and Apple association file. Add `webcredentials:example.com` to Associated Domains. Add `applinks:example.com` only when the application also handles ordinary Universal Links; it is not a replacement for the web-credentials association used by this authentication session. Test association behavior on a physical device because Apple caches AASA data.

See [iOS Internet Identity authentication](docs/ios-internet-identity.md) for callback endpoints, AASA examples, deployment order, and device constraints.

## Session storage

`ICAuthSession` is not `Codable` and exposes no private-key accessor. `ICIdentityStore` keeps the secret in an internal storage DTO and Keychain item protected with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.

```swift
let store = ICIdentityStore(
    configuration: configuration,
    service: "com.example.app.ic"
)

try store.save(identity)
let restored = try store.load() // nil only when no item is registered
```

Saving updates an existing item first and adds only when absent, so an update failure does not delete the prior session. Keychain failures and malformed legacy data are thrown without deleting stored bytes; only an absent item returns `nil`.

To share the session between an application and its extensions, configure the same Keychain access group, service, and account in every target:

```swift
let sharedStore = ICIdentityStore(
    configuration: configuration,
    service: "com.example.app.ic",
    accessGroup: "TEAMID.com.example.shared"
)
```

Every participating target must include that access group in its Keychain Sharing entitlement. ICNativeClient does not migrate items between access groups or from application-specific storage formats. If the shared item is initially absent, authenticate and save the session from the main application before an extension attempts to load it. An invalid access group or missing entitlement is reported as `ICClientError.keychainFailure`.

## New in 0.5.0

0.5.0 is a backward-compatible feature release that adds the typed Candid APIs described above. Existing `queryRaw`, `unsafeQueryRaw`, and `callRaw` integrations continue to work unchanged. Applications can adopt `CandidConvertible`, `queryCandid`, and `callCandid` incrementally for calls where schema-aware encoding and decoding are useful.

## Migration to 0.4.0

0.4.0 intentionally prioritizes verification over source compatibility while retaining 0.3.0 authorization timeout, cancellation, explicit callback-path, and browser-session controls:

- Add `try` to `ICClientConfiguration` construction.
- Rename `identityProvider` to `internetIdentityURL`.
- Replace bridge/native-auth parameters with the exact `callbackURL` used by ICRC-167.
- Replace any intentionally unverified `queryRaw` use with `unsafeQueryRaw`; ordinary `queryRaw` now performs certified key discovery and signature verification.
- Handle structured `ICReject` and `requestDoneWithoutReply` errors.
- Treat `ICIdentityStore.load()` as throwing for Keychain failures and malformed legacy data. Stored bytes are preserved; only an unregistered item returns `nil`.
- Update direct account construction for the throwing 32-byte subaccount validation.

## Security and contribution

See [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). GitHub Private Vulnerability Reporting must be enabled and tested before repository publication.

## License

ICNativeClient is available under the MIT License. Vendored `blst` remains under Apache-2.0; see the third-party notices.
