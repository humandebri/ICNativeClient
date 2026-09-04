# ICNativeClient

ICNativeClient is a Swift package for calling Internet Computer canisters from native Apple applications. Version 0.4.0 makes response verification the default and provides direct ICRC-167 Internet Identity authentication on iOS 17.4 or newer.

It includes principal/account helpers and raw Candid-byte transport; it does not include a general Candid codec.

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
