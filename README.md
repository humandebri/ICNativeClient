# ICNativeClient

Reusable Swift Package for a native iOS Internet Computer client.

## Scope

- Principal text/blob conversion.
- ICP account identifier and ICP amount helpers.
- CBOR envelopes for `/api/v3/canister/.../query`, `/api/v4/canister/.../call`,
  `/api/v3/canister/.../read_state`, with v2 call fallback.
- Signed calls using an Internet Identity delegation session.
- Internet Identity delegation sessions and Keychain storage.
- iOS `ASWebAuthenticationSession` authenticator using the ICRC-167 URL transport.

This package returns raw canister reply bytes. It does not provide a general Candid implementation.
Callers should encode/decode Candid payloads themselves or add a canister-specific layer above `ICClient`.

## Usage

```swift
import ICNativeClient

let configuration = ICClientConfiguration(
    canisterId: "bkyz2-fmaaa-aaaaa-qaaaq-cai",
    derivationOrigin: "https://bkyz2-fmaaa-aaaaa-qaaaq-cai.icp0.io"
)
let client = ICClient(configuration: configuration)
let reply = try await client.queryRaw(method: "some_query", arg: candidArg)
```

For signed calls, obtain an `ICAuthSession` through `ICInternetIdentityAuthenticator` or restore one with `ICIdentityStore`.

## Internet Identity Authentication

`ICInternetIdentityAuthenticator.authenticate()` opens Internet Identity directly
in `ASWebAuthenticationSession`. Authorization is bounded to 330 seconds
by default and throws `ICClientError.authorizationTimedOut` when that deadline
expires. Task cancellation also cancels the active browser session.

```swift
let authenticator = ICInternetIdentityAuthenticator(
    configuration: configuration,
    callbackDomain: "app.example.com",
    callbackPath: "/native-auth-callback"
)
let session = try await authenticator.authenticate(
    timeout: .seconds(330),
    prefersEphemeralWebBrowserSession: false
)
```

The normal shared browser session is the default so passkeys and existing
Internet Identity sessions remain available. Set
`prefersEphemeralWebBrowserSession` only for an explicit clean-session test; do
not enable it as the production default.

## Certificate Verification

`read_state` polling trusts the boundary node response as an update-completion signal and does not verify BLS certificates or certified data roots.
Use this package for update polling and app flows with the same trust model.
Add certificate verification before using it for high-assurance certified reads.
