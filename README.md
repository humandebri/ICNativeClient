# ICNativeClient

Reusable Swift Package for a native iOS Internet Computer client.

## Scope

- Principal text/blob conversion.
- ICP account identifier and ICP amount helpers.
- CBOR envelopes for `/api/v3/canister/.../query`, `/api/v4/canister/.../call`,
  `/api/v3/canister/.../read_state`, with v2 call fallback.
- Signed calls using an Internet Identity delegation session.
- Internet Identity session parsing and Keychain storage.
- iOS `ASWebAuthenticationSession` bridge helper for `/native-auth` style flows.

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

## Certificate Verification

`read_state` polling trusts the boundary node response as an update-completion signal and does not verify BLS certificates or certified data roots.
Use this package for update polling and app flows with the same trust model.
Add certificate verification before using it for high-assurance certified reads.
