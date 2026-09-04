# iOS Internet Identity authentication

ICNativeClient uses direct ICRC-167 URL transport on iOS 17.4 or newer. The app opens
Internet Identity itself with `ASWebAuthenticationSession`; no `/native-auth` page,
`postMessage` relay, query-based delegation payload, or bridge fallback participates in
the flow.

## Roles

- `internetIdentityURL` is the signer transport URL. Production uses
  `https://id.ai/authorize`, optionally with the fixed Apple or Google `openid` query.
- `callbackURL` is the exact HTTPS return URL intercepted by the authentication session.
- `derivationOrigin` is the origin used by Internet Identity to derive the user's
  principal. Preserve its existing value during migration.
- `apiBaseURL` is the IC replica API endpoint used after authentication. It is not a
  callback or derivation origin.

The package sends one `icrc34_delegation` JSON-RPC request in the II URL fragment. It
requires independent request-id and state matches, consumes each callback once, and
validates the returned chain's session key, principal, every delegation signature,
expiration, targets, permissions, cycle/depth/target limits, and content canister scope
before returning an `ICAuthSession`. The default lifetime is 8 hours; callers may
explicitly request a longer lifetime up to 30 days.

`ICAuthenticationOptions` can override the lifetime for one authentication and request
a non-empty list of target canisters. Targets are omitted by default to preserve the
existing relying-party principal behavior. When targets are supplied, they must include
the configured canister ID; the client rejects unscoped responses and effective target
scopes that exceed the requested set. Opting into targets can enable an ICRC-34 account
delegation and may therefore produce a different principal.

Authentication itself has a separate 330-second default timeout. Cancelling the calling
task cancels the active browser session. Shared browser state is used by default so
passkeys and existing II sessions remain available; callers may explicitly request an
ephemeral browser session for clean-session testing. Both the `callbackURL` initializer
and the domain/path initializer require an explicit HTTPS callback path.

## Callback origin contract

Before distributing an app build, the callback origin must serve all three resources:

1. `/.well-known/ii-auth-callbacks` as CORS-readable `application/json`, containing the
   exact callback and no wildcard:

   ```json
   {"callbacks":["https://example.com/ios-auth-callback"]}
   ```

2. `/ios-auth-callback` as a successful terminal response. It must not redirect because
   a redirect can forward the delegation fragment to another origin.
3. `/.well-known/apple-app-site-association` as non-redirecting JSON with the installed
   app's exact Team ID and bundle identifier:

   ```json
   {"webcredentials":{"apps":["TEAMID.com.example.app"]}}
   ```

When an IC canister serves these resources, certify their responses. Deploy and verify
them over public HTTPS before distributing the matching iOS build; a successful Wasm
install alone is not sufficient verification.

Add `webcredentials:example.com` to the app's Associated Domains entitlement.
`ASWebAuthenticationSession.Callback.https` uses associated web credentials. Add
`applinks:example.com` and a corresponding AASA `applinks` entry only if the app also
handles ordinary Universal Links outside the authentication session.

AASA responses are cached by Apple and devices. Reinstall the app or allow for cache
propagation when testing changes, and confirm associated-domain behavior on a physical
device rather than relying only on the simulator.

## Deployment and verification order

1. Preserve the production `derivationOrigin` used by existing users.
2. Deploy the callback declaration, terminal callback, and AASA response.
3. Verify their status, content type, CORS, exact callback value, and lack of redirects.
4. Build the app with the matching `webcredentials` entitlement and callback URL.
5. Test Internet Identity/passkey, Apple, Google, cancellation, and a signed canister call
   on a physical device.
6. Distribute the app. Users upgrading from ICNativeClient 0.1.0 must authenticate again.

For local-device testing, use public HTTPS endpoints reachable by the phone. Do not put
Mac-only `localhost` or `*.raw.localhost` URLs into the authentication session.

## Protocol baseline

This implementation was checked against:

- [ICRC-167 draft at `cd5ef7d2`](https://github.com/dfinity/wg-identity-authentication/blob/cd5ef7d2be5337dda8c9988a4dca18bd120de34b/topics/icrc_167_browser_url_transport.md)
- [ICRC-34 delegation specification](https://github.com/dfinity/wg-identity-authentication/blob/main/topics/icrc_34_delegation.md)
- [Internet Identity release 2026-08-28](https://github.com/dfinity/internet-identity/releases/tag/release-2026-08-28)
- Internet Identity URL transport blob `fce2059982dfde27f1e5403f24f49c95dac99992`
- `@icp-sdk/signer` validation blob `d9486670ccb05b84d40ee11666e783560eb6c95f`

The draft's general Universal Link section uses `applinks`. For this package's specific
`ASWebAuthenticationSession.Callback.https` integration, the current Apple SDK requirement
for associated `webcredentials` domains is controlling.
