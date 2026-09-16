# Changelog

All notable changes are documented here.

## [Unreleased]

### Added

- Add `ICAuthSession.childDelegation(for:options:)` to sign a constrained child delegation for a caller-owned DER public key without exposing the session private key.
- Add split `submitRaw`/`completeRaw` and `submitCandid`/`completeCandid` update APIs so callers can retain the ingress request ID before polling completes.
- Add certified single-shot `requestStatus` APIs that distinguish absent, received, processing, replied, rejected, and done ingress states.
- Add per-request absolute ingress expiry and nonce options across Raw, Candid, and typed query/update APIs.
- Add codable `ICSignedQuery` and `ICSignedUpdate` envelopes with local signing, persisted-request validation, and separate send APIs.

### Compatibility

- Existing call sites and query/call method references retain their original signatures; generated bindings, stored sessions, and default wire formats are unchanged.

## [0.7.8] - 2026-09-12

### Changed

- Reuse validated Candid values during encoding and scan sorted record fields linearly during reply projection.
- Avoid repeated keyword-set allocation in the Swift binding generator and rebuild both bundled macOS architectures.
- Remove unused internal functions, parameters, and unreachable branches.
- Consolidate redundant tests, remove real polling waits from transport tests, and replace ineffective delegation-limit and OID cases with otherwise-valid inputs. Verify shared decoding budgets with smaller fixtures.
- Compile the plugin fixture in the renamed-checkout CI job without repeating its runtime tests.

### Compatibility

- Public APIs, accepted inputs, session storage, wire formats, generated Swift output, and default limits are unchanged. The bundled generator remains version 0.1.3.

## [0.7.7] - 2026-09-09

### Added

- Add `ICAuthSession.delegating(ed25519PrivateKey:configuration:options:)` to create expiring sessions from existing Ed25519 keys without retaining the root secret.

### Compatibility

- This release adds a public authentication API without changing existing session storage or wire formats. The bundled generator remains version 0.1.3.

## [0.7.6] - 2026-09-08

### Fixed

- Bound Candid decoding work across shared-type resolution, normalization, and validation to prevent excessive expansion from small replies. Cached types also retain their nesting depth for limit checks.
- Decode Candid from `Data` slices without assuming a zero-based index.
- Accept padded Candid LEB128 encodings while retaining integer overflow, termination, and length checks. Encoded output remains unchanged.
- Use sorted hash-tree label boundaries to recognize certified absence despite pruned sibling branches, allowing polling to continue and certified rejects without `error_code` to be returned.

### Compatibility

- Public APIs are unchanged. Candid inputs exceeding the fixed internal budget of 1,000,000 work units now throw `ICClientError.invalidCandid`, even if their encoded size is small.

## [0.7.5] - 2026-09-06

### Added

- Query APIs and generated query wrappers accept an optional `delegationTargetCanisterId`, independently of the signed `canisterId` and routing `effectiveCanisterId`.

### Fixed

- Target-scoped identities can authorize management-canister queries against the managed canister while preserving `aaaaa-aa` in signed content.
- Certified subnet-key discovery uses an anonymous read-state request instead of unnecessarily reusing the query identity.
- Typed reply decoding accepts Candid tuple evolution, record and container subtyping, and `nat <: int`, while rejecting non-Candid fixed-width numeric widening.

### Compatibility

- ICNativeClient 0.7.5 is a source-compatible patch release; the new query argument is optional and wire formats are unchanged. The bundled generator is `ic-candid-swift-bindgen` 0.1.3.

## [0.7.4] - 2026-09-06

### Fixed

- Verified queries to canisters on the root subnet, including the ICP Ledger, now derive the root subnet ID from the independently trusted root key instead of requiring a unique subnet entry in the certified state tree.

### Compatibility

- ICNativeClient 0.7.4 is a backward-compatible patch release with no public API, session, principal, or wire-format changes. The bundled generator remains `ic-candid-swift-bindgen` 0.1.2.

## [0.7.3] - 2026-09-05

### Fixed

- Generated Swift bindings project reply record extensions and compatible optional, vector, and recursive values to the Swift model's expected type.
- Generated variants remain strict: unknown or added cases and changed case payload types are rejected rather than silently misdecoded.

### Compatibility

- ICNativeClient 0.7.3 is a patch release with no public API, session, principal, or wire-format changes. The bundled generator is `ic-candid-swift-bindgen` 0.1.2.

## [0.7.2] - 2026-09-05

### Fixed

- Strict CBOR decoding accepts indefinite-length byte strings, text strings, arrays, and maps while retaining nesting, collection, UTF-8, and duplicate-key validation.

## [0.7.1] - 2026-09-04

### Added

- Effective routing canister IDs on raw, Candid, and typed query APIs and generated query wrappers.
- Direct `XcodeBuildToolPlugin` support for generating bindings in Xcode project targets.

### Fixed

- Management-canister queries preserve `aaaaa-aa` in signed request content while using the target canister for HTTP routing, subnet discovery, and certificate range verification.
- Bindgen plugin fixtures resolve the local ICNativeClient package independently of the checkout directory name.

### Compatibility

- ICNativeClient 0.7.1 retains the existing default query behavior when no effective canister ID is supplied. The bundled generator is versioned independently as `ic-candid-swift-bindgen` 0.1.1.

## [0.7.0] - 2026-09-04

### Added

- `ic-candid-swift-bindgen` 0.1.0, a deterministic Rust CLI that generates typed ICNativeClient Swift models and canister method wrappers from selected Candid service methods.
- `ICNativeClientBindgenPlugin`, a SwiftPM build tool plugin that places generated bindings in Derived Sources without checking generated Swift into consuming projects.
- macOS arm64 and x86_64 executable artifacts for build-time generation.
- Build information and CI verification that keep both embedded CLI architectures synchronized with the Rust generator source.

### Fixed

- Internet Identity delegation chains can verify P-256 ECDSA intermediate signatures while retaining strict Ed25519 and canister-signature validation.
- Generated optional and vector values retain declared-type validation, including alpha-equivalent recursive binder checks at method reply boundaries.
- Swift member-name collisions with generated properties and methods are renamed deterministically, while manifest-wide top-level type collisions fail generation with their origins.

### Compatibility

- The generated bindings remain compatible with the ICNativeClient 0.6.0 public Candid and transport APIs. P-256 support changes only delegation-signature acceptance; public APIs, stored sessions, principal derivation, and wire formats are unchanged.

## [0.6.0] - 2026-09-04

### Added

- Optional Keychain access-group selection for sharing `ICIdentityStore` sessions between an application and its extensions.
- `CandidNull`, a typed `CandidConvertible` representation of the Candid `null` value.
- Per-authentication delegation lifetime and explicit target-scope options with response-scope enforcement.
- Configurable HTTP request timeout, polling interval, and default maximum polling attempts.

## [0.5.0] - 2026-09-04

### Added

- A DIDL codec with explicit `CandidType`, `CandidValue`, and `CandidTypedValue` representations.
- Arbitrary-precision Candid integers, validated principals, records, variants, optionals, vectors, blobs, and recursive type references.
- `CandidConvertible` support for Swift primitive, optional, array, data, record, and explicit variant models.
- Typed `query`, `call`, `queryCandid`, and `callCandid` APIs built on the existing verified raw transport.

### Compatibility

- `queryRaw`, `unsafeQueryRaw`, and `callRaw` remain available without behavior changes.
- Typed Candid APIs can be adopted incrementally alongside existing generated bindings and raw payloads.

## [0.4.0] - 2026-09-04

### Added

- BLS12-381 certificate verification with a pinned mainnet trust root and custom-root support.
- Verified query node signatures with a one-hour certified subnet-key cache.
- Strict CBOR parsing, response-size limits, structured rejects, and ICRC-167 native authentication.
- OSS governance, security, third-party notice, and CI files.
- The 0.3.0 authorization timeout, task cancellation, explicit callback path, shared/ephemeral browser selection, and safe base64 URL transport.

### Changed

- `ICClientConfiguration` now has a throwing initializer and validates all security-relevant inputs.
- `queryRaw`, `callRaw`, and `poll` now verify responses before returning them.
- The default Internet Identity session TTL is 8 hours; callers may explicitly request up to 30 days.
- Session private keys are no longer exposed through the public `ICAuthSession` API.
- Keychain loading returns `nil` only for an absent item; operational and malformed-data errors are thrown without deleting the stored session.

### Removed

- The former `identityProvider`, bridge-based native-auth API, and implicit unverified query behavior.
