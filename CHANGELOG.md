# Changelog

All notable changes are documented here.

## [0.7.3] - 2026-09-05

### Fixed

- Generated Swift bindings now decode Candid-compatible reply subtypes: reply records may add fields, and compatible optional, vector, numeric, and recursive values are projected to the Swift model's expected type.
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
