# Changelog

All notable changes are documented here.

## [Unreleased]

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
