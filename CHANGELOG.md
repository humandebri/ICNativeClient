# Changelog

All notable changes are documented here.

## [Unreleased]

### Added

- Optional Keychain access-group selection for sharing `ICIdentityStore` sessions between an application and its extensions.
- `CandidNull`, a typed `CandidConvertible` representation of the Candid `null` value.

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
