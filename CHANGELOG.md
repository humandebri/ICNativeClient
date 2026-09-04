# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.2.0] - 2026-09-04

### Added

- BLS12-381 certificate verification with a pinned mainnet trust root and custom-root support.
- Verified query node signatures with a one-hour certified subnet-key cache.
- Strict CBOR parsing, response-size limits, structured rejects, and ICRC-167 native authentication.
- OSS governance, security, third-party notice, and CI files.

### Changed

- `ICClientConfiguration` now has a throwing initializer and validates all security-relevant inputs.
- `queryRaw`, `callRaw`, and `poll` now verify responses before returning them.
- The default Internet Identity session TTL is 8 hours; callers may explicitly request up to 30 days.
- Session private keys are no longer exposed through the public `ICAuthSession` API.
- Keychain loading returns `nil` only for an absent item; operational and malformed-data errors are thrown without deleting the stored session.

### Removed

- The former `identityProvider`, bridge-based native-auth API, and implicit unverified query behavior.
