# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.4.0] - 2026-09-04

### Added

- BLS12-381 certificate verification with a pinned mainnet trust root and custom-root support.
- Verified query node signatures with a one-hour certified subnet-key cache.
- Strict CBOR parsing, response-size limits, structured rejects, and ICRC-167 native authentication.
- OSS governance, security, third-party notice, and CI files.
- Authorization timeout, task cancellation, shared/ephemeral browser selection, and strict ICRC-167 URL-fragment transport.

### Changed

- `ICClientConfiguration` now has a throwing initializer and validates all security-relevant inputs.
- `queryRaw`, `callRaw`, and `poll` now verify responses before returning them.
- The default Internet Identity session TTL is 30 days; callers may explicitly request a shorter lifetime.
- Session private keys are no longer exposed through the public `ICAuthSession` API.
- Keychain loading discards detected 0.1.x sessions and returns `nil`; operational and malformed current-format errors remain visible without deleting stored bytes.

### Removed

- The former `identityProvider`, domain/path and bridge-based native-auth APIs, and implicit unverified query behavior.
