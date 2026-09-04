# Third-party notices

## blst

- Project: `supranational/blst`
- Pinned commit: `de54cd4684a3adba193a6c50ca5861c8c32c3b8a`
- License: Apache License 2.0
- Copyright: Supranational LLC
- Source: `Vendor/blst`
- Upstream: https://github.com/supranational/blst

The complete upstream Apache-2.0 license is included at `Vendor/blst/LICENSE`. Vendored source files are unmodified; the SwiftPM manifest only selects the upstream C entry point, assembly dispatcher, headers, and Apple assembly sources needed by this package.

## Candid parser

- Projects: `dfinity/candid` and `dfinity/candid_parser`
- Versions: `candid 0.10.35`, `candid_parser 0.4.1`
- License: Apache License 2.0
- Upstream: https://github.com/dfinity/candid

These crates and their transitive Rust dependencies are locked in `Tools/ic-candid-swift-bindgen/Cargo.lock` and are linked into the build-time executable artifacts. They are not linked into application binaries or the ICNativeClient runtime library.

## agent-rs test vector

- Project: `dfinity/agent-rs` / `ic-agent`
- Version: `ic-agent 0.49.2`
- Source commit: `e41d8ac25194086fa19ef6ee676decc34c500b50`
- Upstream path: `ic-agent/src/agent/agent_test/ivg37_time.bin`
- Local path: `Tests/ICNativeClientTests/Fixtures/agent_rs_ivg37_time.bin`
- SHA-256: `6293548b4d416845c0d184607ff6989e0a3efc062ceb3ccc3dbc35502ccb3a7e`
- License: Apache License 2.0
- Upstream: https://github.com/dfinity/agent-rs

This mainnet delegated-certificate response vector cross-checks certificate decoding, BLS verification, subnet delegation, and canister ranges. It is redistributed under Apache-2.0; the complete license text is included at `Vendor/blst/LICENSE`.
