# Contributing

Thank you for improving ICNativeClient.

1. Discuss material API or security-model changes in an issue before implementation.
2. Keep changes narrowly scoped and add regression tests for behavior changes.
3. Run `swift test`, the strict-concurrency build documented in the workflow, and an iOS build.
   Bindgen changes must also pass `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `Tools/ic-candid-swift-bindgen/scripts/verify-artifact-bundle.sh`, and the package under `Tests/BindgenPluginFixture`.
4. Preserve the distinction between content canister IDs, effective routing IDs, verified APIs, and explicitly unsafe APIs.
5. Do not add automatic mainnet root-key fetching or silently downgrade verification.

By contributing, you agree that your contribution is licensed under the MIT License. Vendored third-party code retains its upstream license.
