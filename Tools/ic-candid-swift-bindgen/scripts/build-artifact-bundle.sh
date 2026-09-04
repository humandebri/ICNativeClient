#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
repository_root=$(CDPATH= cd -- "$crate_directory/../.." && pwd)
bundle="$repository_root/Artifacts/ICNativeClientBindgen.artifactbundle"

rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --locked --release --target aarch64-apple-darwin --manifest-path "$crate_directory/Cargo.toml"
cargo build --locked --release --target x86_64-apple-darwin --manifest-path "$crate_directory/Cargo.toml"

install -d \
  "$bundle/ic-candid-swift-bindgen-0.1.2-macos-arm64/bin" \
  "$bundle/ic-candid-swift-bindgen-0.1.2-macos-x86_64/bin"

install -m 755 \
  "$crate_directory/target/aarch64-apple-darwin/release/ic-candid-swift-bindgen" \
  "$bundle/ic-candid-swift-bindgen-0.1.2-macos-arm64/bin/ic-candid-swift-bindgen"
install -m 755 \
  "$crate_directory/target/x86_64-apple-darwin/release/ic-candid-swift-bindgen" \
  "$bundle/ic-candid-swift-bindgen-0.1.2-macos-x86_64/bin/ic-candid-swift-bindgen"

shasum -a 256 "$bundle"/*/bin/ic-candid-swift-bindgen
