#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
repository_root=$(CDPATH= cd -- "$crate_directory/../.." && pwd)
bundle="$repository_root/Artifacts/ICNativeClientBindgen.artifactbundle"
fixture_manifest="$crate_directory/tests/fixtures/bindings.toml"

fail() {
  echo "artifact verification failed: $1" >&2
  exit 1
}

if [ -n "${IC_BINDGEN_SOURCE_BINARY:-}" ]; then
  source_binary=$IC_BINDGEN_SOURCE_BINARY
else
  cargo build --locked --release --manifest-path "$crate_directory/Cargo.toml"
  source_binary="$crate_directory/target/release/ic-candid-swift-bindgen"
fi

source_info=$("$source_binary" --build-info)
expected_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$crate_directory/Cargo.toml" | head -n 1)
actual_version=$(printf '%s\n' "$source_info" | sed -n 's/^version=//p')
source_hash=$(printf '%s\n' "$source_info" | sed -n 's/^source_hash=//p')
[ "$actual_version" = "$expected_version" ] || fail "source binary version is $actual_version, expected $expected_version"
[ "${#source_hash}" -eq 64 ] || fail "source hash is not a SHA-256 digest"
case "$source_hash" in
  *[!0-9a-f]*) fail "source hash is not lowercase hexadecimal" ;;
esac

temporary=$(mktemp -d "${TMPDIR:-/tmp}/ic-bindgen-verify.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
"$source_binary" \
  --manifest "$fixture_manifest" \
  --output "$temporary/source.swift" \
  --project-root "$repository_root"

verify_binary() {
  architecture=$1
  binary=$2
  [ -x "$binary" ] || fail "$architecture binary is missing or not executable"
  actual_architecture=$(lipo -archs "$binary")
  [ "$actual_architecture" = "$architecture" ] || fail "$binary contains $actual_architecture, expected only $architecture"

  artifact_info=$("$binary" --build-info)
  [ "$artifact_info" = "$source_info" ] || fail "$architecture build info does not match the current Rust source"
  "$binary" \
    --manifest "$fixture_manifest" \
    --output "$temporary/$architecture.swift" \
    --project-root "$repository_root"
  cmp -s "$temporary/source.swift" "$temporary/$architecture.swift" || fail "$architecture fixture output differs from the source build"
}

verify_binary \
  arm64 \
  "$bundle/ic-candid-swift-bindgen-0.1.0-macos-arm64/bin/ic-candid-swift-bindgen"
verify_binary \
  x86_64 \
  "$bundle/ic-candid-swift-bindgen-0.1.0-macos-x86_64/bin/ic-candid-swift-bindgen"

printf '%s\n' "artifact bundle matches ic-candid-swift-bindgen $actual_version ($source_hash)"
