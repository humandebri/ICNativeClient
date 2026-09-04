#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate_directory=$(CDPATH= cd -- "$script_directory/.." && pwd)
cargo build --locked --release --manifest-path "$crate_directory/Cargo.toml"
real_source_binary="$crate_directory/target/release/ic-candid-swift-bindgen"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ic-bindgen-verifier-test.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
fake_source_directory="$temporary/source binary"
fake_source_binary="$fake_source_directory/ic-candid-swift-bindgen"
mkdir -p "$fake_source_directory"

printf '%s\n' \
  '#!/bin/sh' \
  'if [ "${1:-}" = "--build-info" ]; then' \
  '  printf "%s\n" "version=0.1.2" "source_hash=0000000000000000000000000000000000000000000000000000000000000000"' \
  'else' \
  '  exec "$IC_BINDGEN_REAL_SOURCE_BINARY" "$@"' \
  'fi' > "$fake_source_binary"
chmod +x "$fake_source_binary"

if IC_BINDGEN_REAL_SOURCE_BINARY="$real_source_binary" \
  IC_BINDGEN_SOURCE_BINARY="$fake_source_binary" \
  "$script_directory/verify-artifact-bundle.sh" > "$temporary/output.log" 2>&1; then
  echo "artifact verifier accepted stale build information" >&2
  exit 1
fi
grep -q "build info does not match the current Rust source" "$temporary/output.log" || {
  echo "artifact verifier did not report the stale source mismatch" >&2
  exit 1
}

printf '%s\n' "artifact verifier rejects stale source build information"
