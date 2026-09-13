#!/usr/bin/env bash
#
# verify-scaffold.sh
#
# Quick sanity check that the scaffold builds and tests pass. Run this
# before sending the first PR or whenever you want to confirm nothing
# rotted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

echo "==> cargo fmt --check"
cargo fmt --all -- --check

echo "==> cargo build (workspace, default features)"
cargo build --workspace

echo "==> cargo test (workspace, default features)"
cargo test --workspace

echo "==> cargo clippy (default features)"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> conformance runner"
cargo run --release -p kfilesync-conformance-runner

echo
echo "✓ Scaffold verification passed."