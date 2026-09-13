#!/usr/bin/env bash
#
# build-android.sh
#
# Build kfilesync-core for all Android ABIs and emit:
#   - .so files under   ./build/android/jniLibs/<abi>/libkfilesync_core.so
#   - Kotlin bindings   ./build/android/kotlin/
#
# Requires:
#   - rustup target add aarch64-linux-android armv7-linux-androideabi \
#                       x86_64-linux-android i686-linux-android
#   - cargo install cargo-ndk
#   - ANDROID_NDK_HOME env var pointing to NDK r27+
#
# Usage:
#   ./scripts/build-android.sh [release|debug]

set -euo pipefail

PROFILE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="$ROOT/build/android"

# Sanity checks
if ! command -v cargo-ndk &>/dev/null; then
    echo "error: cargo-ndk not installed. Run: cargo install cargo-ndk" >&2
    exit 1
fi
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "error: ANDROID_NDK_HOME not set. Point it at NDK r27+." >&2
    exit 1
fi

mkdir -p "$OUT/jniLibs"
mkdir -p "$OUT/kotlin"

# -----------------------------------------------------------------------------
# Build native libraries for all ABIs
# Use stable Rust by default. Switch to `+nightly` and uncomment the
# build-std flags below for the production size-budget build.
# -----------------------------------------------------------------------------
echo "==> building libkfilesync_core.so for all Android ABIs ($PROFILE)..."
(
    cd "$ROOT/kfilesync-core"
    cargo ndk \
        -t arm64-v8a \
        -t armeabi-v7a \
        -t x86_64 \
        -t x86 \
        -o "$OUT/jniLibs" \
        build \
        --profile "$PROFILE" \
        --features ffi
        # Production extra args:
        # -Z build-std=core,alloc,panic_abort
        # -Z build-std-features=panic_immediate_abort
)

# -----------------------------------------------------------------------------
# Generate Kotlin bindings via UniFFI
# -----------------------------------------------------------------------------
echo "==> generating Kotlin bindings..."
(
    cd "$ROOT"
    cargo run --release -p kfilesync-core-uniffi -- \
        generate kfilesync-core/src/kfilesync_core.udl \
        --language kotlin \
        --out-dir "$OUT/kotlin"
)

# -----------------------------------------------------------------------------
# Report sizes
# -----------------------------------------------------------------------------
echo
echo "==> output sizes:"
find "$OUT/jniLibs" -name '*.so' -exec ls -lh {} \; \
    | awk '{ printf "  %-10s %s\n", $5, $9 }'

echo
echo "✓ Android build complete. Artifacts in: $OUT"