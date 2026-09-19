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
    for candidate in "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        if [ -n "$candidate" ] && [ -d "$candidate/ndk" ]; then
            LATEST_NDK=$(ls -1d "$candidate/ndk"/* 2>/dev/null | sort -V | tail -n 1)
            if [ -n "$LATEST_NDK" ] && [ -d "$LATEST_NDK" ]; then
                export ANDROID_NDK_HOME="$LATEST_NDK"
                echo "==> auto-detected ANDROID_NDK_HOME=$ANDROID_NDK_HOME"
                break
            fi
        fi
    done
fi
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "error: ANDROID_NDK_HOME not set. Point it at NDK r27+." >&2
    exit 1
fi

mkdir -p "$OUT/jniLibs"
mkdir -p "$OUT/kotlin"

# Directory name cargo uses under target/ for this profile ("dev" is the
# only built-in profile whose directory name differs from its profile name).
if [ "$PROFILE" = "dev" ]; then
    HOST_PROFILE_DIR="debug"
else
    HOST_PROFILE_DIR="$PROFILE"
fi

case "$(uname -s)" in
    Darwin) HOST_CDYLIB_EXT="dylib" ;;
    Linux)  HOST_CDYLIB_EXT="so" ;;
    *)
        echo "error: unsupported host OS for bindgen: $(uname -s)" >&2
        exit 1
        ;;
esac

# ---------------------------------------------------------------------------
# Build a host-native cdylib for binding generation.
# ---------------------------------------------------------------------------
# `kfilesync-core` has no `.udl` file: its FFI surface is declared with
# `#[uniffi::export]` proc-macros, so `uniffi-bindgen` reads the exported
# metadata directly out of a *compiled* library (`generate --library`)
# instead of parsing an interface-definition file. That metadata is
# target-independent, so rather than pointing bindgen at one of the
# cross-compiled Android `.so`s (which `object`-crate parsing may not
# handle for every target/format), we build one extra host-native cdylib
# purely to hand to bindgen; it is never shipped.
# ---------------------------------------------------------------------------
echo "==> building host-native cdylib for bindgen ($PROFILE)..."
(
    cd "$ROOT/kfilesync-core"
    cargo build --profile "$PROFILE" --features ffi
)
HOST_CDYLIB="$ROOT/target/$HOST_PROFILE_DIR/libkfilesync_core.$HOST_CDYLIB_EXT"

# ---------------------------------------------------------------------------
# Build native libraries for all ABIs
# Use stable Rust by default. Switch to `+nightly` and uncomment the
# build-std flags below for the production size-budget build.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Generate Kotlin bindings via UniFFI (library mode, off the host cdylib)
# ---------------------------------------------------------------------------
echo "==> generating Kotlin bindings..."
(
    cd "$ROOT"
    cargo run --release -p kfilesync-core-uniffi -- \
        generate --library "$HOST_CDYLIB" \
        --language kotlin \
        --out-dir "$OUT/kotlin"
)

# ---------------------------------------------------------------------------
# Report sizes
# ---------------------------------------------------------------------------
echo
echo "==> output sizes:"
find "$OUT/jniLibs" -name '*.so' -exec ls -lh {} \; \
    | awk '{ printf "    %-10s %s\n", $5, $9 }'

echo
echo " Android build complete. Artifacts in: $OUT"