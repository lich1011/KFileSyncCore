#!/usr/bin/env bash
#
# build-ios.sh
#
# Build kfilesync-core for iOS device + simulator slices, lipo the
# simulator slice, then package an XCFramework:
#
#   build/ios/KFileSyncCore.xcframework
#
# Plus Swift bindings:
#
#   build/ios/swift/
#
# Requires: macOS with Xcode + command-line tools.

set -euo pipefail

PROFILE="${1:-release}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT="$ROOT/build/ios"

mkdir -p "$OUT/swift"
mkdir -p "$OUT/include"

# ---------------------------------------------------------------------------
# Add iOS targets if missing
# ---------------------------------------------------------------------------
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# ---------------------------------------------------------------------------
# Build a host-native (macOS) cdylib for binding generation.
# ---------------------------------------------------------------------------
# `kfilesync-core` has no `.udl` file: its FFI surface is declared with
# `#[uniffi::export]` proc-macros, so `uniffi-bindgen` reads the exported
# metadata directly out of a *compiled* library (`generate --library`)
# instead of parsing an interface-definition file. That metadata is
# target-independent, so rather than pointing bindgen at one of the
# cross-compiled iOS `.a` static libraries, we build one extra host-native
# cdylib purely to hand to bindgen; it is never shipped.
# ---------------------------------------------------------------------------
echo "==> building host-native cdylib for bindgen ($PROFILE)..."
(
    cd "$ROOT/kfilesync-core"
    cargo build --profile "$PROFILE" --features ffi
)
if [ "$PROFILE" = "dev" ]; then
    HOST_PROFILE_DIR="debug"
else
    HOST_PROFILE_DIR="$PROFILE"
fi
HOST_CDYLIB="$ROOT/target/$HOST_PROFILE_DIR/libkfilesync_core.dylib"

# ---------------------------------------------------------------------------
# Build all three iOS slices
# ---------------------------------------------------------------------------
echo "==> building libkfilesync_core.a for iOS targets ($PROFILE)..."
(
    cd "$ROOT/kfilesync-core"
    for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
        cargo build --target "$target" --profile "$PROFILE" --features ffi
        # Production extra args:
        # +nightly -Z build-std=core,alloc,panic_abort
    done
)

# ---------------------------------------------------------------------------
# Lipo simulator slices into one universal binary
# ---------------------------------------------------------------------------
echo "==> creating universal simulator binary..."
mkdir -p "$ROOT/target/ios-sim-universal/$PROFILE"
lipo -create \
    "$ROOT/target/aarch64-apple-ios-sim/$PROFILE/libkfilesync_core.a" \
    "$ROOT/target/x86_64-apple-ios/$PROFILE/libkfilesync_core.a" \
    -output "$ROOT/target/ios-sim-universal/$PROFILE/libkfilesync_core.a"

# ---------------------------------------------------------------------------
# Generate Swift bindings + C header
# ---------------------------------------------------------------------------
echo "==> generating Swift bindings..."
(
    cd "$ROOT"
    cargo run --release -p kfilesync-core-uniffi -- \
        generate --library "$HOST_CDYLIB" \
        --language swift \
        --out-dir "$OUT/swift"
)

# Move the generated C header into the include dir for the XCFramework.
cp "$OUT/swift/kfilesync_coreFFI.h" "$OUT/include/" 2>/dev/null || true

# Module map so Swift can import the C symbols.
cat > "$OUT/include/module.modulemap" <<'EOF'
module kfilesync_coreFFI {
    header "kfilesync_coreFFI.h"
    export *
}
EOF

# ---------------------------------------------------------------------------
# Package XCFramework
# ---------------------------------------------------------------------------
echo "==> packaging XCFramework..."
rm -rf "$OUT/KFileSyncCore.xcframework"
xcodebuild -create-xcframework \
    -library "$ROOT/target/aarch64-apple-ios/$PROFILE/libkfilesync_core.a" \
    -headers "$OUT/include" \
    -library "$ROOT/target/ios-sim-universal/$PROFILE/libkfilesync_core.a" \
    -headers "$OUT/include" \
    -output "$OUT/KFileSyncCore.xcframework"

# ---------------------------------------------------------------------------
# Report sizes
# ---------------------------------------------------------------------------
echo
echo "==> output sizes;"
ls -lh \
    "$ROOT/target/aarch64-apple-ios/$PROFILE/libkfilesync_core.a" \
    "$ROOT/target/ios-sim-universal/$PROFILE/libkfilesync_core.a" \
    | awk '{ printf "    %-10s %s\n", $5, $9 }'

echo
echo " iOS build complete, XCFramework at: $OUT/KFileSyncCore.xcframework"