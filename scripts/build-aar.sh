#!/usr/bin/env bash
#
# build-aar.sh
#
# Build kfilesync-core Android native libraries + UniFFI Kotlin bindings,
# then package into a standard Android AAR artifact (.aar).
#
# Usage:
#   ./scripts/build-aar.sh [release|dev] [--publish-local]
#

set -euo pipefail

PROFILE="release"
PUBLISH_LOCAL=false

for arg in "$@"; do
    case "$arg" in
        release|dev)
            PROFILE="$arg"
            ;;
        --publish-local)
            PUBLISH_LOCAL=true
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: ./scripts/build-aar.sh [release|dev] [--publish-local]"
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Auto-detect ANDROID_HOME if not set
if [ -z "${ANDROID_HOME:-}" ]; then
    for candidate in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        if [ -d "$candidate" ]; then
            export ANDROID_HOME="$candidate"
            break
        fi
    done
fi

echo "==> Step 1: Building Android native libraries and UniFFI Kotlin bindings ($PROFILE)..."
bash "$ROOT/scripts/build-android.sh" "$PROFILE"

echo "==> Step 2: Packaging AAR via Gradle..."
cd "$ROOT/android"

if [ "$PUBLISH_LOCAL" = true ]; then
    echo "==> Publishing to Maven Local (~/.m2)..."
    ./gradlew publishToMavenLocal
else
    ./gradlew assembleRelease
fi

AAR_OUTPUT="$ROOT/android/build/outputs/aar/kfilesync-core-android-release.aar"
if [ -f "$AAR_OUTPUT" ]; then
    echo
    echo "==> Success! AAR built at: $AAR_OUTPUT"
    ls -lh "$AAR_OUTPUT"
fi
