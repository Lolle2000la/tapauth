#!/bin/bash
# Regenerate `scripts/ci/fixtures/javap-TapAuthCrypto.txt`.
#
# The fixture is **generated output** — the verbatim `javap -s -p` dump of the
# Kotlin class that compiled `TapAuthCrypto.kt`. Never hand-edit it: it exists
# precisely because `check-jni-signatures.py` must compare the Kotlin type table
# against what the real compiler emitted, not against another table of mine.
#
# A Kotlin signature change therefore lands as a diff in the fixture only after a
# real Android build has produced a new class file. Rebuild the app first:
#
#   cd server-android && ./gradlew :app:compileDebugKotlin
#   ./scripts/ci/refresh-jni-javap-fixture.sh
#
# The classes directory may be overridden with $1 (default: the debug Kotlin
# compile output). The dump goes straight from javap's stdout to the file; do not
# add a header or reorder members by hand.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE="$SCRIPT_DIR/fixtures/javap-TapAuthCrypto.txt"
CLASSES="${1:-$PROJECT_ROOT/server-android/app/build/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes}"
JAVAP_CLASS="dev.rourunisen.tapauth.crypto.TapAuthCrypto"

if [ ! -d "$CLASSES" ]; then
    echo "error: classes directory '$CLASSES' does not exist" >&2
    echo "       build the Android app first: (cd server-android && ./gradlew :app:compileDebugKotlin)" >&2
    exit 2
fi
if ! command -v javap >/dev/null 2>&1; then
    echo "error: \`javap\` is not on PATH (install a JDK)" >&2
    exit 2
fi

# Write to a temporary file and move it into place, so a failed javap run cannot
# leave a truncated fixture behind for the CI check to compare against.
tmp="$(mktemp "$FIXTURE.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
javap -s -p -cp "$CLASSES" "$JAVAP_CLASS" > "$tmp"
mv "$tmp" "$FIXTURE"
trap - EXIT
echo "wrote $FIXTURE from $CLASSES ($(grep -c '\bnative\b' "$FIXTURE" || true) native members)"
