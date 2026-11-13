#!/bin/bash
# Guard: Kotlin's JNI declarations and Rust's JNI exports must be the same names.
#
# `server-android/app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt`
# declares what Kotlin calls as `external fun <name>`; `shared/src/jni_api.rs`
# exports the same names as `Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_<name>`.
# Nothing on either side checks that the pair agrees: a Kotlin declaration with no
# Rust export compiles fine and fails only on the device, at call time, with
# UnsatisfiedLinkError, and a Rust export with no Kotlin declaration is dead code
# nothing ever calls. That gap is how a parallel Kotlin-side rewrite shipped a JNI
# surface Rust had never implemented.
#
# Both sets are parsed from the *source text* rather than from a built library: the
# `initLogging` export sits behind `#[cfg(target_os = "android")]`, so it is simply
# absent from a host build.
#
# Only identifiers are compared, not signatures. No third-party dependencies:
# grep -E, sed -E, sort, uniq and comm. Exit 0 on equality, 1 on divergence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ $# -gt 0 ]; then
    if [ "$1" = "--root" ] && [ $# -eq 2 ]; then
        if [ ! -d "$2" ]; then
            echo "error: --root '$2' is not a directory" >&2
            exit 2
        fi
        PROJECT_ROOT="$(cd -- "$2" && pwd)"
    else
        echo "usage: $0 [--root <dir>]" >&2
        exit 2
    fi
fi

KOTLIN_REL="server-android/app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt"
RUST_REL="shared/src/jni_api.rs"
KOTLIN_FILE="$PROJECT_ROOT/$KOTLIN_REL"
RUST_FILE="$PROJECT_ROOT/$RUST_REL"
SYMBOL_PREFIX="Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_"

for f in "$KOTLIN_FILE" "$RUST_FILE"; do
    if [ ! -r "$f" ]; then
        echo "error: cannot read $f" >&2
        exit 2
    fi
done

# Comment lines are dropped first, so a declaration someone commented out while
# debugging (`// external fun foo(`, `// pub extern "system" fn Java_..._foo(`) is
# really gone: it is not a JNI entry point, and counting it would keep the guard green
# while the device throws UnsatisfiedLinkError. This also drops `//` and `//!`/`///`
# doc comments on the Rust side.
#
# What remains must be an actual declaration at the start of its line: a mention in
# prose, a doc link or a call site can never be counted as an entry point.
# * Kotlin: `external fun sha256(...)`, `private external fun initLogging()` and
#   `external fun pairingCreateConfirmServer(` all match. The identifier always sits on
#   the same physical line as the keywords; only the parameter list continues on later
#   lines.
# * Rust: `#[no_mangle]` above a `pub extern "system" fn Java_..._<name>(`. Requiring
#   the definition means the intra-doc link in this file's own comments
#   (`/// [`Java_dev_..._generateTemporalIdentifier`]`) is not a second export.
kotlin_names="$(grep -v -E '^[[:space:]]*//' "$KOTLIN_FILE" \
    | grep -E '^[[:space:]]*(private[[:space:]]+|internal[[:space:]]+|public[[:space:]]+)?external[[:space:]]+fun[[:space:]]+[A-Za-z_]' \
    | sed -E 's/^[[:space:]]*(private[[:space:]]+|internal[[:space:]]+|public[[:space:]]+)?external[[:space:]]+fun[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\2/' || true)"

rust_names="$(grep -v -E '^[[:space:]]*//' "$RUST_FILE" \
    | grep -E "^[[:space:]]*pub[[:space:]]+extern[[:space:]]+\"system\"[[:space:]]+fn[[:space:]]+${SYMBOL_PREFIX}[A-Za-z0-9_]+" \
    | sed -E "s/^[[:space:]]*pub[[:space:]]+extern[[:space:]]+\"system\"[[:space:]]+fn[[:space:]]+${SYMBOL_PREFIX}([A-Za-z0-9_]+).*/\1/" || true)"

# A silent parse failure must not read as "the surfaces agree", so an empty side is
# an error, not an empty diff.
if [ -z "$(printf '%s\n' "$kotlin_names" | tr -d '[:space:]')" ]; then
    echo "error: found no Kotlin \`external fun\` declarations in $KOTLIN_REL" >&2
    echo "       — the extraction pattern is stale; fix it before trusting this check" >&2
    exit 2
fi
if [ -z "$(printf '%s\n' "$rust_names" | tr -d '[:space:]')" ]; then
    echo "error: found no Rust JNI exports in $RUST_REL" >&2
    echo "       — the extraction pattern is stale; fix it before trusting this check" >&2
    exit 2
fi

kotlin_sorted="$(printf '%s\n' "$kotlin_names" | LC_ALL=C sort)"
rust_sorted="$(printf '%s\n' "$rust_names" | LC_ALL=C sort)"
kotlin_dups="$(printf '%s\n' "$kotlin_sorted" | uniq -d)"
rust_dups="$(printf '%s\n' "$rust_sorted" | uniq -d)"
# comm pairs line N of one file with line N of the other, so a repeated name would
# otherwise show up in the set diff as well as in the duplicate diagnostic. Diff the
# de-duplicated sets and let the `uniq -d` checks above own duplicates.
missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$kotlin_sorted" | LC_ALL=C sort -u) \
    <(printf '%s\n' "$rust_sorted" | LC_ALL=C sort -u))"
unused="$(LC_ALL=C comm -13 <(printf '%s\n' "$kotlin_sorted" | LC_ALL=C sort -u) \
    <(printf '%s\n' "$rust_sorted" | LC_ALL=C sort -u))"

fail=0
report() {
    local heading=$1 names=$2
    [ -n "$names" ] || return 0
    fail=1
    echo "❌ $heading" >&2
    printf '%s\n' "$names" | sed 's/^/     /' >&2
}

report "duplicate declaration in $KOTLIN_REL:" "$kotlin_dups"
report "duplicate export in $RUST_REL:" "$rust_dups"
report "declared in Kotlin but has no Rust symbol:" "$missing"
report "exported from Rust but not declared in Kotlin:" "$unused"

if [ "$fail" != "0" ]; then
    echo "" >&2
    echo "   Kotlin declarations: $KOTLIN_REL (\`external fun <name>\`)" >&2
    echo "   Rust exports:       $RUST_REL (\`pub extern \"system\" fn ${SYMBOL_PREFIX}<name>\`)" >&2
    echo "   Both sides must name the same functions. A one-sided entry still compiles," >&2
    echo "   then fails on the device with UnsatisfiedLinkError, or is dead code no" >&2
    echo "   Kotlin caller can reach. A commented-out declaration does not count:" >&2
    echo "   uncomment it or delete its counterpart." >&2
    exit 1
fi

count="$(printf '%s\n' "$kotlin_sorted" | LC_ALL=C sort -u | wc -l | tr -d '[:space:]')"
echo "JNI surface OK: $count entry points"
