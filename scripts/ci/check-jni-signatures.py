#!/usr/bin/env python3
"""Guard: the Rust JNI exports and the Kotlin `external fun` declarations must
agree on types, not just on names.

`scripts/ci/check-jni-surface.sh` compares identifiers only, and the C ABI the
two sides share encodes no types: a `jlong` implemented as `jint`, or two
same-typed parameters swapped in Rust, still compiles, still links, still passes
that name check, and is undefined behaviour on the device. Nothing else in the
tree can see it, so this compares each Rust parameter list and return type
against the JVM descriptor Kotlin actually compiled to.

Three sets are derived independently and cross-checked:
  (a) Kotlin source, `TapAuthCrypto.kt`   -> this script's Kotlin type table
  (b) `javap` output, checked-in fixture  -> the real compiler's descriptor
  (c) Rust exports, `shared/src/**/*.rs`  -> this script's Rust type table

(a) vs (b) pins the Kotlin type table to what a real Android build emitted,
which the CI job that runs this cannot reproduce (no Android SDK, no Gradle).
The fixture is therefore compiler output, regenerated only by
`refresh-jni-javap-fixture.sh`; editing it by hand would make this comparison
assert against itself. Every extraction has an explicit "is this still true?"
guard, because a parser that silently stops matching a declaration would turn
into an empty diff that reads as agreement.

Exit 0 on agreement, 1 on divergence, 2 on a usage, parse or extraction problem.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

SYMBOL_PREFIX = "Java_dev_rourunisen_tapauth_crypto_TapAuthCrypto_"
KOTLIN_REL = "server-android/app/src/main/java/dev/rourunisen/tapauth/crypto/TapAuthCrypto.kt"
FIXTURE_REL = "scripts/ci/fixtures/javap-TapAuthCrypto.txt"
RUST_SRC_REL = "shared/src"
JAVAP_CLASS = "dev.rourunisen.tapauth.crypto.TapAuthCrypto"

# A type missing from either table is a hard error rather than a skip: a newly
# declared type would otherwise drop out of the comparison while the guard kept
# reporting agreement.
KOTLIN_TYPES = {
    "ByteArray": "[B",
    "Int": "I",
    "Long": "J",
    "Boolean": "Z",
    "String": "Ljava/lang/String;",
    "Array<ByteArray>": "[[B",
    "ParsedAuthRequest": "Ldev/rourunisen/tapauth/crypto/ParsedAuthRequest;",
    "ParsedPairingProvision": "Ldev/rourunisen/tapauth/crypto/ParsedPairingProvision;",
    "ParsedPairingResponse": "Ldev/rourunisen/tapauth/crypto/ParsedPairingResponse;",
    "Unit": "V",
}
# `jobject` / `jobjectArray` are deliberately wildcards: the C ABI cannot tell
# which class or element type is behind the pointer, so claiming more would be a
# guess. Everything else is exact.
RUST_TYPES = {
    "JByteArray": "[B", "jbyteArray": "[B", "jint": "I", "jlong": "J", "jboolean": "Z",
    "JString": "Ljava/lang/String;", "jstring": "Ljava/lang/String;",
    "JObject": "L*", "jobject": "L*", "JObjectArray": "[*", "jobjectArray": "[*",
}
# JNI entry points receive the JVM environment and the class/object receiver
# first; neither has a Kotlin counterpart, so both are dropped from the
# comparison. Matched on the last path segment, so `jni::EnvUnowned` aliases and
# fully qualified spellings are treated alike.
SKIPPED_RECEIVERS = {"JNIEnv", "JClass"}

KOTLIN_DECL = re.compile(
    r"^[ \t]*(?:(?:private|internal|public)[ \t]+)?external[ \t]+fun[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(", re.M)
RUST_FN = re.compile(
    r"^[ \t]*pub[ \t]+extern[ \t]+\"system\"[ \t]+fn[ \t]+"
    + re.escape(SYMBOL_PREFIX) + r"([A-Za-z0-9_]+)[ \t]*\(", re.M)
NO_MANGLE = re.compile(r"^[ \t]*#\[no_mangle\][ \t]*$", re.M)
ATTRIBUTE = re.compile(r"^[ \t]*#\[")


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(2)


def strip_line_comments(text):
    """Drop `//`-comment lines exactly as check-jni-surface.sh does.

    A commented-out declaration is not an entry point; counting it would keep
    this guard green while the device throws UnsatisfiedLinkError. On the Rust
    side this also removes `///` doc comments, whose intra-doc links spell out
    symbol names.
    """
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("//"))


def balanced(code, pos):
    """Return (inner, rest) for the parenthesised group opening just before pos."""
    depth = 1
    for index in range(pos, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return code[pos:index], code[index + 1:]
    return None, None


def split_params(text):
    """Split a parameter list on top-level commas, keeping nested groups whole."""
    parts, depth, current = [], 0, ""
    for char in text:
        if char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return [part.strip() for part in parts if part.strip()]


def make_decl(name, params, ret, filename):
    return {"name": name, "params": params, "ret": ret, "file": filename}


def descriptor_of(decl):
    return "(" + "".join(token for _, _, token in decl["params"]) + ")" + decl["ret"][1]


def describe_params(decl):
    return ", ".join(f"{name}: {raw}" for name, raw, _ in decl["params"])


def map_type(table, key, kind, where, table_name):
    if key not in table:
        fail(f"error: unknown {kind} type `{key}` in {where}\n"
             f"       — add it to {table_name}, do not skip it")
    return table[key]


# (a) Kotlin source.
def parse_kotlin(path):
    with open(path, encoding="utf-8") as handle:
        code = strip_line_comments(handle.read())
    filename = os.path.basename(path)
    decls = {}
    for match in KOTLIN_DECL.finditer(code):
        name = match.group(1)
        params_text, rest = balanced(code, match.end())
        if params_text is None:
            fail(f"error: unbalanced parameter list in Kotlin declaration `{name}`")
        # The return type may start on the next line (`external fun f(x: ByteArray)`
        # then `: ByteArray`), so skip whitespace including newlines before the
        # `:`; otherwise such a declaration would read as `Unit` and surface as a
        # confusing fixture mismatch instead.
        ret_match = re.match(r"\s*:([^=\n{]*)", rest)
        ret_raw = ret_match.group(1).strip() if ret_match else "Unit"
        ret_key = re.sub(r"\s+", "", ret_raw)
        ret = (ret_raw, map_type(KOTLIN_TYPES, ret_key, "Kotlin return", name, "KOTLIN_TYPES"))
        params = []
        for raw in split_params(params_text):
            param_name, sep, param_type = raw.partition(":")
            if not sep:
                fail(f"error: cannot parse parameter `{raw}` of Kotlin `{name}`")
            param_type = param_type.strip()
            key = re.sub(r"\s+", "", param_type)
            where = f"`{name}` (parameter {len(params) + 1}) in {filename}"
            token = map_type(KOTLIN_TYPES, key, "Kotlin parameter", where, "KOTLIN_TYPES")
            params.append((param_name.strip(), param_type, token))
        if name in decls:
            fail(f"error: duplicate Kotlin declaration `{name}` in {filename}")
        decls[name] = make_decl(name, params, ret, filename)
    return decls


# (b) javap output: the checked-in fixture, or a live run with `--javap`.
def parse_javap(text):
    """Map method name -> JVM descriptor for `native` members only.

    javap prints a member line and then its `descriptor:` line. Non-native
    members (`INSTANCE`, `$stable`, the constant ints, constructors, `static {}`)
    have no Rust symbol behind them, so only lines carrying `native` are read.
    """
    members, pending = {}, None
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("descriptor:"):
            if pending is not None:
                members[pending] = stripped.split(":", 1)[1].strip()
            pending = None
        elif line.rstrip().endswith(";") and re.search(r"\bnative\b", line):
            match = re.search(r"([A-Za-z_$][\w$]*)\s*\(", line)
            pending = match.group(1) if match else None
        else:
            pending = None
    return members


def run_javap(classes_dir):
    javap = shutil.which("javap")
    if javap is None:
        fail("error: --javap needs `javap` on PATH (install a JDK or drop the flag)")
    if not os.path.isdir(classes_dir):
        fail(f"error: --javap classes directory '{classes_dir}' does not exist")
    result = subprocess.run([javap, "-s", "-p", "-cp", classes_dir, JAVAP_CLASS],
                            capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"error: `javap -s -p -cp {classes_dir} {JAVAP_CLASS}` failed:\n"
             f"{result.stderr.strip()}")
    return result.stdout


# (c) Rust exports: every .rs file under shared/src, recursed, so `jni_api.rs`
# and `jni_api/*.rs` are both covered and a new module cannot sit outside it.
def rust_files(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(root, RUST_SRC_REL)):
        dirnames.sort()
        found.extend(os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith(".rs"))
    return found


def rust_type_token(raw, where):
    text = raw.strip()
    # Drop references, lifetimes and `mut`: none of them change the JVM type.
    text = re.sub(r"^&\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?", "", text)
    segment = re.sub(r"^mut\s+", "", text).strip().split("::")[-1].strip()
    return segment, map_type(RUST_TYPES, segment, "Rust", where, "RUST_TYPES")


def parse_rust_file(path, relpath, exports):
    with open(path, encoding="utf-8") as handle:
        raw_lines = handle.read().split("\n")
    # Keep the original 1-based line numbers alongside the comment-stripped text,
    # so diagnostics and the prefix guard can point at the real file.
    kept = [(number, line) for number, line in enumerate(raw_lines, start=1)
            if not line.lstrip().startswith("//")]
    code = "\n".join(line for _, line in kept)

    def line_number_at(position):
        index = min(code.count("\n", 0, position), len(kept) - 1)
        return kept[index][0]

    parsed_lines = set()
    for no_mangle in NO_MANGLE.finditer(code):
        where = f"{relpath}:{line_number_at(no_mangle.start())}"
        position = no_mangle.end() + 1
        while position <= len(code):
            end = code.find("\n", position)
            end = len(code) if end == -1 else end
            line = code[position:end]
            if not line.strip() or ATTRIBUTE.match(line):
                position = end + 1
                continue
            fn_match = RUST_FN.match(code, position)
            if fn_match is None:
                fail(f"error: #[no_mangle] at {where} is not followed by a statically "
                     f"parseable `pub extern \"system\" fn {SYMBOL_PREFIX}<name>(`\n"
                     "       — export is not statically parseable — extend this check")
            break
        else:
            fail(f"error: #[no_mangle] at {where} has no following item\n"
                 "       — export is not statically parseable — extend this check")

        name = fn_match.group(1)
        parsed_lines.add(line_number_at(fn_match.start(1)))
        where = f"{relpath}:{line_number_at(fn_match.start(1))}"
        params_text, rest = balanced(code, fn_match.end())
        if params_text is None:
            fail(f"error: unbalanced parameter list in Rust export `{name}` at {where}")
        ret_match = re.match(r"[ \t]*->[ \t]*([^\n{]+?)[ \t]*\{", rest)
        if ret_match:
            ret_raw, ret_token = rust_type_token(ret_match.group(1), where)
        elif re.match(r"[ \t]*\{", rest):
            ret_raw, ret_token = None, "V"
        else:
            fail(f"error: cannot parse the return type of Rust export `{name}` at {where}")

        params = []
        for index, raw in enumerate(split_params(params_text)):
            raw_name, sep, raw_type = raw.partition(":")
            if not sep:
                fail(f"error: cannot parse parameter `{raw}` of Rust export `{name}` at {where}")
            param_name = raw_name.strip()
            if param_name.startswith("mut "):
                param_name = param_name[len("mut "):].strip()
            # Receivers have no Kotlin counterpart, and only the first two
            # positions can be receivers.
            segment = re.sub(r"^&\s*(?:'[A-Za-z_][A-Za-z0-9_]*\s+)?", "", raw_type.strip())
            segment = re.sub(r"^mut\s+", "", segment).strip().split("::")[-1].strip()
            if index < 2 and segment in SKIPPED_RECEIVERS:
                continue
            params.append((param_name,) + rust_type_token(raw_type, where))

        if name in exports:
            fail(f"error: duplicate Rust export `{name}` at {where}")
        exports[name] = make_decl(name, params, (ret_raw, ret_token), os.path.basename(path))

    # Any other mention of the symbol prefix in live code means the name is
    # assembled somewhere this parser cannot read (a macro, a `concat!`, a
    # table); such an export would silently escape the comparison below.
    #
    # `#[export_name = ...]` gets its own guard because the fn still parses
    # under its Rust name while the symbol actually exported is the one the
    # attribute names — `concat!` can split the prefix across strings, so no
    # textual scan for the prefix sees it. A renamed export cannot be checked
    # here, so it is an error rather than a silent pass.
    for number, line in kept:
        if "export_name" in line:
            fail(f"error: {relpath}:{number} uses `export_name`\n"
                 "       — a renamed export cannot be checked statically; extend this check")
        if SYMBOL_PREFIX in line and number not in parsed_lines:
            fail(f"error: {relpath}:{number} mentions `{SYMBOL_PREFIX}` outside a parsed "
                 "export\n       — a symbol assembled elsewhere cannot be checked here")
    return sum(line.count(SYMBOL_PREFIX) for _, line in kept)


def parse_rust(root):
    exports, total_prefix = {}, 0
    for path in rust_files(root):
        total_prefix += parse_rust_file(path, os.path.relpath(path, root), exports)
    if total_prefix != len(exports):
        fail(f"error: found {total_prefix} `{SYMBOL_PREFIX}` occurrences but parsed "
             f"{len(exports)} exports\n"
             "       — export is not statically parseable — extend this check")
    return exports


# Comparisons.
def tokens_agree(rust_token, kotlin_token):
    # `jobject` stays a wildcard for any reference type: the C type genuinely
    # cannot say which class is behind the pointer, so the three `Parsed*`
    # returns are only checked to be *some* object here. The identity of the
    # class is covered elsewhere — `shared/src/jni/objects.rs` constructs it and
    # the Kotlin `JniDescriptorTest` pins the constructor descriptor.
    if rust_token == "L*":
        return kotlin_token.startswith("L") and kotlin_token.endswith(";")
    # `jobjectArray`, by contrast, is a jobject array: it can only hold arrays of
    # references (`[[B`, `[Ljava/lang/String;`), never a primitive array such as
    # `[B`. Accepting any `[` would let `jobjectArray` stand in for a `ByteArray`.
    if rust_token == "[*":
        return kotlin_token.startswith("[[") or kotlin_token.startswith("[L")
    return rust_token == kotlin_token


def canonical(name):
    return name.lower().replace("_", "")


def compare_export(kotlin, rust):
    problems = []
    kparams, rparams = kotlin["params"], rust["params"]
    same_arity = len(kparams) == len(rparams)

    reasons = []
    if same_arity:
        for position, (kp, rp) in enumerate(zip(kparams, rparams), start=1):
            if not tokens_agree(rp[2], kp[2]):
                reasons.append(f"parameter {position} `{kp[0]}`: Kotlin `{kp[1]}` ({kp[2]}) "
                               f"vs Rust `{rp[1]}` ({rp[2]})")
    else:
        reasons.append(f"parameter count: Kotlin {len(kparams)} "
                       f"({describe_params(kotlin) or 'none'}) vs Rust {len(rparams)} "
                       f"({describe_params(rust) or 'none'})")
    if not tokens_agree(rust["ret"][1], kotlin["ret"][1]):
        reasons.append(f"return type: Kotlin `{kotlin['ret'][0]}` ({kotlin['ret'][1]}) "
                       f"vs Rust `{rust['ret'][0] or 'none'}` ({rust['ret'][1]})")
    if reasons:
        lines = [f"❌ JNI signature mismatch in `{kotlin['name']}`",
                 f"     Kotlin ({kotlin['file']}):  {descriptor_of(kotlin)}  — "
                 f"{describe_params(kotlin)}",
                 f"     Rust   ({rust['file']}):        {descriptor_of(rust)}  — "
                 f"{describe_params(rust)}"]
        lines.extend("     " + reason for reason in reasons)
        problems.append("\n".join(lines))

    # Parameter names are compared only where the descriptor is blind: at
    # positions whose Rust token and Kotlin descriptor are identical (`[B`
    # against `[B`, `I` against `I`). A descriptor comparison cannot see a swap
    # between two such parameters, so their names are the only evidence of
    # order. Grouping is by token across the *whole* parameter list, not by
    # adjacency: `(ByteArray, Int, ByteArray)` puts both `[B` positions in one
    # group, and a swap of those two — with an `Int` in between, which no
    # contiguous run would ever pair up — is caught here and nowhere else.
    # Names are never compared across different types, and there is no allowlist
    # of renames.
    #
    # `expected_symmetric_algorithm` (Rust) vs `expectedSymAlg` (Kotlin) differ
    # in spelling but each is alone in its token group, so they are never
    # compared.
    if same_arity:
        groups = {}
        for index, (kp, rp) in enumerate(zip(kparams, rparams)):
            if kp[2] == rp[2]:
                groups.setdefault(kp[2], []).append(index)
        for token, indices in groups.items():
            if len(indices) < 2:
                continue
            for index in indices:
                kp, rp = kparams[index], rparams[index]
                if canonical(kp[0]) != canonical(rp[0]):
                    problems.append(
                        f"❌ JNI parameter order mismatch in `{kotlin['name']}`\n"
                        f"     parameter {index + 1} has type `{token}` on both sides, "
                        "so the JVM descriptor cannot see this swap.\n"
                        f"     Kotlin:  `{kp[0]}: {kp[1]}`\n"
                        f"     Rust:    `{rp[0]}: {rp[1]}`")
    return problems


def main():
    parser = argparse.ArgumentParser(
        description="Compare Rust JNI export types against the Kotlin declarations' "
        "JVM descriptors.")
    parser.add_argument("--root", default=None, help="repository root (default: this script's)")
    parser.add_argument("--javap", default=None, metavar="CLASSES_DIR",
                        help="run javap live over a compiled classes tree instead of "
                        "reading the fixture")
    args = parser.parse_args()

    default_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    root = os.path.abspath(args.root) if args.root else default_root
    if not os.path.isdir(root):
        fail(f"error: --root '{args.root}' is not a directory")
    kotlin_path = os.path.join(root, KOTLIN_REL)
    for path in (kotlin_path, os.path.join(root, RUST_SRC_REL)):
        if not os.path.exists(path):
            fail(f"error: cannot read {path}")

    kotlin = parse_kotlin(kotlin_path)
    if args.javap:
        javap_source = "live javap"
        javap_members = parse_javap(run_javap(os.path.abspath(args.javap)))
    else:
        javap_source = "javap fixture"
        fixture_path = os.path.join(root, FIXTURE_REL)
        if not os.path.isfile(fixture_path):
            fail(f"error: cannot read {fixture_path}")
        with open(fixture_path, encoding="utf-8") as handle:
            javap_members = parse_javap(handle.read())
    rust = parse_rust(root)

    # A silent parse failure must never read as agreement.
    for entries, what, where in (
        (kotlin, "Kotlin `external fun` declarations", KOTLIN_REL),
        (javap_members, "native members", f"the {javap_source}"),
        (rust, "Rust JNI exports", RUST_SRC_REL),
    ):
        if not entries:
            fail(f"error: found no {what} in {where}\n"
                 "       — the extraction pattern is stale; fix it before trusting this check")

    problems = []
    # (a) vs (b): the Kotlin source against what the compiler really emitted. A
    # descriptor difference means either the fixture is stale (regenerate it with
    # refresh-jni-javap-fixture.sh after a real Android build) or this script's
    # Kotlin type table is wrong. Both are tooling bugs, never something to wave
    # through here.
    for name in sorted(set(kotlin) - set(javap_members)):
        problems.append(f"❌ `{name}` is declared in Kotlin ({KOTLIN_REL}) but absent from "
                        f"the {javap_source}\n     — if the declaration is new, rebuild the "
                        "Android app and rerun\n       scripts/ci/refresh-jni-javap-fixture.sh")
    for name in sorted(set(javap_members) - set(kotlin)):
        problems.append(f"❌ `{name}` is a native member in the {javap_source} but not "
                        f"declared in {KOTLIN_REL}")
    for name in sorted(set(kotlin) & set(javap_members)):
        if descriptor_of(kotlin[name]) != javap_members[name]:
            problems.append(
                f"❌ Kotlin source and {javap_source} disagree on `{name}`\n"
                f"     Kotlin source ({kotlin[name]['file']}): {descriptor_of(kotlin[name])}\n"
                f"     {javap_source}: {javap_members[name]}\n"
                "     — the fixture is stale (rebuild the Android app, rerun\n"
                "       scripts/ci/refresh-jni-javap-fixture.sh) or the Kotlin\n"
                "       type→descriptor table in this script is wrong")

    # (c) vs (a): the Rust implementation against the Kotlin declaration.
    for name in sorted(set(kotlin) - set(rust)):
        problems.append(f"❌ `{name}` is declared in Kotlin but has no Rust export")
    for name in sorted(set(rust) - set(kotlin)):
        problems.append(f"❌ `{name}` is exported from Rust but not declared in Kotlin")
    for name in sorted(set(kotlin) & set(rust)):
        problems.extend(compare_export(kotlin[name], rust[name]))

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print("\n   Both sides must describe the same types, not just the same names: the C"
              "\n   ABI cannot catch a retyped primitive or a swapped pair of parameters.",
              file=sys.stderr)
        return 1

    print(f"JNI signatures OK: {len(kotlin)} entry points "
          f"(Kotlin source vs {javap_source} vs Rust)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
