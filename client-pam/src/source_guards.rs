//! Crate-wide source guardrails.
//!
//! These tests read the crate's own sources under `client-pam/src/**` and
//! assert invariants that hold for *every* module — `pam_sys::PAM_*` produced
//! only by `Outcome::into_pam`, no `PAM_IGNORE`, one grant path, one owner of
//! the reuse record, one `PAM_SERVICE` read, one refinement site, no remote-user
//! read — plus the positive controls that keep each scan able to fail. They live
//! here, not beside the code they watch, because no single module owns them:
//! `lib.rs` declares this module `#[cfg(test)]`, so a production build does not
//! contain it.

/// `PAM_SERVICE` is read at exactly one call site, in `CallerContext::capture`.
///
/// The defect this catches: a second `pam_sys::get_service_name(pamh)` call
/// reappearing in `pam_logic/mod.rs`. The pre-refactor tree resolved the service
/// twice — once in the display-manager bypass and once for the conversation
/// mode, the cache key and the request — so the bypass could decide from one
/// string while the cache keyed on another.
///
/// Same technique and the same positive-control discipline as
/// `test_module_source_contains_no_pam_ignore_return`: the source is stripped
/// of comments and literals first, and the detector is proved to fire on an
/// in-memory snippet so an emptied or relocated scan cannot pass silently.
#[test]
fn only_one_get_service_name_call_site() {
    const NEEDLE: &str = "get_service_name";
    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    // The shared recursive walk, not one `read_dir` level: a second read
    // could appear in `mechanism/`, which is a directory with no `rs`
    // extension, and a single-level scan would stay green while missing it.
    for required in [
        "context.rs",
        "pam_sys.rs",
        "mechanism/sequential.rs",
        "mechanism/threaded.rs",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }

    let mut definitions = 0usize;
    let mut call_sites: Vec<String> = Vec::new();
    for path in &files {
        let cleaned = production_source(path);
        let name = &relative_to_src(path);
        for (line, text) in identifier_hits(&cleaned, NEEDLE) {
            if text.contains("fn get_service_name") {
                definitions += 1;
            } else {
                call_sites.push(format!("{name}:{line}: {text}"));
            }
        }
    }

    assert_eq!(
        definitions, 1,
        "expected exactly one definition of {NEEDLE}, found {definitions}"
    );
    assert_eq!(
        call_sites.len(),
        1,
        "PAM_SERVICE must be read at exactly one call site, found:\n{}",
        call_sites.join("\n")
    );
    let only = call_sites.first().map(String::as_str).unwrap_or_default();
    assert!(
        only.starts_with("context.rs:"),
        "the single read must be `CallerContext::capture`, found {only}"
    );

    // Positive control: two planted call sites must both be reported, or a
    // scan that stopped matching would pass the assertion above.
    let planted = stripped_source(
        "let a = pam_sys::get_service_name(pamh);\n\
         let b = pam_sys::get_service_name(pamh);\n",
    );
    assert_eq!(
        identifier_hits(&planted, NEEDLE).len(),
        2,
        "the detector must report both planted call sites"
    );
}

/// `policy::refine` is called at exactly one site, immediately after the
/// config read, so the second decision phase has one home.
///
/// The defect this catches: a second call site re-deriving the configured
/// refusal (the ad-hoc check the phase replaced) or a refinement run before
/// `PamConfig::load` — the first restores the split decision, the second
/// would always see the built-ins only and let a renamed remote stack ring
/// the phone. Same stripped-source technique and positive control as
/// `only_one_get_service_name_call_site`.
///
/// The scan is the second line of defence, not the first: the configured
/// matcher it covers (`refused_service`) is private to `policy`, so a
/// second module cannot reach it at all and this text scan cannot be
/// defeated by an aliased import.
#[test]
fn only_one_refine_call_site() {
    const NEEDLE: &str = "policy::refine";
    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    // The caller and the module that defines the phase. The count below
    // cannot tell "the call site moved" from "the scan stopped reading the
    // file", so each file must also be shown to carry the declarations the
    // claim is about.
    for required in ["pam_logic/mod.rs", "policy/refine.rs"] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }

    let mut call_sites: Vec<String> = Vec::new();
    let mut logic_source = String::new();
    for path in &files {
        let rel = relative_to_src(path);
        let cleaned = production_source(path);
        for (line, text) in identifier_hits(&cleaned, NEEDLE) {
            call_sites.push(format!("{rel}:{line}: {text}"));
        }
        match rel.as_str() {
            "pam_logic/mod.rs" => {
                // `orchestrate` holds the one call site, above this file's
                // only test module; a scan truncated at an early
                // `#[cfg(test)]` item would see neither.
                assert_scan_reaches(&rel, &cleaned, &["fn orchestrate"]);
                logic_source = cleaned;
            }
            "policy/refine.rs" => {
                assert_scan_reaches(&rel, &cleaned, &["fn refine(", "fn refused_service("])
            }
            _ => {}
        }
    }

    assert_eq!(
        call_sites.len(),
        1,
        "the configured refusal must be decided at exactly one site, found:\n{}",
        call_sites.join("\n")
    );
    let only = call_sites.first().map(String::as_str).unwrap_or_default();
    assert!(
        only.starts_with("pam_logic/mod.rs:"),
        "the single refinement must run from `orchestrate`, found {only}"
    );

    // It must run after the config read, or it can never see a configured
    // name: the byte-order check is the same one
    // `cache_lookup_precedes_daemon_contact` uses.
    let config_read = logic_source
        .find("let config = (io.load_config)();")
        .expect("the config read must stay in `orchestrate`");
    let refine_at = logic_source
        .find(NEEDLE)
        .expect("the refinement call must stay in `orchestrate`");
    assert!(
        config_read < refine_at,
        "the refinement (byte {refine_at}) must run after the config read \
         (byte {config_read})"
    );

    // Positive control: two planted call sites must both be reported.
    let planted =
        stripped_source("let a = policy::refine(c, s, cfg);\nlet b = policy::refine(c, s, cfg);\n");
    assert_eq!(
        identifier_hits(&planted, NEEDLE).len(),
        2,
        "the detector must report both planted call sites"
    );
}

/// The remote-user item is read nowhere in this crate's production code.
///
/// The defect this catches: the retired `PAM_RUSER` fallback reappearing,
/// either by identifier or by the item's numeric value — `pam_get_item(pamh,
/// 8, ..)` is the same read without the name, which a name-only scan would
/// miss. A resolved name for the wrong account is the whole reason the
/// fallback is gone: it became the daemon request's username, the cache key
/// and the locale lookup's NSS name.
///
/// Only the production half of each file is scanned, because the test that
/// pins the removal names the item in strings.
#[test]
fn no_ruser_read() {
    const ITEM: &str = "PAM_RUSER";
    // The item's numeric value, spelled arithmetically so this test's own
    // source carries no literal for its own scan to find.
    let item_number: u128 = 2 * 2 * 2;

    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    // The shared recursive walk and the same `#[cfg(test)]`-module split as
    // the other scans, so a read in `mechanism/` is covered and this file's
    // own test module is exempt.
    for required in ["pam_sys.rs", "mechanism/sequential.rs"] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}, home of the user item: {names:?}"
        );
    }

    let mut findings: Vec<String> = Vec::new();
    for path in &files {
        let name = relative_to_src(path);
        let cleaned = production_source(path);
        for (line, text) in identifier_hits(&cleaned, ITEM) {
            findings.push(format!("{name}:{line}: {ITEM} read in: {text}"));
        }
        for (line, text) in numeric_literals_equal_to(&cleaned, item_number) {
            findings.push(format!(
                "{name}:{line}: item value {item_number} used in: {text}"
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "a null PAM_USER must fail closed, not fall back to another item:\n{}",
        findings.join("\n")
    );

    // Positive control: both detectors must fire on an in-memory snippet, or
    // an emptied or broken scan passes for the wrong reason.
    let planted = stripped_source(
        "let a = pam_get_item(pamh, 8, &mut item);\n\
         let b = ffi::PAM_RUSER;\n",
    );
    assert_eq!(
        identifier_hits(&planted, ITEM).len(),
        1,
        "the identifier detector must report the planted item"
    );
    assert_eq!(
        numeric_literals_equal_to(&planted, item_number),
        vec![(1, "8".to_owned())],
        "the numeric detector must report the planted item value"
    );
}

/// Blank every comment, string literal and char literal, keeping the
/// newlines so that the reported line numbers still match the file on disk.
///
/// The docs in this crate deliberately name the forbidden code in prose, and
/// the test's own assertions quote both needles, so scanning raw source
/// would flag those instead of the return site it is looking for.
///
/// Runs over bytes: every delimiter involved is ASCII, and the crate's
/// sources are ASCII apart from localisation strings, which are blanked
/// here.  A non-ASCII *char* literal would be taken for a lifetime and
/// copied verbatim, which can only hide a needle, never invent one.
fn stripped_source(source: &str) -> String {
    let b = source.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        // Line comment.
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment (Rust nests them).
        if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 1usize;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if b[i] == b'\n' {
                        out.push(b'\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        // Raw strings: `r"…"`, `r#"…"#`, `br"…"`, `br#"…"#`.
        let raw_at = if b[i] == b'r' {
            Some(i + 1)
        } else if b[i] == b'b' && b.get(i + 1) == Some(&b'r') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(at) = raw_at {
            let mut hashes = 0usize;
            while b.get(at + hashes) == Some(&b'#') {
                hashes += 1;
            }
            if b.get(at + hashes) == Some(&b'"') {
                let mut j = at + hashes + 1;
                let mut end = b.len();
                while j < b.len() {
                    if b[j] == b'"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&b'#')) {
                        end = j + 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                out.extend(blank(b, i, end));
                i = end;
                continue;
            }
        }
        // Normal and byte strings, honouring backslash escapes.
        let quote_at = if b[i] == b'"' {
            Some(i)
        } else if b[i] == b'b' && b.get(i + 1) == Some(&b'"') {
            Some(i + 1)
        } else {
            None
        };
        if let Some(q) = quote_at {
            let mut j = q + 1;
            while j < b.len() {
                if b[j] == b'\\' {
                    j += 2;
                } else if b[j] == b'"' {
                    j += 1;
                    break;
                } else {
                    j += 1;
                }
            }
            let end = j.min(b.len());
            out.extend(blank(b, i, end));
            i = end;
            continue;
        }
        // Char literals and byte chars.  A tick that does not open a
        // one-character or escaped literal is a lifetime (`'a`) and is
        // copied verbatim.
        let tick_at = if b[i] == b'\'' {
            Some(i)
        } else if b[i] == b'b' && b.get(i + 1) == Some(&b'\'') {
            Some(i + 1)
        } else {
            None
        };
        if let Some(t) = tick_at {
            let opens_literal = matches!(
                (b.get(t + 1), b.get(t + 2)),
                (Some(&b'\\'), _) | (Some(_), Some(&b'\''))
            );
            if !opens_literal {
                out.push(b[i]);
                i += 1;
                continue;
            }
            let mut j = t + 1;
            if b.get(j) == Some(&b'\\') {
                j += 2;
                // `'\u{1F600}'`
                if b.get(j - 1) == Some(&b'u') && b.get(j) == Some(&b'{') {
                    while j < b.len() && b[j] != b'}' {
                        j += 1;
                    }
                    j += 1;
                }
            } else {
                j += 1;
            }
            if b.get(j) == Some(&b'\'') {
                j += 1;
            }
            let end = j.min(b.len());
            out.extend(blank(b, i, end));
            i = end;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `bytes[start..end]` as spaces, keeping its newlines.
fn blank(bytes: &[u8], start: usize, end: usize) -> Vec<u8> {
    bytes[start..end]
        .iter()
        .map(|&c| if c == b'\n' { b'\n' } else { b' ' })
        .collect()
}

/// The source line containing byte offset `at`, trimmed.
fn line_at(source: &str, at: usize) -> String {
    let start = source[..at].rfind('\n').map_or(0, |n| n + 1);
    let end = source[at..].find('\n').map_or(source.len(), |n| at + n);
    source[start..end].trim().to_owned()
}

/// Every occurrence of `needle` used as a whole identifier, as
/// `(line, source line)`.
fn identifier_hits(cleaned: &str, needle: &str) -> Vec<(usize, String)> {
    let b = cleaned.as_bytes();
    let mut hits = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = cleaned[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        let is_ident_char = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
        let whole_word = !(start > 0 && is_ident_char(&b[start - 1]))
            && !(end < b.len() && is_ident_char(&b[end]));
        if whole_word {
            let line = cleaned[..start].matches('\n').count() + 1;
            hits.push((line, line_at(cleaned, start)));
        }
        from = end;
    }
    hits
}

/// Every occurrence of `PAM_IGNORE` used as an identifier, as
/// `(line, source line)`.
fn pam_ignore_identifiers(cleaned: &str) -> Vec<(usize, String)> {
    identifier_hits(cleaned, "PAM_IGNORE")
}

/// Every numeric literal in `cleaned` whose value equals `code`, as
/// `(line, token)`.
///
/// The literal is evaluated rather than substring-matched, so `0.25`
/// (rounded float), `0x25` (hex 37) and `1_025` (1025) are not hits while
/// `25u32` is.
fn numeric_literals_equal_to(cleaned: &str, code: u128) -> Vec<(usize, String)> {
    let b = cleaned.as_bytes();
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        // Skip a digit that continues an identifier (`foo25`).
        let begins_literal = b[i].is_ascii_digit()
            && !(i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'));
        if !begins_literal {
            i += 1;
            continue;
        }
        let (value, next) = read_numeric_literal(b, i);
        if value == Some(code) {
            let line = cleaned[..i].matches('\n').count() + 1;
            hits.push((line, cleaned[i..next].to_owned()));
        }
        i = next.max(i + 1);
    }
    hits
}

/// Read the numeric literal starting at `start` as `(value, end)`, with
/// `None` for floats.
fn read_numeric_literal(b: &[u8], start: usize) -> (Option<u128>, usize) {
    let mut i = start;
    let radix = if b[i] == b'0' {
        match b.get(i + 1).copied() {
            Some(b'x' | b'X') => Some(16u32),
            Some(b'o' | b'O') => Some(8u32),
            Some(b'b' | b'B') => Some(2u32),
            _ => None,
        }
    } else {
        None
    };
    if let Some(radix) = radix {
        i += 2;
        let mut digits = String::new();
        while let Some(&c) = b.get(i) {
            if c == b'_' {
                i += 1;
            } else if (c as char).is_digit(radix) {
                digits.push(c as char);
                i += 1;
            } else {
                break;
            }
        }
        while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
            i += 1;
        }
        return (u128::from_str_radix(&digits, radix).ok(), i);
    }

    let mut digits = String::new();
    let mut is_float = false;
    while let Some(&c) = b.get(i) {
        if c == b'_' {
            i += 1;
        } else if c.is_ascii_digit() {
            digits.push(c as char);
            i += 1;
        } else {
            break;
        }
    }
    if b.get(i) == Some(&b'.') && matches!(b.get(i + 1), Some(c) if c.is_ascii_digit()) {
        is_float = true;
        i += 1;
        while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
            i += 1;
        }
    }
    if matches!(b.get(i).copied(), Some(b'e' | b'E'))
        && matches!(b.get(i + 1).copied(), Some(c) if c.is_ascii_digit() || c == b'+' || c == b'-')
    {
        is_float = true;
        i += 2;
        while matches!(b.get(i), Some(c) if c.is_ascii_digit() || *c == b'_') {
            i += 1;
        }
    }
    // Integer/float suffix (`25u32`, `1.5f64`).
    while matches!(b.get(i), Some(c) if c.is_ascii_alphanumeric()) {
        i += 1;
    }
    if is_float {
        return (None, i);
    }
    (digits.parse::<u128>().ok(), i)
}

// ------------------------------------------------------------------
// The two scans step 4d turns on: no PAM code outside `outcome.rs`, and
// no grant outside the two constructors.
// ------------------------------------------------------------------

/// Every `client-pam/src/**/*.rs`, sorted, so a new module cannot be added
/// and stay outside the scans.
///
/// Recursive: `src/mechanism/` is a directory with no `rs` extension, so a
/// single-level `read_dir` would silently stop covering the mechanisms once
/// step 6 creates them.
fn source_files() -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<std::path::PathBuf> = entries
            .map(|entry| entry.expect("readable dir entry").path())
            .collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut files = Vec::new();
    walk(src, &mut files);
    files.sort();
    files
}

/// `client-pam/src`: the root of the module tree every scan reads.
fn src_root() -> &'static std::path::Path {
    std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))
}

/// The files `lib.rs` compiles into production, cached for the whole run.
///
/// This is the answer to "is this file shipped code?", which the scans now have
/// to ask: a test module may live in its own file, and a file the compiler only
/// sees under `#[cfg(test)]` must not be scanned as production.
fn production_paths() -> &'static std::collections::HashSet<std::path::PathBuf> {
    static PATHS: std::sync::OnceLock<std::collections::HashSet<std::path::PathBuf>> =
        std::sync::OnceLock::new();
    PATHS.get_or_init(|| module_tree(src_root()).0.into_iter().collect())
}

/// Split the module tree rooted at `root` into (production files, files that
/// only a `#[cfg(test)] mod` declares).
///
/// `lib.rs` is the root and every `mod NAME;` declaration is followed to
/// `NAME.rs` or `NAME/mod.rs`, so the walk mirrors the compiler rather than a
/// directory listing. Gating is inherited: once a file is reached through a
/// `#[cfg(test)]` declaration, everything it declares is test-only too, which
/// is what keeps a `src/**/tests/*.rs` file out of the production set.
fn module_tree(root: &std::path::Path) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let mut production: Vec<std::path::PathBuf> = Vec::new();
    let mut gated: Vec<std::path::PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();
    let mut queue: Vec<(std::path::PathBuf, bool)> = vec![(root.join("lib.rs"), false)];
    while let Some((file, under_test)) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        if under_test {
            gated.push(file.clone());
        } else {
            production.push(file.clone());
        }
        for (name, is_test) in module_declarations(&source) {
            if let Some(child) = module_file(&file, &name) {
                queue.push((child, under_test || is_test));
            }
        }
    }
    production.sort();
    gated.sort();
    (production, gated)
}

/// Whether an attribute line gates its item on `#[cfg(test)]`.
fn gates_on_cfg_test(line: &str) -> bool {
    line.replace(' ', "").contains("cfg(test)")
}

/// The module name of a `mod NAME;` line, if that line declares a file.
///
/// `mod tests { … }` declares no file and is therefore not a declaration: only
/// a line ending in `;` whose item head is `mod`.
fn module_declaration_name(line: &str) -> Option<String> {
    let head = line.strip_suffix(';')?;
    let (visibility, rest) = head.rsplit_once("mod ")?;
    let visibility = visibility.trim_end();
    let visible = visibility.is_empty()
        || visibility == "pub"
        || visibility == "pub(crate)"
        || visibility == "pub(super)"
        || (visibility.starts_with("pub(in ") && visibility.ends_with(')'));
    if !visible {
        return None;
    }
    let name = rest.trim_end();
    let identifier =
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    identifier.then(|| name.to_owned())
}

/// Every `mod NAME;` declaration in `source`, as `(name, gated on cfg(test))`.
///
/// The gate is the attribute block directly above the declaration, which may
/// span several lines (`#[allow(…)]` is written multi-line in this crate), so
/// the block is skipped by square-bracket depth, as `test_module_start` does.
/// Doc comments and line comments are skipped without counting, so a doc block
/// quoting an attribute cannot confuse the association.
///
/// A declaration nested inside an inline `mod … { … }` block carries the `cfg`
/// of its own attribute block only, not that of the enclosing block. The
/// walker's positive control asserts the production set exactly, so such a
/// layout fails that test instead of quietly shrinking the scans.
fn module_declarations(source: &str) -> Vec<(String, bool)> {
    let mut declarations = Vec::new();
    let mut gated = false;
    let mut depth = 0i64;
    for line in source.lines() {
        let trimmed = line.trim();
        if depth > 0 {
            if !gated && gates_on_cfg_test(trimmed) {
                gated = true;
            }
            depth += trimmed.matches('[').count() as i64;
            depth -= trimmed.matches(']').count() as i64;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            if !gated && gates_on_cfg_test(trimmed) {
                gated = true;
            }
            depth += trimmed.matches('[').count() as i64;
            depth -= trimmed.matches(']').count() as i64;
            continue;
        }
        if let Some(name) = module_declaration_name(trimmed) {
            declarations.push((name, gated));
        }
        gated = false;
    }
    declarations
}

/// The file a `mod NAME;` declaration in `declaring` refers to.
///
/// `lib.rs` and `mod.rs` declare siblings in their own directory; any other
/// file declares children under a directory named after it.
fn module_file(declaring: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    let stem = declaring.file_stem()?.to_str()?;
    let parent = declaring.parent()?;
    let base = if stem == "lib" || stem == "mod" {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    };
    let flat = base.join(format!("{name}.rs"));
    if flat.is_file() {
        return Some(flat);
    }
    let nested = base.join(name).join("mod.rs");
    nested.is_file().then_some(nested)
}

/// A source file's path relative to `src`, e.g. `outcome.rs` or
/// `mechanism/threaded.rs`. Every exemption below is written against this,
/// never against a bare file name.
fn relative_to_src(path: &std::path::Path) -> String {
    let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    path.strip_prefix(src)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The production half of a source file: everything before the first
/// `#[cfg(test)]` **module**, and nothing at all for a file that only a
/// `#[cfg(test)] mod` declares.
///
/// The tests below quote every forbidden token, so scanning the whole file
/// would flag the assertions instead of the code. Cutting at the test
/// *module* rather than at the first `#[cfg(test)]` item is what keeps the
/// production code above it in the scan: a file that carries a test-only
/// accessor early (`transaction/lifecycle.rs`'s `Finished::outcome`, `context.rs`'s
/// `from_parts`, `pam_sys.rs`'s `dummy`) would otherwise be scanned only up
/// to that item, and every assertion over the file would pass vacuously.
///
/// A test *file* is never compiled into the module at all, so it has no
/// production half: it is answered with an empty scan. `production_paths` is
/// the authority for that, and `the_walker_separates_test_modules_from_production`
/// proves it does not also drop a production file.
fn production_source(path: &std::path::Path) -> String {
    if !production_paths().contains(path) {
        return String::new();
    }
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let end = test_module_start(&source).unwrap_or(source.len());
    stripped_source(&source[..end])
}

/// The byte offset of the first `#[cfg(test)]` **module**, i.e. the start
/// of the file's test module.
///
/// Only an attribute that decorates a `mod` item counts — not a test-only
/// `fn`, accessor or `impl`, which sits inside the production half and must
/// stay in the scanned text. The attribute block may carry further
/// attributes (`#[allow(..)]`, which is what every test module here uses)
/// and indentation, so the item is found by skipping to the first line that
/// is not itself an attribute, a doc comment or blank.
fn test_module_start(source: &str) -> Option<usize> {
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let mut offsets = Vec::with_capacity(lines.len() + 1);
    let mut offset = 0usize;
    for line in &lines {
        offsets.push(offset);
        offset += line.len();
    }
    offsets.push(offset);

    for (index, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(test)]" {
            continue;
        }
        let mut next = index + 1;
        // Square-bracket depth, so a multi-line `#[allow(..)]` between the
        // `cfg` and the `mod` does not look like the item. Comments are
        // skipped without counting, so a doc block quoting `[` cannot push
        // the scan past the item it is looking for.
        let mut depth = 0i64;
        while let Some(ahead) = lines.get(next) {
            let trimmed = ahead.trim();
            if trimmed.starts_with("//") {
                next += 1;
                continue;
            }
            if depth == 0 && (trimmed.is_empty() || !trimmed.starts_with("#[")) {
                break;
            }
            depth += trimmed.matches('[').count() as i64;
            depth -= trimmed.matches(']').count() as i64;
            next += 1;
        }
        let item = lines.get(next).map(|line| line.trim()).unwrap_or("");
        let is_mod = item == "mod"
            || [
                "mod ",
                "pub mod ",
                "pub(crate) mod ",
                "pub(super) mod ",
                "pub(in ",
            ]
            .iter()
            .any(|prefix| item.starts_with(prefix));
        if is_mod {
            return Some(offsets[index]);
        }
    }
    None
}

/// Assert a scan reached the code its assertion is about.
///
/// The defect this catches: a truncated or relocated scan. Every assertion
/// over a production half is "no forbidden token is present", which is also
/// true of an empty string — so each scan names the declarations it must
/// have seen, and this is the one place the message lives. The needles are
/// substrings of the declarations as written (`run` takes a `&mut Effects`,
/// so a scan that only had to reach the `fn run` head still does).
fn assert_scan_reaches(rel: &str, cleaned: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            cleaned.contains(needle),
            "the scanned text of {rel} does not contain {needle:?}: the scan \
             must stop at the first `#[cfg(test)]` module, not at the first \
             test-only item"
        );
    }
}

/// The walker's own positive control: a file a `#[cfg(test)] mod` declares is
/// not production, and no file under `src` is silently left out.
///
/// The defect this catches, in both directions: a test file treated as
/// production (so its test code is scanned as though it shipped), and a
/// production file the walker stops reading — which would make every "no
/// forbidden token" assertion over that file vacuous while the suite stayed
/// green. The coverage list below is the claim the scans make about which files
/// they read, so a module that is added, moved or split must update it
/// deliberately rather than appear in the tree unread.
///
/// The fixture tree is written outside `src/`, because planting files there
/// would race the parallel recursive walk.
#[test]
fn the_walker_separates_test_modules_from_production() {
    let root = std::env::temp_dir().join(format!("tapauth-module-tree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("tests")).expect("create the fixture tree");
    std::fs::write(root.join("lib.rs"), "mod wire;\n#[cfg(test)]\nmod tests;\n")
        .expect("write the fixture root");
    std::fs::write(root.join("wire.rs"), "fn wire() {}\n").expect("write a production module");
    std::fs::write(root.join("tests.rs"), "mod cases;\n").expect("write the test module");
    std::fs::write(root.join("tests/cases.rs"), "fn case() {}\n")
        .expect("write a nested test module");
    let (fixture_production, fixture_gated) = module_tree(&root);
    let names = |files: &[std::path::PathBuf]| -> Vec<String> {
        let mut names: Vec<String> = files
            .iter()
            .map(|path| {
                path.strip_prefix(&root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    };
    let fixture_production = names(&fixture_production);
    let fixture_gated = names(&fixture_gated);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        fixture_production,
        vec!["lib.rs".to_owned(), "wire.rs".to_owned()],
        "a `#[cfg(test)] mod` file must not be production, and neither is a \
         child it declares"
    );
    assert_eq!(
        fixture_gated,
        vec!["tests.rs".to_owned(), "tests/cases.rs".to_owned()],
        "the gated file and the file it declares are both test-only"
    );

    // The same rule on the real tree: every shipped module is on the production
    // side, this module is the only gated file, and no file is in neither list.
    let (production, gated) = module_tree(src_root());
    let shipped: Vec<String> = production.iter().map(|p| relative_to_src(p)).collect();
    for required in [
        "conclusion_cache.rs",
        "config.rs",
        "context.rs",
        "ipc_client.rs",
        "lib.rs",
        "logging.rs",
        "mechanism/handoff.rs",
        "mechanism/mod.rs",
        "mechanism/sequential.rs",
        "mechanism/threaded.rs",
        "outcome.rs",
        "pam_logic/mod.rs",
        "pam_logic/wiring.rs",
        "pam_messages.rs",
        "pam_sys.rs",
        "plan.rs",
        "policy/mod.rs",
        "policy/refine.rs",
        "policy/table.rs",
        "transaction/host_io.rs",
        "transaction/lifecycle.rs",
        "transaction/mod.rs",
        "transaction/run.rs",
    ] {
        assert!(
            shipped.iter().any(|name| name == required),
            "the walker dropped the production file {required}: {shipped:?}"
        );
    }
    let test_only: Vec<String> = gated.iter().map(|p| relative_to_src(p)).collect();
    assert_eq!(
        test_only,
        vec![
            "pam_logic/tests/mod.rs".to_owned(),
            "pam_logic/tests/reuse.rs".to_owned(),
            "source_guards.rs".to_owned(),
            "transaction/tests/mod.rs".to_owned(),
        ],
        "these are the only files a `#[cfg(test)] mod` declares"
    );
    let mut listed = shipped;
    listed.extend(test_only);
    listed.sort();
    let mut on_disk: Vec<String> = source_files().iter().map(|p| relative_to_src(p)).collect();
    on_disk.sort();
    assert_eq!(
        listed, on_disk,
        "every file under `src` must be production or declared under \
         `#[cfg(test)] mod`, never neither"
    );

    // The reader the scans use honours the split in both directions.
    assert!(
        production_source(&src_root().join("source_guards.rs")).is_empty(),
        "a `#[cfg(test)] mod` file must scan as empty production"
    );
    assert!(
        production_source(&src_root().join("transaction/tests/mod.rs")).is_empty(),
        "a test module in its own file must scan as empty production"
    );
    assert!(
        production_source(&src_root().join("transaction/run.rs")).contains("fn run"),
        "a production file must still be read, not dropped"
    );
}

/// `pam_sys` constants that are not return codes: they name an item type, so
/// a line holding one is an argument (`pam_get_authtok(.., PAM_AUTHTOK, ..)`,
/// which rustfmt may put on its own line), never a verdict.
const NON_CODE_PAM_CONSTANTS: [&str; 1] = ["pam_sys::PAM_AUTHTOK"];

/// The `pam_sys::PAM_*` values this crate returns, as `(byte offset, line)`.
///
/// A site is a line of the *stripped* source that either returns one
/// (`return pam_sys::PAM_X`) or is a bare code in tail position
/// (`pam_sys::PAM_X` / `pam_sys::PAM_X,` — a match arm or a function tail).
/// Comparisons and arguments (`res != pam_sys::PAM_SUCCESS`,
/// `pam_get_authtok(.., pam_sys::PAM_AUTHTOK, ..)`) are not sites: they
/// consume a code, they do not produce one.
fn pam_code_sites(cleaned: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let mut offset = 0usize;
    for line in cleaned.lines() {
        let trimmed = line.trim();
        if trimmed.contains("pam_sys::PAM_") {
            let bare_token = trimmed.trim_end_matches([',', ';']).trim();
            let bare = !NON_CODE_PAM_CONSTANTS.contains(&bare_token)
                && bare_token
                    .strip_prefix("pam_sys::PAM_")
                    .is_some_and(|rest| {
                        !rest.is_empty()
                            && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    });
            if trimmed.contains("return ") || bare {
                hits.push((offset, trimmed.to_owned()));
            }
        }
        offset += line.len() + 1;
    }
    hits
}

/// The name of the function whose body contains `at`, as written.
///
/// Used only for the `lib.rs` exemption, which names the six ABI functions
/// (`guard`'s panic arm and the five constant stubs) — never a line number,
/// so an edit above them cannot silently move the exemption.
fn enclosing_fn(cleaned: &str, at: usize) -> Option<String> {
    let before = cleaned.get(..at)?;
    let start = before.rfind("fn ")? + "fn ".len();
    let name: String = before[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The `lib.rs` functions allowed to answer with a constant: the five
/// constant ABI stubs and `guard`'s panic arm.
///
/// These are the whole ABI surface: they convert no verdict, never see an
/// `Outcome`, and are not part of any authentication decision.
const LIB_PAM_EXEMPTIONS: [&str; 6] = [
    "guard",
    "pam_sm_setcred",
    "pam_sm_acct_mgmt",
    "pam_sm_open_session",
    "pam_sm_close_session",
    "pam_sm_chauthtok",
];

/// No `pam_sys::PAM_*` value is produced outside `outcome.rs`, except the
/// six `lib.rs` ABI sites named above.
///
/// The defect this catches: a return code minted at the site that observed
/// the failure instead of through `Outcome::into_pam` — the 24 `pam_logic.rs`
/// sites this step removes. Such a site can return `PAM_SUCCESS`, can return
/// a code the verdict does not imply, and adds a path no outcome test
/// covers. The exemption is by *function name* and the scan asserts it
/// covered `outcome.rs` (by path), `lib.rs`, the orchestration, the
/// transaction and every mechanism module, so a moved or emptied scan cannot
/// pass vacuously.
#[test]
fn only_outcome_rs_returns_pam_constants() {
    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    for required in [
        "outcome.rs",
        "lib.rs",
        "pam_logic/mod.rs",
        "pam_logic/wiring.rs",
        "transaction/run.rs",
        "transaction/lifecycle.rs",
        "transaction/host_io.rs",
        "mechanism/mod.rs",
        "mechanism/threaded.rs",
        "mechanism/sequential.rs",
        "mechanism/handoff.rs",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }

    let mut findings: Vec<String> = Vec::new();
    let mut exempted = 0usize;
    for path in &files {
        let rel = relative_to_src(path);
        // Exempt by path, not by file name: a future `mechanism/outcome.rs`
        // must not inherit this file's exemption.
        if rel == "outcome.rs" {
            continue;
        }
        let cleaned = production_source(path);
        if rel == "transaction/run.rs" {
            // Guard against a re-truncated scan: this test's claim is that
            // `run` mints no `PAM_*` code of its own, so the scanned text
            // must actually reach it (see `production_source`). Only `run`
            // is asserted: the reuse cache is no longer in the transaction —
            // it lives in `conclusion_cache.rs`, which this loop still scans
            // for codes like any other module but whose ownership
            // assertion is `cache_owner_is_local`'s, not this one's.
            assert_scan_reaches(&rel, &cleaned, &["fn run"]);
        }
        for (offset, text) in pam_code_sites(&cleaned) {
            if rel == "lib.rs" {
                let enclosing = enclosing_fn(&cleaned, offset).unwrap_or_default();
                if LIB_PAM_EXEMPTIONS.contains(&enclosing.as_str()) {
                    exempted += 1;
                    continue;
                }
            }
            findings.push(format!("{rel}: {text}"));
        }
    }

    assert!(
        findings.is_empty(),
        "every PAM code must come from `Outcome::into_pam`, found:\n{}",
        findings.join("\n")
    );
    assert_eq!(
        exempted, 6,
        "the six `lib.rs` ABI sites (guard's panic arm and the five constant \
         stubs) are the only exemption; found {exempted}"
    );
}

/// The grant constructors, and any hand-built `Outcome::Granted`, as
/// findings for the file `rel`.
///
/// `outcome.rs` is where both constructors are defined, and the orchestration
/// (`pam_logic/mod.rs`) and the transaction's concluding half
/// (`transaction/lifecycle.rs`) are the only code allowed to call them. A
/// mechanism, a rule, a plan or a test helper calling either — or building
/// `Outcome::Granted` by hand — is a second way to mint a grant.
fn grant_findings(rel: &str, cleaned: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for (line, text) in identifier_hits(cleaned, "granted_from_daemon")
        .into_iter()
        .chain(identifier_hits(cleaned, "replayed"))
        .chain(identifier_hits(cleaned, "Granted"))
    {
        let call = text.contains("granted_from_daemon")
            || text.contains("Outcome::replayed")
            || text.contains("fn replayed");
        let allowed = match rel {
            "outcome.rs" => true,
            "pam_logic/mod.rs" | "transaction/lifecycle.rs" => call,
            _ => false,
        };
        if !allowed {
            findings.push(format!("{rel}:{line}: {text}"));
        }
    }
    findings
}

/// A `Granted` is minted only by `Outcome::granted_from_daemon` or
/// `Outcome::replayed`, from the orchestration, and nowhere else.
///
/// The defect this catches: a mechanism (or anything else outside the
/// orchestration) building `Outcome::Granted(..)` directly, or calling one
/// of the two constructors, which would be a second grant path beside the
/// daemon's `Success` and the replay. The retired check — "the token
/// `Outcome::Granted` appears only in `outcome.rs`" — is not used: it
/// passes for the very code that defines the constructors, so it cannot
/// catch a grant minted inside that module or reached from a mechanism.
#[test]
fn granted_only_from_daemon() {
    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    for required in [
        "outcome.rs",
        "pam_logic/mod.rs",
        "pam_logic/wiring.rs",
        "transaction/run.rs",
        "transaction/lifecycle.rs",
        "mechanism/mod.rs",
        "mechanism/threaded.rs",
        "mechanism/sequential.rs",
        "mechanism/handoff.rs",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }

    let mut findings: Vec<String> = Vec::new();
    let mut definitions = 0usize;
    for path in &files {
        let rel = relative_to_src(path);
        let cleaned = production_source(path);
        if rel == "transaction/run.rs" {
            // Guard against a re-truncated scan: what this file must be
            // shown to contain is `run`, the orchestration half that reaches
            // a constructor. The other half this comment used to name — the
            // reuse cache, which is what stops a replay from reaching one —
            // is in `conclusion_cache.rs` now, scanned by the loop below
            // like any other module; its ownership assertion is
            // `cache_owner_is_local`'s.
            assert_scan_reaches(&rel, &cleaned, &["fn run"]);
        }
        if rel == "outcome.rs" {
            definitions += cleaned.matches("fn granted_from_daemon").count();
            definitions += cleaned.matches("fn replayed").count();
            continue;
        }
        findings.extend(grant_findings(&rel, &cleaned));
    }

    assert!(
        findings.is_empty(),
        "only the orchestration may reach a grant constructor, and only \
         `outcome.rs` may build a `Granted`:\n{}",
        findings.join("\n")
    );
    assert_eq!(
        definitions, 2,
        "the two grant constructors — granted_from_daemon and replayed — are \
         defined once, in outcome.rs"
    );
}

/// The `PAM_*` return-site detector fires on a planted return and on a
/// planted bare arm, and not on a comparison or on prose.
///
/// Without this, a detector that stopped matching would make
/// `only_outcome_rs_returns_pam_constants` pass for every tree.
#[test]
fn pam_return_scan_detects_a_planted_return() {
    let planted = stripped_source(
        "fn returns_one() -> c_int {\n    return pam_sys::PAM_AUTH_ERR;\n}\n\
         fn tail_position() -> c_int {\n    pam_sys::PAM_SUCCESS\n}\n\
         fn compares_one(res: c_int) -> c_int {\n    if res != pam_sys::PAM_SUCCESS {}\n    0\n}\n",
    );
    let sites = pam_code_sites(&planted);
    assert_eq!(
        sites.len(),
        2,
        "the detector must report the return and the tail expression, and \
         not the comparison: {sites:?}"
    );
    assert_eq!(
        enclosing_fn(&planted, sites[0].0).as_deref(),
        Some("returns_one"),
        "the exemption is by enclosing function name"
    );
    assert_eq!(
        enclosing_fn(&planted, sites[1].0).as_deref(),
        Some("tail_position")
    );

    // Prose is not a site, which is what makes the whole-crate assertion
    // meaningful: this file's docs name the forbidden codes.
    let prose = stripped_source(
        "// return pam_sys::PAM_AUTH_ERR;\nlet s = \"return pam_sys::PAM_SUCCESS;\";\n",
    );
    assert!(pam_code_sites(&prose).is_empty());

    // An item type is not a verdict, even alone on its line: the whole-crate
    // scan would otherwise report `pam_get_authtok`'s argument.
    let item = stripped_source(
        "pam_get_authtok(\n    pamh,\n    pam_sys::PAM_AUTHTOK,\n    &mut tok,\n);\n",
    );
    assert!(
        pam_code_sites(&item).is_empty(),
        "an item-type constant is not a return code"
    );
}

/// The grant detector reports a hand-built `Granted` and a constructor call
/// from a mechanism, and accepts `outcome.rs` and the orchestration.
///
/// Without this, `granted_only_from_daemon` would pass for a tree in which
/// the detector had stopped matching.
#[test]
fn granted_scan_detects_a_planted_construction() {
    let planted = stripped_source(
        "fn drive() -> Outcome {\n    Outcome::Granted(GrantVia::PhoneTap)\n}\n\
         fn other() -> Outcome {\n    Outcome::granted_from_daemon()\n}\n",
    );

    let mechanism = grant_findings("mechanism/threaded.rs", &planted);
    assert_eq!(
        mechanism.len(),
        2,
        "a mechanism must not build a grant or call a grant constructor: {mechanism:?}"
    );

    let orchestration = grant_findings("pam_logic/mod.rs", &planted);
    assert_eq!(
        orchestration.len(),
        1,
        "the orchestration may call the constructor but may not build a \
         `Granted` by hand: {orchestration:?}"
    );
    assert!(orchestration[0].contains("Outcome::Granted"));

    assert!(
        grant_findings("outcome.rs", &planted).is_empty(),
        "outcome.rs defines both constructors, so it is exempt by path"
    );
}

/// The mapping above only covers daemon responses.  Guard *every* file of
/// this crate — not just `pam_logic` and `lib.rs` — against
/// reintroducing `PAM_IGNORE`, by identifier and by its numeric value.
///
/// The numeric half is the one that matters for regressions: the vectors
/// that remain are a `pam_sys::PAM_IGNORE` re-export reaching a `return`, or
/// a bare literal equal to PAM_IGNORE's value, in any `client-pam/src/**`
/// — either is a single edit away from the bypass this guards, and a
/// name-only scan would miss the numeric form.
///
/// The walk is `source_files`, i.e. recursive: `src/mechanism/` is a
/// directory with no `rs` extension, so a single-level `read_dir` would
/// silently stop covering the modules that read daemon responses and the one
/// that decides `PreCollected` — and the scan would stay green while the
/// coverage it claims evaporated.
#[test]
fn test_module_source_contains_no_pam_ignore_return() {
    let files = source_files();
    let names: Vec<String> = files.iter().map(|p| relative_to_src(p)).collect();
    // An empty or relocated scan must not pass silently: these files carry
    // the mechanism exits, the verdict mapping and the orchestration.
    for required in [
        "pam_logic/mod.rs",
        "pam_logic/wiring.rs",
        "outcome.rs",
        "mechanism/sequential.rs",
        "mechanism/threaded.rs",
        "mechanism/handoff.rs",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }

    // Spelled arithmetically so this test's own source carries no literal
    // for its own scan to find.
    let ignore_code: u128 = 5 * 5;
    let mut findings: Vec<String> = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        let name = relative_to_src(path);
        let cleaned = stripped_source(&source);
        for (line, text) in pam_ignore_identifiers(&cleaned) {
            findings.push(format!("{name}:{line}: PAM_IGNORE identifier in: {text}"));
        }
        for (line, text) in numeric_literals_equal_to(&cleaned, ignore_code) {
            findings.push(format!(
                "{name}:{line}: PAM_IGNORE value {ignore_code} used in: {text}"
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "the module must never return PAM_IGNORE:\n{}",
        findings.join("\n")
    );
}

/// The whole-crate scan above returns empty for two independent reasons —
/// every `PAM_IGNORE` in this crate is prose inside a comment, and no bare
/// literal holds its value — so it would stay green even if the stripper or
/// either detector were broken.  Prove both detectors fire on a synthetic
/// snippet, and that a comment or a string naming the code does not count.
#[test]
fn test_pam_ignore_scan_detects_a_real_return() {
    // Spelled arithmetically so this test's own source carries no literal
    // for its own scan to find (as in the whole-crate scan above).
    let ignore_code: u128 = 5 * 5;

    let source = format!(
        "// PAM_IGNORE in a comment is prose, not a return.\n\
         /* PAM_IGNORE and {ignore_code} in a block comment, too. */\n\
         let prose = \"return pam_sys::PAM_IGNORE; return {ignore_code};\";\n\
         let code = {{ let x = pam_sys::PAM_IGNORE; x }};\n\
         return pam_sys::PAM_IGNORE;\n\
         return {ignore_code}u32;\n"
    );
    let cleaned = stripped_source(&source);

    assert_eq!(
        pam_ignore_identifiers(&cleaned),
        vec![
            (
                4,
                "let code = { let x = pam_sys::PAM_IGNORE; x };".to_owned()
            ),
            (5, "return pam_sys::PAM_IGNORE;".to_owned()),
        ],
        "the identifier scan must report the bare identifier and the real \
         return, and neither the comment nor the string"
    );

    assert_eq!(
        numeric_literals_equal_to(&cleaned, ignore_code),
        vec![(6, format!("{ignore_code}u32"))],
        "the numeric scan must report the bare value and neither the \
         comment nor the string"
    );

    // The negative half: prose alone must never be reported, which is what
    // makes the whole-crate assertion meaningful today.
    assert_eq!(
        pam_ignore_identifiers(&stripped_source("// PAM_IGNORE\n")),
        Vec::new(),
        "a comment naming PAM_IGNORE is not a return"
    );
}

/// **Smoke test only.**  It compares source byte offsets, so it would still
/// pass if the lookup sat behind a branch that never executes.
///
/// The authoritative coverage is the `duplicate`, `duplicate-unavailable`,
/// `duplicate-cross-user` and `duplicate-cross-service` shapes in
/// `scripts/ci/test-pam-conv-thread.sh`, which count the connections the
/// fake daemon accepted: this ordering is what makes those counts
/// meaningful.
#[test]
fn cache_lookup_precedes_daemon_contact() {
    // The lookup and the daemon contact both live in `run`, which is
    // `transaction/run.rs`. `production_source` is the same reader every other
    // scan uses: it cuts the file at its first `#[cfg(test)]` *module* and
    // answers a test-only file with an empty scan, so the transaction's test
    // module is not read as production however it is declared.
    let production = production_source(&src_root().join("transaction/run.rs"));
    // An empty scan would satisfy no assertion below (both searches panic), so
    // the guard is that the read reached the driver at all.
    assert_scan_reaches(
        "transaction/run.rs",
        &production,
        &[
            "fn run",
            "replay_for(username, service_name.original(), Instant::now())",
            "let request = SendParams {",
        ],
    );

    // The call, not the `if let` that contains it: rustfmt is free to break
    // the pattern across lines.
    let lookup = production
        .find("replay_for(username, service_name.original(), Instant::now())")
        .unwrap_or_else(|| panic!("invariant broken: the reuse lookup is gone from `run`"));

    let daemon_contact = production
        .find("let request = SendParams {")
        .unwrap_or_else(|| {
            panic!("invariant broken: production call to the IPC connect not found")
        });

    assert!(
        lookup < daemon_contact,
        "invariant broken: the verdict-reuse lookup (byte {}) must run before the \
         module contacts the daemon (byte {}), otherwise a duplicate transaction \
         still sends a request and rings the phone",
        lookup,
        daemon_contact
    );
}

/// The reuse suite is the fifteen named cases, and no test in the crate is
/// ignored (the fork experiment is fixed and runs normally).
///
/// The defect this catches: a rewritten suite that silently drops a case —
/// presence is asserted by name, so a deleted test fails here rather than
/// passing as "all green with fewer tests". The ignore rule is the other
/// half: if `#[ignore]` could be used to silence a broken case, a defect
/// could ship as "green", so the crate must contain none.
#[test]
fn reuse_suite_is_intact() {
    let files = source_files();
    let names: Vec<String> = files.iter().map(|path| relative_to_src(path)).collect();
    for required in [
        "pam_logic/tests/reuse.rs",
        "transaction/tests/mod.rs",
        "conclusion_cache.rs",
        "source_guards.rs",
    ] {
        assert!(
            names.iter().any(|name| name == required),
            "the scan did not cover {required}: {names:?}"
        );
    }
    // Comment- and string-stripped, so a doc comment that quotes a name or
    // an attribute is not a finding, and this test's own literals cannot
    // satisfy its searches.
    let sources: String = files
        .iter()
        .map(|path| {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            stripped_source(&source)
        })
        .collect();

    // The fifteen: the fourteen cases that survived the retargeting, plus
    // `armed_requires_both_connect_and_send`, which replaces
    // `the_verdict_record_is_armed_only_inside_the_helper` — that one is
    // deleted below because the by-value `Concluded` makes its source scan
    // redundant, and a replacement asserting "the type is constructed here"
    // would be strictly weaker than the type.
    const REUSE_CASES: [&str; 15] = [
        "a_success_inside_the_window_is_reused",
        "a_success_after_the_window_is_not_reused",
        "an_unavailability_inside_the_window_is_reused",
        "a_denial_inside_the_window_is_reused",
        "an_unavailability_after_the_window_is_not_reused",
        "another_users_conclusion_is_never_reused",
        "another_services_conclusion_is_never_reused",
        "recording_a_failure_replaces_the_cached_success",
        "a_failed_connect_records_nothing_and_the_retry_dials_again",
        "a_from_cache_verdict_is_not_recorded",
        "an_unresolved_service_is_not_recorded",
        "a_poisoned_lock_reads_as_a_cache_miss",
        "a_future_timestamp_does_not_panic",
        "cache_lookup_precedes_daemon_contact",
        "armed_requires_both_connect_and_send",
    ];
    for name in REUSE_CASES {
        assert!(
            sources.contains(&format!("fn {name}(")),
            "the reuse case `{name}` is missing: the suite may not be \
             rewritten by dropping a case"
        );
    }
    assert!(
        !sources.contains(concat!(
            "fn the_verdict_record_is_armed_only_inside_the",
            "_helper("
        )),
        "the arming source scan is deleted, not renamed: the by-value \
         `Concluded` replaces it, and a weaker copy must not return"
    );

    // The new cases this step adds, so a dropped one fails like any other.
    for name in [
        "reuse_key_is_case_sensitive",
        "replay_notice_is_silent",
        "cache_owner_is_local",
        "conclusion_cache_survives_fork",
    ] {
        assert!(
            sources.contains(&format!("fn {name}(")),
            "the new reuse case `{name}` is missing"
        );
    }

    // No ignored test in the crate: the fork experiment was the last one,
    // and `#[ignore]` may not be reused to silence a broken case.
    let ignored = sources.matches("#[ignore").count();
    assert_eq!(
        ignored, 0,
        "no test may be ignored (the fork experiment now runs); found {ignored}"
    );
}

/// No other module may name the reuse record's lock or its static.
///
/// The defect this catches: a second file reaching `LAST_CONCLUSION` (or
/// any `.lock()` on it), or this module handing the guard out through a
/// non-test `pub(crate)` getter — either defeats the ownership that keeps a
/// fork fix (an `atfork` reinit, an atomic cell, or dropping the cache)
/// inside one file. The scan is over the comment- and string-stripped
/// production half of every `src/**/*.rs`, so `#[cfg(test)]` code is exempt
/// by construction and a doc comment that quotes the token is not a
/// finding. The positive control runs the detector over an in-memory
/// string, never a planted file under `src/`, which would race the parallel
/// recursive walk.
#[test]
fn cache_owner_is_local() {
    let files = source_files();
    let names: Vec<String> = files.iter().map(|path| relative_to_src(path)).collect();
    assert!(
        names.iter().any(|name| name == "conclusion_cache.rs"),
        "the scan did not cover the cache's own module: {names:?}"
    );

    let mut findings: Vec<String> = Vec::new();
    for path in &files {
        let rel = relative_to_src(path);
        let production = production_source(path);
        if rel == "conclusion_cache.rs" {
            // Guard against a re-truncated scan: the whole claim is about
            // what the owner's module may do, and an empty production half
            // satisfies "no other module names the lock" vacuously.
            assert_scan_reaches(
                &rel,
                &production,
                &[
                    "impl ConclusionCache",
                    "LAST_CONCLUSION",
                    "fn reinit_cache_in_child",
                ],
            );
            // The owner may lock the static; it may not hand the lock, the
            // guard or the record out.
            for (line, text) in production.lines().enumerate() {
                let leaks_guard = text.contains("MutexGuard");
                let exposes_record =
                    text.contains("pub(crate) fn") && text.contains("LastConclusion");
                if leaks_guard || exposes_record {
                    findings.push(format!("{rel}:{}: {}", line + 1, text.trim()));
                }
            }
            continue;
        }
        for hit in lock_references(&production) {
            findings.push(format!("{rel}: {hit}"));
        }
    }
    assert!(
        findings.is_empty(),
        "only `conclusion_cache.rs` may name the reuse record's lock:\n{}",
        findings.join("\n")
    );

    // Positive control: the detector fires on a planted reach.
    let planted = stripped_source(
        "fn steal() -> Option<Outcome> {\n    let guard = LAST_CONCLUSION.lock().ok()?;\n    None\n}\n",
    );
    assert!(
        !lock_references(&planted).is_empty(),
        "the detector must report a planted `LAST_CONCLUSION.lock()`"
    );
    let getter = lock_references(&stripped_source(
        "pub(crate) fn guard() -> MutexGuard<'static, ()> { CACHE_SLOT_LOCK.lock().unwrap() }\n",
    ));
    assert!(
        !getter.is_empty(),
        "the detector must report a getter that hands the guard out"
    );
    // Negative control: prose and strings are not reaches.
    let prose = stripped_source(
        "// LAST_CONCLUSION.lock() is what this module forbids elsewhere\n\
         let doc = \"LAST_CONCLUSION\";\n",
    );
    assert!(
        lock_references(&prose).is_empty(),
        "comments and string literals are not lock references"
    );
}

/// Every line of `source` that reaches the cache's lock or its static.
fn lock_references(source: &str) -> Vec<String> {
    const TOKENS: [&str; 5] = [
        ".lock()",
        ".try_lock()",
        ".try_lock_for",
        "LAST_CONCLUSION",
        "MutexGuard",
    ];
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| TOKENS.iter().any(|token| line.contains(token)))
        .map(|(line, text)| format!("line {}: {}", line + 1, text.trim()))
        .collect()
}
