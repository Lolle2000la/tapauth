package dev.rourunisen.tapauth.data

/**
 * Defensive re-sanitization of untrusted Client-supplied context strings (PAM service, process
 * name, command line preview) before they are rendered on the phone.
 *
 * This is a **mirror** of the Rust `sanitize_context_string` helper
 * (`shared/src/protocol/messages.rs`), not a caller of the UniFFI export: `ContextSanitizer` is
 * exercised by JVM unit tests (`src/test`), and `./gradlew test` cannot load `libshared.so` or a
 * host JNA dispatcher — the generated binding would fail at class init
 * (`UnsatisfiedLinkError`/`NoClassDefFoundError`). The two implementations are therefore pinned
 * against each other by one checked-in vector file,
 * `shared/testdata/context_sanitizer_vectors.json`, which both test suites read. Change behaviour
 * there first, never in one side only.
 *
 * The guarantees are the Rust ones: ANSI escape sequences are deleted as a unit (a CSI or OSC whose
 * parameter bytes would otherwise be rendered), whitespace runs collapse to one ASCII space and are
 * trimmed, the control/bidi/zero-width code points listed in [isForbidden] are dropped, and the
 * result is truncated on a UTF-8 code point boundary to at most `maxBytes` bytes.
 *
 * Pure Kotlin, so it is usable from JVM unit tests.
 */
object ContextSanitizer {

    private const val ESC = '\u001B'
    private const val BEL = '\u0007'
    private const val ELLIPSIS = "\u2026"
    private const val ELLIPSIS_UTF8_BYTES = 3

    /**
     * Sanitize [input] for display.
     *
     * @return the sanitized string, or `""` for `null`/blank input
     */
    fun sanitize(input: String?, maxBytes: Int = 128): String {
        if (input.isNullOrEmpty()) return ""
        val collapsed = normalize(input)
        if (collapsed.isEmpty()) return ""
        return truncateUtf8(collapsed, maxBytes)
    }

    /**
     * Remove ANSI escape sequences and forbidden code points, and collapse whitespace.
     *
     * One pass, in the Rust order: an escape sequence is consumed whole, then a whitespace code
     * point becomes a pending space, then a forbidden code point is dropped, everything else is
     * kept. Whitespace is tested *before* the forbidden set because `U+0009`..`U+000D` and `U+0085`
     * belong to both — deleting them would turn `sudo\tapt` into `sudoapt`.
     */
    private fun normalize(value: String): String {
        val out = StringBuilder(value.length)
        var pendingSpace = false
        var index = 0
        while (index < value.length) {
            if (value[index] == ESC) {
                // A lone ESC (end of input, or followed by anything but `[`/`]`) is just a
                // forbidden character: drop it and filter the next character normally.
                index += ansiSequenceLength(value, index) ?: 1
                continue
            }
            val c = value[index]
            index += 1
            if (isContextWhitespace(c)) {
                pendingSpace = out.isNotEmpty()
                continue
            }
            if (isForbidden(c)) continue
            if (pendingSpace) {
                out.append(' ')
                pendingSpace = false
            }
            out.append(c)
        }
        return out.toString()
    }

    /**
     * Length of the ANSI escape sequence starting at [start], terminator included.
     *
     * `null` when `value[start]` is an `ESC` that begins neither a CSI nor an OSC. An unterminated
     * CSI/OSC reports the rest of the input, so a truncated escape cannot leak its parameter bytes
     * (`[31m`) into the prompt.
     */
    private fun ansiSequenceLength(value: String, start: Int): Int? {
        if (start + 1 >= value.length) return null
        return when (value[start + 1]) {
            // CSI: ESC '[' params intermediates final
            '[' -> {
                var cursor = start + 2
                while (cursor < value.length && isCsiParameter(value[cursor])) cursor++
                while (cursor < value.length && isCsiIntermediate(value[cursor])) cursor++
                if (cursor < value.length && isCsiFinal(value[cursor])) {
                    cursor + 1 - start
                } else {
                    value.length - start
                }
            }
            // OSC: ESC ']' ... (BEL | ESC '\')
            ']' -> {
                var cursor = start + 2
                while (cursor < value.length) {
                    if (value[cursor] == BEL) return cursor + 1 - start
                    if (
                        value[cursor] == ESC &&
                            cursor + 1 < value.length &&
                            value[cursor + 1] == '\\'
                    ) {
                        return cursor + 2 - start
                    }
                    cursor++
                }
                value.length - start
            }
            else -> null
        }
    }

    /** One byte of a CSI parameter string: `0x30..=0x3F` (ECMA-48 §5.4). */
    private fun isCsiParameter(c: Char): Boolean = c in '\u0030'..'\u003F'

    /** One byte of a CSI intermediate string: `0x20..=0x2F` (ECMA-48 §5.4). */
    private fun isCsiIntermediate(c: Char): Boolean = c in '\u0020'..'\u002F'

    /** The single final byte of a CSI sequence: `0x40..=0x7E` (ECMA-48 §5.4). */
    private fun isCsiFinal(c: Char): Boolean = c in '\u0040'..'\u007E'

    /**
     * The code points that become one ASCII space, collapsed and trimmed.
     *
     * Spelled out rather than delegating to `Char.isWhitespace`/`Character.isSpaceChar`, whose
     * Unicode sets differ from this contract's (`Character.isWhitespace` excludes `U+00A0`,
     * `U+2007` and `U+202F`).
     */
    private fun isContextWhitespace(c: Char): Boolean =
        c in '\u0009'..'\u000D' ||
            c == '\u0020' ||
            c == '\u0085' ||
            c == '\u00A0' ||
            c == '\u1680' ||
            c in '\u2000'..'\u200A' ||
            c == '\u2028' ||
            c == '\u2029' ||
            c == '\u202F' ||
            c == '\u205F' ||
            c == '\u3000'

    /** Code points that must never reach the prompt: controls, bidi formatters, zero-width. */
    private fun isForbidden(c: Char): Boolean =
        c in '\u0000'..'\u001F' ||
            c in '\u007F'..'\u009F' ||
            c == '\u061C' ||
            c in '\u200B'..'\u200F' ||
            c in '\u202A'..'\u202E' ||
            c in '\u2060'..'\u2064' ||
            c in '\u2066'..'\u2069' ||
            c == '\uFEFF'

    /**
     * Truncate [value] to at most [maxBytes] UTF-8 bytes, on a code point boundary.
     *
     * Matches the Rust truncation exactly: when the value has to be cut, `…` is appended *inside*
     * the budget, so a budget of [ELLIPSIS_UTF8_BYTES] bytes or less cuts without an ellipsis and a
     * 3-byte budget can still fit one 3-byte character. Nothing is trimmed after the cut — the
     * collapsed input already has no trailing whitespace, and trimming here would make a cut right
     * after an interior space differ from Rust.
     */
    private fun truncateUtf8(value: String, maxBytes: Int): String {
        if (value.toByteArray(Charsets.UTF_8).size <= maxBytes) return value

        val withEllipsis = maxBytes > ELLIPSIS_UTF8_BYTES
        val budget = if (withEllipsis) maxBytes - ELLIPSIS_UTF8_BYTES else maxBytes

        val out = StringBuilder()
        var used = 0
        var index = 0
        while (index < value.length) {
            val width = codePointWidth(value, index)
            val encodedSize = utf8Size(codePointAt(value, index, width))
            if (used + encodedSize > budget) break
            out.append(value, index, index + width)
            used += encodedSize
            index += width
        }
        return out.toString() + if (withEllipsis) ELLIPSIS else ""
    }

    /** Number of `Char`s (1 or 2) forming the code point that starts at [index]. */
    private fun codePointWidth(value: String, index: Int): Int {
        val c = value[index]
        val hasPair =
            c.isHighSurrogate() && index + 1 < value.length && value[index + 1].isLowSurrogate()
        return if (hasPair) 2 else 1
    }

    private fun codePointAt(value: String, index: Int, width: Int): Int {
        if (width == 1) return value[index].code
        val high = value[index].code - 0xD800
        val low = value[index + 1].code - 0xDC00
        return 0x10000 + (high shl 10) + low
    }

    private fun utf8Size(codePoint: Int): Int =
        when {
            codePoint < 0x80 -> 1
            codePoint < 0x800 -> 2
            codePoint < 0x10000 -> 3
            else -> 4
        }
}
