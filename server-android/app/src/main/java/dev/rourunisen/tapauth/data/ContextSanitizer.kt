package dev.rourunisen.tapauth.data

/**
 * Defensive re-sanitization of untrusted Client-supplied context strings (PAM service, process
 * name, command line preview) before they are rendered on the phone.
 *
 * Mirrors the Rust `sanitize_context_string` helper, so a Client that skips or defeats its own
 * sanitization still cannot inject terminal escapes, bidi overrides that visually reorder text, or
 * an unbounded blobs into the approval prompt. Pure Kotlin, so it is usable from JVM unit tests.
 */
object ContextSanitizer {

    private const val ELLIPSIS = "\u2026"
    private const val ELLIPSIS_UTF8_BYTES = 3

    /**
     * Sanitize [input] for display.
     *
     * Control characters (`0x00..=0x1F`, `0x7F`), the Unicode bidi controls (`U+200E`/`U+200F`,
     * `U+202A..=U+202E`, `U+2066..=U+2069`) and whitespace runs are removed or collapsed, the
     * result is trimmed, and it is truncated on a UTF-8 code point boundary to at most [maxBytes]
     * bytes. A truncation appends `…`, which counts toward that budget.
     *
     * @return the sanitized string, or `""` for `null`/blank input
     */
    fun sanitize(input: String?, maxBytes: Int = 128): String {
        if (input.isNullOrEmpty()) return ""
        val collapsed = collapseWhitespace(stripForbidden(input))
        if (collapsed.isEmpty()) return ""
        return truncateUtf8(collapsed, maxBytes)
    }

    private fun stripForbidden(value: String): String {
        val out = StringBuilder(value.length)
        for (c in value) {
            if (isForbidden(c)) continue
            out.append(c)
        }
        return out.toString()
    }

    private fun isForbidden(c: Char): Boolean {
        val code = c.code
        return when {
            code <= 0x1F || code == 0x7F -> true
            code in 0x202A..0x202E -> true
            code in 0x2066..0x2069 -> true
            code == 0x200E || code == 0x200F -> true
            else -> false
        }
    }

    /**
     * Collapse every whitespace run to a single space and drop leading/trailing whitespace.
     *
     * Whitespace is classified as ASCII space or a Unicode space separator/line/paragraph
     * separator, matching Rust's `char::is_whitespace` for the characters that reach here:
     * `Char.isWhitespace` maps to `Character.isWhitespace`, which excludes `U+00A0`, `U+2007` and
     * `U+202F`, so a non-breaking space would otherwise survive into the prompt.
     */
    private fun collapseWhitespace(value: String): String {
        val out = StringBuilder(value.length)
        var pendingSpace = false
        for (c in value) {
            if (isWhitespace(c)) {
                pendingSpace = true
                continue
            }
            if (pendingSpace && out.isNotEmpty()) out.append(' ')
            pendingSpace = false
            out.append(c)
        }
        return out.toString()
    }

    /**
     * `codePoint == 0x20 || Character.isSpaceChar(codePoint)`, per Rust's `char::is_whitespace`.
     */
    private fun isWhitespace(c: Char): Boolean = c.code == 0x20 || Character.isSpaceChar(c.code)

    private fun truncateUtf8(value: String, maxBytes: Int): String {
        if (value.toByteArray(Charsets.UTF_8).size <= maxBytes) return value
        if (maxBytes < ELLIPSIS_UTF8_BYTES) return ""

        val budget = maxBytes - ELLIPSIS_UTF8_BYTES
        val out = StringBuilder()
        var used = 0
        var index = 0
        while (index < value.length) {
            val width = codePointWidth(value, index)
            val codePoint = codePointAt(value, index, width)
            val encodedSize = utf8Size(codePoint)
            if (used + encodedSize > budget) break
            out.append(value, index, index + width)
            used += encodedSize
            index += width
        }
        return out.toString().trimEnd() + ELLIPSIS
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
