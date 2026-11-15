package dev.rourunisen.tapauth.service

/** Longest value [scrubLogValue] returns, not counting the truncation marker. */
internal const val MAX_LOG_VALUE_LENGTH = 200

/** Appended once a value is cut at [MAX_LOG_VALUE_LENGTH]. */
private const val TRUNCATION_MARKER = "…"

/**
 * Make one caller-supplied value safe to interpolate into a logcat line.
 *
 * ## Guarantees
 * - Every code point [isLogControl] names (C0, DEL, C1, U+2028/2029) becomes one ASCII space.
 * - Everything else is copied verbatim, so the E2E greps keep matching the token.
 * - The cap is [MAX_LOG_VALUE_LENGTH] UTF-16 code units plus [TRUNCATION_MARKER].
 *
 * ## Not the prompt sanitizer
 * Not `sanitize_context_string`/`ContextSanitizer`, and it must not become them: theirs is rendered
 * on the prompt, this only ever makes a log line — `ESC` neutralised rather than a sequence parsed,
 * nothing trimmed or collapsed, the cap in code units rather than bytes.
 *
 * @return the scrubbed value; `""` for null or empty input, so a log line still renders every
 *   `key=` pair.
 */
internal fun scrubLogValue(value: String?): String {
    if (value.isNullOrEmpty()) return ""
    val builder = StringBuilder(minOf(value.length, MAX_LOG_VALUE_LENGTH + 1))
    for (char in value) {
        if (builder.length >= MAX_LOG_VALUE_LENGTH) {
            builder.append(TRUNCATION_MARKER)
            break
        }
        builder.append(if (isLogControl(char)) ' ' else char)
    }
    return builder.toString()
}

/** Whether [char] can move the cursor, start a line or drive a terminal. */
private fun isLogControl(char: Char): Boolean {
    val code = char.code
    return code < 0x20 ||
        code == 0x7f ||
        code in 0x80..0x9f ||
        code == 0x2028 || // LINE SEPARATOR
        code == 0x2029 // PARAGRAPH SEPARATOR
}
