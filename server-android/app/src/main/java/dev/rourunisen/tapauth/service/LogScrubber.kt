package dev.rourunisen.tapauth.service

/** Longest value [scrubLogValue] returns, not counting the truncation marker. */
internal const val MAX_LOG_VALUE_LENGTH = 200

/** Appended once a value is cut at [MAX_LOG_VALUE_LENGTH]. */
private const val TRUNCATION_MARKER = "…"

/**
 * Make one caller-supplied value safe to interpolate into a logcat line.
 *
 * The protocol-v2 caller context (`pam_service`, `process_name`, `command_preview`) comes from the
 * desktop's own argv, which any unprivileged local user controls: a newline in it would forge an
 * extra logcat line, an ANSI escape would rewrite the terminal of whoever reads the buffer, and a
 * secret passed on the command line would outlive the prompt in the phone's log buffer. So the
 * values are scrubbed before they are logged rather than after.
 *
 * ISO control characters — C0 (`\n`, `\r`, `\t`, ESC and the rest), DEL, and the C1 range, plus the
 * Unicode line and paragraph separators — are replaced by a space, which keeps the value on one
 * line and keeps ordinary ASCII tokens (the E2E suite greps them) byte-for-byte unchanged. The
 * result is capped at [MAX_LOG_VALUE_LENGTH] characters plus [TRUNCATION_MARKER].
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
