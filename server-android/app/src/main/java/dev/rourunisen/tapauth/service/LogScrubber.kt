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
 * ## What this guarantees, and nothing else
 *
 * 1. **One line.** Every code unit [isLogControl] names — C0 (`\n`, `\r`, `\t`, ESC and the rest),
 *    DEL, the whole C1 range, and U+2028/U+2029 — becomes one ASCII space, one for one: no run is
 *    collapsed and nothing is trimmed.
 * 2. **Everything else byte-for-byte.** Every other code unit, plain ASCII included, is copied
 *    unchanged: not trimmed, not case-folded, not unescaped. The E2E suite greps
 *    `pamService=…`/`processName=…` out of this value (`assert_caller_context_delivered` in
 *    `scripts/test-e2e.sh`), so the field has to stay greppable — but those tokens are
 *    single-spaced ASCII, which is why the greps cannot police this function and `LogScrubberTest`
 *    does.
 *
 * The result is capped at [MAX_LOG_VALUE_LENGTH] UTF-16 code units (`String.length`, so a non-BMP
 * character costs two and a cut can land inside a surrogate pair, as
 * `aCutLandsInsideASurrogatePair` pins) plus [TRUNCATION_MARKER].
 *
 * ## What this deliberately does not do
 *
 * It is not the canonical context sanitizer (`sanitize_context_string` in `shared`, mirrored by
 * `ContextSanitizer` in this app), and it must not become it. Those two are pinned to each other by
 * `shared/testdata/context_sanitizer_vectors.json` because what they return is *rendered on the
 * prompt*; what this returns is only ever a log line. So it deliberately does not:
 *
 * - remove an ANSI sequence as a unit: the `ESC` becomes a space and `[31m` survives as inert text,
 *   which neutralises the escape without the log path and the prompt path having to agree on what a
 *   sequence is;
 * - collapse or trim whitespace, or drop the bidi/zero-width code points: none of them can forge a
 *   line in a log buffer, and a token's exact spacing, colons and slashes are evidence of what the
 *   caller's argv actually was;
 * - budget in UTF-8 bytes with the marker inside the budget: the cap counts code units and the
 *   marker sits on top of it.
 *
 * Unifying the two is still the wrong move: the prompt path's rules buy a log line nothing, and a
 * value rewritten here no longer says what the caller's argv said. The guard is `LogScrubberTest`,
 * not the E2E suite — its phase tokens are single-spaced ASCII with no surrounding whitespace, so
 * trim, whitespace collapse and bidi stripping would return them unchanged and the greps would
 * never notice.
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
