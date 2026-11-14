package dev.rourunisen.tapauth.data

/**
 * Display strings built from an [AuthRequest] for the notification and both biometric prompts.
 *
 * Every input string here is untrusted: `commandPreview`, `processName` and `pamService` come from
 * the Client's signed-but-peer-chosen context, and `deviceName` is the peer-chosen
 * `client_hostname` from the provision payload, persisted verbatim at pairing time. Each part is
 * therefore re-sanitized with [ContextSanitizer] before it is rendered, so a Client cannot inject
 * terminal escapes, bidi overrides or additional prompt lines.
 *
 * Pure Kotlin (no Android types) so the strings are reachable from JVM unit tests.
 */
object AuthContextDisplay {

    /** Byte budget for the secondary context line under the notification header. */
    const val CONTEXT_LINE_MAX_BYTES = 128

    /** Byte budget for the context paragraph inside the biometric prompt. */
    const val PROMPT_CONTEXT_MAX_BYTES = 256

    /** Byte budget for each identity string (`deviceName`, `username`, `hostname`). */
    const val IDENTITY_MAX_BYTES = 64

    private const val TTY_TAG = "tty"
    private const val CONTEXT_SEPARATOR = " · "

    /**
     * Secondary context line rendered under the primary `username@hostname` header (§3.3).
     *
     * The Client's `command_preview`/`process_name`/`pam_service` are untrusted, so every part is
     * re-sanitized with [ContextSanitizer] here and the assembled line is sanitized again — that
     * bounds the whole line to [CONTEXT_LINE_MAX_BYTES] and re-adds the end ellipsis after the
     * join.
     *
     * Degradation order: the command preview when present, otherwise `pamService · processName`;
     * the `tty` indicator is prepended so truncation cannot hide it. Returns "" when the Client
     * sent no context at all, in which case the caller renders nothing extra.
     */
    fun contextLine(request: AuthRequest): String = contextLine(request, CONTEXT_LINE_MAX_BYTES)

    private fun contextLine(request: AuthRequest, maxBytes: Int): String {
        val command = ContextSanitizer.sanitize(request.commandPreview, maxBytes)
        val parts = ArrayList<String>(3)
        if (command.isNotEmpty()) {
            parts.add(command)
        } else {
            // Degrade to `pamService · processName` when the Client sent no command line.
            val pamService = ContextSanitizer.sanitize(request.pamService)
            val processName = ContextSanitizer.sanitize(request.processName)
            if (pamService.isNotEmpty()) parts.add(pamService)
            if (processName.isNotEmpty()) parts.add(processName)
        }
        if (parts.isEmpty()) return ""
        if (request.ttyPresent) parts.add(0, TTY_TAG)
        return ContextSanitizer.sanitize(parts.joinToString(CONTEXT_SEPARATOR), maxBytes)
    }

    /**
     * Description shown by both biometric prompts: one sanitized context paragraph followed by the
     * device/transport line that was already there. Both the in-app prompt and the
     * notification-launched one render exactly this string, so they cannot drift apart.
     *
     * [AuthRequest.deviceName] is the peer-chosen hostname persisted at pairing time, so it is
     * sanitized (and byte-bounded) here rather than trusted.
     */
    fun promptDescription(request: AuthRequest): String {
        val deviceName = ContextSanitizer.sanitize(request.deviceName, IDENTITY_MAX_BYTES)
        val deviceLine = "From device: $deviceName via ${request.transportType.displayName}"
        val contextText = contextLine(request, PROMPT_CONTEXT_MAX_BYTES)
        return if (contextText.isEmpty()) deviceLine else "$contextText\n\n$deviceLine"
    }
}
