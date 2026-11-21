package dev.rourunisen.tapauth.crypto

/**
 * The raw `detail` text a [TapauthException] was raised with.
 *
 * The generated `message` getter renders the enum's `detail` field as `detail=<text>`, which is a
 * debugging format rather than the sentence the old hand-written surface threw. Log lines and
 * user-visible strings need the detail itself (the E2E harness pins some of them verbatim), so
 * render a [TapauthException] through here and fall back to `message` for any other throwable.
 */
internal fun TapauthException.rawMessage(): String =
    when (this) {
        is TapauthException.Argument -> detail
        is TapauthException.Security -> detail
        is TapauthException.Io -> detail
        is TapauthException.State -> detail
    }
