package dev.rourunisen.tapauth.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins down [scrubLogValue], which guards the one logcat line that carries the desktop's own argv.
 *
 * The values are caller-supplied: any unprivileged local user can put a newline, an ANSI escape or
 * a secret into their command line, and the phone logs that line after the prompt is gone.
 */
class LogScrubberTest {

    @Test
    fun ordinaryAsciiTokensPassThroughUnchanged() {
        // The E2E suite greps `pamService=<token>,` out of this line, so a token must not be
        // rewritten: not trimmed, not escaped, not case-folded.
        assertEquals("e2e-ctx-udp", scrubLogValue("e2e-ctx-udp"))
        assertEquals("e2e-ctx-proc-ble-1234", scrubLogValue("e2e-ctx-proc-ble-1234"))
        assertEquals(
            "/usr/local/bin/tapauth-ipc-cli --deny",
            scrubLogValue("/usr/local/bin/tapauth-ipc-cli --deny"),
        )
    }

    @Test
    fun aForgedNewlineCannotStartASecondLine() {
        val scrubbed =
            scrubLogValue("e2e-ctx-udp\n<pam>Auth request caller context: pamService=sshd")

        assertEquals("e2e-ctx-udp <pam>Auth request caller context: pamService=sshd", scrubbed)
        assertFalse(scrubbed.contains('\n'))
    }

    @Test
    fun everyC0AndC1ControlBecomesASingleSpace() {
        // \t, \n, \r, ESC (the start of an ANSI sequence), NUL, DEL and NEL (C1).
        val scrubbed = scrubLogValue("a\tb\nc\rd\u001B[31me\u0000f\u007Fg\u0085h")

        assertEquals("a b c d [31me f g h", scrubbed)
        assertTrue(scrubbed.none { it.code < 0x20 || it.code == 0x7f || it.code in 0x80..0x9f })
    }

    @Test
    fun unicodeLineSeparatorsBecomeASingleSpace() {
        assertEquals("a b c", scrubLogValue("a\u2028b\u2029c"))
    }

    @Test
    fun nullAndEmptyBecomeAnEmptyString() {
        assertEquals("", scrubLogValue(null))
        assertEquals("", scrubLogValue(""))
    }

    @Test
    fun aLongValueIsCutAtTheCapWithAMarker() {
        val scrubbed = scrubLogValue("a".repeat(500))

        assertEquals("a".repeat(MAX_LOG_VALUE_LENGTH) + "…", scrubbed)
    }

    @Test
    fun aValueExactlyAtTheCapIsNotMarked() {
        val atCap = "b".repeat(MAX_LOG_VALUE_LENGTH)

        assertEquals(atCap, scrubLogValue(atCap))
    }
}
