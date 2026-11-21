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

    /**
     * The divergence from the prompt-path sanitizer, pinned as a guarantee rather than as prose.
     *
     * `ContextSanitizer` trims and collapses whitespace, so a value like `" pamService=x "` or
     * `--user=root:wheel /etc` would come back rewritten. Here spacing, slashes and colons are part
     * of the token: the defect this catches is anyone "unifying" the two sanitizers. The E2E greps
     * are no guard against that — their phase tokens are single-spaced ASCII with no surrounding
     * whitespace, so trim, collapse and bidi stripping would hand them back unchanged — which makes
     * this test the place the split is actually held.
     */
    @Test
    fun aTokenKeepsItsSpacesColonsAndSlashes() {
        val argv = "/usr/local/bin/tapauth-ipc-cli --user=root:wheel /etc/tapauth"

        assertEquals(argv, scrubLogValue(argv))
        assertEquals("  pamService=x  ", scrubLogValue("  pamService=x  "))
        assertEquals("a  b", scrubLogValue("a  b"))
    }

    /**
     * The other half of that split: what the divergence still has to hold is the one-line
     * invariant, for a newline and for a C1 control (U+0085 NEL), which is a plain `Char` here and
     * so slips past any check written only for the C0 range.
     *
     * The defect this catches: treating C1 as printable, which lets a caller-supplied NEL start a
     * line in the log buffer and forge the line the test above asserts is intact.
     */
    @Test
    fun aNewlineAndAC1NelDoNotSurvive() {
        val scrubbed = scrubLogValue("cmd --flag\nnext\u0085line")

        assertEquals("cmd --flag next line", scrubbed)
        assertFalse(scrubbed.contains('\n'))
        assertFalse(scrubbed.contains('\u0085'))
    }

    /**
     * An escape is neutralised, not parsed: only the `ESC` is a cursor-driving code unit, so `[31m`
     * is left as inert text where the context sanitizer deletes the whole CSI.
     *
     * The defect this catches: giving the log path the prompt path's sequence-aware removal, which
     * means the two can now disagree about what a sequence is and the log value no longer matches
     * the bytes the Client sent.
     */
    @Test
    fun anAnsiEscapeIsNeutralisedWithoutParsingTheSequence() {
        assertEquals("a [31mb", scrubLogValue("a\u001B[31mb"))
        assertEquals("a ]0;titleb", scrubLogValue("a\u001B]0;titleb"))
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

    /**
     * The cap counts UTF-16 code units, not code points, so a long enough value is cut between the
     * two halves of a non-BMP character — the sentence in [scrubLogValue]'s contract.
     *
     * The defect this catches: an implementation that counts code points (or refuses to cut a
     * pair), which makes the 200-unit promise mean 201 units on a value like this one.
     */
    @Test
    fun aCutLandsInsideASurrogatePair() {
        val scrubbed = scrubLogValue("a" + "\uD83D\uDE00".repeat(100))

        assertEquals("a" + "\uD83D\uDE00".repeat(99) + "\uD83D" + "…", scrubbed)
        assertEquals(MAX_LOG_VALUE_LENGTH + 1, scrubbed.length)
    }
}
