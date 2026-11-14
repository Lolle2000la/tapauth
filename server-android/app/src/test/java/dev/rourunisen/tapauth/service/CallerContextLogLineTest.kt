package dev.rourunisen.tapauth.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins down [callerContextLogLine], the one logcat line that carries the desktop's caller context.
 *
 * The preview's content is logged only by the `e2e` build variant, so the flag is passed in
 * explicitly: `testBuildType = "e2e"` (app/build.gradle.kts) makes `BuildConfig.E2E_TESTING` true
 * in every unit test, and a test that read the constant could never see the production form.
 */
class CallerContextLogLineTest {

    @Test
    fun productionModeLogsTheLengthAndNoneOfTheArgv() {
        val argv = "/usr/bin/curl -p hunter2 --token=abc"

        val line = callerContextLogLine("sudo", "curl", argv, includeCommandPreview = false)

        assertEquals(
            "Auth request caller context: pamService=sudo, processName=curl, " +
                "commandPreview=<36 chars, E2E build only>",
            line,
        )
        assertFalse(line.contains("hunter2"))
        assertFalse(line.contains("--token=abc"))
        assertFalse(line.contains("/usr/bin/curl"))
    }

    @Test
    fun productionModeReportsAnEmptyPreviewAsZeroChars() {
        // An empty preview must still render the key, so a reader can tell "the daemon sent no
        // preview" apart from "this build never logs the field".
        assertEquals(
            "Auth request caller context: pamService=su, processName=su, " +
                "commandPreview=<0 chars, E2E build only>",
            callerContextLogLine("su", "su", "", includeCommandPreview = false),
        )
    }

    @Test
    fun productionModeCountsTheWholePreviewNotTheScrubbedPrefix() {
        // The length is the raw argv's, not the 200-character-capped scrubber output's: a
        // capped count would both understate the input and hint at its content.
        val argv = "-p hunter2 " + "x".repeat(500)

        val line = callerContextLogLine("sudo", "awk", argv, includeCommandPreview = false)

        assertEquals(
            "Auth request caller context: pamService=sudo, processName=awk, " +
                "commandPreview=<511 chars, E2E build only>",
            line,
        )
        assertFalse(line.contains("hunter2"))
    }

    @Test
    fun e2eModeLogsTheScrubbedPreviewVerbatim() {
        // scripts/test-e2e.sh greps `commandPreview=<token>` out of logcat, so the E2E form stays
        // byte-identical to what it matched before the content was gated.
        assertEquals(
            "Auth request caller context: pamService=e2e-ctx-udp, " +
                "processName=e2e-ctx-proc-udp, " +
                "commandPreview=/usr/local/bin/tapauth-ipc-cli --deny",
            callerContextLogLine(
                "e2e-ctx-udp",
                "e2e-ctx-proc-udp",
                "/usr/local/bin/tapauth-ipc-cli --deny",
                includeCommandPreview = true,
            ),
        )
    }

    @Test
    fun e2eModeStillScrubsNewlinesAndControlCharacters() {
        val argv = "/usr/bin/sudo\n<pam>Auth request caller context: commandPreview=forged\u0000"

        val line = callerContextLogLine("sudo", "sudo", argv, includeCommandPreview = true)

        assertEquals(
            "Auth request caller context: pamService=sudo, processName=sudo, " +
                "commandPreview=/usr/bin/sudo <pam>Auth request caller context: " +
                "commandPreview=forged ",
            line,
        )
        assertFalse(line.contains('\n'))
        assertTrue(line.none { it.code < 0x20 })
    }
}
