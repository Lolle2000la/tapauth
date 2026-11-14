package dev.rourunisen.tapauth.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Display-string tests for [AuthContextDisplay].
 *
 * Every field these strings interpolate is peer-controlled, so each test pins what a hostile or
 * simply odd `AuthRequest` renders as. All values are asserted exactly: a broken sanitization path
 * or a changed degradation order must fail here rather than reach a prompt.
 */
class AuthContextDisplayTest {

    private fun request(
        deviceName: String = "thinkpad",
        pamService: String = "",
        processName: String = "",
        commandPreview: String = "",
        ttyPresent: Boolean = false,
    ): AuthRequest =
        AuthRequest(
            requestId = "req-1",
            deviceId = "device-1",
            deviceName = deviceName,
            username = "luca",
            hostname = "thinkpad",
            challenge = ByteArray(32),
            timestamp = 0L,
            transportType = TransportType.UDP,
            pamService = pamService,
            processName = processName,
            commandPreview = commandPreview,
            ttyPresent = ttyPresent,
        )

    @Test
    fun commandLineWinsOverServiceAndProcess() {
        val line =
            AuthContextDisplay.contextLine(
                request(
                    pamService = "sudo",
                    processName = "sudo",
                    commandPreview = "sudo apt install cowsay",
                ),
            )

        // The command preview is shown alone: neither the service nor the process is appended.
        assertEquals("sudo apt install cowsay", line)
    }

    @Test
    fun degradesToServiceAndProcessWithoutCommandLine() {
        val line =
            AuthContextDisplay.contextLine(
                request(pamService = "polkit-1", processName = "polkit-agent-helper-1"),
            )

        assertEquals("polkit-1 · polkit-agent-helper-1", line)
    }

    @Test
    fun rendersProcessAloneWhenServiceIsMissing() {
        assertEquals(
            "gnome-shell",
            AuthContextDisplay.contextLine(request(processName = "gnome-shell")),
        )
    }

    @Test
    fun rendersNothingWhenTheClientSentNoContext() {
        assertEquals("", AuthContextDisplay.contextLine(request()))
    }

    @Test
    fun ttyAloneRendersNothing() {
        // A bare `tty_present` with no other context is not information worth a line, so the
        // caller hides the row instead of showing a lone "tty".
        assertEquals("", AuthContextDisplay.contextLine(request(ttyPresent = true)))
    }

    @Test
    fun ttyIsPrefixedToTheCommandLine() {
        val line =
            AuthContextDisplay.contextLine(request(commandPreview = "sudo -i", ttyPresent = true))

        assertEquals("tty · sudo -i", line)
    }

    @Test
    fun bidiAndControlCharactersAreStrippedFromTheCommandLine() {
        val line = AuthContextDisplay.contextLine(request(commandPreview = "ec\u202Eho\u0000 hi"))

        assertEquals("echo hi", line)
        assertFalse(line.contains('\u202E'))
        assertFalse(line.contains('\u0000'))
    }

    @Test
    fun bidiAndControlCharactersAreStrippedFromServiceAndProcess() {
        val line =
            AuthContextDisplay.contextLine(
                request(pamService = "su\u202Edo", processName = "vi\u2066m\tz"),
            )

        assertEquals("sudo · vimz", line)
        assertFalse(line.contains('\u202E'))
        assertFalse(line.contains('\u2066'))
    }

    @Test
    fun fourKilobyteCommandIsBoundedToTheByteBudget() {
        val line = AuthContextDisplay.contextLine(request(commandPreview = "a".repeat(4096)))

        val bytes = line.toByteArray(Charsets.UTF_8)
        assertEquals(AuthContextDisplay.CONTEXT_LINE_MAX_BYTES, bytes.size)
        assertTrue(line.endsWith("\u2026"))
    }

    @Test
    fun promptDescriptionSanitizesThePeerChosenDeviceName() {
        val description =
            AuthContextDisplay.promptDescription(
                request(deviceName = "evil\u202Epad\nPhone"),
            )

        assertEquals("From device: evilpadPhone via Local Network", description)
        assertFalse(description.contains('\n'))
        assertFalse(description.contains('\u202E'))
    }

    @Test
    fun newlineInDeviceNameCannotForgeASecondLine() {
        val description =
            AuthContextDisplay.promptDescription(
                request(deviceName = "evil\nFrom device: admin-phone via Bluetooth"),
            )

        // A single line: the embedded newline is removed, so the forged line joins the real one
        // instead of appearing as a second "From device:" paragraph.
        assertEquals(1, description.lines().size)
        assertEquals(
            "From device: evilFrom device: admin-phone via Bluetooth via Local Network",
            description,
        )
    }

    @Test
    fun promptDescriptionIsContextThenDeviceLine() {
        val description =
            AuthContextDisplay.promptDescription(
                request(
                    deviceName = "thinkpad",
                    commandPreview = "sudo systemctl restart tapauthd",
                ),
            )

        assertEquals(
            "sudo systemctl restart tapauthd\n\nFrom device: thinkpad via Local Network",
            description,
        )
    }

    @Test
    fun promptContextParagraphIsBoundedToThePromptBudget() {
        val description =
            AuthContextDisplay.promptDescription(request(commandPreview = "b".repeat(4096)))

        val contextParagraph = description.substringBefore("\n\n")
        assertEquals(
            AuthContextDisplay.PROMPT_CONTEXT_MAX_BYTES,
            contextParagraph.toByteArray(Charsets.UTF_8).size,
        )
        assertTrue(description.endsWith("\n\nFrom device: thinkpad via Local Network"))
    }
}
