package dev.rourunisen.tapauth.data

import java.util.Arrays
import java.util.Base64
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `PairedDevice.toString()` must identify a device without printing its CSK.
 *
 * The defect this pins down is the rendering every Kotlin `data class` gets for free: a `ByteArray`
 * field goes through `java.util.Arrays.toString`, so one log line — or one `PairingUpdate.Complete`
 * interpolated into one — carried `csk=[12, 255, …]`, which is the key itself rather than an
 * identity. `assurance-strategy.md` §6 records it as a known gap; nothing logs the record today,
 * which is exactly why it needed pinning before something does.
 *
 * The three forms a key is normally printed in are each asserted absent, because a hand-written
 * `toString()` that redacts one and leaks another is the failure mode worth catching: the
 * `Arrays.toString` form the derived one would have used, hex, and base64.
 */
class PairedDeviceRedactionTest {

    private companion object {
        /** A CSK with no repeated byte, so each of its rendered forms is distinctive. */
        val CSK = ByteArray(32) { (it * 7 + 3).toByte() }

        /** The desktop's Ed25519 public key. Public by definition: it may be rendered. */
        val DESKTOP_KEY = ByteArray(32) { 0x11 }
    }

    private fun device() =
        PairedDevice(
            deviceId = "aa11bb22cc33",
            publicKey = DESKTOP_KEY,
            csk = CSK,
            displayName = "laptop",
            pairedAt = 1_700_000_000_000L,
            allowedUsers = listOf("alice"),
        )

    @Test
    fun theCskIsNotPrintedInAnyOfItsRenderedForms() {
        val rendered = device().toString()

        assertFalse(
            "the derived Arrays.toString form: $rendered",
            rendered.contains(Arrays.toString(CSK)),
        )
        assertFalse(
            "the contentToString form: $rendered",
            rendered.contains(CSK.contentToString()),
        )
        assertFalse("hex form: $rendered", rendered.contains(CSK.toHex()))
        assertFalse(
            "base64 form: $rendered",
            rendered.contains(Base64.getEncoder().encodeToString(CSK)),
        )
        assertFalse(
            "unpadded base64 form: $rendered",
            rendered.contains(Base64.getEncoder().withoutPadding().encodeToString(CSK)),
        )
    }

    @Test
    fun theDeviceIsStillIdentified() {
        val rendered = device().toString()

        assertTrue(
            "the device id identifies the record: $rendered",
            rendered.contains("aa11bb22cc33"),
        )
        assertTrue(
            "the name is what a log line is read for: $rendered",
            rendered.contains("laptop"),
        )
        assertTrue("the allowed user list is not secret: $rendered", rendered.contains("[alice]"))
        assertTrue(
            "the public key prefix identifies the device and is not secret: $rendered",
            rendered.contains("1111111111111111"),
        )
        assertTrue(
            "the rendering has to say the key was withheld, not just omit it: $rendered",
            rendered.contains("csk=<redacted>"),
        )
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { ((it.toInt() and 0xff) + 0x100).toString(16).substring(1) }
}
