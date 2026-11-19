package dev.rourunisen.tapauth.service

import java.util.Arrays
import java.util.Base64
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The temporal-identifier cache keeps one entry per paired device, and that entry holds the CSK.
 *
 * `CachedDevice` is a `data class`, so its compiler-derived `toString()` renders the key through
 * `java.util.Arrays.toString` — the same latent leak `PairedDevice` had. It is the *other* carrier
 * `assurance-strategy.md` §6's row does not name, found while fixing that one; nothing logs it
 * today, and the override is what keeps a future `Log.d(TAG, "cache: $cachedDevices")` from being
 * the leak.
 */
class CachedDeviceRedactionTest {

    private companion object {
        /** A CSK with no repeated byte, so each of its rendered forms is distinctive. */
        val CSK = ByteArray(32) { (it * 7 + 3).toByte() }
    }

    /**
     * The defect this catches: the derived `toString()` of a `data class` holding a `ByteArray`,
     * which prints the key bytes in `Arrays.toString` form — and, if someone "improves" the
     * rendering by hand, in hex or base64.
     */
    @Test
    fun theCacheEntryDoesNotPrintItsKey() {
        val rendered =
            TemporalIdCache.CachedDevice("aa11bb22cc33", CSK, hashAlgorithm = 1).toString()

        assertFalse(
            "the derived Arrays.toString form: $rendered",
            rendered.contains(Arrays.toString(CSK)),
        )
        assertFalse("hex form: $rendered", rendered.contains(CSK.toHex()))
        assertFalse(
            "base64 form: $rendered",
            rendered.contains(Base64.getEncoder().encodeToString(CSK)),
        )
        assertTrue(
            "the device id is what makes the line useful: $rendered",
            rendered.contains("aa11bb22cc33"),
        )
        assertTrue(
            "the rendering has to say the key was withheld: $rendered",
            rendered.contains("csk=<redacted>"),
        )
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { ((it.toInt() and 0xff) + 0x100).toString(16).substring(1) }
}
