package dev.rourunisen.tapauth.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContextSanitizerTest {

    @Test
    fun testControlCharactersRemoved() {
        assertEquals("abcd", ContextSanitizer.sanitize("a\u0000b\u001Fc\u007Fd"))
    }

    @Test
    fun testNewlineAndTabRemoved() {
        // \n and \t are in 0x00..0x1F, so they are stripped rather than kept as separators.
        assertEquals("abc", ContextSanitizer.sanitize("a\nb\tc"))
    }

    @Test
    fun testBidiControlsRemoved() {
        assertEquals(
            "abcdef",
            ContextSanitizer.sanitize("a\u202Eb\u200Fc\u2066d\u2069e\u202Cf"),
        )
    }

    @Test
    fun testWhitespaceCollapsedAndTrimmed() {
        assertEquals(
            "sudo /usr/bin/apt install",
            ContextSanitizer.sanitize("  sudo   /usr/bin/apt    install  "),
        )
    }

    @Test
    fun testNonBreakingSpaceIsWhitespace() {
        // U+00A0 is not `Char.isWhitespace`, but Rust's `char::is_whitespace` collapses it.
        assertEquals(
            "sudo apt install",
            ContextSanitizer.sanitize("sudo\u00A0apt\u00A0\u00A0install"),
        )
        assertEquals(
            "sudo apt",
            ContextSanitizer.sanitize("\u00A0sudo\u00A0apt\u00A0"),
        )
    }

    @Test
    fun testNarrowNoBreakSpaceIsWhitespace() {
        // U+202F, and the neighbouring U+2007 figure space, are space separators too.
        assertEquals(
            "systemctl restart tapauthd",
            ContextSanitizer.sanitize("systemctl\u202Frestart\u2007tapauthd"),
        )
        assertEquals("", ContextSanitizer.sanitize("\u00A0\u202F\u2007"))
    }

    @Test
    fun testShortInputUnchanged() {
        assertEquals("sudo", ContextSanitizer.sanitize("sudo"))
        assertEquals(
            "systemctl restart tapauthd",
            ContextSanitizer.sanitize("systemctl restart tapauthd"),
        )
    }

    @Test
    fun testNullAndBlankBecomeEmpty() {
        assertEquals("", ContextSanitizer.sanitize(null))
        assertEquals("", ContextSanitizer.sanitize("   \n\t "))
    }

    @Test
    fun testAsciiTruncationRespectsBudgetWithEllipsis() {
        val result = ContextSanitizer.sanitize("a".repeat(200), maxBytes = 10)

        assertEquals("aaaaaaa\u2026", result)
        assertEquals(10, result.toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun testMultiByteTruncationNeverSplitsCodePoint() {
        // Each "€" is 3 UTF-8 bytes, so a 10-byte budget fits two of them plus the 3-byte ellipsis.
        val result = ContextSanitizer.sanitize("\u20ac".repeat(100), maxBytes = 10)

        assertEquals("\u20ac\u20ac\u2026", result)
        assertEquals(9, result.toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun testFourByteCodePointNotSplit() {
        // U+1F600 is 4 UTF-8 bytes and a surrogate pair in UTF-16; maxBytes=7 leaves 4 bytes.
        val result = ContextSanitizer.sanitize("\uD83D\uDE00\uD83D\uDE00", maxBytes = 7)

        assertEquals("\uD83D\uDE00\u2026", result)
        assertEquals(7, result.toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun testEllipsisOnlyWhenNothingFits() {
        assertEquals("\u2026", ContextSanitizer.sanitize("\u20ac\u20ac", maxBytes = 3))
        assertEquals("", ContextSanitizer.sanitize("\u20ac\u20ac", maxBytes = 2))
    }

    @Test
    fun testTruncationNeverExceedsBudget() {
        val input = "\u20ac".repeat(100)

        for (maxBytes in 1..12) {
            val result = ContextSanitizer.sanitize(input, maxBytes = maxBytes)
            val size = result.toByteArray(Charsets.UTF_8).size
            assertTrue("maxBytes=$maxBytes produced $size bytes: '$result'", size <= maxBytes)
        }
    }
}
