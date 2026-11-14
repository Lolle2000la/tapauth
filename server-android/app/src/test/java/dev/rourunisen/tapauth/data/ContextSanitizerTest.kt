package dev.rourunisen.tapauth.data

import com.google.gson.JsonParser
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContextSanitizerTest {

    @Test
    fun testControlCharactersRemoved() {
        assertEquals("abcd", ContextSanitizer.sanitize("a\u0000b\u001Fc\u007Fd"))
    }

    @Test
    fun testNewlineAndTabSeparateWords() {
        // \t and \n are whitespace as well as C0 controls: the whitespace rule wins, so they
        // collapse to one space instead of being deleted.
        assertEquals("a b c", ContextSanitizer.sanitize("a\nb\tc"))
        assertEquals("sudo apt update", ContextSanitizer.sanitize("sudo\tapt\nupdate"))
        assertEquals(
            "U+0085 is C1 but collapses like every other whitespace code point",
            "a b",
            ContextSanitizer.sanitize("a\u0085b"),
        )
    }

    @Test
    fun testAnsiEscapeSequencesRemovedAsAUnit() {
        // Stripping only the ESC would leave "[31m" in the prompt.
        assertEquals("root", ContextSanitizer.sanitize("\u001B[31mroot\u001B[0m"))
        assertEquals("ab", ContextSanitizer.sanitize("a\u001B[1;31mb"))
        assertEquals("unterminated CSI", "x", ContextSanitizer.sanitize("x\u001B[31"))
        assertEquals("OSC + BEL", "ab", ContextSanitizer.sanitize("a\u001B]0;evil\u0007b"))
        assertEquals("OSC + ST", "ab", ContextSanitizer.sanitize("a\u001B]8;;http://e\u001B\\b"))
        assertEquals("lone ESC", "ab", ContextSanitizer.sanitize("a\u001Bb"))
    }

    @Test
    fun testBidiControlsRemoved() {
        assertEquals(
            "abcdef",
            ContextSanitizer.sanitize("a\u202Eb\u200Fc\u2066d\u2069e\u202Cf"),
        )
        // A right-to-left override must not reorder the rendered line.
        assertEquals("safeexe.txt", ContextSanitizer.sanitize("safe\u202Eexe.txt"))
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
        // U+00A0 is not `Char.isWhitespace`, but it is one of the contract's whitespace code
        // points, so it collapses instead of welding the words together.
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

    /**
     * A budget of exactly [ELLIPSIS]'s width cuts without an ellipsis, as Rust does.
     *
     * The defect this catches: the previous `if (maxBytes < ELLIPSIS_UTF8_BYTES) return ""` left
     * `maxBytes == 3` returning "…" where Rust returns the first 3-byte character, so the phone
     * rendered a different string (an ellipsis) than the Client had sanitized-and-truncated.
     */
    @Test
    fun testEllipsisOnlyAboveItsOwnWidth() {
        assertEquals("\u2026", ContextSanitizer.sanitize("\u20ac\u20ac", maxBytes = 4))
        assertEquals("\u20ac", ContextSanitizer.sanitize("\u20ac\u20ac", maxBytes = 3))
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

    /**
     * Every case of the file the Rust sanitizer is pinned to, including one case per code point of
     * the whitespace and forbidden sets and the truncation boundaries.
     *
     * The defect this catches: this mirror drifting from `sanitize_context_string` — the vector a
     * Client actually sends is sanitized twice (once in Rust before signing, once here before
     * rendering), so any disagreement renders text the Client never produced.
     *
     * The case count is asserted exactly, not as a lower bound: a bound would let the file lose
     * whole groups (every truncation boundary, say) while staying green. Adding a vector means
     * bumping this number and `test_context_sanitizer_vectors_are_honoured`'s together.
     */
    @Test
    fun testSharedVectorsAreHonoured() {
        assertTrue(
            "vector file ${VECTORS_FILE.absolutePath} not found (test working directory " +
                "${File(".").absolutePath})",
            VECTORS_FILE.isFile,
        )
        val vectors =
            JsonParser.parseString(VECTORS_FILE.readText()).asJsonObject.getAsJsonArray("cases")

        assertEquals(
            "the shared vector file must hold exactly $EXPECTED_VECTOR_CASES cases",
            EXPECTED_VECTOR_CASES,
            vectors.size(),
        )
        for (element in vectors) {
            val case = element.asJsonObject
            val name = case.get("name").asString
            val input = case.get("input").asString
            val maxBytes = case.get("max_bytes").asInt
            val expected = case.get("expected").asString

            assertEquals(
                "vector '$name' (maxBytes=$maxBytes)",
                expected,
                ContextSanitizer.sanitize(input, maxBytes),
            )
        }
    }

    private companion object {
        /**
         * The shared vector file, named relative to this module's Gradle test working directory
         * (`server-android/app`, the default for a `Test` task, so `../../` is the repository
         * root). Deliberately not wired through a Gradle `sourceSets` entry: the file belongs to
         * `shared/`, and the Rust test reads the very same path with `include_str!`.
         */
        val VECTORS_FILE = File("../../shared/testdata/context_sanitizer_vectors.json")

        /** Must equal `EXPECTED_CASES` in `messages.rs`; see [testSharedVectorsAreHonoured]. */
        const val EXPECTED_VECTOR_CASES = 130
    }
}
