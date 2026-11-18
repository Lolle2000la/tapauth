package dev.rourunisen.tapauth.data

import com.google.gson.JsonParser
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingUrlTest {

    // 32 hex chars (16 bytes) and 64 hex chars (32 bytes), as a v2 QR code carries them.
    private val sessionId = "00112233445566778899aabbccddeeff"
    private val publicKey = "ab".repeat(32)

    private val sessionIdBytes =
        byteArrayOf(
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
            0x77,
            0x88.toByte(),
            0x99.toByte(),
            0xaa.toByte(),
            0xbb.toByte(),
            0xcc.toByte(),
            0xdd.toByte(),
            0xee.toByte(),
            0xff.toByte(),
        )

    @Test
    fun testParsesAllSixFields() {
        val parsed =
            PairingUrl.parse(
                "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=36692" +
                    "&ip4=192.168.1.5&ip6=fe80::1",
            )

        assertNotNull(parsed)
        assertEquals(2, parsed!!.version)
        assertEquals(sessionId, parsed.sessionId)
        assertEquals(publicKey, parsed.publicKey)
        assertEquals(36692, parsed.port)
        assertEquals("192.168.1.5", parsed.ipv4)
        assertEquals("fe80::1", parsed.ipv6)
    }

    @Test
    fun testVersionOneRejected() {
        assertNull(
            PairingUrl.parse("tapauth://pair?v=1&sid=$sessionId&pk=$publicKey&p=36692"),
        )
    }

    @Test
    fun testMissingVersionRejected() {
        assertNull(PairingUrl.parse("tapauth://pair?sid=$sessionId&pk=$publicKey&p=36692"))
    }

    @Test
    fun testWrongSchemeRejected() {
        assertNull(PairingUrl.parse("https://pair?v=2&sid=$sessionId&pk=$publicKey&p=36692"))
        assertNull(PairingUrl.parse("tapauth://pair"))
    }

    @Test
    fun testMissingSessionIdRejected() {
        assertNull(PairingUrl.parse("tapauth://pair?v=2&pk=$publicKey&p=36692"))
    }

    @Test
    fun testMissingPublicKeyRejected() {
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&p=36692"))
    }

    @Test
    fun testMalformedSessionIdRejected() {
        val shortSid = sessionId.dropLast(2) // 30 hex chars
        val longSid = sessionId + "00" // 34 hex chars
        val nonHexSid = sessionId.dropLast(2) + "zz" // 32 chars, not hex

        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$shortSid&pk=$publicKey"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$longSid&pk=$publicKey"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$nonHexSid&pk=$publicKey"))
    }

    @Test
    fun testMalformedPublicKeyRejected() {
        val shortPk = publicKey.dropLast(2) // 62 hex chars
        val longPk = publicKey + "00" // 66 hex chars
        val nonHexPk = publicKey.dropLast(2) + "zz" // 64 chars, not hex

        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$shortPk"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$longPk"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$nonHexPk"))
    }

    @Test
    fun testAllZeroPublicKeyRejected() {
        // An all-zero `pk` is the "skip the constant-time QR comparison" sentinel that
        // `pairingVerifyResponse` understands, so a scanned QR must not be able to request it.
        val allZeroPk = "0".repeat(64)

        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$allZeroPk"))
        assertNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$allZeroPk&p=36692"),
        )

        // A single non-zero nibble is a real key again, so the rejection is exactly the sentinel.
        assertNotNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=${"0".repeat(63)}1&p=36692"),
        )
    }

    @Test
    fun testAbsentPortYieldsNullPort() {
        // BLE-only pairing: no UDP endpoint in the QR code.
        val parsed = PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey")

        assertNotNull(parsed)
        assertNull(parsed!!.port)
        assertNull(parsed.ipv4)
        assertNull(parsed.ipv6)
    }

    @Test
    fun testAbsentAddressesParse() {
        val parsed = PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=36692")

        assertNotNull(parsed)
        assertEquals(36692, parsed!!.port)
        assertNull(parsed.ipv4)
        assertNull(parsed.ipv6)
    }

    @Test
    fun testOutOfRangePortRejected() {
        // Port 0 is not a valid UDP endpoint
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=0"))
        // Port 70000 exceeds 65535
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=70000"))
        // Non-numeric port must be rejected
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=abc"))
    }

    @Test
    fun testPercentEncodedValuesDecoded() {
        val parsed =
            PairingUrl.parse(
                "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=36692&ip6=fe80%3A%3A1",
            )

        assertNotNull(parsed)
        assertEquals("fe80::1", parsed!!.ipv6)
    }

    @Test
    fun testSessionIdBytesRoundTripHex() {
        val parsed = PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey")

        assertNotNull(parsed)
        assertArrayEquals(sessionIdBytes, parsed!!.sessionIdBytes())
    }

    @Test
    fun testPublicKeyBytesRoundTripHex() {
        val parsed = PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey")

        assertNotNull(parsed)
        assertArrayEquals(ByteArray(32) { 0xab.toByte() }, parsed!!.publicKeyBytes())
    }

    /**
     * A repeated key is refused rather than resolved first-wins (the rule this parser used to have)
     * or last-wins (the rule the Rust parser had).
     *
     * The defect this catches: one sticker pinning a different `pk` or `sid` on the phone than on
     * the desktop, because each side quietly kept a different duplicate.
     */
    @Test
    fun testDuplicateKeyRejected() {
        assertNull(
            PairingUrl.parse(
                "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&pk=${"0".repeat(63)}1",
            ),
        )
        assertNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&sid=$sessionId&pk=$publicKey"),
        )
        assertNull(PairingUrl.parse("tapauth://pair?v=2&v=2&sid=$sessionId&pk=$publicKey"))
        assertNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&serial=1&serial=2"),
        )
    }

    /**
     * The 512-byte cap, measured in UTF-8 bytes exactly as `MAX_PAIRING_URL_LEN` measures it.
     *
     * The defect this catches: a cap compared against `String.length`, which is UTF-16 code units —
     * 300 two-byte characters are 429 `length` but 729 bytes, so a URL the desktop refuses would be
     * accepted here.
     */
    @Test
    fun testOverlongUrlRejected() {
        val base = "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&note="
        assertEquals(129, base.length)

        val atCap = base + "x".repeat(512 - base.length)
        assertEquals(512, atCap.toByteArray(Charsets.UTF_8).size)
        assertNotNull("a URL of exactly 512 bytes is still a pairing URL", PairingUrl.parse(atCap))

        val overCap = atCap + "y"
        assertEquals(513, overCap.toByteArray(Charsets.UTF_8).size)
        assertNull(PairingUrl.parse(overCap))

        val wide = base + "\u00e9".repeat(300)
        assertTrue(wide.length < 512)
        assertTrue(wide.toByteArray(Charsets.UTF_8).size > 512)
        assertNull(PairingUrl.parse(wide))
    }

    /**
     * A `%` that does not introduce two ASCII hex digits makes the URL invalid; it is never a
     * literal `%` and `%FF` is never decoded to `ÿ`.
     *
     * The defect this catches: passthrough of a broken escape (the old decoder appended it
     * verbatim) and Latin-1 decoding of a high escape, both of which the Rust parser refuses — so
     * the same QR was valid on one side of the wire only.
     */
    @Test
    fun testMalformedPercentEscapeRejected() {
        for (bad in listOf("%", "%2", "%zz", "%2G", "%FF", "%C3%A9")) {
            assertNull(
                "escape '$bad' must be refused",
                PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip6=fe80$bad"),
            )
        }
        // A malformed escape in a key the parser does not use is still malformed.
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&x=%zz"))
    }

    /**
     * `p` is decimal ASCII digits only, inside `1..=65535`.
     *
     * The defect this catches: `toIntOrNull` accepts a leading `+` and any Unicode digit (`٣٦٦٩٢`
     * is 36692 to it), so a port Rust refuses would be accepted here.
     */
    @Test
    fun testPortMustBeAsciiDigits() {
        for (port in listOf("+36692", "٣٦٦٩٢", "3 6692", "0x8f54")) {
            assertNull(
                "port '$port' must be refused",
                PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=$port"),
            )
        }
    }

    /**
     * A `sid`/`pk` written in Unicode digits is refused, not parsed.
     *
     * The defect this catches: `digitToIntOrNull(16)` accepts `０` as 0 while `toInt(16)` in
     * `hexToBytes` throws on it, so the old check let such a QR through `parse` and failed later,
     * inside the pairing flow instead of at the scanner.
     */
    @Test
    fun testNonAsciiHexRejected() {
        assertNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=${"０".repeat(64)}"),
        )
        assertNull(
            PairingUrl.parse("tapauth://pair?v=2&sid=${"０".repeat(32)}&pk=$publicKey"),
        )
    }

    /**
     * A present-but-empty `ip4`/`ip6` is malformed, not an absent address.
     *
     * The defect this catches: `ip4=` becoming `ipv4 = null`, which the Rust parser refuses as an
     * invalid address, so the two sides disagreed about the same URL.
     */
    @Test
    fun testEmptyAddressValuesRejected() {
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip4="))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip6="))
    }

    /**
     * `ip4`/`ip6` must be the IP literals `PairingInfo::parse` reads them as, and an accepted one
     * is kept in the canonical text Rust renders.
     *
     * The defect this catches: the phone accepting an `ip4`/`ip6` that is not an address at all — a
     * hostname, or a zone-id form — so a QR the desktop refuses becomes a pairing URL here and the
     * session opens against an endpoint the desktop never advertised. The last two assertions catch
     * the other half: keeping the verbatim text, so the fully expanded and the compressed spelling
     * of one address reach the transport as two different strings.
     */
    @Test
    fun testAddressFieldsMustBeIpLiterals() {
        for (bad in
            listOf(
                "example.com",
                "1.2.3",
                "999.1.1.1",
                "01.2.3.4",
                "1.2.3.4 ",
            )) {
            assertNull(
                "ip4 '$bad' must be refused",
                PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip4=$bad"),
            )
        }
        // `%25` is a literal `%`, so the zone id reaches the address check instead of failing the
        // percent-escape check first.
        for (bad in listOf("example.com", "fe80::1%25eth0", "[::1]", "1:2:3:4:5:6:7:8:9")) {
            assertNull(
                "ip6 '$bad' must be refused",
                PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip6=$bad"),
            )
        }

        // The accepted spellings of one address all yield the one canonical value.
        val compressed =
            PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip6=2001:db8::1")
        val expanded =
            PairingUrl.parse(
                "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey" +
                    "&ip6=2001:0db8:0000:0000:0000:0000:0000:0001",
            )
        assertEquals("2001:db8::1", compressed!!.ipv6)
        assertEquals("2001:db8::1", expanded!!.ipv6)

        val ipv4 = PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&ip4=1.2.3.4")
        assertEquals("1.2.3.4", ipv4!!.ipv4)
    }

    /** An unknown key is ignored, so a future extension stays forward-compatible. */
    @Test
    fun testUnknownQueryKeyIgnored() {
        val parsed =
            PairingUrl.parse(
                "tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=36692&serial=9f",
            )

        assertNotNull(parsed)
        assertEquals(36692, parsed!!.port)
    }

    /**
     * A query pair must be `key=value`, with no second `=` in the value.
     *
     * The defect this catches: a pair without `=` being skipped (the old `if (pair.isEmpty())
     * continue`) or a value truncated at its first `=`, both of which the Rust parser refuses.
     */
    @Test
    fun testMalformedPairRejected() {
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid$sessionId&pk=$publicKey"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&"))
        assertNull(PairingUrl.parse("tapauth://pair?v=2&sid=$sessionId&pk=$publicKey&p=36=692"))
    }

    /**
     * Every case of the file both parsers are pinned to, including the duplicate keys, the port and
     * key-length boundaries, the percent-escape failures and the length cap.
     *
     * The defect this catches: this parser drifting from `PairingInfo::parse` — the desktop
     * generates the QR the phone scans, so any disagreement is either a pairing that cannot start
     * or one where the two sides believe different values.
     *
     * The case count is asserted exactly, not as a lower bound: a bound would let the file lose
     * whole groups (every duplicate case, say) while staying green. Adding a vector means bumping
     * this number and `test_pairing_url_vectors_are_honoured`'s together.
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
            val url = case.get("url").asString
            val accept = case.get("accept").asBoolean
            val parsed = PairingUrl.parse(url)

            if (!accept) {
                assertNull("vector '$name' must be refused: $url", parsed)
                continue
            }

            assertNotNull("vector '$name' must parse: $url", parsed)
            assertEquals("vector '$name' sid", case.get("sid").asString, parsed!!.sessionId)
            assertEquals("vector '$name' pk", case.get("pk").asString, parsed.publicKey)
            val port = case.get("port")
            if (port.isJsonNull) {
                assertNull("vector '$name' port", parsed.port)
            } else {
                assertEquals("vector '$name' port", port.asInt, parsed.port)
            }
            val ip4 = case.get("ip4")
            assertEquals(
                "vector '$name' ip4",
                if (ip4.isJsonNull) null else ip4.asString,
                parsed.ipv4,
            )
            val ip6 = case.get("ip6")
            assertEquals(
                "vector '$name' ip6",
                if (ip6.isJsonNull) null else ip6.asString,
                parsed.ipv6,
            )
        }
    }

    private companion object {
        /**
         * The shared vector file, named relative to this module's Gradle test working directory
         * (`server-android/app`, the default for a `Test` task, so `../../` is the repository
         * root). Deliberately not wired through a Gradle `sourceSets` entry: the file belongs to
         * `shared/`, and the Rust test reads the very same file with `include_str!`. Nothing
         * declares that working directory, so the path resolves only because of it.
         */
        val VECTORS_FILE = File("../../shared/testdata/pairing_url_vectors.json")

        /** Must equal `EXPECTED_CASES` in `models.rs`; see [testSharedVectorsAreHonoured]. */
        const val EXPECTED_VECTOR_CASES = 49
    }
}
