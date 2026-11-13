package dev.rourunisen.tapauth.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
}
