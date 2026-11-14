package dev.rourunisen.tapauth.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.IOException
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation tests for the protocol-v2 TapAuth JNI surface.
 *
 * These are the executable proof of the Rust ↔ Kotlin JNI contract: FFI conversions, the exception
 * contract, and the properties the Rust side must guarantee (AAD binding, no algorithm downgrade,
 * verify-before-parse, a mandatory QR pin, authenticated aborts, window-based temporal
 * identifiers). The surface itself is documented on `TapAuthCrypto`; the plan is
 * `docs/design-documents/protocol-stabilization-plan.md` §2.3 / §6.1.
 *
 * ## Running These Tests
 *
 * These are **instrumentation tests** that must run on an Android device or emulator. They cannot
 * run as JVM unit tests because they load native libraries from jniLibs.
 *
 * ### Prerequisites
 * 1. Build native libraries: `./build-native.sh` (from server-android/ directory)
 * 2. Start an emulator or connect a device
 *
 * ### Run Tests
 *
 * ```bash
 * ./gradlew connectedAndroidTest
 * ```
 *
 * See server-android/TESTING.md for more details.
 */
@RunWith(AndroidJUnit4::class)
class TapAuthCryptoTest {

    // ========== Key Generation ==========

    @Test
    fun testGenerateKeypairHasExpectedSizesAndIsUnique() {
        val keypair = TapAuthCrypto.generateKeypair()
        assertEquals("Ed25519 keypair should have 2 elements", 2, keypair.size)
        assertEquals("Ed25519 private key should be 32 bytes", 32, keypair[0].size)
        assertEquals("Ed25519 public key should be 32 bytes", 32, keypair[1].size)
        assertFalse(
            "A keypair must not return the same bytes for both halves",
            keypair[0].contentEquals(keypair[1]),
        )
        assertFalse(
            "Two keypairs must not share a private key",
            TapAuthCrypto.generateKeypair()[0].contentEquals(keypair[0]),
        )
    }

    // ========== EncryptedPacket round-trip ==========

    @Test
    fun testGrantPacketRoundTripsThroughDecrypt() {
        val csk = csk()
        val server = TapAuthCrypto.generateKeypair()
        val challenge = ByteArray(32) { (it + 32).toByte() }

        val packet = createGrant(server, challenge, csk)
        val wrapper =
            TapAuthCrypto.decryptEncryptedPacket(packet, csk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)

        assertEquals(
            "The decrypted grant wrapper must still be a grant",
            "AUTH_GRANT",
            TapAuthCrypto.determineMessageType(wrapper),
        )
        // v2 signs only the WrapperMessage, so the grant carries the raw 32-byte challenge.
        assertTrue(
            "The signed grant payload must contain the raw challenge",
            indexOfSubsequence(wrapper, challenge) >= 0,
        )
    }

    @Test
    fun testDenialPacketRoundTripsThroughDecrypt() {
        val csk = csk()
        val server = TapAuthCrypto.generateKeypair()
        val challenge = ByteArray(32) { (it + 1).toByte() }

        val packet =
            TapAuthCrypto.createDenialWrapperMessage(
                challenge,
                "Denied on device",
                server[0],
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )
        val wrapper =
            TapAuthCrypto.decryptEncryptedPacket(packet, csk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)

        assertEquals(
            "The decrypted denial wrapper must still be a denial",
            "AUTH_DENIAL",
            TapAuthCrypto.determineMessageType(wrapper),
        )
        assertTrue(
            "The signed denial payload must contain the challenge it denies",
            indexOfSubsequence(wrapper, challenge) >= 0,
        )
        assertTrue(
            "The signed denial payload must contain the reason the Client forwards",
            indexOfSubsequence(wrapper, "Denied on device".toByteArray(Charsets.UTF_8)) >= 0,
        )
    }

    @Test
    fun testBuildPacketEmbedsTheWindowDerivedTemporalIdentifier() {
        val csk = csk()
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk)

        val identifier = TapAuthCrypto.extractTemporalIdentifier(packet)
        assertEquals("EncryptedPacket.temporal_identifier must be 16 bytes", 16, identifier.size)

        // The identifier is the keyed MAC of the *window* the packet was built in, so it must match
        // the negotiated hash derivation for that window rather than anything time-of-day shaped.
        val window = TapAuthCrypto.currentTimeWindow()
        val acceptable =
            listOf(window, window - 1).map {
                TapAuthCrypto.generateTemporalIdentifier(csk, it, TapAuthCrypto.HASH_SHA256)
            }
        assertTrue(
            "Packet temporal identifier must be the HMAC of the current or previous window",
            acceptable.any { it.contentEquals(identifier) },
        )
    }

    // ========== EncryptedPacket rejections ==========

    @Test
    fun testDecryptWithWrongCskIsRejected() {
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk())
        val wrongCsk = ByteArray(32) { (it + 1).toByte() }

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.decryptEncryptedPacket(
                packet,
                wrongCsk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testTamperedTemporalIdentifierIsRejectedByTheAad() {
        val csk = csk()
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk)

        val temporalId = TapAuthCrypto.extractTemporalIdentifier(packet)
        val offset = indexOfSubsequence(packet, temporalId)
        assertTrue("temporal_identifier must be embedded verbatim in the packet", offset >= 0)

        val tampered =
            packet.copyOf().also { it[offset + 1] = (it[offset + 1].toInt() xor 0x01).toByte() }
        assertFalse(
            "The tampered packet must carry a different temporal_identifier",
            temporalId.contentEquals(TapAuthCrypto.extractTemporalIdentifier(tampered)),
        )

        // temporal_identifier is bound into the AAD, so the tag must no longer verify.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.decryptEncryptedPacket(
                tampered,
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testTamperedCiphertextIsRejected() {
        val csk = csk()
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk)
        val tampered =
            packet.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.decryptEncryptedPacket(
                tampered,
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testAlgorithmRelabelIsRejected() {
        val csk = csk()
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk)

        val algorithmOffset = encryptionAlgorithmOffset(packet)
        assertEquals(
            "createGrantWrapperMessage must declare AES-256-GCM",
            TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            packet[algorithmOffset].toInt(),
        )

        // Re-label an AES-GCM packet as ChaCha20-Poly1305: dispatch, not the caller's word, must
        // decide, and the AAD binding makes the original tag invalid either way.
        val relabelled =
            packet.copyOf().also { it[algorithmOffset] = SYMMETRIC_CHACHA20_POLY1305.toByte() }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.decryptEncryptedPacket(
                relabelled,
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testUnknownAlgorithmIdsAreRejectedAsArguments() {
        val csk = csk()
        val packet = createGrant(TapAuthCrypto.generateKeypair(), ByteArray(32), csk)

        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.decryptEncryptedPacket(packet, csk, 99)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(32),
                TapAuthCrypto.generateKeypair()[0],
                csk,
                99,
                TapAuthCrypto.HASH_SHA256,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(32),
                TapAuthCrypto.generateKeypair()[0],
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                99,
            )
        }
    }

    @Test
    fun testBuildPacketRejectsShortChallengeAndCsk() {
        val server = TapAuthCrypto.generateKeypair()

        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(31),
                server[0],
                csk(),
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(32),
                server[0],
                ByteArray(16),
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )
        }
    }

    @Test
    fun testExtractTemporalIdentifierRejectsGarbage() {
        assertThrows(IOException::class.java) {
            TapAuthCrypto.extractTemporalIdentifier(ByteArray(5) { 0xFF.toByte() })
        }
    }

    // ========== Temporal identifiers ==========

    @Test
    fun testTemporalIdentifierMatchesTheHmacSha256Formula() {
        val csk = csk()
        val window = TapAuthCrypto.currentTimeWindow()

        // `HMAC-SHA256(csk, be64(window))[..16]` (cryptography-specification.md §1). Computing it
        // with the JDK proves Rust hashes the *window*, big-endian, keyed by the CSK — not a
        // timestamp, not a little-endian encoding, not an unkeyed digest.
        val expected = hmacSha256(csk, bigEndianBytes(window))

        assertArrayEquals(
            "UDP temporal identifier must be the 16-byte HMAC of the window",
            expected.copyOf(16),
            TapAuthCrypto.generateTemporalIdentifier(csk, window, TapAuthCrypto.HASH_SHA256),
        )
        assertArrayEquals(
            "BLE temporal identifier must be the 10-byte truncation of the same MAC",
            expected.copyOf(10),
            TapAuthCrypto.generateBleTemporalIdentifier(csk, window, TapAuthCrypto.HASH_SHA256),
        )
        assertFalse(
            "A different window must produce a different identifier",
            TapAuthCrypto.generateTemporalIdentifier(csk, window + 1, TapAuthCrypto.HASH_SHA256)
                .contentEquals(expected.copyOf(16)),
        )
    }

    @Test
    fun testVerifyTemporalIdentifierAcceptsCurrentAndPreviousWindowOnly() {
        val csk = csk()

        assertTrue(
            "The current window's identifier must verify",
            verifiesForWindowOffset(csk, 0),
        )
        assertTrue(
            "The previous window's identifier must verify (clock skew tolerance)",
            verifiesForWindowOffset(csk, -1),
        )
        assertFalse(
            "An identifier from two windows ago must not verify (replay window)",
            verifiesForWindowOffset(csk, -2),
        )
        assertFalse(
            "A future window's identifier must not verify",
            verifiesForWindowOffset(csk, 2),
        )

        val window = TapAuthCrypto.currentTimeWindow()
        val identifier =
            TapAuthCrypto.generateTemporalIdentifier(csk, window, TapAuthCrypto.HASH_SHA256)
        assertFalse(
            "A wrong CSK must never verify",
            TapAuthCrypto.verifyTemporalIdentifier(
                identifier,
                csk().also { it[0] = (it[0].toInt() xor 0x01).toByte() },
                TapAuthCrypto.HASH_SHA256,
            ),
        )
        // The 10-byte BLE form follows the same window.
        val bleIdentifier =
            TapAuthCrypto.generateBleTemporalIdentifier(csk, window, TapAuthCrypto.HASH_SHA256)
        assertTrue(
            "The BLE identifier must verify through the same entry point",
            TapAuthCrypto.verifyTemporalIdentifier(bleIdentifier, csk, TapAuthCrypto.HASH_SHA256),
        )
    }

    @Test
    fun testVerifyTemporalIdentifierRejectsWrongLengthAndUnknownAlgorithm() {
        val csk = csk()
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.verifyTemporalIdentifier(ByteArray(8), csk, TapAuthCrypto.HASH_SHA256)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.verifyTemporalIdentifier(ByteArray(16), csk, 99)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.generateTemporalIdentifier(csk, 41_000_000L, 99)
        }
    }

    @Test
    fun testCurrentTimeWindowIsUnixSecondsOverSixty() {
        val window = TapAuthCrypto.currentTimeWindow()
        val expected = System.currentTimeMillis() / 1000 / 60

        // Within one window: proves the value is a window count, not a timestamp (which would be
        // ~60× larger — the mistake that made every generated identifier unmatchable).
        assertTrue(
            "currentTimeWindow $window must be within one window of $expected",
            window in (expected - 1)..(expected + 1),
        )
        assertTrue("A plausible clock must be past 2020", window > 26_000_000)
    }

    // ========== BLE pairing advertisement id ==========

    @Test
    fun testDeriveBlePairingAdvIdMatchesTheSpecFormula() {
        val sessionId = ByteArray(16) { it.toByte() }
        val clientPublic = ByteArray(32) { (it * 3 + 1).toByte() }

        val advId = TapAuthCrypto.deriveBlePairingAdvId(sessionId, clientPublic)
        assertEquals("BLE pairing advertisement id must be 10 bytes", 10, advId.size)

        // `SHA-256("tapauth-ble-pair-v2" || sid || pk)[..10]`, no length prefix.
        val digest =
            java.security.MessageDigest.getInstance("SHA-256")
                .apply {
                    update("tapauth-ble-pair-v2".toByteArray(Charsets.UTF_8))
                    update(sessionId)
                    update(clientPublic)
                }
                .digest()
        assertArrayEquals(
            "The advertisement id must be the truncated context-prefixed SHA-256",
            digest.copyOf(10),
            advId,
        )
        assertArrayEquals(
            "The advertisement id must be deterministic for one QR code",
            advId,
            TapAuthCrypto.deriveBlePairingAdvId(sessionId, clientPublic),
        )
        assertFalse(
            "A different client public key must yield a different advertisement id",
            advId.contentEquals(
                TapAuthCrypto.deriveBlePairingAdvId(
                    sessionId,
                    clientPublic.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() },
                ),
            ),
        )
    }

    // ========== Authenticated wrapper parsing (rejections) ==========

    @Test
    fun testParsersRejectAGrantWrapper() {
        // No JNI entry builds an AuthenticationRequest, GrantConfirmation or AuthenticationCancel
        // wrapper (those are the Client's, and `shared/src/protocol/messages.rs` is not exported),
        // so
        // a signature-valid wrapper of another payload type is the strongest input available. The
        // payload type is bound by the signature, so the parser must refuse it as a security error.
        val csk = csk()
        val server = TapAuthCrypto.generateKeypair()
        val wrapper =
            TapAuthCrypto.decryptEncryptedPacket(
                createGrant(server, ByteArray(32), csk),
                csk,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            )

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthCancel(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
    }

    @Test
    fun testParsersRejectGarbageBytesAsIoErrors() {
        val server = TapAuthCrypto.generateKeypair()

        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(
                ByteArray(12) { 0xFF.toByte() },
                server[1],
                PROTOCOL_V2,
                ED25519,
            )
        }
        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(
                ByteArray(12) { 0xFF.toByte() },
                server[1],
                PROTOCOL_V2,
                ED25519,
            )
        }
        assertThrows(IOException::class.java) {
            TapAuthCrypto.determineMessageType(ByteArray(12) { 0xFF.toByte() })
        }
    }

    @Test
    fun testParsersRejectAnUnsupportedProtocolVersionOrAlgorithm() {
        val server = TapAuthCrypto.generateKeypair()
        val wrapper = ByteArray(12) { 0x00 }

        // Both checks run before the wrapper is even decoded, so the caller's pinned values can
        // never be talked down by a peer. Both values come from the paired Client's persisted
        // record (`PairedDevice.protocolVersion` / `.signatureAlgorithm`), so an id this build
        // cannot speak means the stored pairing is unusable: a security failure, never an
        // argument error the caller could correct.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(wrapper, server[1], 1, ED25519)
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(wrapper, server[1], PROTOCOL_V2, 99)
        }
    }

    // ========== Pairing handle ==========

    @Test
    fun testPairingSessionHandleLifecycle() {
        val sessionId = ByteArray(16) { (it * 11 + 3).toByte() }
        val identity = TapAuthCrypto.generateKeypair()

        val handle = createSession(sessionId, identity[0])
        assertTrue("A created pairing session must return a positive handle", handle > 0)

        val init = TapAuthCrypto.pairingCreateInit(handle)
        assertArrayEquals(
            "PairingInit must carry the QR session id",
            sessionId,
            TapAuthCrypto.pairingPacketSessionId(init),
        )
        // Rust caches the init: a second, different init payload would derive a second SAS because
        // the transcript hash binds the init bytes.
        assertArrayEquals(
            "PairingInit must be the same bytes on every retransmission",
            init,
            TapAuthCrypto.pairingCreateInit(handle),
        )
        assertTrue(
            "PairingInit must carry our device name",
            indexOfSubsequence(init, SERVER_DEVICE_NAME.toByteArray(Charsets.UTF_8)) >= 0,
        )

        val keepalive = TapAuthCrypto.pairingCreateKeepalive(handle)
        assertArrayEquals(
            "PairingKeepalive must carry the QR session id",
            sessionId,
            TapAuthCrypto.pairingPacketSessionId(keepalive),
        )
        assertFalse(
            "A keepalive must not be the init frame",
            keepalive.contentEquals(init),
        )

        val abort =
            TapAuthCrypto.pairingCreateAbort(handle, TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS)
        assertArrayEquals(
            "PairingAbort must carry the QR session id",
            sessionId,
            TapAuthCrypto.pairingPacketSessionId(abort),
        )
        assertFalse(
            "A tag-less abort (no key exists yet) must report unauthenticated, never success",
            TapAuthCrypto.pairingVerifyAbort(handle, abort),
        )

        // The completion proof needs the session keys, which only a verified PairingResponse
        // installs; before that it is a security failure, not a packet.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingCreateConfirmServer(handle, csk())
        }

        // A frame belonging to another session is a caller error, never attributed to this one.
        val otherHandle = createSession(ByteArray(16) { (it * 7 + 1).toByte() }, identity[0])
        val foreignInit = TapAuthCrypto.pairingCreateInit(otherHandle)
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(handle, foreignInit)
        }
        TapAuthCrypto.pairingServerSessionFree(otherHandle)

        // Freeing zeroizes the session keys and retires the handle.
        TapAuthCrypto.pairingServerSessionFree(handle)
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.pairingServerSessionFree(handle)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.pairingCreateInit(handle)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.pairingCreateKeepalive(handle)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.pairingCreateAbort(handle, TapAuthCrypto.PAIRING_ABORT_SESSION_EXPIRED)
        }
    }

    @Test
    fun testPairingSessionCreateRejectsMalformedArguments() {
        val identity = TapAuthCrypto.generateKeypair()

        assertThrows(IllegalArgumentException::class.java) {
            createSession(ByteArray(15), identity[0])
        }
        assertThrows(IllegalArgumentException::class.java) {
            createSession(ByteArray(16), ByteArray(16))
        }
    }

    @Test
    fun testPairingVerifyResponseRejectsUndecodableAndForeignPackets() {
        val sessionId = ByteArray(16) { (it * 5 + 9).toByte() }
        val identity = TapAuthCrypto.generateKeypair()
        val handle = createSession(sessionId, identity[0])
        val qrPublicKey = ByteArray(32) { (it + 2).toByte() }

        try {
            assertThrows(IllegalArgumentException::class.java) {
                TapAuthCrypto.pairingVerifyResponse(
                    handle,
                    ByteArray(64) { 0xFF.toByte() },
                    qrPublicKey,
                )
            }

            // Our own PairingInit is a well-formed PairingPacket of the wrong role and the right
            // session: accepting it as the Client's response would derive keys from the Server's
            // own ephemeral key.
            val init = TapAuthCrypto.pairingCreateInit(handle)
            assertThrows(IllegalArgumentException::class.java) {
                TapAuthCrypto.pairingVerifyResponse(handle, init, qrPublicKey)
            }

            // The QR pin cannot be skipped and its length is fixed.
            assertThrows(IllegalArgumentException::class.java) {
                TapAuthCrypto.pairingVerifyResponse(handle, init, ByteArray(16))
            }
        } finally {
            TapAuthCrypto.pairingServerSessionFree(handle)
        }
    }

    // ========== Helpers ==========

    private fun csk(): ByteArray = ByteArray(32) { it.toByte() }

    private fun createGrant(server: Array<ByteArray>, challenge: ByteArray, csk: ByteArray) =
        TapAuthCrypto.createGrantWrapperMessage(
            challenge,
            server[0],
            csk,
            TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            TapAuthCrypto.HASH_SHA256,
        )

    private fun createSession(sessionId: ByteArray, ed25519PrivateKey: ByteArray): Long =
        TapAuthCrypto.pairingServerSessionCreate(sessionId, ed25519PrivateKey, SERVER_DEVICE_NAME)

    /**
     * Whether an identifier built [offset] windows away from the current one verifies.
     *
     * The window is re-read after the check and the attempt repeated when it rolled over, so a
     * 60-second boundary landing between the two calls cannot turn a correct rejection into a
     * flake.
     */
    private fun verifiesForWindowOffset(csk: ByteArray, offset: Long): Boolean {
        val window = TapAuthCrypto.currentTimeWindow()
        val identifier =
            TapAuthCrypto.generateTemporalIdentifier(
                csk,
                window + offset,
                TapAuthCrypto.HASH_SHA256,
            )
        val verified =
            TapAuthCrypto.verifyTemporalIdentifier(identifier, csk, TapAuthCrypto.HASH_SHA256)
        if (TapAuthCrypto.currentTimeWindow() == window) return verified

        val fresh = TapAuthCrypto.currentTimeWindow()
        val freshIdentifier =
            TapAuthCrypto.generateTemporalIdentifier(csk, fresh + offset, TapAuthCrypto.HASH_SHA256)
        return TapAuthCrypto.verifyTemporalIdentifier(
            freshIdentifier,
            csk,
            TapAuthCrypto.HASH_SHA256,
        )
    }

    private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    private fun bigEndianBytes(value: Long): ByteArray =
        ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array()

    /**
     * Offset of the `EncryptedPacket.encryption_algorithm` varint payload.
     *
     * `EncryptedPacket` serialises in field order (`proto/auth_protocol.proto`): field 1 is the
     * length-delimited 16-byte `temporal_identifier` (tag `0x0A`), field 2 the
     * `encryption_algorithm` varint (tag `0x10`). Asserting both tags keeps the offset honest
     * rather than guessed.
     */
    private fun encryptionAlgorithmOffset(packet: ByteArray): Int {
        assertEquals(
            "EncryptedPacket field 1 tag (length-delimited temporal_identifier)",
            0x0A,
            packet[0].toInt(),
        )
        val offset = 2 + packet[1].toInt()
        assertEquals(
            "EncryptedPacket field 2 tag (encryption_algorithm varint)",
            0x10,
            packet[offset].toInt(),
        )
        return offset + 1
    }
}

/** `SymmetricAlgorithm.CHACHA20_POLY1305` (`proto/auth_protocol.proto`). */
private const val SYMMETRIC_CHACHA20_POLY1305 = 2

/** `SignatureAlgorithm.ED25519`, spelled once as the fourth JNI argument. */
private const val ED25519 = TapAuthCrypto.SIGNATURE_ED25519

private const val PROTOCOL_V2 = 2
private const val SERVER_DEVICE_NAME = "Pixel 9 Pro"

/** Index of [needle] inside this array, or -1. */
private fun indexOfSubsequence(haystack: ByteArray, needle: ByteArray): Int {
    if (needle.isEmpty() || needle.size > haystack.size) return -1
    outer@ for (start in 0..(haystack.size - needle.size)) {
        for (offset in needle.indices) {
            if (haystack[start + offset] != needle[offset]) continue@outer
        }
        return start
    }
    return -1
}
