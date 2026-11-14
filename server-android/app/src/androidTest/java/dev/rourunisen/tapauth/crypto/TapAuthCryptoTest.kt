package dev.rourunisen.tapauth.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.nio.ByteBuffer
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
 * Instrumentation tests for the protocol-v2 TapAuth UniFFI surface.
 *
 * These are the executable proof of the Rust ↔ Kotlin FFI contract: the generated bindings, the
 * single `TapauthException` hierarchy and the properties the Rust side must guarantee (AAD binding,
 * no algorithm downgrade, verify-before-parse, a mandatory QR pin, authenticated aborts,
 * window-based temporal identifiers). The surface is the generated `shared.kt` in this package,
 * produced by UniFFI from `shared`'s `#[uniffi::export]` declarations; the plan is
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
        val keypair = generateKeypair()
        assertEquals("Ed25519 keypair should have 2 elements", 2, keypair.size)
        assertEquals("Ed25519 private key should be 32 bytes", 32, keypair[0].size)
        assertEquals("Ed25519 public key should be 32 bytes", 32, keypair[1].size)
        assertFalse(
            "A keypair must not return the same bytes for both halves",
            keypair[0].contentEquals(keypair[1]),
        )
        assertFalse(
            "Two keypairs must not share a private key",
            generateKeypair()[0].contentEquals(keypair[0]),
        )
    }

    // ========== EncryptedPacket round-trip ==========

    @Test
    fun testGrantPacketRoundTripsThroughDecrypt() {
        val csk = csk()
        val server = generateKeypair()
        val challenge = ByteArray(32) { (it + 32).toByte() }

        val packet = createGrant(server, challenge, csk)
        val wrapper = decryptEncryptedPacket(packet, csk, SYMMETRIC_AES_256_GCM)

        assertEquals(
            "The decrypted grant wrapper must still be a grant",
            "AUTH_GRANT",
            determineMessageType(wrapper),
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
        val server = generateKeypair()
        val challenge = ByteArray(32) { (it + 1).toByte() }

        val packet =
            createDenialWrapperMessage(
                challenge,
                "Denied on device",
                server[0],
                csk,
                SYMMETRIC_AES_256_GCM,
                HASH_SHA256,
            )
        val wrapper = decryptEncryptedPacket(packet, csk, SYMMETRIC_AES_256_GCM)

        assertEquals(
            "The decrypted denial wrapper must still be a denial",
            "AUTH_DENIAL",
            determineMessageType(wrapper),
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
        val packet = createGrant(generateKeypair(), ByteArray(32), csk)

        val identifier = extractTemporalIdentifier(packet)
        assertEquals("EncryptedPacket.temporal_identifier must be 16 bytes", 16, identifier.size)

        // The identifier is the keyed MAC of the *window* the packet was built in, so it must match
        // the negotiated hash derivation for that window rather than anything time-of-day shaped.
        val window = currentTimeWindow()
        val acceptable =
            listOf(window, window - 1).map {
                generateTemporalIdentifier(csk, it, HASH_SHA256)
            }
        assertTrue(
            "Packet temporal identifier must be the HMAC of the current or previous window",
            acceptable.any { it.contentEquals(identifier) },
        )
    }

    // ========== EncryptedPacket rejections ==========

    @Test
    fun testDecryptWithWrongCskIsRejected() {
        val packet = createGrant(generateKeypair(), ByteArray(32), csk())
        val wrongCsk = ByteArray(32) { (it + 1).toByte() }

        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(
                packet,
                wrongCsk,
                SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testTamperedTemporalIdentifierIsRejectedByTheAad() {
        val csk = csk()
        val packet = createGrant(generateKeypair(), ByteArray(32), csk)

        val temporalId = extractTemporalIdentifier(packet)
        val offset = indexOfSubsequence(packet, temporalId)
        assertTrue("temporal_identifier must be embedded verbatim in the packet", offset >= 0)

        val tampered =
            packet.copyOf().also { it[offset + 1] = (it[offset + 1].toInt() xor 0x01).toByte() }
        assertFalse(
            "The tampered packet must carry a different temporal_identifier",
            temporalId.contentEquals(extractTemporalIdentifier(tampered)),
        )

        // temporal_identifier is bound into the AAD, so the tag must no longer verify.
        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(
                tampered,
                csk,
                SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testTamperedCiphertextIsRejected() {
        val csk = csk()
        val packet = createGrant(generateKeypair(), ByteArray(32), csk)
        val tampered =
            packet.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }

        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(
                tampered,
                csk,
                SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testAlgorithmRelabelIsRejected() {
        val csk = csk()
        val packet = createGrant(generateKeypair(), ByteArray(32), csk)

        val algorithmOffset = encryptionAlgorithmOffset(packet)
        assertEquals(
            "createGrantWrapperMessage must declare AES-256-GCM",
            SYMMETRIC_AES_256_GCM,
            packet[algorithmOffset].toInt(),
        )

        // Re-label an AES-GCM packet as ChaCha20-Poly1305: dispatch, not the caller's word, must
        // decide, and the AAD binding makes the original tag invalid either way.
        val relabelled =
            packet.copyOf().also { it[algorithmOffset] = SYMMETRIC_CHACHA20_POLY1305.toByte() }
        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(
                relabelled,
                csk,
                SYMMETRIC_AES_256_GCM,
            )
        }
    }

    @Test
    fun testUnknownAlgorithmIdsAreRejectedAsArguments() {
        val csk = csk()
        val packet = createGrant(generateKeypair(), ByteArray(32), csk)

        assertThrows(TapauthException.Argument::class.java) {
            decryptEncryptedPacket(packet, csk, 99)
        }
        assertThrows(TapauthException.Argument::class.java) {
            createGrantWrapperMessage(
                ByteArray(32),
                generateKeypair()[0],
                csk,
                99,
                HASH_SHA256,
            )
        }
        assertThrows(TapauthException.Argument::class.java) {
            createGrantWrapperMessage(
                ByteArray(32),
                generateKeypair()[0],
                csk,
                SYMMETRIC_AES_256_GCM,
                99,
            )
        }
    }

    @Test
    fun testBuildPacketRejectsShortChallengeAndCsk() {
        val server = generateKeypair()

        assertThrows(TapauthException.Argument::class.java) {
            createGrantWrapperMessage(
                ByteArray(31),
                server[0],
                csk(),
                SYMMETRIC_AES_256_GCM,
                HASH_SHA256,
            )
        }
        assertThrows(TapauthException.Argument::class.java) {
            createGrantWrapperMessage(
                ByteArray(32),
                server[0],
                ByteArray(16),
                SYMMETRIC_AES_256_GCM,
                HASH_SHA256,
            )
        }
    }

    @Test
    fun testExtractTemporalIdentifierRejectsGarbage() {
        assertThrows(TapauthException.Io::class.java) {
            extractTemporalIdentifier(ByteArray(5) { 0xFF.toByte() })
        }
    }

    // ========== Algorithm suite 2: ChaCha20-Poly1305 + BLAKE3 ==========
    //
    // Suite 1 (AES-256-GCM + SHA-256) is what every test above exercises. The Rust layer
    // implements both (`shared/src/crypto/encryption.rs:95` dispatches on the negotiated
    // algorithm, `shared/src/crypto/temporal.rs:43` on the negotiated hash), so suite 2 is
    // reachable through this surface and has to work through it too.

    @Test
    fun testChaCha20GrantRoundTripsAndDeclaresSuite2OnTheWire() {
        val csk = csk()
        val challenge = ByteArray(32) { (it + 64).toByte() }

        val packet = createSuite2Grant(generateKeypair(), challenge, csk)

        // The header is what a peer dispatches on. An AEAD that encrypts with
        // ChaCha20-Poly1305 but writes AES-256-GCM into field 2 would still round-trip
        // locally and then fail against every Client that trusts the header.
        assertEquals(
            "A suite-2 grant must declare CHACHA20_POLY1305 in EncryptedPacket field 2",
            SYMMETRIC_CHACHA20_POLY1305,
            packet[encryptionAlgorithmOffset(packet)].toInt(),
        )

        // The identifier is derived with the *negotiated* hash, so a suite-2 packet carries
        // keyed BLAKE3. A BLAKE3 Client whose identifier came back as the HMAC-SHA256 value
        // would never match its own pre-computed identifiers.
        val window = currentTimeWindow()
        val identifier = extractTemporalIdentifier(packet)
        val candidates = listOf(window, window - 1)
        assertTrue(
            "A suite-2 packet's temporal identifier must be the keyed BLAKE3 of the current or previous window",
            candidates.any {
                generateTemporalIdentifier(csk, it, HASH_BLAKE3).contentEquals(identifier)
            },
        )
        assertTrue(
            "The BLAKE3 identifier must not be the HMAC-SHA256 one for either candidate window",
            candidates.none {
                generateTemporalIdentifier(csk, it, HASH_SHA256).contentEquals(identifier)
            },
        )

        val wrapper = decryptEncryptedPacket(packet, csk, SYMMETRIC_CHACHA20_POLY1305)
        assertEquals(
            "The decrypted suite-2 grant must still be a grant",
            "AUTH_GRANT",
            determineMessageType(wrapper),
        )
        assertTrue(
            "The signed suite-2 grant payload must contain the raw challenge",
            indexOfSubsequence(wrapper, challenge) >= 0,
        )
    }

    @Test
    fun testChaCha20DenialRoundTripsUnderSuite2() {
        val csk = csk()
        val server = generateKeypair()
        val challenge = ByteArray(32) { (it + 3).toByte() }

        // The denial builder is a separate exported entry point, so it can hard-code suite 1
        // while the grant builder honours the negotiated one.
        val packet =
            createDenialWrapperMessage(
                challenge,
                "Denied on device",
                server[0],
                csk,
                SYMMETRIC_CHACHA20_POLY1305,
                HASH_BLAKE3,
            )
        assertEquals(
            "A suite-2 denial must declare CHACHA20_POLY1305 in EncryptedPacket field 2",
            SYMMETRIC_CHACHA20_POLY1305,
            packet[encryptionAlgorithmOffset(packet)].toInt(),
        )

        val wrapper = decryptEncryptedPacket(packet, csk, SYMMETRIC_CHACHA20_POLY1305)
        assertEquals(
            "The decrypted suite-2 denial must still be a denial",
            "AUTH_DENIAL",
            determineMessageType(wrapper),
        )
        assertTrue(
            "The suite-2 denial must carry the challenge it denies",
            indexOfSubsequence(wrapper, challenge) >= 0,
        )
        assertTrue(
            "The suite-2 denial must carry the reason the Client forwards",
            indexOfSubsequence(wrapper, "Denied on device".toByteArray(Charsets.UTF_8)) >= 0,
        )
    }

    @Test
    fun testSuite1CiphertextIsRejectedAsSuite2AndViceVersa() {
        val csk = csk()
        val server = generateKeypair()
        val challenge = ByteArray(32) { (it + 96).toByte() }

        val suite1 = createGrant(server, challenge, csk)
        val suite2 = createSuite2Grant(server, challenge, csk)

        // The header-vs-pinned comparison runs before any AEAD work
        // (`shared/src/ffi/ops.rs:297`), so a peer cannot talk the phone down to the
        // algorithm it prefers. The detail is pinned because a *tag* failure would also be a
        // `Security` error: only the message distinguishes the downgrade check from it.
        val downgrade =
            assertThrows(TapauthException.Security::class.java) {
                decryptEncryptedPacket(suite1, csk, SYMMETRIC_CHACHA20_POLY1305)
            }
        assertTrue(
            "An AES-256-GCM packet presented as suite 2 must fail the pinned-algorithm check, got: ${downgrade.detail}",
            downgrade.detail.contains("does not match the negotiated algorithm"),
        )
        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(suite2, csk, SYMMETRIC_AES_256_GCM)
        }

        // UNSPECIFIED is not a wildcard: asking for it must not fall back to a default
        // algorithm, which would turn a malformed persisted record into an accepted packet.
        assertThrows(TapauthException.Argument::class.java) {
            decryptEncryptedPacket(suite2, csk, 0)
        }
    }

    @Test
    fun testChaCha20TamperedCiphertextIsRejected() {
        val csk = csk()
        val packet = createSuite2Grant(generateKeypair(), ByteArray(32), csk)
        val body = ciphertextRange(packet)

        // The body is `nonce(12) || ciphertext || tag(16)`, so its midpoint is real
        // ciphertext. Flipping a *header* byte instead would only prove the AAD is bound.
        val middle = body.first + body.count() / 2
        val tampered = packet.copyOf().also { it[middle] = (it[middle].toInt() xor 0x01).toByte() }
        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(tampered, csk, SYMMETRIC_CHACHA20_POLY1305)
        }
    }

    @Test
    fun testChaCha20TamperedTemporalIdentifierIsRejectedByTheAad() {
        val csk = csk()
        val packet = createSuite2Grant(generateKeypair(), ByteArray(32), csk)

        val temporalId = extractTemporalIdentifier(packet)
        val offset = indexOfSubsequence(packet, temporalId)
        assertTrue("temporal_identifier must be embedded verbatim in the packet", offset >= 0)

        // The suite-2 AAD is `"tapauth-pkt-v2" || be32(2) || be16(16) || temporal_identifier`
        // (`shared/src/crypto/encryption.rs:137`), so a tampered identifier must fail the
        // Poly1305 tag even though the algorithm header still matches what the caller pinned.
        val tampered =
            packet.copyOf().also { it[offset + 2] = (it[offset + 2].toInt() xor 0x01).toByte() }
        assertFalse(
            "The tampered packet must carry a different temporal_identifier",
            temporalId.contentEquals(extractTemporalIdentifier(tampered)),
        )
        assertThrows(TapauthException.Security::class.java) {
            decryptEncryptedPacket(tampered, csk, SYMMETRIC_CHACHA20_POLY1305)
        }
    }

    @Test
    fun testChaCha20PacketsForTheSameInputsUseFreshNonces() {
        val csk = csk()
        val server = generateKeypair()
        val challenge = ByteArray(32) { (it + 17).toByte() }

        // Both packets must be built inside one window, otherwise the differing temporal
        // identifiers would make the packets differ for the wrong reason.
        val (first, second) = twoSuite2GrantsInOneWindow(csk, server, challenge)

        val firstBody = ciphertextRange(first)
        val secondBody = ciphertextRange(second)
        assertEquals(
            "Two packets for the same plaintext must be the same size",
            firstBody.count(),
            secondBody.count(),
        )
        // Both packets must carry the identical plaintext, otherwise differing ciphertext
        // bodies would prove nothing about the nonce.
        assertArrayEquals(
            "The two packets must encrypt the same plaintext",
            decryptEncryptedPacket(first, csk, SYMMETRIC_CHACHA20_POLY1305),
            decryptEncryptedPacket(second, csk, SYMMETRIC_CHACHA20_POLY1305),
        )
        // A reused nonce under the same key is the ChaCha20-Poly1305 catastrophic failure:
        // the two ciphertext bodies (nonce || ciphertext || tag) would be byte-identical.
        assertFalse(
            "Two suite-2 packets for the same plaintext must use fresh nonces",
            first
                .copyOfRange(firstBody.first, firstBody.last + 1)
                .contentEquals(second.copyOfRange(secondBody.first, secondBody.last + 1)),
        )
    }

    // ========== Temporal identifiers ==========

    @Test
    fun testTemporalIdentifierMatchesTheHmacSha256Formula() {
        val csk = csk()
        val window = currentTimeWindow()

        // `HMAC-SHA256(csk, be64(window))[..16]` (cryptography-specification.md §1). Computing it
        // with the JDK proves Rust hashes the *window*, big-endian, keyed by the CSK — not a
        // timestamp, not a little-endian encoding, not an unkeyed digest.
        val expected = hmacSha256(csk, bigEndianBytes(window))

        assertArrayEquals(
            "UDP temporal identifier must be the 16-byte HMAC of the window",
            expected.copyOf(16),
            generateTemporalIdentifier(csk, window, HASH_SHA256),
        )
        assertArrayEquals(
            "BLE temporal identifier must be the 10-byte truncation of the same MAC",
            expected.copyOf(10),
            generateBleTemporalIdentifier(csk, window, HASH_SHA256),
        )
        assertFalse(
            "A different window must produce a different identifier",
            generateTemporalIdentifier(csk, window + 1, HASH_SHA256)
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

        val window = currentTimeWindow()
        val identifier = generateTemporalIdentifier(csk, window, HASH_SHA256)
        assertFalse(
            "A wrong CSK must never verify",
            verifyTemporalIdentifier(
                identifier,
                csk().also { it[0] = (it[0].toInt() xor 0x01).toByte() },
                HASH_SHA256,
            ),
        )
        // The 10-byte BLE form follows the same window.
        val bleIdentifier = generateBleTemporalIdentifier(csk, window, HASH_SHA256)
        assertTrue(
            "The BLE identifier must verify through the same entry point",
            verifyTemporalIdentifier(bleIdentifier, csk, HASH_SHA256),
        )
    }

    @Test
    fun testVerifyTemporalIdentifierRejectsWrongLengthAndUnknownAlgorithm() {
        val csk = csk()
        assertThrows(TapauthException.Argument::class.java) {
            verifyTemporalIdentifier(ByteArray(8), csk, HASH_SHA256)
        }
        assertThrows(TapauthException.Argument::class.java) {
            verifyTemporalIdentifier(ByteArray(16), csk, 99)
        }
        assertThrows(TapauthException.Argument::class.java) {
            generateTemporalIdentifier(csk, 41_000_000L, 99)
        }
    }

    @Test
    fun testCurrentTimeWindowIsUnixSecondsOverSixty() {
        val window = currentTimeWindow()
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

        val advId = deriveBlePairingAdvId(sessionId, clientPublic)
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
            deriveBlePairingAdvId(sessionId, clientPublic),
        )
        assertFalse(
            "A different client public key must yield a different advertisement id",
            advId.contentEquals(
                deriveBlePairingAdvId(
                    sessionId,
                    clientPublic.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() },
                ),
            ),
        )
    }

    // ========== Authenticated wrapper parsing (rejections) ==========

    @Test
    fun testParsersRejectAGrantWrapper() {
        // No exported function builds an AuthenticationRequest, GrantConfirmation or
        // AuthenticationCancel wrapper (those are the Client's, and
        // `shared/src/protocol/messages.rs` is not exported), so a signature-valid wrapper of
        // another payload type is the strongest input available. The payload type is bound by the
        // signature, so the parser must refuse it as a security error.
        val csk = csk()
        val server = generateKeypair()
        val wrapper =
            decryptEncryptedPacket(
                createGrant(server, ByteArray(32), csk),
                csk,
                SYMMETRIC_AES_256_GCM,
            )

        assertThrows(TapauthException.Security::class.java) {
            parseAndVerifyGrantConfirmation(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
        assertThrows(TapauthException.Security::class.java) {
            parseAndVerifyAuthCancel(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
        assertThrows(TapauthException.Security::class.java) {
            parseAndVerifyAuthRequest(wrapper, server[1], PROTOCOL_V2, ED25519)
        }
    }

    @Test
    fun testParsersRejectGarbageBytesAsIoErrors() {
        val server = generateKeypair()

        assertThrows(TapauthException.Io::class.java) {
            parseAndVerifyAuthRequest(
                ByteArray(12) { 0xFF.toByte() },
                server[1],
                PROTOCOL_V2,
                ED25519,
            )
        }
        assertThrows(TapauthException.Io::class.java) {
            parseAndVerifyGrantConfirmation(
                ByteArray(12) { 0xFF.toByte() },
                server[1],
                PROTOCOL_V2,
                ED25519,
            )
        }
        assertThrows(TapauthException.Io::class.java) {
            determineMessageType(ByteArray(12) { 0xFF.toByte() })
        }
    }

    @Test
    fun testParsersRejectAnUnsupportedProtocolVersionOrAlgorithm() {
        val server = generateKeypair()
        val wrapper = ByteArray(12) { 0x00 }

        // Both checks run before the wrapper is even decoded, so the caller's pinned values can
        // never be talked down by a peer. Both values come from the paired Client's persisted
        // record (`PairedDevice.protocolVersion` / `.signatureAlgorithm`), so an id this build
        // cannot speak means the stored pairing is unusable: a security failure, never an
        // argument error the caller could correct.
        assertThrows(TapauthException.Security::class.java) {
            parseAndVerifyAuthRequest(wrapper, server[1], 1, ED25519)
        }
        assertThrows(TapauthException.Security::class.java) {
            parseAndVerifyAuthRequest(wrapper, server[1], PROTOCOL_V2, 99)
        }
    }

    // ========== Pairing session ==========

    @Test
    fun testPairingSessionHandleLifecycle() {
        val sessionId = ByteArray(16) { (it * 11 + 3).toByte() }
        val otherSessionId = ByteArray(16) { (it * 7 + 1).toByte() }
        val identity = generateKeypair()

        val session = createSession(sessionId, identity[0])
        val other = createSession(otherSessionId, identity[0])
        // A frame belonging to another session. The two sessions are independent objects rather
        // than entries in a shared handle table, so this frame can never be attributed to
        // `session` — the property the old foreign-handle assertion protected.
        val foreignInit = other.createInit()
        try {
            assertFalse("A created pairing session must be live", session.uniffiIsDestroyed)

            val init = session.createInit()
            assertArrayEquals(
                "PairingInit must carry the QR session id",
                sessionId,
                pairingPacketSessionId(init),
            )
            // Rust caches the init: a second, different init payload would derive a second SAS
            // because the transcript hash binds the init bytes.
            assertArrayEquals(
                "PairingInit must be the same bytes on every retransmission",
                init,
                session.createInit(),
            )
            assertTrue(
                "PairingInit must carry our device name",
                indexOfSubsequence(init, SERVER_DEVICE_NAME.toByteArray(Charsets.UTF_8)) >= 0,
            )

            val keepalive = session.createKeepalive()
            assertArrayEquals(
                "PairingKeepalive must carry the QR session id",
                sessionId,
                pairingPacketSessionId(keepalive),
            )
            assertFalse(
                "A keepalive must not be the init frame",
                keepalive.contentEquals(init),
            )

            // A peer's tag-less abort (no key exists yet) must report unauthenticated, never
            // success. The frame has to be built by another session: `createAbort` concludes the
            // session that builds it (`testCreatingAnAbortConcludesTheSession`), so no session can
            // both produce an abort and still be in a state to verify one.
            assertFalse(
                "A tag-less abort (no key exists yet) must report unauthenticated, never success",
                session.verifyAbort(taglessAbortFor(sessionId, identity[0])),
            )

            // The completion proof needs the session keys, which only a verified PairingResponse
            // installs; before that it is a security failure, not a packet.
            assertThrows(TapauthException.Security::class.java) {
                session.createConfirmServer(csk())
            }

            // The other session keeps its own identity and its own transcript.
            assertArrayEquals(
                "The other session must carry its own session id",
                otherSessionId,
                pairingPacketSessionId(foreignInit),
            )
            assertFalse(
                "Two sessions must not hand out the same init frame",
                foreignInit.contentEquals(init),
            )
            // A frame of the wrong session is a caller error, never a packet of this one.
            assertThrows(TapauthException.Argument::class.java) {
                session.verifyAbort(foreignInit)
            }
        } finally {
            session.close()
        }

        // There is no handle to free: a session is released by dropping the reference. The second
        // release is therefore a no-op instead of the old double-free error, and no integer can
        // outlive its session to be looked up again.
        session.close()
        assertTrue("A released session must report itself destroyed", session.uniffiIsDestroyed)

        // Releasing one session must not disturb another: the reference counts are per object.
        try {
            assertArrayEquals(
                "A live session must keep its transcript after another is released",
                foreignInit,
                other.createInit(),
            )
            assertArrayEquals(
                "A live session must keep building frames after another is released",
                otherSessionId,
                pairingPacketSessionId(other.createKeepalive()),
            )
            assertFalse(
                "A live session must keep its pre-key abort semantics after another is released",
                other.verifyAbort(taglessAbortFor(otherSessionId, identity[0])),
            )
        } finally {
            other.close()
        }

        // The generated wrapper refuses to call into a released object (its call counter is zero),
        // which is the only "stale" case left to represent.
        assertThrows(IllegalStateException::class.java) {
            session.createInit()
        }
        assertThrows(IllegalStateException::class.java) {
            session.createKeepalive()
        }
        assertThrows(IllegalStateException::class.java) {
            session.createAbort(PAIRING_ABORT_SESSION_EXPIRED)
        }
    }

    @Test
    fun testCreatingAnAbortConcludesTheSession() {
        val sessionId = ByteArray(16) { (it * 9 + 4).toByte() }
        val identity = generateKeypair()
        val session = createSession(sessionId, identity[0])

        try {
            // A cancellation is the last message of the handshake: creating the abort drops the
            // session keys and the ephemeral secret, so a second abort — or any other call, an
            // incoming abort included — is refused instead of reviving a session whose key material
            // is gone. The defect this catches: createAbort leaving the session live, which would
            // let a cancelled handshake keep answering.
            session.createAbort(PAIRING_ABORT_USER_REJECTED_SAS)
            assertThrows(TapauthException.State::class.java) {
                session.createAbort(PAIRING_ABORT_SESSION_EXPIRED)
            }
            assertThrows(TapauthException.State::class.java) {
                session.createInit()
            }
            assertThrows(TapauthException.State::class.java) {
                session.verifyAbort(taglessAbortFor(sessionId, identity[0]))
            }
        } finally {
            session.close()
        }
    }

    @Test
    fun testPairingSessionCreateRejectsMalformedArguments() {
        val identity = generateKeypair()

        assertThrows(TapauthException.Argument::class.java) {
            createSession(ByteArray(15), identity[0])
        }
        assertThrows(TapauthException.Argument::class.java) {
            createSession(ByteArray(16), ByteArray(16))
        }
    }

    @Test
    fun testPairingVerifyResponseRejectsUndecodableAndForeignPackets() {
        val sessionId = ByteArray(16) { (it * 5 + 9).toByte() }
        val identity = generateKeypair()
        val session = createSession(sessionId, identity[0])
        val qrPublicKey = ByteArray(32) { (it + 2).toByte() }

        try {
            assertThrows(TapauthException.Argument::class.java) {
                session.verifyResponse(
                    ByteArray(64) { 0xFF.toByte() },
                    qrPublicKey,
                )
            }

            // Our own PairingInit is a well-formed PairingPacket of the wrong role and the right
            // session: accepting it as the Client's response would derive keys from the Server's
            // own ephemeral key.
            val init = session.createInit()
            assertThrows(TapauthException.Argument::class.java) {
                session.verifyResponse(init, qrPublicKey)
            }

            // The QR pin cannot be skipped and its length is fixed.
            assertThrows(TapauthException.Argument::class.java) {
                session.verifyResponse(init, ByteArray(16))
            }
        } finally {
            session.close()
        }
    }

    // ========== Helpers ==========

    private fun csk(): ByteArray = ByteArray(32) { it.toByte() }

    private fun createGrant(server: List<ByteArray>, challenge: ByteArray, csk: ByteArray) =
        createGrantWrapperMessage(
            challenge,
            server[0],
            csk,
            SYMMETRIC_AES_256_GCM,
            HASH_SHA256,
        )

    /** A grant under algorithm suite 2: ChaCha20-Poly1305 + keyed BLAKE3. */
    private fun createSuite2Grant(server: List<ByteArray>, challenge: ByteArray, csk: ByteArray) =
        createGrantWrapperMessage(
            challenge,
            server[0],
            csk,
            SYMMETRIC_CHACHA20_POLY1305,
            HASH_BLAKE3,
        )

    /**
     * Two suite-2 grants built from identical inputs inside one 60-second window.
     *
     * The window is re-read after both builds and the pair rebuilt when it rolled over, so a caller
     * comparing the two packets is never comparing different windows by accident.
     */
    private fun twoSuite2GrantsInOneWindow(
        csk: ByteArray,
        server: List<ByteArray>,
        challenge: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        repeat(3) {
            val first = createSuite2Grant(server, challenge, csk)
            val second = createSuite2Grant(server, challenge, csk)
            val firstId = extractTemporalIdentifier(first)
            val secondId = extractTemporalIdentifier(second)
            if (firstId.contentEquals(secondId)) return first to second
        }
        throw AssertionError("the 60-second window rolled over on every attempt")
    }

    /**
     * The byte range of `EncryptedPacket.ciphertext`'s payload.
     *
     * `EncryptedPacket` serialises in field order (`proto/auth_protocol.proto`): field 1 the
     * 16-byte `temporal_identifier`, field 2 the `encryption_algorithm` varint, field 3 the
     * length-delimited `ciphertext`. The field-3 tag and the length are asserted against the packet
     * rather than assumed, so a layout change fails here instead of silently pointing a tamper test
     * at a header byte it did not mean to touch.
     */
    private fun ciphertextRange(packet: ByteArray): IntRange {
        val algorithmOffset = encryptionAlgorithmOffset(packet)
        val (_, algorithmVarintLength) = readVarint(packet, algorithmOffset)
        val tagOffset = algorithmOffset + algorithmVarintLength
        assertEquals(
            "EncryptedPacket field 3 tag (length-delimited ciphertext)",
            0x1A,
            packet[tagOffset].toInt(),
        )
        val (length, lengthVarintLength) = readVarint(packet, tagOffset + 1)
        val start = tagOffset + 1 + lengthVarintLength
        assertEquals(
            "ciphertext must be the last field, running to the end of the packet",
            packet.size,
            start + length,
        )
        // `nonce(12) || ciphertext || tag(16)` at minimum.
        assertTrue("the ciphertext must carry a body beyond nonce and tag", length > 28)
        return start until (start + length)
    }

    /** Read the LEB128 varint at [offset] as its value and its byte length. */
    private fun readVarint(packet: ByteArray, offset: Int): Pair<Int, Int> {
        var value = 0
        var shift = 0
        var cursor = offset
        while (cursor < packet.size && shift <= 28) {
            val byte = packet[cursor].toInt() and 0xFF
            value = value or ((byte and 0x7F) shl shift)
            cursor += 1
            if (byte and 0x80 == 0) return value to (cursor - offset)
            shift += 7
        }
        throw AssertionError("no complete varint at offset $offset")
    }

    private fun createSession(sessionId: ByteArray, ed25519PrivateKey: ByteArray): PairingSession =
        PairingSession(sessionId, ed25519PrivateKey, SERVER_DEVICE_NAME)

    /**
     * A tag-less `PairingAbort` frame carrying [sessionId], as a peer sends it before any key
     * exists.
     *
     * A live session cannot build the frame it must verify: `PairingSession.createAbort` is
     * terminal (it concludes the session, exactly like `create_confirm_server`), which
     * `testCreatingAnAbortConcludesTheSession` pins. The frame is therefore built by a throwaway
     * session for a different id and has the envelope's session id rewritten — the abort body is a
     * reason byte and an empty tag, and neither a signature nor a tag covers the envelope.
     */
    private fun taglessAbortFor(sessionId: ByteArray, ed25519PrivateKey: ByteArray): ByteArray {
        val sourceId = ByteArray(16) { (it * 13 + 5).toByte() }
        val source = createSession(sourceId, ed25519PrivateKey)
        try {
            val frame = source.createAbort(PAIRING_ABORT_USER_REJECTED_SAS)
            assertArrayEquals(
                "A PairingAbort must carry the session id it was built for",
                sourceId,
                pairingPacketSessionId(frame),
            )
            val offset = indexOfSubsequence(frame, sourceId)
            assertTrue(
                "The abort envelope must carry the 16-byte session id verbatim",
                offset >= 0,
            )
            assertTrue(
                "The session id must appear exactly once in a tag-less abort",
                indexOfSubsequence(frame.copyOfRange(offset + 1, frame.size), sourceId) < 0,
            )
            val patched = frame.copyOf()
            sessionId.copyInto(patched, offset)
            assertArrayEquals(
                "The rewritten frame must decode as an abort of the target session",
                sessionId,
                pairingPacketSessionId(patched),
            )
            return patched
        } finally {
            source.close()
        }
    }

    /**
     * Whether an identifier built [offset] windows away from the current one verifies.
     *
     * The window is re-read after the check and the attempt repeated when it rolled over, so a
     * 60-second boundary landing between the two calls cannot turn a correct rejection into a
     * flake.
     */
    private fun verifiesForWindowOffset(csk: ByteArray, offset: Long): Boolean {
        val window = currentTimeWindow()
        val identifier = generateTemporalIdentifier(csk, window + offset, HASH_SHA256)
        val verified = verifyTemporalIdentifier(identifier, csk, HASH_SHA256)
        if (currentTimeWindow() == window) return verified

        val fresh = currentTimeWindow()
        val freshIdentifier = generateTemporalIdentifier(csk, fresh + offset, HASH_SHA256)
        return verifyTemporalIdentifier(freshIdentifier, csk, HASH_SHA256)
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

/**
 * `SymmetricAlgorithm.AES_256_GCM` (`proto/auth_protocol.proto`).
 *
 * The generated surface takes the raw enum id, so the test names the value the proto defines rather
 * than importing a Kotlin constant that no longer exists.
 */
private const val SYMMETRIC_AES_256_GCM = 1

/** `SymmetricAlgorithm.CHACHA20_POLY1305` (`proto/auth_protocol.proto`). */
private const val SYMMETRIC_CHACHA20_POLY1305 = 2

/** `HashAlgorithm.SHA256` (`proto/auth_protocol.proto`). */
private const val HASH_SHA256 = 1

/** `HashAlgorithm.BLAKE3` (`proto/auth_protocol.proto`). */
private const val HASH_BLAKE3 = 2

/**
 * `SignatureAlgorithm.ED25519` (`proto/auth_protocol.proto`), spelled once as the fourth parser
 * argument: the paired Client's persisted `signatureAlgorithm`, never derived from the message.
 */
private const val ED25519 = 1

/** `PairingAbortReason.USER_REJECTED_SAS` (`proto/auth_protocol.proto`). */
private const val PAIRING_ABORT_USER_REJECTED_SAS = 1

/** `PairingAbortReason.SESSION_EXPIRED` (`proto/auth_protocol.proto`). */
private const val PAIRING_ABORT_SESSION_EXPIRED = 5

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
