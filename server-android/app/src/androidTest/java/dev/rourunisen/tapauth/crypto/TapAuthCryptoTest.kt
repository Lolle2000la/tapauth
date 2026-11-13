package dev.rourunisen.tapauth.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.IOException
import java.security.GeneralSecurityException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation tests for the protocol-v2 TapAuth JNI crypto bindings.
 *
 * These tests are the executable proof of the Rust <-> Kotlin JNI contract: they validate the FFI
 * type conversions, the exception contract, and the cryptographic properties the Rust side must
 * guarantee (AAD binding, no algorithm downgrade, verify-before-parse, transcript-bound pairing
 * AEAD). The contract itself is documented on `TapAuthCrypto` (see `crypto/TapAuthCrypto.kt`) and
 * in `docs/design-documents/protocol-stabilization-plan.md` §2.3 / §6.1.
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
 * Or run this specific test class:
 * ```bash
 * ./gradlew connectedAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=dev.rourunisen.tapauth.crypto.TapAuthCryptoTest
 * ```
 *
 * See server-android/TESTING.md for more details.
 */
@RunWith(AndroidJUnit4::class)
class TapAuthCryptoTest {

    @Before
    fun loadNativeLibrary() {
        // Native library is loaded automatically via static initializer in TapAuthCrypto
        // This ensures it's available before tests run
    }

    // ========== Key Generation Tests ==========

    @Test
    fun testGenerateKeypairsHaveExpectedSizes() {
        val ed25519 = TapAuthCrypto.generateKeypair()
        assertEquals("Ed25519 keypair should have 2 elements", 2, ed25519.size)
        assertEquals("Ed25519 private key should be 32 bytes", 32, ed25519[0].size)
        assertEquals("Ed25519 public key should be 32 bytes", 32, ed25519[1].size)
        assertFalse(
            "A keypair must not return the same bytes for both halves",
            ed25519[0].contentEquals(ed25519[1]),
        )

        val x25519 = TapAuthCrypto.generateX25519Keypair()
        assertEquals("X25519 keypair should have 2 elements", 2, x25519.size)
        assertEquals("X25519 private key should be 32 bytes", 32, x25519[0].size)
        assertEquals("X25519 public key should be 32 bytes", 32, x25519[1].size)
        assertFalse(
            "A keypair must not return the same bytes for both halves",
            x25519[0].contentEquals(x25519[1]),
        )
    }

    @Test
    fun testGenerateKeypairsAreUnique() {
        val edPrivate1 = TapAuthCrypto.generateKeypair()[0]
        val edPrivate2 = TapAuthCrypto.generateKeypair()[0]
        assertFalse(
            "Two Ed25519 keypairs must not share a private key",
            edPrivate1.contentEquals(edPrivate2),
        )

        val xPrivate1 = TapAuthCrypto.generateX25519Keypair()[0]
        val xPrivate2 = TapAuthCrypto.generateX25519Keypair()[0]
        assertFalse(
            "Two X25519 keypairs must not share a private key",
            xPrivate1.contentEquals(xPrivate2),
        )
    }

    // ========== Key Exchange Tests ==========

    @Test
    fun testKeyExchangeDerivesSameSecretOnBothSides() {
        val alice = X25519Keypair.generate()
        val bob = X25519Keypair.generate()

        val aliceSecret = TapAuthCrypto.keyExchange(alice.privateKey, bob.publicKey)
        val bobSecret = TapAuthCrypto.keyExchange(bob.privateKey, alice.publicKey)

        assertEquals("Shared secret should be 32 bytes", 32, aliceSecret.size)
        assertArrayEquals("Both parties must derive the same secret", aliceSecret, bobSecret)

        val carol = X25519Keypair.generate()
        val otherSecret = TapAuthCrypto.keyExchange(alice.privateKey, carol.publicKey)
        assertFalse(
            "A different peer must derive a different secret",
            otherSecret.contentEquals(aliceSecret),
        )
    }

    @Test
    fun testKeyExchangeWithInvalidKeyLength() {
        val validPrivate = TapAuthCrypto.generateX25519Keypair()[0]
        val invalidPublic = ByteArray(16)

        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.keyExchange(validPrivate, invalidPublic)
        }
    }

    // ========== SHA-256 Tests ==========

    @Test
    fun testSha256KnownAnswerAndDeterminism() {
        val abc = "abc".toByteArray(Charsets.UTF_8)
        // FIPS 180-2 test vector, lower-case hex.
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

        val hash = TapAuthCrypto.sha256(abc)
        assertEquals("SHA-256 must match the FIPS 180-2 vector for \"abc\"", expected, hash)
        assertEquals(
            "Hashing the same input twice must produce the same digest",
            hash,
            TapAuthCrypto.sha256(abc.copyOf()),
        )
        assertFalse(
            "A different input must produce a different digest",
            expected == TapAuthCrypto.sha256("abd".toByteArray(Charsets.UTF_8)),
        )
    }

    // ========== Signature Tests ==========

    @Test
    fun testSignAndVerify() {
        val signer = Ed25519Keypair.generate()
        val message = "Test message for signing".toByteArray(Charsets.UTF_8)

        val signature = TapAuthCrypto.signData(signer.privateKey, message)

        assertEquals("Ed25519 signature should be 64 bytes", 64, signature.size)
        assertTrue(
            "Signature must verify under the matching public key",
            TapAuthCrypto.verifySignature(signer.publicKey, message, signature),
        )
    }

    @Test
    fun testVerifySignatureWithWrongMessage() {
        val signer = Ed25519Keypair.generate()
        val signature = TapAuthCrypto.signData(signer.privateKey, "Original message".toByteArray())

        assertFalse(
            "Signature must not verify against a modified message",
            TapAuthCrypto.verifySignature(
                signer.publicKey,
                "Modified message".toByteArray(),
                signature,
            ),
        )
    }

    @Test
    fun testVerifySignatureWithWrongPublicKey() {
        val signer = Ed25519Keypair.generate()
        val impostor = Ed25519Keypair.generate()
        val message = "Test message".toByteArray()

        val signature = TapAuthCrypto.signData(signer.privateKey, message)

        assertFalse(
            "Signature must not verify under another identity's public key",
            TapAuthCrypto.verifySignature(impostor.publicKey, message, signature),
        )
    }

    @Test
    fun testSignAndVerifyRejectInvalidLengths() {
        val signer = Ed25519Keypair.generate()
        val message = "test".toByteArray()

        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.signData(ByteArray(16), message)
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.verifySignature(ByteArray(16), message, ByteArray(64))
        }
        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.verifySignature(signer.publicKey, message, ByteArray(32))
        }
    }

    // ========== Temporal Identifier Tests ==========

    @Test
    fun testGenerateTemporalIdUdpAndBle() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = 1_700_000_000L

        val udpId = TapAuthCrypto.generateTemporalId(csk, timestamp)
        assertEquals("UDP temporal ID should be 16 bytes", 16, udpId.size)
        assertArrayEquals(
            "The same 60s window must yield the same UDP temporal ID",
            udpId,
            TapAuthCrypto.generateTemporalId(csk, timestamp),
        )
        assertFalse(
            "A different window must yield a different UDP temporal ID",
            udpId.contentEquals(TapAuthCrypto.generateTemporalId(csk, timestamp + 60)),
        )

        val bleId = TapAuthCrypto.generateTemporalIdBle(csk, timestamp)
        assertEquals("BLE temporal ID should be 10 bytes", 10, bleId.size)
        assertArrayEquals(
            "The same 60s window must yield the same BLE temporal ID",
            bleId,
            TapAuthCrypto.generateTemporalIdBle(csk, timestamp),
        )
        assertFalse(
            "A different window must yield a different BLE temporal ID",
            bleId.contentEquals(TapAuthCrypto.generateTemporalIdBle(csk, timestamp + 60)),
        )
    }

    @Test
    fun testVerifyTemporalIdAcceptsOwnAndRejectsWrongCsk() {
        val csk = ByteArray(32) { it.toByte() }
        val wrongCsk = ByteArray(32) { (it + 1).toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val udpId = TapAuthCrypto.generateTemporalId(csk, timestamp)
        assertTrue(
            "A freshly generated UDP temporal ID must verify",
            TapAuthCrypto.verifyTemporalId(udpId, csk),
        )
        assertFalse(
            "A UDP temporal ID must not verify under a different CSK",
            TapAuthCrypto.verifyTemporalId(udpId, wrongCsk),
        )

        val bleId = TapAuthCrypto.generateTemporalIdBle(csk, timestamp)
        assertTrue(
            "A freshly generated BLE temporal ID must verify",
            TapAuthCrypto.verifyTemporalId(bleId, csk),
        )
        assertFalse(
            "A BLE temporal ID must not verify under a different CSK",
            TapAuthCrypto.verifyTemporalId(bleId, wrongCsk),
        )
    }

    @Test
    fun testVerifyTemporalIdWithInvalidLength() {
        val csk = ByteArray(32) { it.toByte() }

        assertThrows(IllegalArgumentException::class.java) {
            TapAuthCrypto.verifyTemporalId(ByteArray(8), csk)
        }
    }

    @Test
    fun testGenerateTemporalIdWithSha256MatchesDefault() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = 1_700_000_000L

        assertArrayEquals(
            "HASH_SHA256 must reproduce the default UDP wrapper's output",
            TapAuthCrypto.generateTemporalId(csk, timestamp),
            TapAuthCrypto.generateTemporalIdWithAlg(csk, timestamp, TapAuthCrypto.HASH_SHA256),
        )
        assertArrayEquals(
            "HASH_SHA256 must reproduce the default BLE wrapper's output",
            TapAuthCrypto.generateTemporalIdBle(csk, timestamp),
            TapAuthCrypto.generateTemporalIdBleWithAlg(
                csk,
                timestamp,
                TapAuthCrypto.HASH_SHA256,
            ),
        )
    }

    @Test
    fun testGenerateTemporalIdWithBlake3DiffersFromSha256() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = 1_700_000_000L

        val sha256Id =
            TapAuthCrypto.generateTemporalIdWithAlg(csk, timestamp, TapAuthCrypto.HASH_SHA256)
        val blake3Id = TapAuthCrypto.generateTemporalIdWithAlg(csk, timestamp, HASH_BLAKE3)

        assertEquals("BLAKE3 temporal ID should be 16 bytes", 16, blake3Id.size)
        assertFalse(
            "BLAKE3 and SHA-256 must not derive the same temporal ID for one input",
            blake3Id.contentEquals(sha256Id),
        )
        assertArrayEquals(
            "BLAKE3 temporal ID must be stable for one input",
            blake3Id,
            TapAuthCrypto.generateTemporalIdWithAlg(csk, timestamp, HASH_BLAKE3),
        )
    }

    @Test
    fun testGenerateTemporalIdBleWithBlake3DiffersFromSha256() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = 1_700_000_000L

        val sha256Id =
            TapAuthCrypto.generateTemporalIdBleWithAlg(csk, timestamp, TapAuthCrypto.HASH_SHA256)
        val blake3Id = TapAuthCrypto.generateTemporalIdBleWithAlg(csk, timestamp, HASH_BLAKE3)

        assertEquals("BLAKE3 BLE temporal ID should be 10 bytes", 10, blake3Id.size)
        assertFalse(
            "BLAKE3 and SHA-256 must not derive the same BLE temporal ID",
            blake3Id.contentEquals(sha256Id),
        )
        assertArrayEquals(
            "BLAKE3 BLE temporal ID must be stable for one input",
            blake3Id,
            TapAuthCrypto.generateTemporalIdBleWithAlg(csk, timestamp, HASH_BLAKE3),
        )
    }

    // ========== EncryptedPacket Tests ==========

    @Test
    fun testCreateAndDecryptEncryptedPacket() {
        val csk = ByteArray(32) { it.toByte() }
        val server = Ed25519Keypair.generate()
        val challenge = ByteArray(32) { (it + 32).toByte() }

        val wrapper = TapAuthCrypto.createGrantWrapperMessage(challenge, server.privateKey)
        val packet =
            createEncryptedPacket(
                csk,
                wrapper,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )

        val decrypted = decryptEncryptedPacket(packet, csk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)
        assertArrayEquals("Round-tripped wrapper must be byte-identical", wrapper, decrypted)
        assertEquals(
            "Round-tripped wrapper must still be the grant we put in",
            "AUTH_GRANT",
            TapAuthCrypto.determineMessageType(decrypted),
        )
    }

    @Test
    fun testDecryptEncryptedPacketWithWrongKey() {
        val csk = ByteArray(32) { it.toByte() }
        val wrongCsk = ByteArray(32) { (it + 1).toByte() }
        val wrapper = ByteArray(10) { 0x42 }

        val packet =
            createEncryptedPacket(
                csk,
                wrapper,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )

        assertThrows(GeneralSecurityException::class.java) {
            decryptEncryptedPacket(packet, wrongCsk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)
        }
    }

    @Test
    fun testDecryptEncryptedPacketRejectsTamperedTemporalIdentifier() {
        val csk = ByteArray(32) { it.toByte() }
        val wrapper =
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(32) { it.toByte() },
                Ed25519Keypair.generate().privateKey,
            )
        val packet =
            createEncryptedPacket(
                csk,
                wrapper,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )

        val temporalId = TapAuthCrypto.extractTemporalIdentifier(packet)
        val offset = indexOfSubsequence(packet, temporalId)
        assertTrue("temporal_identifier must be embedded verbatim in the packet", offset >= 0)

        val tampered =
            packet.copyOf().also {
                it[offset + 1] = (it[offset + 1].toInt() xor 0x01).toByte()
            }
        assertFalse(
            "The tampered packet must carry a different temporal_identifier",
            temporalId.contentEquals(TapAuthCrypto.extractTemporalIdentifier(tampered)),
        )

        // temporal_identifier is bound into the AAD, so the tag must no longer verify.
        assertThrows(GeneralSecurityException::class.java) {
            decryptEncryptedPacket(tampered, csk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)
        }
    }

    @Test
    fun testDecryptEncryptedPacketRejectsAlgorithmDowngrade() {
        val csk = ByteArray(32) { it.toByte() }
        val wrapper = ByteArray(10) { 0x42 }
        val packet =
            createEncryptedPacket(
                csk,
                wrapper,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )

        val algorithmOffset = encryptionAlgorithmOffset(packet)
        assertEquals(
            "createEncryptedPacket must declare AES-256-GCM",
            TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            packet[algorithmOffset].toInt(),
        )

        // Re-label an AES-GCM packet as ChaCha20-Poly1305: dispatch, not the caller's word, must
        // decide, and the AAD binding makes the original tag invalid either way.
        val relabelled =
            packet.copyOf().also {
                it[algorithmOffset] = SYMMETRIC_CHACHA20_POLY1305.toByte()
            }
        assertThrows(GeneralSecurityException::class.java) {
            decryptEncryptedPacket(relabelled, csk, TapAuthCrypto.SYMMETRIC_AES_256_GCM)
        }
    }

    @Test
    fun testParseEncryptedPacketStructureMatchesExtractedIdentifier() {
        val csk = ByteArray(32) { it.toByte() }
        val wrapper = ByteArray(10) { 0x42 }
        val packet =
            createEncryptedPacket(
                csk,
                wrapper,
                TapAuthCrypto.SYMMETRIC_AES_256_GCM,
                TapAuthCrypto.HASH_SHA256,
            )

        val info = TapAuthCrypto.parseEncryptedPacketStructure(packet)

        assertEquals("temporal_identifier should be 16 bytes", 16, info.temporalIdentifier.size)
        assertArrayEquals(
            "Structure and extractor must report the same temporal_identifier",
            TapAuthCrypto.extractTemporalIdentifier(packet),
            info.temporalIdentifier,
        )
        assertEquals(
            "Packet must declare AES-256-GCM",
            TapAuthCrypto.SYMMETRIC_AES_256_GCM,
            info.encryptionAlgorithm,
        )
        assertEquals(
            "ciphertext must be nonce(12) || AEAD ciphertext || tag(16)",
            wrapper.size + 12 + 16,
            info.ciphertext.size,
        )
    }

    @Test
    fun testExtractTemporalIdentifierFromInvalidData() {
        assertThrows(IOException::class.java) {
            TapAuthCrypto.extractTemporalIdentifier(ByteArray(5) { 0xFF.toByte() })
        }
    }

    @Test
    fun testDetermineMessageType() {
        val server = Ed25519Keypair.generate()
        val challenge = ByteArray(32) { it.toByte() }

        assertEquals(
            "A grant wrapper must report AUTH_GRANT",
            "AUTH_GRANT",
            TapAuthCrypto.determineMessageType(
                TapAuthCrypto.createGrantWrapperMessage(challenge, server.privateKey),
            ),
        )
        assertEquals(
            "A denial wrapper must report AUTH_DENIAL",
            "AUTH_DENIAL",
            TapAuthCrypto.determineMessageType(
                TapAuthCrypto.createDenialWrapperMessage(challenge, "denied", server.privateKey),
            ),
        )
    }

    // ========== Authenticated Wrapper Parsing Tests ==========

    @Test
    fun testParseAndVerifyGrantConfirmation() {
        val server = Ed25519Keypair.generate()
        val challenge = ByteArray(32) { (it + 32).toByte() }

        val wrapper = TapAuthCrypto.createGrantWrapperMessage(challenge, server.privateKey)
        val confirmation =
            TapAuthCrypto.parseAndVerifyGrantConfirmation(wrapper, server.publicKey, PROTOCOL_V2)

        assertArrayEquals(
            "Parsed challenge must match the granted one",
            challenge,
            confirmation.challenge,
        )
        assertEquals(
            "Wrapper signature algorithm must be surfaced as Ed25519",
            TapAuthCrypto.SIGNATURE_ED25519,
            confirmation.signatureAlgorithm,
        )
        assertEquals(
            "Parsed wrapper signature must be the 64-byte Ed25519 signature",
            64,
            confirmation.signature.size,
        )
    }

    @Test
    fun testParseAndVerifyGrantConfirmationWithWrongPublicKey() {
        val server = Ed25519Keypair.generate()
        val impostor = Ed25519Keypair.generate()
        val wrapper = TapAuthCrypto.createGrantWrapperMessage(ByteArray(32), server.privateKey)

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(wrapper, impostor.publicKey, PROTOCOL_V2)
        }
    }

    @Test
    fun testParseAndVerifyGrantConfirmationRejectsTamperedSignature() {
        val server = Ed25519Keypair.generate()
        val wrapper =
            TapAuthCrypto.createGrantWrapperMessage(
                ByteArray(32) { it.toByte() },
                server.privateKey,
            )

        // The signature is the last field of the wrapper: flip its final bit.
        val tampered =
            wrapper.copyOf().also {
                it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte()
            }

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(tampered, server.publicKey, PROTOCOL_V2)
        }
    }

    @Test
    fun testParseAndVerifyGrantConfirmationRejectsTamperedPayload() {
        val server = Ed25519Keypair.generate()
        val challenge = ByteArray(32) { (it + 32).toByte() }
        val wrapper = TapAuthCrypto.createGrantWrapperMessage(challenge, server.privateKey)

        // Flip a challenge byte but leave the signature intact: verification must cover the
        // payload.
        val offset = indexOfSubsequence(wrapper, challenge)
        assertTrue("The challenge must be embedded verbatim in the wrapper", offset >= 0)
        val tampered =
            wrapper.copyOf().also {
                it[offset] = (it[offset].toInt() xor 0x01).toByte()
            }

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(tampered, server.publicKey, PROTOCOL_V2)
        }
    }

    @Test
    fun testGrantConfirmationParserRejectsDenialWrapper() {
        val server = Ed25519Keypair.generate()
        val denial =
            TapAuthCrypto.createDenialWrapperMessage(
                ByteArray(32),
                "user denied",
                server.privateKey,
            )

        // Valid signature, wrong payload type: the parser must not hand back a "confirmation", and
        // the rejection must be the documented "this is not a GrantConfirmation" IOException rather
        // than an arbitrary failure such as a parser NPE.
        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyGrantConfirmation(denial, server.publicKey, PROTOCOL_V2)
        }
    }

    @Test
    fun testAuthRequestAndCancelParsersRejectGrantWrapper() {
        val server = Ed25519Keypair.generate()
        val grant = TapAuthCrypto.createGrantWrapperMessage(ByteArray(32), server.privateKey)

        // No JNI entry builds an AuthenticationRequest or AuthenticationCancel wrapper (the Client
        // role's request builder lives in shared/src/protocol/messages.rs and is not exported), so
        // these two parsers can only be proved to reject a signature-valid wrapper of another type,
        // as the documented "not an AuthenticationRequest/Cancel" IOException.
        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(grant, server.publicKey, PROTOCOL_V2)
        }
        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthCancel(grant, server.publicKey, PROTOCOL_V2)
        }
    }

    @Test
    fun testParseAndVerifyAuthRequestRejectsGarbage() {
        val server = Ed25519Keypair.generate()

        assertThrows(IOException::class.java) {
            TapAuthCrypto.parseAndVerifyAuthRequest(
                ByteArray(12) { 0xFF.toByte() },
                server.publicKey,
                PROTOCOL_V2,
            )
        }
    }

    // ========== v2 Pairing: BLE advertisement id & transcript hash ==========

    @Test
    fun testDeriveBlePairingAdvId() {
        val sessionId = ByteArray(16) { it.toByte() }
        val clientPublic = X25519Keypair.generate().publicKey

        val advId = TapAuthCrypto.deriveBlePairingAdvId(sessionId, clientPublic)

        assertEquals("BLE pairing advertisement id must be 10 bytes", 10, advId.size)
        assertArrayEquals(
            "The advertisement id must be deterministic for one QR code",
            advId,
            TapAuthCrypto.deriveBlePairingAdvId(sessionId, clientPublic),
        )
        assertFalse(
            "A different session id must yield a different advertisement id",
            advId.contentEquals(
                TapAuthCrypto.deriveBlePairingAdvId(
                    ByteArray(16) { (it + 1).toByte() },
                    clientPublic,
                ),
            ),
        )
        assertFalse(
            "A different client public key must yield a different advertisement id",
            advId.contentEquals(
                TapAuthCrypto.deriveBlePairingAdvId(
                    sessionId,
                    X25519Keypair.generate().publicKey,
                ),
            ),
        )
    }

    @Test
    fun testComputePairingTranscriptHashIsBoundToBothPackets() {
        val fixture = PairingFixture()
        val base =
            TapAuthCrypto.computePairingTranscriptHash(
                fixture.sessionId,
                fixture.initPacket,
                fixture.responseStub,
            )

        assertEquals("Transcript hash must be 32 bytes", 32, base.size)
        assertArrayEquals(
            "Transcript hash must be deterministic",
            base,
            TapAuthCrypto.computePairingTranscriptHash(
                fixture.sessionId,
                fixture.initPacket,
                fixture.responseStub,
            ),
        )
        assertFalse(
            "Changing the init packet must change the transcript hash",
            base.contentEquals(
                TapAuthCrypto.computePairingTranscriptHash(
                    fixture.sessionId,
                    fixture.initPacket.withXorAt(fixture.initPacket.size - 1, 0x01),
                    fixture.responseStub,
                ),
            ),
        )
        assertFalse(
            "Changing the response packet must change the transcript hash",
            base.contentEquals(
                TapAuthCrypto.computePairingTranscriptHash(
                    fixture.sessionId,
                    fixture.initPacket,
                    fixture.responseStub.withXorAt(fixture.responseStub.size - 1, 0x01),
                ),
            ),
        )
        assertFalse(
            "Changing the session id must change the transcript hash",
            base.contentEquals(
                TapAuthCrypto.computePairingTranscriptHash(
                    fixture.sessionId.withXorAt(0, 0x01),
                    fixture.initPacket,
                    fixture.responseStub,
                ),
            ),
        )
    }

    // ========== v2 Pairing: handshake packets ==========

    @Test
    fun testPairingInitCarriesServerMaterial() {
        val fixture = PairingFixture()
        val init = fixture.initPacket

        assertTrue(
            "PairingInit must carry the session id",
            indexOfSubsequence(init, fixture.sessionId) >= 0,
        )
        assertTrue(
            "PairingInit must carry our ephemeral X25519 public key",
            indexOfSubsequence(init, fixture.serverX25519.publicKey) >= 0,
        )
        assertTrue(
            "PairingInit must carry our static Ed25519 public key",
            indexOfSubsequence(init, fixture.serverEd25519.publicKey) >= 0,
        )
        assertTrue(
            "PairingInit must carry our device name",
            indexOfSubsequence(init, SERVER_DEVICE_NAME.toByteArray(Charsets.UTF_8)) >= 0,
        )

        // A different keypair must produce different bytes (no cached/constant packet).
        assertFalse(
            "PairingInit must not be a fixed constant",
            init.contentEquals(
                TapAuthCrypto.pairingInit(
                    fixture.sessionId,
                    X25519Keypair.generate().publicKey,
                    fixture.serverEd25519.publicKey,
                    SERVER_DEVICE_NAME,
                    intArrayOf(TapAuthCrypto.SYMMETRIC_AES_256_GCM),
                    intArrayOf(TapAuthCrypto.HASH_SHA256),
                    intArrayOf(TapAuthCrypto.SIGNATURE_ED25519),
                ),
            ),
        )
    }

    @Test
    fun testPairingVerifyResponseRejectsGarbage() {
        val fixture = PairingFixture()

        // No JNI entry builds a valid PairingResponse, so only the rejection path is reachable. A
        // packet that is not a PairingPacket at all is the documented IOException, not just "any
        // exception".
        assertThrows(IOException::class.java) {
            TapAuthCrypto.pairingVerifyResponse(
                fixture.sessionId,
                ByteArray(64) { 0xFF.toByte() },
                fixture.clientX25519.publicKey,
                fixture.serverX25519.privateKey,
            )
        }
    }

    @Test
    fun testPairingVerifyResponseRejectsInitPacketInResponseSlot() {
        val fixture = PairingFixture()

        // Our own PairingInit is a well-formed PairingPacket of the wrong role: accepting it as the
        // Client's response would derive keys from the Server's own ephemeral key.
        assertThrows(IOException::class.java) {
            TapAuthCrypto.pairingVerifyResponse(
                fixture.sessionId,
                fixture.initPacket,
                fixture.clientX25519.publicKey,
                fixture.serverX25519.privateKey,
            )
        }
    }

    @Test
    fun testPairingProvisionRoundTrip() {
        val fixture = PairingFixture()

        val packet =
            TapAuthCrypto.pairingEncryptProvision(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                fixture.csk,
                PAIRED_USERNAME,
                CLIENT_HOSTNAME,
            )
        val provision =
            TapAuthCrypto.pairingDecryptProvision(fixture.kC2s, fixture.transcriptHash, packet)

        assertEquals("Provision must expose 3 slots", 3, provision.size)
        assertEquals("CSK slot must be 32 bytes", 32, provision[0].size)
        assertArrayEquals("CSK must survive the provision round-trip", fixture.csk, provision[0])
        assertEquals(
            "Username must survive the provision round-trip",
            PAIRED_USERNAME,
            String(provision[1], Charsets.UTF_8),
        )
        assertEquals(
            "Client hostname must survive the provision round-trip",
            CLIENT_HOSTNAME,
            String(provision[2], Charsets.UTF_8),
        )

        // A second encryption with the same inputs (fresh nonce) must decrypt identically.
        val secondPacket =
            TapAuthCrypto.pairingEncryptProvision(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                fixture.csk,
                PAIRED_USERNAME,
                CLIENT_HOSTNAME,
            )
        val secondProvision =
            TapAuthCrypto.pairingDecryptProvision(
                fixture.kC2s,
                fixture.transcriptHash,
                secondPacket,
            )
        assertArrayEquals(
            "Re-encrypting the same provision must yield the same plaintext",
            fixture.csk,
            secondProvision[0],
        )
        assertEquals(
            "Re-encrypting the same provision must yield the same username",
            PAIRED_USERNAME,
            String(secondProvision[1], Charsets.UTF_8),
        )
    }

    @Test
    fun testPairingDecryptProvisionRejectsWrongKeyAndCorruption() {
        val fixture = PairingFixture()
        val packet =
            TapAuthCrypto.pairingEncryptProvision(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                fixture.csk,
                PAIRED_USERNAME,
                CLIENT_HOSTNAME,
            )

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptProvision(
                fixture.kC2s.withXorAt(0, 0xFF),
                fixture.transcriptHash,
                packet,
            )
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptProvision(
                fixture.kC2s,
                fixture.transcriptHash.withXorAt(0, 0x01),
                packet,
            )
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptProvision(
                fixture.kC2s,
                fixture.transcriptHash,
                packet.withXorAt(packet.size - 1, 0x01),
            )
        }
    }

    @Test
    fun testPairingConfirmServerRoundTripReturnsCsk() {
        val fixture = PairingFixture()

        val packet =
            TapAuthCrypto.pairingCreateConfirmServer(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                fixture.serverEd25519.privateKey,
                fixture.csk,
            )
        val completed =
            TapAuthCrypto.pairingDecryptComplete(
                fixture.kS2c,
                fixture.transcriptHash,
                packet,
                fixture.serverEd25519.publicKey,
            )

        assertEquals("Completed CSK must be 32 bytes", 32, completed.size)
        assertArrayEquals("PairingComplete must echo the exact CSK", fixture.csk, completed)

        // A different CSK must echo back unchanged, not a constant.
        val otherCsk = ByteArray(32) { (it * 3 + 1).toByte() }
        val otherPacket =
            TapAuthCrypto.pairingCreateConfirmServer(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                fixture.serverEd25519.privateKey,
                otherCsk,
            )
        assertArrayEquals(
            "PairingComplete must echo whichever CSK the Server provisioned",
            otherCsk,
            TapAuthCrypto.pairingDecryptComplete(
                fixture.kS2c,
                fixture.transcriptHash,
                otherPacket,
                fixture.serverEd25519.publicKey,
            ),
        )
    }

    @Test
    fun testPairingDecryptCompleteWithWrongTranscriptHashThrows() {
        val fixture = PairingFixture()
        val packet =
            TapAuthCrypto.pairingCreateConfirmServer(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                fixture.serverEd25519.privateKey,
                fixture.csk,
            )

        // The transcript hash is the AEAD AAD: a different H must not decrypt.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptComplete(
                fixture.kS2c,
                fixture.transcriptHash.withXorAt(0, 0x01),
                packet,
                fixture.serverEd25519.publicKey,
            )
        }
    }

    @Test
    fun testPairingDecryptCompleteRejectsTamperedPacket() {
        val fixture = PairingFixture()
        val packet =
            TapAuthCrypto.pairingCreateConfirmServer(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                fixture.serverEd25519.privateKey,
                fixture.csk,
            )

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptComplete(
                fixture.kS2c,
                fixture.transcriptHash,
                packet.withXorAt(packet.size - 1, 0x01),
                fixture.serverEd25519.publicKey,
            )
        }
        // The completion is authenticated against the Server's static Ed25519 identity too.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingDecryptComplete(
                fixture.kS2c,
                fixture.transcriptHash,
                packet,
                Ed25519Keypair.generate().publicKey,
            )
        }
    }

    // ========== v2 Pairing: authenticated abort ==========

    @Test
    fun testPairingAbortRoundTripPreservesReason() {
        val fixture = PairingFixture()

        val rejected =
            TapAuthCrypto.pairingCreateAbort(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            )
        assertEquals(
            "USER_REJECTED_SAS must survive the abort round-trip",
            TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            TapAuthCrypto.pairingVerifyAbort(fixture.kC2s, fixture.transcriptHash, rejected),
        )

        val mismatch =
            TapAuthCrypto.pairingCreateAbort(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                TapAuthCrypto.PAIRING_ABORT_KEY_MISMATCH,
            )
        assertEquals(
            "KEY_MISMATCH must survive the abort round-trip",
            TapAuthCrypto.PAIRING_ABORT_KEY_MISMATCH,
            TapAuthCrypto.pairingVerifyAbort(fixture.kS2c, fixture.transcriptHash, mismatch),
        )
    }

    @Test
    fun testPairingAbortRejectsTheOppositeDirectionKey() {
        val fixture = PairingFixture()

        // `K_c2s` carries Client -> Server aborts, `K_s2c` Server -> Client ones
        // (`cryptography-specification.md` §2.2). A swapped direction must not verify.
        val fromClient =
            TapAuthCrypto.pairingCreateAbort(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            )
        val fromServer =
            TapAuthCrypto.pairingCreateAbort(
                fixture.sessionId,
                fixture.kS2c,
                fixture.transcriptHash,
                TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            )

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(fixture.kS2c, fixture.transcriptHash, fromClient)
        }
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(fixture.kC2s, fixture.transcriptHash, fromServer)
        }
        // Each still verifies under its own direction, so the rejection above is the direction and
        // not a broken packet.
        assertEquals(
            TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            TapAuthCrypto.pairingVerifyAbort(fixture.kC2s, fixture.transcriptHash, fromClient),
        )
        assertEquals(
            TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            TapAuthCrypto.pairingVerifyAbort(fixture.kS2c, fixture.transcriptHash, fromServer),
        )
    }

    @Test
    fun testPairingVerifyAbortRejectsTamperedTagAndWrongTranscript() {
        val fixture = PairingFixture()
        val abort =
            TapAuthCrypto.pairingCreateAbort(
                fixture.sessionId,
                fixture.kC2s,
                fixture.transcriptHash,
                TapAuthCrypto.PAIRING_ABORT_USER_REJECTED_SAS,
            )

        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(
                fixture.kC2s,
                fixture.transcriptHash,
                abort.withXorAt(abort.size - 1, 0x01),
            )
        }
        // The tag covers the transcript hash: replaying an abort from another handshake must fail.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(
                fixture.kC2s,
                fixture.transcriptHash.withXorAt(0, 0x01),
                abort,
            )
        }
        // ... and the direction key.
        assertThrows(GeneralSecurityException::class.java) {
            TapAuthCrypto.pairingVerifyAbort(
                fixture.kC2s.withXorAt(0, 0x01),
                fixture.transcriptHash,
                abort,
            )
        }
    }

    // ========== Helpers ==========

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

/** `HashAlgorithm.BLAKE3` (`proto/auth_protocol.proto`); `TapAuthCrypto` has no constant yet. */
private const val HASH_BLAKE3 = 2

/** `SymmetricAlgorithm.CHACHA20_POLY1305` (`proto/auth_protocol.proto`). */
private const val SYMMETRIC_CHACHA20_POLY1305 = 2

private const val PROTOCOL_V2 = 2
private const val SERVER_DEVICE_NAME = "Pixel 9 Pro"
private const val PAIRED_USERNAME = "testuser"
private const val CLIENT_HOSTNAME = "testhost.local"

/**
 * Material for the in-process v2 pairing handshake: one process plays both the Phone (Server) and
 * the Desktop (Client) role, with no network involved.
 */
private class PairingFixture {
    val sessionId: ByteArray = ByteArray(16) { (it * 11 + 3).toByte() }
    val clientX25519: X25519Keypair = X25519Keypair.generate()
    val serverX25519: X25519Keypair = X25519Keypair.generate()
    val serverEd25519: Ed25519Keypair = Ed25519Keypair.generate()
    val csk: ByteArray = ByteArray(32) { (it * 5 + 7).toByte() }

    val initPacket: ByteArray =
        TapAuthCrypto.pairingInit(
            sessionId,
            serverX25519.publicKey,
            serverEd25519.publicKey,
            SERVER_DEVICE_NAME,
            intArrayOf(TapAuthCrypto.SYMMETRIC_AES_256_GCM),
            intArrayOf(TapAuthCrypto.HASH_SHA256),
            intArrayOf(TapAuthCrypto.SIGNATURE_ED25519),
        )

    /**
     * Stand-in for the Client's `PairingResponse` packet.
     *
     * No JNI entry builds one: the Client role's `handle_init` lives in
     * `shared/src/protocol/pairing.rs` and is not exported. Only
     * [testComputePairingTranscriptHashIsBoundToBothPackets] consumes it, as an opaque second
     * input.
     */
    val responseStub: ByteArray = ByteArray(48) { (it + 5).toByte() }

    /**
     * Fixed 32-byte transcript hash `H`.
     *
     * `H` is opaque to every AEAD / abort helper: it is only ever concatenated into the AAD or the
     * tag input. Using a constant here keeps those tests attributable to the helper under test.
     * `computePairingTranscriptHash` itself is covered by
     * [testComputePairingTranscriptHashIsBoundToBothPackets].
     */
    val transcriptHash: ByteArray = ByteArray(32) { (it * 13 + 1).toByte() }

    /**
     * Raw ECDH secret between the two ephemeral X25519 keys.
     *
     * Production derives `K_c2s` and `K_s2c` from this secret through
     * `derive_pairing_keys_and_sas(secret, H)`, which the JNI exposes only through
     * `pairingVerifyResponse` — unreachable without a real `PairingResponse`. Using the secret
     * itself still exercises the AEAD / AAD wiring around the directional keys; the HKDF split is
     * covered by the Rust unit tests.
     */
    val sharedSecret: ByteArray =
        TapAuthCrypto.keyExchange(clientX25519.privateKey, serverX25519.publicKey)

    /**
     * Directional keys, kept **distinct** because production derives two different HKDF expansions.
     *
     * Equal keys would let a swapped direction pass unnoticed: `PairingSession` tags an outgoing
     * abort with `K_s2c` and verifies an incoming one with `K_c2s`, so
     * [testPairingAbortRejectsTheOppositeDirectionKey] relies on the two diverging.
     */
    val kC2s: ByteArray = sharedSecret.withXorAt(0, 0x01)
    val kS2c: ByteArray = sharedSecret.withXorAt(0, 0x02)
}

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

/** A copy of this array with the byte at [index] XOR-ed by [mask]. */
private fun ByteArray.withXorAt(index: Int, mask: Int): ByteArray =
    copyOf().also { it[index] = (it[index].toInt() xor mask).toByte() }
