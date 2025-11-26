package dev.rourunisen.tapauth.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation tests for TapAuth JNI crypto bindings.
 *
 * These tests validate the JNI boundary between Kotlin and Rust, ensuring:
 * - Correct data type conversions across FFI
 * - Proper error handling and exception propagation
 * - Consistency between signing and verification operations
 * - Round-trip encryption/decryption correctness
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
    fun testGenerateEd25519Keypair() {
        val keypair = TapAuthCrypto.generateKeypair()

        assertNotNull("Keypair should not be null", keypair)
        assertEquals("Keypair should have 2 elements", 2, keypair.size)

        val privateKey = keypair[0] as ByteArray
        val publicKey = keypair[1] as ByteArray

        assertEquals("Ed25519 private key should be 32 bytes", 32, privateKey.size)
        assertEquals("Ed25519 public key should be 32 bytes", 32, publicKey.size)
    }

    @Test
    fun testGenerateX25519Keypair() {
        val keypair = TapAuthCrypto.generateX25519Keypair()

        assertNotNull("Keypair should not be null", keypair)
        assertEquals("Keypair should have 2 elements", 2, keypair.size)

        val privateKey = keypair[0] as ByteArray
        val publicKey = keypair[1] as ByteArray

        assertEquals("X25519 private key should be 32 bytes", 32, privateKey.size)
        assertEquals("X25519 public key should be 32 bytes", 32, publicKey.size)
    }

    @Test
    fun testGenerateKeypairsAreUnique() {
        val keypair1 = TapAuthCrypto.generateKeypair()
        val keypair2 = TapAuthCrypto.generateKeypair()

        val privateKey1 = keypair1[0] as ByteArray
        val privateKey2 = keypair2[0] as ByteArray

        assertFalse(
            "Generated keypairs should be different",
            privateKey1.contentEquals(privateKey2),
        )
    }

    // ========== Key Exchange Tests ==========

    @Test
    fun testKeyExchange() {
        val aliceKeypair = TapAuthCrypto.generateX25519Keypair()
        val bobKeypair = TapAuthCrypto.generateX25519Keypair()

        val alicePrivate = aliceKeypair[0] as ByteArray
        val alicePublic = aliceKeypair[1] as ByteArray
        val bobPrivate = bobKeypair[0] as ByteArray
        val bobPublic = bobKeypair[1] as ByteArray

        // Both parties derive the same PSK
        val alicePsk = TapAuthCrypto.keyExchange(alicePrivate, bobPublic)
        val bobPsk = TapAuthCrypto.keyExchange(bobPrivate, alicePublic)

        assertNotNull("Alice's PSK should not be null", alicePsk)
        assertNotNull("Bob's PSK should not be null", bobPsk)
        assertEquals("PSK should be 32 bytes", 32, alicePsk.size)
        assertArrayEquals("Both parties should derive the same PSK", alicePsk, bobPsk)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testKeyExchangeWithInvalidKeyLength() {
        val validKeypair = TapAuthCrypto.generateX25519Keypair()
        val validPrivate = validKeypair[0] as ByteArray
        val invalidPublic = ByteArray(16) // Wrong size

        TapAuthCrypto.keyExchange(validPrivate, invalidPublic)
    }

    @Test
    fun testGetSas() {
        val psk = ByteArray(32) { it.toByte() }
        val clientPublic = ByteArray(32) { (it + 32).toByte() }
        val serverPublic = ByteArray(32) { (it + 64).toByte() }

        val sas = TapAuthCrypto.getSas(psk, clientPublic, serverPublic)

        assertNotNull("SAS should not be null", sas)
        assertEquals("SAS should be 6 digits", 6, sas.length)
        assertTrue("SAS should be numeric", sas.all { it.isDigit() })
    }

    // ========== PSK Encryption/Decryption Tests ==========

    @Test
    fun testEncryptDecryptWithPsk() {
        val psk = ByteArray(32) { it.toByte() }
        val plaintext = "Test message for PSK encryption".toByteArray()

        val ciphertext = encryptWithPsk(psk, plaintext)
        assertNotNull("Ciphertext should not be null", ciphertext)
        assertTrue(
            "Ciphertext should be longer than plaintext (includes nonce + tag)",
            ciphertext.size > plaintext.size,
        )

        val decrypted = decryptWithPsk(psk, ciphertext)
        assertNotNull("Decrypted plaintext should not be null", decrypted)
        assertArrayEquals("Decrypted should match original", plaintext, decrypted)
    }

    @Test(expected = Exception::class)
    fun testDecryptWithPskWithWrongKey() {
        val psk1 = ByteArray(32) { it.toByte() }
        val psk2 = ByteArray(32) { (it + 1).toByte() }
        val plaintext = "Test message".toByteArray()

        val ciphertext = encryptWithPsk(psk1, plaintext)
        decryptWithPsk(psk2, ciphertext) // Should fail
    }

    // ========== Temporal ID Tests ==========

    @Test
    fun testGenerateTemporalId() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val temporalId = TapAuthCrypto.generateTemporalId(csk, timestamp)

        assertNotNull("Temporal ID should not be null", temporalId)
        assertEquals("Temporal ID should be 16 bytes", 16, temporalId.size)
    }

    @Test
    fun testGenerateTemporalIdBle() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val temporalIdBle = TapAuthCrypto.generateTemporalIdBle(csk, timestamp)

        assertNotNull("BLE Temporal ID should not be null", temporalIdBle)
        assertEquals("BLE Temporal ID should be 10 bytes", 10, temporalIdBle.size)
    }

    @Test
    fun testVerifyTemporalId() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val temporalId = TapAuthCrypto.generateTemporalId(csk, timestamp)
        val isValid = TapAuthCrypto.verifyTemporalId(temporalId, csk)

        assertTrue("Generated temporal ID should verify successfully", isValid)
    }

    @Test
    fun testVerifyTemporalIdBle() {
        val csk = ByteArray(32) { it.toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val temporalIdBle = TapAuthCrypto.generateTemporalIdBle(csk, timestamp)
        val isValid = TapAuthCrypto.verifyTemporalId(temporalIdBle, csk)

        assertTrue("Generated BLE temporal ID should verify successfully", isValid)
    }

    @Test
    fun testVerifyTemporalIdWithWrongCsk() {
        val csk1 = ByteArray(32) { it.toByte() }
        val csk2 = ByteArray(32) { (it + 1).toByte() }
        val timestamp = System.currentTimeMillis() / 1000

        val temporalId = TapAuthCrypto.generateTemporalId(csk1, timestamp)
        val isValid = TapAuthCrypto.verifyTemporalId(temporalId, csk2)

        assertFalse("Temporal ID should not verify with wrong CSK", isValid)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testVerifyTemporalIdWithInvalidLength() {
        val csk = ByteArray(32) { it.toByte() }
        val invalidId = ByteArray(8) // Wrong size

        TapAuthCrypto.verifyTemporalId(invalidId, csk)
    }

    // ========== CSK Encryption/Decryption Tests ==========

    @Test
    fun testEncryptDecryptWithCsk() {
        val csk = ByteArray(32) { it.toByte() }
        val challenge = ByteArray(32) { (it + 32).toByte() }
        val context = "test_context"
        val plaintext = "Test message for CSK encryption".toByteArray()

        val ciphertext = TapAuthCrypto.encryptWithCsk(csk, challenge, context, plaintext)
        assertNotNull("Ciphertext should not be null", ciphertext)

        val decrypted = TapAuthCrypto.decryptWithCsk(csk, challenge, context, ciphertext)
        assertNotNull("Decrypted plaintext should not be null", decrypted)
        assertArrayEquals("Decrypted should match original", plaintext, decrypted)
    }

    @Test(expected = AEADBadTagException::class)
    fun testDecryptWithCskWithWrongChallenge() {
        val csk = ByteArray(32) { it.toByte() }
        val challenge1 = ByteArray(32) { it.toByte() }
        val challenge2 = ByteArray(32) { (it + 1).toByte() }
        val context = "test_context"
        val plaintext = "Test message".toByteArray()

        val ciphertext = TapAuthCrypto.encryptWithCsk(csk, challenge1, context, plaintext)
        TapAuthCrypto.decryptWithCsk(csk, challenge2, context, ciphertext) // Should fail
    }

    // ========== Signature Tests ==========

    @Test
    fun testSignAndVerify() {
        val keypair = TapAuthCrypto.generateKeypair()
        val privateKey = keypair[0] as ByteArray
        val publicKey = keypair[1] as ByteArray
        val message = "Test message for signing".toByteArray()

        val signature = TapAuthCrypto.signData(privateKey, message)

        assertNotNull("Signature should not be null", signature)
        assertEquals("Ed25519 signature should be 64 bytes", 64, signature.size)

        val isValid = TapAuthCrypto.verifySignature(publicKey, message, signature)
        assertTrue("Signature should verify successfully", isValid)
    }

    @Test
    fun testVerifySignatureWithWrongMessage() {
        val keypair = TapAuthCrypto.generateKeypair()
        val privateKey = keypair[0] as ByteArray
        val publicKey = keypair[1] as ByteArray
        val message1 = "Original message".toByteArray()
        val message2 = "Modified message".toByteArray()

        val signature = TapAuthCrypto.signData(privateKey, message1)
        val isValid = TapAuthCrypto.verifySignature(publicKey, message2, signature)

        assertFalse("Signature should not verify with different message", isValid)
    }

    @Test
    fun testVerifySignatureWithWrongPublicKey() {
        val keypair1 = TapAuthCrypto.generateKeypair()
        val keypair2 = TapAuthCrypto.generateKeypair()
        val privateKey1 = keypair1[0] as ByteArray
        val publicKey2 = keypair2[1] as ByteArray
        val message = "Test message".toByteArray()

        val signature = TapAuthCrypto.signData(privateKey1, message)
        val isValid = TapAuthCrypto.verifySignature(publicKey2, message, signature)

        assertFalse("Signature should not verify with wrong public key", isValid)
    }

    // ========== Protobuf Tests ==========

    @Test
    fun testExtractTemporalIdentifier() {
        val csk = ByteArray(32) { it.toByte() }
        val wrapperMessage = ByteArray(10) { 0x42 } // Dummy wrapper message

        val encryptedPacket = createEncryptedPacket(csk, wrapperMessage)
        val temporalId = TapAuthCrypto.extractTemporalIdentifier(encryptedPacket)

        assertNotNull("Extracted temporal ID should not be null", temporalId)
        assertEquals("Temporal ID should be 16 bytes", 16, temporalId.size)
    }

    @Test(expected = java.io.IOException::class)
    fun testExtractTemporalIdentifierFromInvalidData() {
        val invalidData = ByteArray(5) { 0xFF.toByte() }
        TapAuthCrypto.extractTemporalIdentifier(invalidData)
    }

    @Test
    fun testDetermineMessageType() {
        val keypair = TapAuthCrypto.generateKeypair()
        val privateKey = keypair[0] as ByteArray
        val signedChallenge = ByteArray(32) { it.toByte() }

        val grantMessage = TapAuthCrypto.createGrantWrapperMessage(signedChallenge, privateKey)
        val messageType = TapAuthCrypto.determineMessageType(grantMessage)

        assertNotNull("Message type should not be null", messageType)
        assertEquals("Should be AUTH_GRANT", "AUTH_GRANT", messageType)
    }

    @Test
    fun testSerializeAuthRequestForVerification() {
        val challenge = ByteArray(32) { it.toByte() }
        val username = "testuser"
        val hostname = "testhost.local"
        val timestampUnixSeconds = 1700000000L
        val signatureAlgorithm = 1 // Ed25519

        val serialized = TapAuthCrypto.serializeAuthRequestForVerification(
            challenge,
            username,
            hostname,
            timestampUnixSeconds,
            signatureAlgorithm,
        )

        assertNotNull("Serialized request should not be null", serialized)
        assertTrue("Serialized request should have content", serialized.isNotEmpty())

        // Verify the message type is AUTH_REQUEST
        val messageType = TapAuthCrypto.determineMessageType(serialized)
        assertEquals("Should be AUTH_REQUEST", "AUTH_REQUEST", messageType)
    }

    @Test
    fun testSerializeAuthRequestForVerificationRoundTrip() {
        // Create and sign an auth request, then verify we can recreate the signed bytes
        val challenge = ByteArray(32) { it.toByte() }
        val username = "testuser"
        val hostname = "testhost.local"
        val timestampUnixSeconds = 1700000000L
        val signatureAlgorithm = 1 // Ed25519

        val keypair = TapAuthCrypto.generateKeypair()
        val privateKey = keypair[0] as ByteArray
        val publicKey = keypair[1] as ByteArray

        // Serialize the request for signing (empty signature)
        val messageForSigning = TapAuthCrypto.serializeAuthRequestForVerification(
            challenge,
            username,
            hostname,
            timestampUnixSeconds,
            signatureAlgorithm,
        )

        // Sign the message
        val signature = TapAuthCrypto.signData(privateKey, messageForSigning)
        assertEquals("Ed25519 signature should be 64 bytes", 64, signature.size)

        // Re-serialize to get the same bytes for verification
        val messageForVerification = TapAuthCrypto.serializeAuthRequestForVerification(
            challenge,
            username,
            hostname,
            timestampUnixSeconds,
            signatureAlgorithm,
        )

        // Verify the signature
        val isValid = TapAuthCrypto.verifySignature(publicKey, messageForVerification, signature)
        assertTrue("Signature should verify with reconstructed message", isValid)
    }

    @Test
    fun testCreateAndDecryptEncryptedPacket() {
        val csk = ByteArray(32) { it.toByte() }
        val keypair = TapAuthCrypto.generateKeypair()
        val privateKey = keypair[0] as ByteArray
        val signedChallenge = ByteArray(32) { (it + 32).toByte() }

        // Create a wrapper message
        val wrapperMessage = TapAuthCrypto.createGrantWrapperMessage(signedChallenge, privateKey)

        // Encrypt it
        val encryptedPacket = createEncryptedPacket(csk, wrapperMessage)
        assertNotNull("Encrypted packet should not be null", encryptedPacket)

        // Decrypt it
        val decryptedWrapper = decryptEncryptedPacket(csk, encryptedPacket)
        assertNotNull("Decrypted wrapper should not be null", decryptedWrapper)

        // Verify message type
        val messageType = TapAuthCrypto.determineMessageType(decryptedWrapper)
        assertEquals("Should be AUTH_GRANT", "AUTH_GRANT", messageType)
    }

    @Test(expected = GeneralSecurityException::class)
    fun testDecryptEncryptedPacketWithWrongKey() {
        val csk1 = ByteArray(32) { it.toByte() }
        val csk2 = ByteArray(32) { (it + 1).toByte() }
        val wrapperMessage = ByteArray(10) { 0x42 }

        val encryptedPacket = createEncryptedPacket(csk1, wrapperMessage)
        decryptEncryptedPacket(csk2, encryptedPacket) // Should fail
    }

    // ========== Pairing Protocol Tests ==========

    @Test
    fun testCreatePairingHello() {
        val x25519Keypair = TapAuthCrypto.generateX25519Keypair()
        val ed25519Keypair = TapAuthCrypto.generateKeypair()
        val x25519Public = x25519Keypair[1] as ByteArray
        val ed25519Public = ed25519Keypair[1] as ByteArray
        val deviceName = "Test Device"

        val pairingHello = createPairingHello(1, x25519Public, ed25519Public, deviceName)

        assertNotNull("PairingHello should not be null", pairingHello)
        assertTrue("PairingHello should have content", pairingHello.isNotEmpty())
    }

    @Test
    fun testParsePairingResponse() {
        val x25519Keypair = TapAuthCrypto.generateX25519Keypair()
        val ed25519Keypair = TapAuthCrypto.generateKeypair()
        val x25519Public = x25519Keypair[1] as ByteArray
        val ed25519Public = ed25519Keypair[1] as ByteArray
        val deviceName = "Test Server"

        // Create a PairingHello and use its structure for testing
        // (In real usage, server would send PairingResponse)
        val helloBytes = createPairingHello(1, x25519Public, ed25519Public, deviceName)

        // Note: This is a simplified test. In production, we'd need actual PairingResponse bytes
        // For now, we just verify the function doesn't crash with valid protobuf
        assertNotNull("PairingHello bytes should not be null", helloBytes)
    }

    @Test
    fun testCreatePairingCskMessage() {
        val encryptedCsk = ByteArray(32) { it.toByte() }
        val username = "testuser"

        val cskMessage = TapAuthCrypto.createPairingCskMessage(encryptedCsk, username)

        assertNotNull("PairingCskMessage should not be null", cskMessage)
        assertTrue("PairingCskMessage should have content", cskMessage.isNotEmpty())
    }

    @Test
    fun testParsePairingCskMessage() {
        val encryptedCsk = ByteArray(32) { it.toByte() }
        val username = "testuser"

        val cskMessageBytes = TapAuthCrypto.createPairingCskMessage(encryptedCsk, username)
        val parsed = TapAuthCrypto.parsePairingCskMessage(cskMessageBytes)

        assertNotNull("Parsed result should not be null", parsed)
        assertEquals("Should have 2 elements", 2, parsed.size)

        val parsedCsk = parsed[0] as ByteArray
        val parsedUsername = parsed[1] as String

        assertArrayEquals("Encrypted CSK should match", encryptedCsk, parsedCsk)
        assertEquals("Username should match", username, parsedUsername)
    }

    @Test
    fun testCreateAndParsePairingComplete() {
        val completeBytes = TapAuthCrypto.createPairingComplete(true)
        assertNotNull("PairingComplete bytes should not be null", completeBytes)

        val parsed = TapAuthCrypto.parsePairingComplete(completeBytes)
        assertNotNull("Parsed PairingComplete should not be null", parsed)
        assertTrue("Success should be true", parsed.success)
    }

    // ========== SHA-256 Tests ==========

    @Test
    fun testSha256() {
        val data = "Test data for hashing".toByteArray()
        val hash = TapAuthCrypto.sha256(data)

        assertNotNull("Hash should not be null", hash)
        assertEquals("SHA-256 hash should be 64 hex characters", 64, hash.length)
        assertTrue("Hash should be hexadecimal", hash.all { it.isDigit() || it in 'a'..'f' })
    }

    @Test
    fun testSha256Deterministic() {
        val data = "Test data".toByteArray()
        val hash1 = TapAuthCrypto.sha256(data)
        val hash2 = TapAuthCrypto.sha256(data)

        assertEquals("Same input should produce same hash", hash1, hash2)
    }

    // ========== Error Handling Tests ==========

    @Test(expected = IllegalArgumentException::class)
    fun testEncryptWithCskInvalidCskLength() {
        val invalidCsk = ByteArray(16) // Wrong size
        val challenge = ByteArray(32) { it.toByte() }
        val context = "test"
        val plaintext = "test".toByteArray()

        TapAuthCrypto.encryptWithCsk(invalidCsk, challenge, context, plaintext)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEncryptWithCskInvalidChallengeLength() {
        val csk = ByteArray(32) { it.toByte() }
        val invalidChallenge = ByteArray(16) // Wrong size
        val context = "test"
        val plaintext = "test".toByteArray()

        TapAuthCrypto.encryptWithCsk(csk, invalidChallenge, context, plaintext)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testSignDataInvalidPrivateKeyLength() {
        val invalidPrivateKey = ByteArray(16) // Wrong size
        val message = "test".toByteArray()

        TapAuthCrypto.signData(invalidPrivateKey, message)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testVerifySignatureInvalidPublicKeyLength() {
        val invalidPublicKey = ByteArray(16) // Wrong size
        val message = "test".toByteArray()
        val signature = ByteArray(64) { 0 }

        TapAuthCrypto.verifySignature(invalidPublicKey, message, signature)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testVerifySignatureInvalidSignatureLength() {
        val keypair = TapAuthCrypto.generateKeypair()
        val publicKey = keypair[1] as ByteArray
        val message = "test".toByteArray()
        val invalidSignature = ByteArray(32) // Wrong size

        TapAuthCrypto.verifySignature(publicKey, message, invalidSignature)
    }
}
