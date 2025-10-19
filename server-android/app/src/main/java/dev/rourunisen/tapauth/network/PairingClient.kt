package dev.rourunisen.tapauth.network

import android.util.Log
import dev.rourunisen.tapauth.crypto.Ed25519Keypair
import dev.rourunisen.tapauth.crypto.X25519Keypair
import dev.rourunisen.tapauth.crypto.generateSAS
import dev.rourunisen.tapauth.crypto.performKeyExchange
import dev.rourunisen.tapauth.data.PairedDevice
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Client for TCP-based device pairing
 * Implements the TapAuth pairing protocol as per specification:
 * 1. Server (phone) sends PairingHandshake with its ephemeral public key
 * 2. Both compute PSK via X25519 ECDH
 * 3. Both derive and display SAS for anti-MITM verification
 * 4. Client (desktop) sends ClientKeyDelivery with CSK encrypted with PSK
 * 5. Server confirms by sending hash of CSK encrypted with PSK
 * 6. Both discard PSK and store CSK for future communication
 */
class PairingClient {
    
    companion object {
        private const val TAG = "PairingClient"
        private const val TIMEOUT_MS = 30000 // 30 seconds
    }
    
    /**
     * Initiate pairing with desktop client
     * Returns intermediate state with socket and SAS for user verification
     */
    suspend fun initiatePairing(
        ipAddress: String,
        port: Int,
        clientPublicKeyHex: String
    ): PairingInitResult = withContext(Dispatchers.IO) {
        var socket: Socket? = null
        
        try {
            Log.d(TAG, "Connecting to $ipAddress:$port")
            
            // Connect to client (desktop)
            socket = Socket(InetAddress.getByName(ipAddress), port)
            socket.soTimeout = TIMEOUT_MS
            
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())
            
            // Step 1: Generate our (server's) ephemeral X25519 keypair
            val serverEphemeralKeyPair = X25519Keypair.generate()
            
            // Step 2: Send PairingHello message (protobuf) - SERVER SENDS FIRST
            val pairingHello = dev.rourunisen.tapauth.crypto.createPairingHello(
                version = 1,
                x25519PublicKey = serverEphemeralKeyPair.publicKey,
                ed25519PublicKey = serverEphemeralKeyPair.publicKey // TODO: Use proper Ed25519 for signing
            )
            
            // Send length-prefixed protobuf message
            output.writeInt(pairingHello.size)
            output.write(pairingHello)
            output.flush()
            
            Log.d(TAG, "Sent PairingHello (${pairingHello.size} bytes)")
            
            // Step 3: Receive PairingResponse message (protobuf) from CLIENT
            val responseSize = input.readInt()
            val responseBytes = ByteArray(responseSize)
            input.readFully(responseBytes)
            
            Log.d(TAG, "Received PairingResponse (${responseBytes.size} bytes)")
            
            // Parse PairingResponse
            val (clientVersion, clientX25519Key, clientEd25519Key) = 
                dev.rourunisen.tapauth.crypto.parsePairingResponse(responseBytes)
            
            Log.d(TAG, "Parsed PairingResponse: version=$clientVersion")
            
            // Step 4: Perform X25519 key exchange to compute PSK
            // PSK = ECDH(server_ephemeral_private, client_x25519_public_from_response)
            val clientPublicKey = clientX25519Key
            
            Log.d(TAG, "Server X25519 private key: ${serverEphemeralKeyPair.privateKey.joinToString("") { "%02x".format(it) }}")
            Log.d(TAG, "Server X25519 public key: ${serverEphemeralKeyPair.publicKey.joinToString("") { "%02x".format(it) }}")
            Log.d(TAG, "Client X25519 public key: ${clientPublicKey.joinToString("") { "%02x".format(it) }}")
            
            val psk = performKeyExchange(serverEphemeralKeyPair.privateKey, clientPublicKey)
            
            Log.d(TAG, "Computed PSK (${psk.size} bytes)")
            Log.d(TAG, "PSK (hex): ${psk.joinToString("") { "%02x".format(it) }}")
            
            // Step 5: Generate SAS for anti-MITM verification
            // SAS is derived from both public keys using the PSK
            val sas = generateSAS(psk, clientPublicKey, serverEphemeralKeyPair.publicKey)
            
            Log.d(TAG, "Generated SAS: $sas")
            
            // Return intermediate state - user must verify SAS before continuing
            PairingInitResult.AwaitingSASVerification(
                socket = socket,
                psk = psk,
                clientPublicKey = clientPublicKey,
                clientEd25519Key = clientEd25519Key,
                sas = sas
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Pairing initiation failed", e)
            socket?.close()
            PairingInitResult.Error(e.message ?: "Unknown error")
        }
    }
    
    /**
     * Complete pairing after user verifies SAS
     * Receives CSK from client, confirms with hash, stores paired device
     */
    suspend fun completePairing(
        socket: Socket,
        psk: ByteArray,
        clientPublicKey: ByteArray,
        clientEd25519Key: ByteArray,
        sasConfirmed: Boolean
    ): PairingResult = withContext(Dispatchers.IO) {
        try {
            if (!sasConfirmed) {
                socket.close()
                return@withContext PairingResult.Error("User rejected SAS verification")
            }
            
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())
            
            // Step 6: Receive PairingCskMessage (protobuf with CSK encrypted with PSK) from client
            val cskMessageSize = input.readInt()
            val cskMessageBytes = ByteArray(cskMessageSize)
            input.readFully(cskMessageBytes)
            
            Log.d(TAG, "Received PairingCskMessage (${cskMessageBytes.size} bytes)")
            
            // Parse PairingCskMessage to extract encrypted CSK
            val encryptedCsk = dev.rourunisen.tapauth.crypto.parsePairingCskMessage(cskMessageBytes)
            
            Log.d(TAG, "Extracted encrypted CSK (${encryptedCsk.size} bytes)")
            Log.d(TAG, "PSK (hex): ${psk.joinToString("") { "%02x".format(it) }}")
            Log.d(TAG, "Encrypted CSK (hex): ${encryptedCsk.joinToString("") { "%02x".format(it) }}")
            
            // Decrypt CSK using PSK with AES-256-GCM
            val csk = dev.rourunisen.tapauth.crypto.decryptWithPsk(
                psk = psk,
                context = "csk_exchange",
                ciphertext = encryptedCsk
            )
            
            Log.d(TAG, "Decrypted CSK (${csk.size} bytes)")
            
            // Step 7: Send PairingComplete message (protobuf) to confirm success
            val completeMessage = dev.rourunisen.tapauth.crypto.createPairingComplete(true)
            
            output.writeInt(completeMessage.size)
            output.write(completeMessage)
            output.flush()
            
            Log.d(TAG, "Sent PairingComplete message")
            
            // Step 8: Generate device ID and create paired device
            val deviceId = generateDeviceId()
            
            val pairedDevice = PairedDevice(
                deviceId = deviceId,
                publicKey = clientEd25519Key,  // Use Ed25519 key for identification
                csk = csk,  // Store the Client Symmetric Key
                displayName = "Desktop Computer",
                pairedAt = System.currentTimeMillis()
            )
            
            // Important: Discard PSK immediately
            psk.fill(0)
            
            Log.d(TAG, "Pairing completed successfully")
            
            PairingResult.Success(pairedDevice)
            
        } catch (e: Exception) {
            Log.e(TAG, "Pairing completion failed", e)
            PairingResult.Error(e.message ?: "Unknown error")
        } finally {
            socket.close()
        }
    }
    
    /**
     * Generate unique device ID for this pairing
     */
    private fun generateDeviceId(): String {
        val random = SecureRandom()
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytesToHex(bytes)
    }
    
    private fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
    
    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Intermediate result after initiating pairing
 * User must verify SAS before calling completePairing()
 */
sealed class PairingInitResult {
    data class AwaitingSASVerification(
        val socket: Socket,
        val psk: ByteArray,
        val clientPublicKey: ByteArray,
        val clientEd25519Key: ByteArray,
        val sas: String
    ) : PairingInitResult()
    data class Error(val message: String) : PairingInitResult()
}

/**
 * Final result after completing pairing
 */
sealed class PairingResult {
    data class Success(val device: PairedDevice) : PairingResult()
    data class Error(val message: String) : PairingResult()
}
