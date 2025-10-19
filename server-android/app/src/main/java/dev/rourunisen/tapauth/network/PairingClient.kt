package dev.rourunisen.tapauth.network

import android.util.Log
import dev.rourunisen.tapauth.crypto.Ed25519Keypair
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
            val serverEphemeralKeyPair = Ed25519Keypair.generate()
            
            // Step 2: Send PairingHandshake - our ephemeral public key
            output.writeInt(serverEphemeralKeyPair.publicKey.size)
            output.write(serverEphemeralKeyPair.publicKey)
            output.flush()
            
            Log.d(TAG, "Sent server ephemeral public key (${serverEphemeralKeyPair.publicKey.size} bytes)")
            
            // Step 3: Perform X25519 key exchange to compute PSK
            // PSK = ECDH(server_ephemeral_private, client_public_from_qr)
            val clientPublicKey = hexToBytes(clientPublicKeyHex)
            val psk = performKeyExchange(serverEphemeralKeyPair.privateKey, clientPublicKey)
            
            Log.d(TAG, "Computed PSK (${psk.size} bytes)")
            
            // Step 4: Generate SAS for anti-MITM verification
            // SAS is derived from both public keys using the PSK
            val sas = generateSAS(psk, clientPublicKey, serverEphemeralKeyPair.publicKey)
            
            Log.d(TAG, "Generated SAS: $sas")
            
            // Return intermediate state - user must verify SAS before continuing
            PairingInitResult.AwaitingSASVerification(
                socket = socket,
                psk = psk,
                clientPublicKey = clientPublicKey,
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
        sasConfirmed: Boolean
    ): PairingResult = withContext(Dispatchers.IO) {
        try {
            if (!sasConfirmed) {
                socket.close()
                return@withContext PairingResult.Error("User rejected SAS verification")
            }
            
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())
            
            // Step 5: Receive ClientKeyDelivery (CSK encrypted with PSK)
            val encryptedCskSize = input.readInt()
            val encryptedCsk = ByteArray(encryptedCskSize)
            input.readFully(encryptedCsk)
            
            Log.d(TAG, "Received encrypted CSK (${encryptedCsk.size} bytes)")
            
            // Decrypt CSK using PSK with AES-256-GCM
            val csk = dev.rourunisen.tapauth.crypto.decryptWithPsk(
                psk = psk,
                context = "csk_delivery",
                ciphertext = encryptedCsk
            )
            
            Log.d(TAG, "Decrypted CSK (${csk.size} bytes)")
            
            // Step 6: Compute SHA-256 hash of CSK
            val cskHashHex = dev.rourunisen.tapauth.crypto.sha256(csk)
            val cskHash = hexToBytes(cskHashHex)
            
            Log.d(TAG, "Computed CSK hash: $cskHashHex")
            
            // Encrypt hash with PSK and send PairingConfirmation
            val encryptedHash = dev.rourunisen.tapauth.crypto.encryptWithPsk(
                psk = psk,
                context = "pairing_confirmation",
                plaintext = cskHash
            )
            
            output.writeInt(encryptedHash.size)
            output.write(encryptedHash)
            output.flush()
            
            Log.d(TAG, "Sent pairing confirmation")
            
            // Step 7: Generate device ID and create paired device
            val deviceId = generateDeviceId()
            
            val pairedDevice = PairedDevice(
                deviceId = deviceId,
                publicKey = clientPublicKey,
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
