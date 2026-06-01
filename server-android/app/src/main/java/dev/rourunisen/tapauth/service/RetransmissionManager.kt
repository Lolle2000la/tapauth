package dev.rourunisen.tapauth.service

import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*

/**
 * Manages retransmission of AuthenticationGrant and AuthenticationDenial messages according to
 * authentication-flow.md Section 2.3.
 *
 * Per specification:
 * - Server retransmits Grant/Denial every 500ms until GrantConfirmation received
 * - Retransmission stops on GrantConfirmation or timeout
 */
class RetransmissionManager {

    private val activeRetransmissions = ConcurrentHashMap<String, Job>()

    companion object {
        private const val TAG = "RetransmissionManager"
        private const val RETRANSMISSION_INTERVAL_MS = 500L // Fixed 500ms per spec
        // Retransmission timeout: 10 seconds provides ~20 retry attempts
        // This is sufficient for local network delivery even with poor conditions
        // The session timeout (120s) governs user interaction time separately
        private const val MAX_RETRANSMISSION_DURATION_MS = 10_000L
        // With 500ms interval and 10s timeout, max 20 attempts possible
        private const val MAX_RETRANSMISSION_ATTEMPTS = 20

        @Volatile private var instance: RetransmissionManager? = null

        fun getInstance(): RetransmissionManager {
            return instance
                ?: synchronized(this) { instance ?: RetransmissionManager().also { instance = it } }
        }
    }

    /** Data class for UDP retransmission */
    data class UdpRetransmissionRequest(
        val challenge: ByteArray,
        val responseData: ByteArray,
        val socket: DatagramSocket,
        val destinationAddress: InetAddress,
        val destinationPort: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as UdpRetransmissionRequest
            return challenge.contentEquals(other.challenge)
        }

        override fun hashCode(): Int {
            return challenge.contentHashCode()
        }
    }

    /** Data class for BLE retransmission */
    data class BleRetransmissionRequest(
        val challenge: ByteArray,
        val responseData: ByteArray,
        val sendCallback: suspend (ByteArray) -> Unit,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as BleRetransmissionRequest
            return challenge.contentEquals(other.challenge)
        }

        override fun hashCode(): Int {
            return challenge.contentHashCode()
        }
    }

    /** Start retransmitting a grant/denial over UDP */
    fun startUdpRetransmission(scope: CoroutineScope, request: UdpRetransmissionRequest) {
        val challengeKey = request.challenge.toHex()

        // Cancel any existing retransmission for this challenge
        stopRetransmission(challengeKey)

        Log.d(TAG, "Starting UDP retransmission for challenge ${challengeKey.take(16)}...")

        val job =
            scope.launch {
                var attempts = 0
                val startTime = android.os.SystemClock.elapsedRealtime()

                while (isActive && attempts < MAX_RETRANSMISSION_ATTEMPTS) {
                    try {
                        // Send the response
                        val packet =
                            DatagramPacket(
                                request.responseData,
                                request.responseData.size,
                                request.destinationAddress,
                                request.destinationPort,
                            )
                        request.socket.send(packet)
                        attempts++

                        val elapsed = android.os.SystemClock.elapsedRealtime() - startTime
                        Log.d(TAG, "UDP retransmission attempt #$attempts (elapsed=${elapsed}ms)")

                        // Check if we've exceeded max duration or attempts
                        if (elapsed >= MAX_RETRANSMISSION_DURATION_MS) {
                            Log.w(TAG, "UDP retransmission timeout after ${elapsed}ms, stopping")
                            break
                        }

                        if (attempts >= MAX_RETRANSMISSION_ATTEMPTS) {
                            Log.w(
                                TAG,
                                "UDP retransmission max attempts reached ($attempts), stopping",
                            )
                            break
                        }

                        // Wait for the fixed interval
                        delay(RETRANSMISSION_INTERVAL_MS)
                    } catch (e: Exception) {
                        if (isActive) {
                            Log.e(TAG, "Error during UDP retransmission", e)
                        }
                        break
                    }
                }

                // Clean up
                activeRetransmissions.remove(challengeKey)
                Log.d(
                    TAG,
                    "UDP retransmission completed for challenge ${challengeKey.take(16)}... (attempts=$attempts)",
                )
            }

        activeRetransmissions[challengeKey] = job
    }

    /** Start retransmitting a grant/denial over BLE */
    fun startBleRetransmission(scope: CoroutineScope, request: BleRetransmissionRequest) {
        val challengeKey = request.challenge.toHex()

        // Cancel any existing retransmission for this challenge
        stopRetransmission(challengeKey)

        Log.d(TAG, "Starting BLE retransmission for challenge ${challengeKey.take(16)}...")

        val job =
            scope.launch {
                var attempts = 0
                val startTime = android.os.SystemClock.elapsedRealtime()

                while (isActive && attempts < MAX_RETRANSMISSION_ATTEMPTS) {
                    try {
                        // Send the response via callback
                        request.sendCallback(request.responseData)
                        attempts++

                        val elapsed = android.os.SystemClock.elapsedRealtime() - startTime
                        Log.d(TAG, "BLE retransmission attempt #$attempts (elapsed=${elapsed}ms)")

                        // Check if we've exceeded max duration or attempts
                        if (elapsed >= MAX_RETRANSMISSION_DURATION_MS) {
                            Log.w(TAG, "BLE retransmission timeout after ${elapsed}ms, stopping")
                            break
                        }

                        if (attempts >= MAX_RETRANSMISSION_ATTEMPTS) {
                            Log.w(
                                TAG,
                                "BLE retransmission max attempts reached ($attempts), stopping",
                            )
                            break
                        }

                        // Wait for the fixed interval
                        delay(RETRANSMISSION_INTERVAL_MS)
                    } catch (e: Exception) {
                        if (isActive) {
                            Log.e(TAG, "Error during BLE retransmission", e)
                        }
                        break
                    }
                }

                // Clean up
                activeRetransmissions.remove(challengeKey)
                Log.d(
                    TAG,
                    "BLE retransmission completed for challenge ${challengeKey.take(16)}... (attempts=$attempts)",
                )
            }

        activeRetransmissions[challengeKey] = job
    }

    /** Stop retransmission for a specific challenge Call this when GrantConfirmation is received */
    fun stopRetransmission(challenge: ByteArray) {
        stopRetransmission(challenge.toHex())
    }

    private fun stopRetransmission(challengeKey: String) {
        activeRetransmissions.remove(challengeKey)?.let { job ->
            job.cancel()
            Log.d(TAG, "Stopped retransmission for challenge ${challengeKey.take(16)}...")
        }
    }

    /** Stop all active retransmissions */
    fun stopAll() {
        val count = activeRetransmissions.size
        activeRetransmissions.values.forEach { it.cancel() }
        activeRetransmissions.clear()
        Log.d(TAG, "Stopped all retransmissions ($count active)")
    }

    /** Get statistics for debugging */
    fun getStats(): Map<String, Any> {
        return mapOf("active_retransmissions" to activeRetransmissions.size)
    }
}

/** Extension function to convert ByteArray to hex string */
private fun ByteArray.toHex(): String {
    return joinToString("") { "%02x".format(it) }
}
