package dev.rourunisen.tapauth.service

import android.util.Log
import dev.rourunisen.tapauth.data.TransportType
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe manager to ensure only one transport channel (UDP or BLE) is used per authentication
 * session. This prevents duplicate responses when both channels are available.
 *
 * The first transport to claim a challenge "wins" and the other is ignored.
 */
class TransportLockManager private constructor() {

    private data class TransportLock(val transport: TransportType, val timestamp: Long)

    // Map challenge (as hex string) to the transport that claimed it
    private val challengeLocks = ConcurrentHashMap<String, TransportLock>()

    companion object {
        private const val TAG = "TransportLockManager"

        // Locks expire after 2 minutes to prevent memory leaks
        private const val LOCK_EXPIRY_MS = 120_000L

        @Volatile private var instance: TransportLockManager? = null

        fun getInstance(): TransportLockManager {
            return instance
                ?: synchronized(this) { instance ?: TransportLockManager().also { instance = it } }
        }
    }

    /**
     * Try to claim this challenge for the given transport. Returns true if successful (first to
     * claim), false if already claimed by another transport.
     */
    fun tryClaimTransport(challenge: ByteArray, transport: TransportType): Boolean {
        val challengeHex = challenge.toHex()
        val now = android.os.SystemClock.elapsedRealtime()

        // Clean up expired locks
        cleanupExpiredLocks(now)

        // Try to claim the lock atomically
        val existingLock = challengeLocks.putIfAbsent(challengeHex, TransportLock(transport, now))

        if (existingLock == null) {
            // Successfully claimed - we're first
            Log.d(TAG, "Transport $transport claimed challenge ${challengeHex.take(16)}...")
            return true
        }

        // Check if existing lock is expired
        if (now - existingLock.timestamp > LOCK_EXPIRY_MS) {
            // Expired, try to replace it
            val replaced =
                challengeLocks.replace(challengeHex, existingLock, TransportLock(transport, now))
            if (replaced) {
                Log.d(
                    TAG,
                    "Transport $transport claimed expired challenge ${challengeHex.take(16)}...",
                )
                return true
            }
        }

        // Already claimed by another transport
        if (existingLock.transport != transport) {
            Log.i(
                TAG,
                "Transport $transport blocked - challenge ${challengeHex.take(16)}... already claimed by ${existingLock.transport}",
            )
            return false
        }

        // Already claimed by same transport (retransmission) - allow
        return true
    }

    /** Check if a challenge is claimed by a specific transport */
    fun isClaimedBy(challenge: ByteArray, transport: TransportType): Boolean {
        val challengeHex = challenge.toHex()
        val lock = challengeLocks[challengeHex] ?: return false

        // Check expiry
        val now = android.os.SystemClock.elapsedRealtime()
        if (now - lock.timestamp > LOCK_EXPIRY_MS) {
            challengeLocks.remove(challengeHex)
            return false
        }

        return lock.transport == transport
    }

    /** Release the lock for a challenge (called when authentication completes) */
    fun releaseLock(challenge: ByteArray) {
        val challengeHex = challenge.toHex()
        val removed = challengeLocks.remove(challengeHex)
        if (removed != null) {
            Log.d(
                TAG,
                "Released lock for challenge ${challengeHex.take(16)}... (transport: ${removed.transport})",
            )
        }
    }

    /** Clean up expired locks to prevent memory leaks */
    private fun cleanupExpiredLocks(now: Long) {
        val iterator = challengeLocks.entries.iterator()
        var removedCount = 0

        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.timestamp > LOCK_EXPIRY_MS) {
                iterator.remove()
                removedCount++
            }
        }

        if (removedCount > 0) {
            Log.d(TAG, "Cleaned up $removedCount expired transport locks")
        }
    }

    /** Get current number of active locks (for debugging) */
    fun getActiveLockCount(): Int = challengeLocks.size

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
