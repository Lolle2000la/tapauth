package dev.rourunisen.tapauth.network

/**
 * Waits for the next pairing frame on a source that is notified *and* readable, with a periodic
 * read fallback and a first-wins rule between the two.
 *
 * ### Why a read fallback
 *
 * The pairing characteristic is `WRITE | NOTIFY | READ` and the desktop keeps the last frame it
 * wrote in the readable value (`docs/design-documents/protocol/ble-gatt-specification.md` §2: "plus
 * updates readable value as fallback"). A notification is therefore an optimisation, not the only
 * path: an ATT notification can be dropped when the link is busy, and without a poll the pairing
 * would sit on a frame that is still sitting in that readable value until its 30 s (or 120 s)
 * deadline expires. So whenever no notification arrives for [intervalMs], the caller's [readValue]
 * is invoked once.
 *
 * ### First wins
 *
 * The two sources can both carry the same frame — the notification, and the readable value it
 * updates. A poll that repeats the frame the waiter already received is dropped, and a notification
 * that is already queued when a read becomes due wins over the poll (a poll can only ever return
 * the value the characteristic had *before* that notification). A notification that arrives while a
 * read is in flight is delivered as the next frame: byte-identical frames are exactly what the
 * desktop's verbatim retransmission looks like, so they cannot be told apart, and the pairing state
 * machine tolerates a repeated frame by design.
 *
 * ### Testability
 *
 * Both the interval and the clock are constructor parameters, and every source is a lambda, so the
 * whole wait is driven from a unit test with a fake clock and no GATT stack.
 */
internal class PairingReadFallback(
    private val intervalMs: Long = DEFAULT_INTERVAL_MS,
    private val nowMs: () -> Long = System::currentTimeMillis,
) {
    companion object {
        /**
         * How often the readable pairing value is polled while no notification arrives.
         *
         * Short enough to stay well inside the desktop's 500 ms `PairingConfirmClient`
         * retransmission interval, long enough that a healthy link never polls at all.
         */
        const val DEFAULT_INTERVAL_MS = 500L
    }

    /** When the next fallback read is due, or null before the first wait. */
    private var nextReadAtMs: Long? = null

    /** The last frame handed to the waiter, so a poll repeating it is not delivered twice. */
    private var lastDelivered: ByteArray? = null

    /**
     * Wait for the next frame, polling whenever notifications stop arriving.
     *
     * @param isClosed whether the link is gone; the wait then returns null at once
     * @param awaitNotification the next notified frame, or null when [timeoutMs]'s slice expired
     * @param pollNotification a frame already queued by a notification, or null
     * @param readValue one fallback read of the characteristic's current value, or null
     * @return the first frame of either source, or null once [isClosed] reports the link is gone
     */
    suspend fun awaitFrame(
        isClosed: () -> Boolean,
        awaitNotification: suspend (timeoutMs: Long) -> ByteArray?,
        pollNotification: () -> ByteArray?,
        readValue: suspend () -> ByteArray?,
    ): ByteArray? {
        // The schedule is armed once and then kept across waits: the caller waits in short slices
        // (200 ms), so re-arming per slice would push the read out past every slice and it would
        // never happen.
        if (nextReadAtMs == null) nextReadAtMs = nowMs() + intervalMs

        while (!isClosed()) {
            val notified = awaitNotification(msUntilRead())
            if (notified != null) {
                delivered(notified)
                return notified
            }
            if (!takeReadSlot()) continue
            // A notification that reached the queue while the read became due is newer than
            // anything a poll can return, so it wins.
            val queued = pollNotification()
            if (queued != null) {
                delivered(queued)
                return queued
            }
            val polled = readValue() ?: continue
            if (!isNew(polled)) continue
            return polled
        }
        return null
    }

    /** Milliseconds until the fallback read is due; 0 when it is due or overdue. */
    fun msUntilRead(): Long {
        val due = nextReadAtMs ?: return intervalMs
        return (due - nowMs()).coerceAtLeast(0)
    }

    /** Whether a fallback read is due now; a due read re-arms the interval. */
    fun takeReadSlot(): Boolean {
        val due = nextReadAtMs ?: return false
        val now = nowMs()
        if (now < due) return false
        nextReadAtMs = now + intervalMs
        return true
    }

    /** Whether a polled [value] is new relative to what the waiter already received. */
    fun isNew(value: ByteArray): Boolean {
        val previous = lastDelivered
        if (previous != null && previous.contentEquals(value)) return false
        lastDelivered = value
        return true
    }

    private fun delivered(value: ByteArray) {
        lastDelivered = value
        nextReadAtMs = nowMs() + intervalMs
    }
}
