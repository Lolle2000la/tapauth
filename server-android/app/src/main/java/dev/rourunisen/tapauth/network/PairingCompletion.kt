package dev.rourunisen.tapauth.network

import kotlinx.coroutines.delay

/**
 * The completion half of a pairing: build the proof, persist the device, send
 * `PairingConfirmServer`, then keep answering `PairingConfirmClient` retransmissions for a bounded
 * linger.
 *
 * ### Why the burst is not enough
 *
 * The desktop re-sends the same `PairingConfirmClient` every 500 ms until it verifies a
 * `PairingConfirmServer` (`tapauthd/src/pairing.rs`, `RETRANSMIT_INTERVAL`), and it runs that clock
 * from its own side: if every datagram of the burst is dropped, the first retry is 500 ms away and
 * every later one lands on a socket this phone has already closed — the phone is paired and the
 * desktop never is (ICMP port-unreachable on every retry). So the link stays open for [lingerMs]
 * after the burst and each retransmission is answered with the same bytes; calling
 * `create_confirm_server` again would draw a fresh nonce and be a different message.
 *
 * ### Ordering
 *
 * [confirm] builds the proof, persists, sends the burst, then lingers. Persisting never waits for
 * the linger and the linger never repeats it, gates it or reports it: a retransmission during the
 * linger is answered and nothing else happens. A `PairingAbort` during the linger is ignored — the
 * pairing is already durable, so it must neither be un-persisted nor turned into a failure.
 *
 * ### Testability
 *
 * The duration, the clock and the slice length are constructor parameters, so a unit test can drive
 * the whole window without waiting for it. Every wait is `delay`/suspend, never a blocking sleep,
 * so the caller's dispatcher stays free.
 */
internal class PairingCompletion(
    private val lingerMs: Long = DEFAULT_LINGER_MS,
    private val nowMs: () -> Long = System::currentTimeMillis,
    private val sliceMs: Long = DEFAULT_SLICE_MS,
) {
    companion object {
        /**
         * How long the link keeps answering after the burst.
         *
         * Covers two desktop retries (at +500 ms and +1000 ms from a lost burst) with margin, and
         * so also a first retransmission that a slow Wi-Fi link delivers late.
         */
        const val DEFAULT_LINGER_MS = 1_250L

        /** One receive slice inside the linger, so an abort or a close is noticed promptly. */
        const val DEFAULT_SLICE_MS = 200L
    }

    /**
     * Build the completion proof, persist [persist]'s device, send the burst, then linger.
     *
     * @param burstDelaysMs delays before each `PairingConfirmServer` send, relative to the first
     *   one (`listOf(0, 100, 150)` is a send at 0 ms, 100 ms and 250 ms)
     * @param buildConfirmation the serialized `PairingConfirmServer`, built once and re-sent
     *   verbatim for every retransmission
     * @param persist saves the device; called exactly once, before anything is sent
     * @param send writes one frame to the locked transport
     * @param receive the next session frame, or null once the budget it was given is spent. The
     *   budget is a total for the call, not a per-frame slice, so a stream of frames belonging to
     *   another session cannot keep this from returning and the linger's own clock check from
     *   running
     * @param isRetransmission whether a frame is a `PairingConfirmClient` for this session
     * @param isClosed whether the session has been closed (the linger then ends at once)
     * @return what [persist] returned
     */
    suspend fun <T> confirm(
        burstDelaysMs: List<Long>,
        buildConfirmation: () -> ByteArray,
        persist: suspend () -> T,
        send: suspend (ByteArray) -> Unit,
        receive: suspend (Long) -> ByteArray?,
        isRetransmission: (ByteArray) -> Boolean,
        isClosed: () -> Boolean = { false },
    ): T {
        val confirmation = buildConfirmation()
        val persisted = persist()

        for (delayMs in burstDelaysMs) {
            if (delayMs > 0) delay(delayMs)
            send(confirmation)
        }

        linger(confirmation, send, receive, isRetransmission, isClosed)
        return persisted
    }

    private suspend fun linger(
        confirmation: ByteArray,
        send: suspend (ByteArray) -> Unit,
        receive: suspend (Long) -> ByteArray?,
        isRetransmission: (ByteArray) -> Boolean,
        isClosed: () -> Boolean,
    ) {
        val deadline = nowMs() + lingerMs
        while (!isClosed()) {
            val remaining = deadline - nowMs()
            if (remaining <= 0) return
            // Never more than what is left of the linger: the budget is a total, so a peer that
            // keeps sending frames of another session cannot push this check out.
            val packet = receive(minOf(sliceMs, remaining)) ?: continue
            // Anything else — a keepalive, a duplicate of the provision payload already
            // persisted, an authenticated abort — is dropped: the pairing is concluded.
            if (isRetransmission(packet)) send(confirmation)
        }
    }
}
