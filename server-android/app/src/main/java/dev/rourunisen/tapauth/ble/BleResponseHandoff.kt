package dev.rourunisen.tapauth.ble

import java.util.concurrent.ConcurrentHashMap

/**
 * Holds the answer built for an in-flight BLE challenge until the Client has it.
 *
 * The bytes are produced for the GATT handle that was live when the user answered the prompt, but
 * the Client can lose that link and reconnect before the answer reaches it: it keeps retransmitting
 * the same request, the scan reconnects, and the initial `CLIENT_COMMAND` read presents the same
 * challenge on a brand-new handle. The answer therefore has to outlive the handle it was first
 * written to, or the reconnect is answered by nothing more than a write to a dead handle.
 *
 * [record] runs before the first write. [redeliverOn] answers the only question the service asks
 * when a duplicate of the challenge arrives from the same peer: has the answer's handle been
 * replaced, and if so which retransmission loop has to stop before the bytes are written again. A
 * duplicate that arrives on the handle the bytes are already being written to needs nothing, and a
 * different peer is never handed these bytes at all.
 *
 * A record is dropped once the Client's confirmation proves the answer arrived ([finish]), once its
 * peer is given up on ([abandonPeer]), when the service goes away ([clear]), and — for a link whose
 * teardown is never reported — once it is older than [MAX_AGE_MS].
 */
internal class BleResponseHandoff<H : Any>(
    private val elapsedMillis: () -> Long,
) {

    /**
     * The bytes built for [challengeKey], the peer they belong to, and the handle they are being
     * written to right now.
     */
    class Delivery<H : Any>
    internal constructor(
        val challengeKey: String,
        val peerAddress: String,
        val response: ByteArray,
        val handle: H,
        /** When this record was made, so an answer nobody collected can expire. */
        internal val recordedAtMillis: Long,
    ) {
        /** Stops the retransmission loop writing [handle]; registered when that loop starts. */
        @Volatile private var cancelRetransmission: (() -> Unit)? = null

        /**
         * Set when [redeliverOn] replaced this delivery with one aimed at a new handle, so a loop
         * that had not taken its first step yet can bail out instead of writing to the dead one.
         */
        @Volatile
        internal var superseded: Boolean = false
            private set

        internal fun onRetransmission(cancel: () -> Unit) {
            cancelRetransmission = cancel
        }

        internal fun supersede() {
            superseded = true
        }

        internal fun takeCanceller(): (() -> Unit)? = cancelRetransmission.also {
            cancelRetransmission = null
        }
    }

    /**
     * An answer that has to be written again on [delivery]'s handle, plus the loop that was writing
     * the previous handle and must be stopped first.
     */
    class Redelivery<H : Any>(
        val delivery: Delivery<H>,
        val cancelPrevious: (() -> Unit)?,
    )

    private val pending = ConcurrentHashMap<String, Delivery<H>>()

    /** Number of answers currently held (tests and diagnostics). */
    val pendingCount: Int
        get() = pending.size

    /** Hold [response] for [challengeKey], written to [handle] on behalf of [peerAddress]. */
    fun record(
        challengeKey: String,
        peerAddress: String,
        handle: H,
        response: ByteArray,
    ): Delivery<H> {
        pruneExpired()
        val delivery = Delivery(challengeKey, peerAddress, response, handle, elapsedMillis())
        pending[challengeKey] = delivery
        return delivery
    }

    /**
     * Decide what a duplicate of [challengeKey] from [peerAddress] arriving on [handle] means.
     *
     * Returns null when there is nothing to write again — no answer was built, the answer belongs
     * to another peer, or it is already being written to exactly this handle. Otherwise the answer
     * is re-aimed at [handle] and returned together with the stop handle of the loop that was
     * writing the previous one, which must be invoked before the new loop starts.
     */
    fun redeliverOn(challengeKey: String, peerAddress: String, handle: H): Redelivery<H>? {
        pruneExpired()
        var redelivery: Redelivery<H>? = null
        pending.compute(challengeKey) { _, existing ->
            if (
                existing == null ||
                    existing.peerAddress != peerAddress ||
                    existing.handle === handle
            ) {
                existing
            } else {
                existing.supersede()
                val next =
                    Delivery(
                        challengeKey,
                        peerAddress,
                        existing.response,
                        handle,
                        existing.recordedAtMillis,
                    )
                redelivery = Redelivery(next, existing.takeCanceller())
                next
            }
        }
        return redelivery
    }

    /**
     * Forget [delivery]: the Client confirmed it, so nothing is owed for that challenge any more.
     *
     * Only an identity match is removed, so a loop that finishes late (or is cancelled because a
     * re-delivery took over) cannot drop the delivery that replaced it.
     */
    fun finish(delivery: Delivery<H>) {
        delivery.takeCanceller()
        pending.remove(delivery.challengeKey, delivery)
    }

    /** Drop every answer held for [peerAddress]: its link is gone and is not coming back. */
    fun abandonPeer(peerAddress: String) {
        pending.entries.removeIf { it.value.peerAddress == peerAddress }
    }

    /** Drop every answer; the service is going away. */
    fun clear() {
        pending.clear()
    }

    /**
     * Drop answers that outlived any plausible delivery window.
     *
     * The grace-expiry release is what normally retires them; this bounds the leak for a link whose
     * teardown is never reported, and is far longer than any retransmission window, so a live
     * answer is never pruned.
     */
    private fun pruneExpired() {
        val cutoff = elapsedMillis() - MAX_AGE_MS
        pending.entries.removeIf { it.value.recordedAtMillis < cutoff }
    }

    companion object {
        /** Longer than the retransmission window plus the reconnection grace. */
        private const val MAX_AGE_MS = 600_000L
    }
}
