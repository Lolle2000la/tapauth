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

    /**
     * Hold [response] for [challengeKey] on behalf of [peerAddress], aimed at the link that has to
     * carry it.
     *
     * [capturedHandle] is the handle the answer was built for — the one the service's request
     * callback closed over, i.e. the handle the prompt was raised on. [liveHandle] is the handle
     * [challengeKey] is tracked on at the moment the answer is recorded, or null when none is
     * known.
     *
     * The two differ when the prompt outlived the link it was raised on: the Client dropped that
     * GATT connection and reconnected on a new handle *before* the user answered, so the captured
     * handle is already closed. Aiming the answer there writes to a dead handle, the write fails,
     * and the Client — which only reads its request on connect — never hears the verdict. The live
     * handle therefore wins whenever it is known. The captured handle is the fallback for an answer
     * built while the link is still down: there the reconnect's duplicate of the challenge is what
     * re-aims the bytes ([redeliverOn]).
     */
    fun record(
        challengeKey: String,
        peerAddress: String,
        capturedHandle: H,
        liveHandle: H?,
        response: ByteArray,
    ): Delivery<H> {
        pruneExpired()
        val delivery =
            Delivery(
                challengeKey,
                peerAddress,
                response,
                liveHandle ?: capturedHandle,
                elapsedMillis(),
            )
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
     * Retire [delivery] once the Client's [confirmed] it, so nothing is owed for that challenge any
     * more.
     *
     * Retirement is conditioned on the confirmation because every other way a delivery loop can end
     * — the link dropped, the retransmission window elapsed, a re-delivery cancelled it — leaves
     * the Client possibly still waiting, and only the held bytes can answer its next copy of the
     * request. An unconfirmed end therefore keeps the record: the reconnect's duplicate re-delivers
     * it, and [abandonPeer] or [pruneExpired] eventually bounds it.
     *
     * Only an identity match is removed, so a loop that finishes late (or is cancelled because a
     * re-delivery took over) cannot drop the delivery that replaced it.
     *
     * @return true when the delivery was retired, false when it was kept for a possible
     *   re-delivery.
     */
    fun finish(delivery: Delivery<H>, confirmed: Boolean): Boolean {
        if (!confirmed) return false
        delivery.takeCanceller()
        pending.remove(delivery.challengeKey, delivery)
        return true
    }

    /** Drop every answer held for [peerAddress]: its link is gone and is not coming back. */
    fun abandonPeer(peerAddress: String) {
        pending.entries.removeIf { it.value.peerAddress == peerAddress }
    }

    /**
     * Whether an answer is held for [challengeKey] on [peerAddress]'s behalf.
     *
     * The duplicate-in-flight decision needs this to tell an open prompt from one that was already
     * answered: a release drops the prompt while the claim stays for a retry, and only the second
     * case may raise a new prompt instead of writing the held bytes again.
     */
    fun holdsAnswerFor(challengeKey: String, peerAddress: String): Boolean =
        pending[challengeKey]?.peerAddress == peerAddress

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
