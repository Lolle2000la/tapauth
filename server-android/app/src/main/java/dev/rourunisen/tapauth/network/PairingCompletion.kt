package dev.rourunisen.tapauth.network

import android.util.Log
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

/**
 * The slice of the Rust pairing session that the confirmation phase needs.
 *
 * The generated UniFFI object's methods live in `libshared.so`, which `./gradlew test` cannot load,
 * so the phase talks to this interface and [PairingSession] adapts the live session onto it.
 * Keeping it this narrow is what lets a JVM test drive the *production* completion wiring — the
 * frame intake, the retransmission predicate, the linger and the conclusion — with fake crypto
 * instead of a hand-written copy of that wiring.
 */
internal interface PairingConfirmationCrypto {
    /**
     * Build the serialized `PairingConfirmServer` for [csk].
     *
     * Called once per pairing: a retransmission must re-send these exact bytes, because a second
     * call would draw a fresh AEAD nonce and produce a different message.
     */
    fun createConfirmServer(csk: ByteArray): ByteArray

    /**
     * Decrypt a `PairingConfirmClient`.
     *
     * @return the decrypted CSK, or null when [packet] is anything else — a keepalive, an abort, a
     *   frame that does not decrypt. Non-null therefore means "a retransmission to answer".
     */
    fun processConfirmClient(packet: ByteArray): ByteArray?

    /**
     * Conclude the session: zeroize the directional keys, the transcript hash and the ephemeral
     * X25519 secret. Every later call reports `State`. Idempotent.
     */
    fun conclude()
}

/**
 * The mutually exclusive commit/close boundary of one pairing.
 *
 * A pairing ends in exactly one of two ways, and they must not both happen:
 *
 * * the device record begins to be written ([beginCommit]) — from then on the desktop has to be
 *   told the pairing succeeded, so a close may only ask;
 * * the session is released ([requestClose]) — then nothing may be persisted and nothing sent.
 *
 * Two independent flags cannot express that, whichever way they are read: a close can observe "not
 * committing yet", a commit can observe "not closed yet", and both proceed. The close then cancels
 * the session's coroutine while `persist()` is suspended, so the device is on disk with no
 * `PairingConfirmServer` behind it — the phone is paired and the desktop times out retrying into a
 * socket this side already closed. Hence one lock over one three-state field:
 * ```
 * Open --beginCommit()--> Committed   (a close is deferred; the confirmation runs to its end)
 * Open --requestClose()-> Closed      (a later beginCommit() is refused: nothing happens)
 * ```
 *
 * Both outcomes are terminal, so the two transitions can never both succeed. `requestClose()` after
 * the commit keeps answering "deferred", and `beginCommit()` after a deferred close keeps answering
 * "the close did not win": neither transition can be undone by the other.
 */
internal class PairingCommitLatch {
    private enum class State {
        /** Neither decision has been taken. */
        Open,

        /** The device record is being written; the confirmation must finish. */
        Committed,

        /** The session is being released; nothing may be persisted or sent. */
        Closed,
    }

    private val lock = Any()

    private var state = State.Open

    /**
     * Take the commit side of the boundary, immediately before the device record is written.
     *
     * @return false when a close already won, in which case the caller must not persist and must
     *   not send anything; true otherwise (including a repeat call, because the close did not win)
     */
    fun beginCommit(): Boolean =
        synchronized(lock) {
            if (state == State.Closed) false
            else {
                state = State.Committed
                true
            }
        }

    /**
     * Ask to release the session.
     *
     * @return true when the close is **deferred** — a commit is in flight, so the confirmation
     *   burst and linger must still run and the session releases itself afterwards; false when the
     *   close may release now, either because it won the boundary just now (nothing was or will be
     *   persisted) or because it had already won
     */
    fun requestClose(): Boolean =
        synchronized(lock) {
            when (state) {
                State.Open -> {
                    state = State.Closed
                    false
                }
                State.Committed -> true
                State.Closed -> false
            }
        }
}

/**
 * The confirmation phase of a pairing over one locked transport: everything
 * [PairingSession.finishPairing] does that needs no Android `Context`.
 *
 * It owns the four things that must stay in one place for the desktop's retransmissions to be
 * answered correctly:
 *
 * * the frame intake, [awaitOwnFrame] — the same budgeted read every other phase uses, so a
 *   foreign-frame stream cannot keep the linger from re-reading its own clock;
 * * the retransmission predicate, which consults [PairingConfirmationCrypto.processConfirmClient]
 *   rather than comparing bytes, because the desktop re-sends the frame verbatim but a keepalive or
 *   an abort must not be answered with a second proof;
 * * the linger itself ([PairingCompletion]), reached only through the injected instance;
 * * the conclusion, [PairingConfirmationCrypto.conclude], which runs after the linger so a
 *   retransmitted `PairingConfirmClient` can still be decrypted while it lasts;
 * * the commit boundary ([PairingCommitLatch]), taken before anything is persisted and before the
 *   first send, so a close either defers to the whole confirmation or prevents all of it.
 *
 * Production builds it over the live Rust session; a unit test builds the same object over a fake
 * link and fake crypto, so a regression in any of them is caught by the same code path that ships.
 *
 * @param belongsToSession whether a frame carries this session's id (Rust's
 *   `pairingPacketSessionId` in production); shared with every other phase through
 *   [PairingSession]'s frame intake
 */
internal class PairingConfirmPhase(
    private val crypto: PairingConfirmationCrypto,
    private val frameReader: PairingFrameReader,
    private val completion: PairingCompletion,
    private val belongsToSession: (ByteArray) -> Boolean,
) {
    private companion object {
        /** The session's own tag: this is its frame intake. */
        const val TAG = "PairingSession"
    }

    /**
     * The next frame of this session on [link], within [budgetMs] in total.
     *
     * See [PairingFrameReader.awaitOwnFrame]: dropped foreign frames are paid for out of the same
     * budget, so the caller's own deadline is re-read no matter what the peer sends.
     *
     * @param budgetMs how long this call may wait in total, dropped frames included
     */
    suspend fun awaitOwnFrame(link: PairingLink, budgetMs: Long): ByteArray? =
        frameReader.awaitOwnFrame(
            budgetMs = budgetMs,
            receive = { sliceMs -> link.receive(sliceMs) },
            belongsToSession = belongsToSession,
        )

    /**
     * Persist [persist]'s device, confirm to the desktop, linger, then conclude the session.
     *
     * @param link the locked transport; the winner of the response race
     * @param csk the Client Symmetric Key from the provision payload, which the proof is signed
     *   over
     * @param burstDelaysMs delays of the `PairingConfirmServer` burst, relative to the first send
     * @param persist saves the device; called exactly once, before anything is sent, and never at
     *   all when [beginCommit] refuses
     * @param beginCommit the commit transition of [PairingCommitLatch], called synchronously right
     *   before the confirmation sequence: from the moment it returns true a close must not cut the
     *   confirmation, and when it returns false the session was already released, so nothing may be
     *   persisted and nothing sent. There is no suspension point between it and [persist], so no
     *   close can slip in between the two.
     * @param isClosed whether the session has been closed; the linger then ends at once
     * @return what [persist] returned, or null when [beginCommit] refused the commit
     */
    suspend fun <T : Any> finish(
        link: PairingLink,
        csk: ByteArray,
        burstDelaysMs: List<Long>,
        persist: suspend () -> T,
        beginCommit: () -> Boolean,
        isClosed: () -> Boolean = { false },
    ): T? =
        try {
            if (!beginCommit()) {
                // A close won the boundary: the session is being released, so there is nothing to
                // promise the desktop and nothing may be recorded locally either.
                Log.i(TAG, "Confirmation refused: the session was released first")
                return null
            }
            completion.confirm(
                burstDelaysMs = burstDelaysMs,
                // Built before persisting: a failure here must not leave a device record for a
                // pairing the desktop never accepted.
                buildConfirmation = { crypto.createConfirmServer(csk) },
                persist = persist,
                send = { packet ->
                    if (!link.send(packet)) {
                        Log.w(TAG, "PairingConfirmServer write failed; device record is kept")
                    }
                },
                // The linger's own budget goes through the same adapter every other phase uses,
                // so the bound belongs to the reader and not to whoever is sending frames.
                receive = { budgetMs -> awaitOwnFrame(link, budgetMs) },
                // The desktop re-sends the frame verbatim, so decrypting it again is how a
                // retransmission is told apart from a keepalive or an abort. The keys are still
                // alive here: concluding waits for the linger to return.
                isRetransmission = { packet -> crypto.processConfirmClient(packet) != null },
                isClosed = isClosed,
            )
        } finally {
            // Terminal, and after the linger: an explicit conclusion is the normal end, so the
            // Rust `Drop` stays the backstop for a session that never reaches this line (a
            // cancelled pairing, a crash) rather than the only thing that ever concludes.
            // `finally` and not the success path alone, because a burst that throws half-way has
            // still keyed the session.
            crypto.conclude()
        }
}
