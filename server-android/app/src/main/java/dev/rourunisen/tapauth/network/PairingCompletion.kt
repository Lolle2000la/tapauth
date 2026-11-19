package dev.rourunisen.tapauth.network

import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
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
     * Whether [packet] decrypts as a `PairingConfirmClient` — the linger's retransmission
     * predicate.
     *
     * A `Boolean` and not the decrypted CSK: the only question the linger asks is "was this frame
     * already consumed?", and answering it by handing the key back left a plaintext copy of the CSK
     * on the heap for every retransmission, read by nobody and cleared by nothing. The decrypt
     * still happens (nothing else can tell a retransmission from a keepalive, a duplicate or an
     * abort), it just does not let the key cross this boundary.
     *
     * @return true for a `PairingConfirmClient` of this session, false for anything else
     */
    fun isConfirmClient(packet: ByteArray): Boolean

    /**
     * Conclude the session: zeroize the directional keys, the transcript hash and the ephemeral
     * X25519 secret. Every later call reports `State`. Idempotent, **including after a concurrent
     * release closed the session** — see [LiveConfirmationCrypto.conclude].
     */
    fun conclude()
}

/**
 * Adapts the live Rust pairing session onto [PairingConfirmationCrypto].
 *
 * The session is resolved per call rather than captured, because the object only exists between
 * `prepareSession` and the release.
 *
 * [conclude] is deliberately not a plain delegation. The generated UniFFI object is ref-counted and
 * `close()` drops the last reference, after which every call throws `IllegalStateException("…
 * object has already been destroyed")`. The release runs on another thread (a back press,
 * `onCleared`, a configuration change), so a completion that is already in its `finally` can find
 * the object closed under it. That is the close winning — the session is concluded and gone, which
 * is the whole of what this call asks for — so it must not replace the phase's result: an exception
 * escaping there turns a cancellation (`finish` returning null) into `PairingUpdate.Failed` for a
 * pairing the user ended themselves.
 */
internal class LiveConfirmationCrypto(
    private val buildConfirmation: (csk: ByteArray) -> ByteArray,
    private val decryptIsConfirmClient: (packet: ByteArray) -> Boolean,
    private val concludeSession: () -> Unit,
) : PairingConfirmationCrypto {
    private companion object {
        /** The session's own tag: this is its conclusion path. */
        const val TAG = "PairingSession"
    }

    override fun createConfirmServer(csk: ByteArray): ByteArray = buildConfirmation(csk)

    override fun isConfirmClient(packet: ByteArray): Boolean = decryptIsConfirmClient(packet)

    override fun conclude() {
        try {
            concludeSession()
        } catch (e: IllegalStateException) {
            // The generated wrapper's only `IllegalStateException` from this call is the
            // destroyed/call-counter one: the release concluded and closed the session already, so
            // there is nothing left to zeroize. Rust errors arrive as `TapauthException` and still
            // reach the caller.
            Log.d(TAG, "Pairing session was already released: ${e.message}")
        }
    }
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
 * socket this side already closed. Hence one lock over one four-state field:
 * ```
 * Open --beginCommit()--> Committed --completeCommit()--> Completed
 *                          (a close is deferred)          (a close releases)
 * Open --requestClose()-> Closed      (a later beginCommit() is refused: nothing happens)
 * Committed/Completed --requestClose()-> Closed
 * ```
 *
 * The deferral is bounded by the confirmation, not permanent: while [State.Committed] the
 * `PairingConfirmServer` burst and the linger that answers the desktop's retransmissions are still
 * running, so cutting the coroutine there is what loses the pairing. Once the confirmation is over
 * ([completeCommit], reached from `finally` so a burst that throws ends it too) there is nothing
 * left to protect, so a close releases like it does before the commit — otherwise a close arriving
 * after a finished pairing would be answered "deferred" forever and nothing would ever cancel the
 * coroutine that owns the transports. A close that won the boundary keeps `beginCommit` refused and
 * a deferred close keeps the commit standing: neither transition can be undone by the other.
 */
internal class PairingCommitLatch {
    private enum class State {
        /** Neither decision has been taken. */
        Open,

        /** The device record is being written; the confirmation must finish. */
        Committed,

        /** The confirmation finished; the commit no longer defers a close. */
        Completed,

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
                if (state == State.Open) state = State.Committed
                true
            }
        }

    /**
     * The confirmation is over: the commit is no longer in flight.
     *
     * Called from a `finally`, so a burst that throws also ends the deferral. It only moves
     * [State.Committed] on; a close that won the boundary stays won.
     */
    fun completeCommit() {
        synchronized(lock) {
            if (state == State.Committed) state = State.Completed
        }
    }

    /**
     * Ask to release the session.
     *
     * @return [CloseOutcome.Deferred] when a commit is in flight, so the confirmation burst and
     *   linger must still run and the session releases itself afterwards; [CloseOutcome.Released]
     *   when the close may release now, either because it won the boundary just now (nothing was or
     *   will be persisted), because it had already won, or because the confirmation has completed
     */
    fun requestClose(): CloseOutcome =
        synchronized(lock) {
            when (state) {
                State.Open -> {
                    state = State.Closed
                    CloseOutcome.Released
                }
                State.Committed -> CloseOutcome.Deferred
                State.Completed -> {
                    state = State.Closed
                    CloseOutcome.Released
                }
                State.Closed -> CloseOutcome.Released
            }
        }
}

/**
 * What one close decided, and what the session did with it.
 *
 * The contract `PairingHandle.close()` publishes is exactly these two cases, so a caller reads the
 * answer by name instead of by the polarity of a Boolean: a close is either deferred to a
 * confirmation that is already in flight, or it released everything.
 */
enum class CloseOutcome {
    /**
     * The close is deferred to a confirmation that is in flight: the device record is written but
     * the `PairingConfirmServer` burst and the linger that answers the desktop's retransmissions
     * have not finished. The session keeps running and releases itself when they end.
     */
    Deferred,

    /**
     * The session released everything: the coroutine, the transports and the Rust session. Also the
     * answer when the confirmation had already completed, or on a repeated close.
     */
    Released,
}

/**
 * The close side of a pairing's commit boundary, and the only place a release is decided.
 *
 * `PairingSession.close()` cannot be driven from a JVM test — it needs an Android `Context`, a
 * running transport and the generated UniFFI object — so the decision it makes, "release now or
 * defer to a confirmation that is already in flight?", lives here with the release injected:
 * [PairingCommitLatch] answers the question and [onRelease] is the release itself (`PairingSession`
 * passes cancel-the-job / close-the-links / zeroize-the-keys).
 *
 * The [CloseOutcome] it returns is the whole contract `PairingHandle.close()` publishes and
 * `PairingViewModel.releaseSession()` acts on. Getting it wrong either way undoes finding F: a
 * deferred close answered `Released` cancels the attempt scope mid-confirmation (the phone persists
 * and the desktop times out), and a close that won answered `Deferred` leaks a session with no
 * screen. A close that arrives once the confirmation has completed
 * (`PairingCommitLatch.completeCommit`) releases like any other: the latch no longer reports a
 * deferral, so there is no state in which a finished session answers "deferred" and keeps its
 * transports for the life of the process.
 *
 * [onRelease] runs at most once, because a repeat close finds nothing left to release.
 */
internal class PairingSessionRelease(
    private val latch: PairingCommitLatch,
    private val onRelease: () -> Unit,
) {
    private companion object {
        /** The session's own tag: this is its close path. */
        const val TAG = "PairingSession"
    }

    private val lock = Any()

    private var released = false

    /**
     * Ask for the release.
     *
     * @return [CloseOutcome.Deferred] when the release is deferred — a commit is in flight and the
     *   confirmation must finish, so [onRelease] must not run — [CloseOutcome.Released] when it ran
     *   now, or had already run
     */
    fun requestClose(): CloseOutcome =
        synchronized(lock) {
            when {
                // A commit is in flight: the confirmation must finish, so nothing is released.
                latch.requestClose() == CloseOutcome.Deferred -> {
                    Log.i(TAG, "close() deferred: the pairing confirmation is in flight")
                    CloseOutcome.Deferred
                }
                released -> CloseOutcome.Released
                else -> {
                    released = true
                    onRelease()
                    CloseOutcome.Released
                }
            }
        }
}

/**
 * The lifecycle seam of one pairing: whether it is closed, when a close may release, and the one
 * release that follows.
 *
 * `PairingSession` cannot be constructed from a JVM test — it needs an Android `Context`, a running
 * transport and the generated UniFFI object — so the composition it ships lives here, with the two
 * side effects injected: [onClose] (cancel the coroutine and close the transports) and [zeroize]
 * (conclude and drop the Rust session, clear the handshake buffers). `PairingSession` delegates
 * every lifecycle decision to this object:
 *
 * * [close], the release decision [PairingSessionRelease] owns on top of [PairingCommitLatch];
 * * [isClosed], the flag every wait loop reads and the confirmation linger is handed as `isClosed`;
 * * [beginCommit] / [completeCommit], the boundary the confirmation phase is gated on;
 * * [zeroizeEphemeralState], which the success path and the release path both reach and which
 *   therefore runs [zeroize] exactly once.
 *
 * [finish] is part of the seam on purpose: it hands [PairingConfirmPhase.finish] *this* object's
 * [beginCommit] and [isClosed] rather than values a caller picked, so a test that drives [finish]
 * exercises the boundary the production close actually competes with. A test that armed the phase
 * with `{ true }` (as the phase's own tests do, for their unrelated assertions) would stay green
 * with the whole boundary unwired.
 */
internal class PairingSessionLifecycle(
    private val onClose: () -> Unit,
    private val zeroize: () -> Unit,
) {
    private val latch = PairingCommitLatch()

    private val closed = AtomicBoolean(false)

    private val zeroized = AtomicBoolean(false)

    /** The release body: stop waiting, tear the transports down, drop the keys. */
    private val release =
        PairingSessionRelease(latch) {
            closed.set(true)
            onClose()
            zeroizeEphemeralState()
        }

    /** True once a close has won the boundary; every wait loop and the linger read it. */
    fun isClosed(): Boolean = closed.get()

    /**
     * The commit transition, taken synchronously before anything is written or sent.
     *
     * @return false when a close already won the boundary, so nothing may be persisted or sent
     */
    fun beginCommit(): Boolean = latch.beginCommit()

    /**
     * The confirmation is over: from here a close releases instead of deferring to it.
     *
     * Idempotent, and it never undoes a close.
     */
    fun completeCommit() {
        latch.completeCommit()
    }

    /** Run [zeroize] at most once, whether the success path or the release reaches it first. */
    fun zeroizeEphemeralState() {
        if (zeroized.compareAndSet(false, true)) zeroize()
    }

    /**
     * Ask for the release.
     *
     * @return [CloseOutcome.Deferred] when it was deferred to the confirmation in flight,
     *   [CloseOutcome.Released] when it ran now (or had already run, or the confirmation had
     *   completed)
     */
    fun close(): CloseOutcome = release.requestClose()

    /**
     * Run the confirmation phase under this lifecycle's boundary.
     *
     * Zeroization runs here rather than around the call, so the Rust session outlives the linger
     * and a retransmitted `PairingConfirmClient` can still be decrypted; it happens once even
     * though `runSession`'s epilogue asks again.
     *
     * @return the persisted device and whether the transport accepted the proof, or null when a
     *   close had already won the boundary
     */
    suspend fun <T : Any> finish(
        phase: PairingConfirmPhase,
        link: PairingLink,
        csk: ByteArray,
        burstDelaysMs: List<Long>,
        persist: suspend () -> T,
    ): PairingConfirmation<T>? =
        try {
            phase
                .finish(
                    link = link,
                    csk = csk,
                    burstDelaysMs = burstDelaysMs,
                    persist = persist,
                    beginCommit = ::beginCommit,
                    isClosed = ::isClosed,
                )
                ?.also { zeroizeEphemeralState() }
        } finally {
            // From `finally`, so a burst that throws still ends the deferral; a close that won the
            // boundary keeps it (completeCommit only moves Committed on).
            completeCommit()
        }
}

/**
 * What one confirmation achieved, in the two halves that can differ.
 *
 * The device record is written before anything is sent, so "persisted" and "the desktop was told"
 * are independent facts and the pair that matters is a pair: a burst every send of which the
 * transport rejected leaves the phone paired and the desktop unpaired — it retries the same
 * `PairingConfirmClient` into a socket this side has closed, then times out. Reporting only the
 * persisted half is how the UI came to announce a successful pairing that existed on one side only.
 *
 * [proofDelivered] is monotone over the whole confirmation: the burst and every answer the linger
 * sends are attempts, and one that the transport accepted is delivery. There is no retry protocol
 * here and this adds none — it reports what the transport did, not what it might still do. Its
 * meaning stops at the transport: `true` says a write was not rejected, never that the desktop
 * received it, because neither transport acknowledges a pairing write.
 */
internal data class PairingConfirmation<T : Any>(
    /** What `persist` returned: the device record, in production. */
    val persisted: T,

    /**
     * Whether at least one `PairingConfirmServer` write was accepted by the transport — not
     * acknowledged by the desktop. `false` means no write is known to have been accepted: no socket
     * or endpoint, every target's send failed, or a write that timed out.
     */
    val proofDelivered: Boolean,
)

/**
 * The confirmation phase of a pairing over one locked transport: everything
 * [PairingSession.finishPairing] does that needs no Android `Context`.
 *
 * It owns the four things that must stay in one place for the desktop's retransmissions to be
 * answered correctly:
 *
 * * the frame intake, [awaitOwnFrame] — the same budgeted read every other phase uses, so a
 *   foreign-frame stream cannot keep the linger from re-reading its own clock;
 * * the retransmission predicate, which consults [PairingConfirmationCrypto.isConfirmClient] rather
 *   than comparing bytes, because the desktop re-sends the frame verbatim but a keepalive or an
 *   abort must not be answered with a second proof;
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
     * @return the persisted device and whether the transport accepted any `PairingConfirmServer`,
     *   or null when [beginCommit] refused the commit
     */
    suspend fun <T : Any> finish(
        link: PairingLink,
        csk: ByteArray,
        burstDelaysMs: List<Long>,
        persist: suspend () -> T,
        beginCommit: () -> Boolean,
        isClosed: () -> Boolean = { false },
    ): PairingConfirmation<T>? =
        try {
            if (!beginCommit()) {
                // A close won the boundary: the session is being released, so there is nothing to
                // promise the desktop and nothing may be recorded locally either.
                Log.i(TAG, "Confirmation refused: the session was released first")
                return null
            }
            // Monotone over the burst and the linger: a send the transport accepted is delivery,
            // and a later retransmission that lands is delivery too. Nothing here retries.
            var proofDelivered = false
            val persisted =
                completion.confirm(
                    burstDelaysMs = burstDelaysMs,
                    // Built before persisting: a failure here must not leave a device record for a
                    // pairing the desktop never accepted.
                    buildConfirmation = { crypto.createConfirmServer(csk) },
                    persist = persist,
                    send = { packet ->
                        if (link.send(packet)) {
                            proofDelivered = true
                        } else {
                            // Reported, not hidden: the record stays, the desktop never got the
                            // proof, and the outcome says so instead of claiming success.
                            Log.w(
                                TAG,
                                "PairingConfirmServer write failed; the device record is kept, " +
                                    "the desktop was not told",
                            )
                        }
                    },
                    // The linger's own budget goes through the same adapter every other phase uses,
                    // so the bound belongs to the reader and not to whoever is sending frames.
                    receive = { budgetMs -> awaitOwnFrame(link, budgetMs) },
                    // The desktop re-sends the frame verbatim, so decrypting it again is how a
                    // retransmission is told apart from a keepalive or an abort. The keys are still
                    // alive here: concluding waits for the linger to return.
                    isRetransmission = crypto::isConfirmClient,
                    isClosed = isClosed,
                )
            PairingConfirmation(persisted, proofDelivered)
        } finally {
            // Terminal, and after the linger: an explicit conclusion is the normal end, so the
            // Rust `Drop` stays the backstop for a session that never reaches this line (a
            // cancelled pairing, a crash) rather than the only thing that ever concludes.
            // `finally` and not the success path alone, because a burst that throws half-way has
            // still keyed the session.
            crypto.conclude()
        }
}
