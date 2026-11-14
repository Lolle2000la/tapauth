package dev.rourunisen.tapauth.ui.pairing

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingSession
import dev.rourunisen.tapauth.network.PairingUpdate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Why the pairing screen went away.
 *
 * The two cases are separate because they must behave differently. A configuration change disposes
 * the *composition*, not the pairing: the desktop is still pairing with a phone whose screen merely
 * rotated, so the session has to stay alive and no `PairingAbort` may be sent. A back press is a
 * decision, and `docs/design-documents/protocol/initial-key-exchange.md` (Step 4) says the phone
 * answers it with an authenticated `PairingAbort(USER_REJECTED_SAS)`.
 */
enum class PairingExit {
    /**
     * The composition that hosted the screen was disposed — a configuration change, or the host
     * navigating on after a terminal update. Neither is a user decision: keep the session, abort
     * nothing.
     */
    ScreenDisposed,

    /** Back press or the top bar's back arrow: the user ended the pairing. */
    UserRequested,
}

/**
 * The slice of [PairingSession] that [PairingViewModel] drives.
 *
 * [PairingSession] needs an Android [Context] and real UDP/BLE transports, so it cannot run in a
 * plain JVM unit test; the state machine talks to this interface instead and the production factory
 * adapts the real session onto it.
 */
interface PairingHandle {
    fun start(scope: CoroutineScope, onUpdate: (PairingUpdate) -> Unit)

    fun approveSas()

    /**
     * Ask the session to reject the SAS. Returns true when the reject was recorded and an abort
     * will be written, false when a decision had already been recorded, so this call was a no-op.
     */
    fun rejectSas(): Boolean

    /**
     * Ask the session to release its transports, keys and coroutine.
     *
     * @return true when the close was **deferred** because the pairing confirmation is still in
     *   flight — the device record is written but the `PairingConfirmServer` burst and the linger
     *   that answers the desktop's retransmissions have not finished, so the session keeps running
     *   and releases itself when they end — false when this call released everything, including
     *   when the confirmation has already completed. See `PairingSession.close`.
     */
    fun close(): Boolean
}

/** Creates the session for one attempt. Replaced by a fake in the unit tests. */
fun interface PairingHandleFactory {
    fun create(pairingUrl: PairingUrl): PairingHandle
}

/**
 * Owns the pairing session and the state [PairingScreen] renders, so a configuration change
 * re-attaches to a live session instead of disposing it.
 *
 * Both used to live in the composition — `TapAuthApp` kept the screen in a plain `remember`, and
 * `PairingScreen` created its session in a `remember` released by `DisposableEffect`. Rotating
 * during SAS verification therefore disposed the session: the user dropped back to Home and the
 * desktop was left waiting for a response that never came, because nothing sent the
 * `PairingAbort(USER_REJECTED_SAS)` the protocol expects from the phone.
 *
 * The lifecycle now is:
 * * a configuration change re-creates the screen, which calls [beginPairing] again with the same
 *   URL and gets the running session back;
 * * [leave] with [PairingExit.UserRequested] ends a pairing the user chose to abandon, aborting a
 *   live SAS prompt;
 * * [onCleared] releases the session when the owner is really going away. It never aborts: a back
 *   press has already aborted, and an activity that is being finished cannot promise the desktop
 *   would receive the packet. The one exception is an abort that is still being written — see
 *   [attemptScope].
 *
 * A response that fails verification is still dropped inside [PairingSession] and never reaches
 * this class, so no exit path here can turn a bad packet into an abort.
 *
 * Every method runs on the main thread, and so does every update ([PairingSession] marshals them
 * there); [update] is a [StateFlow] so the Compose screen can collect it from any thread, and
 * [outcomes] is a [SharedFlow] of the terminal ones.
 */
class PairingViewModel(
    private val sessionFactory: PairingHandleFactory,
    private val scope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) : ViewModel() {

    private val _update = MutableStateFlow<PairingUpdate>(PairingUpdate.Connecting)

    /** What the screen renders. Outlives a configuration change because the ViewModel does. */
    val update: StateFlow<PairingUpdate> = _update.asStateFlow()

    /**
     * The terminal outcomes ([PairingUpdate.Complete], [PairingUpdate.Failed],
     * [PairingUpdate.Cancelled]), each delivered once, as an event rather than as state.
     *
     * [update] deliberately stays `Complete` after a successful pairing, because the success view
     * is rendered from it. That is also why the outcome cannot be re-derived from [update]: a
     * screen seeded with a retained `Complete` would report it as the *next* attempt's outcome and
     * bounce that attempt back to Home before its own `Connecting` arrived, leaving the new session
     * running with no screen at all — no SAS ever shown, and the desktop waiting out its deadline.
     *
     * `replay = 0` is the other half: an outcome emitted while no screen is attached is dropped
     * instead of being handed to the next screen that attaches, so a re-attached (or the next)
     * screen can never be told about an attempt it did not witness.
     */
    private val _outcomes = MutableSharedFlow<PairingUpdate>(extraBufferCapacity = 1, replay = 0)

    /** The terminal outcomes of the current attempt; see [_outcomes]. */
    val outcomes: SharedFlow<PairingUpdate> = _outcomes.asSharedFlow()

    private var pairingUrl: PairingUrl? = null
    private var session: PairingHandle? = null

    /**
     * The scope the current attempt's session runs on, or null when there is none.
     *
     * Deliberately not [scope]: a `PairingAbort` is written *inside* the session's own coroutine
     * (`PairingSession.sendAbort`), so cancelling the scope it runs on would cut the packet before
     * the transport write. "Back during the SAS, then immediately navigate Home or swipe the app
     * away" is exactly that: [onCleared] arrives before the session's next receive slice. Leaving
     * the attempt's own scope alone keeps the abort in flight; the session releases its sockets and
     * keys itself when `runSession` returns, so nothing else has to.
     */
    private var attemptScope: CoroutineScope? = null

    /** Set once the current attempt's session has been released, so it is never released twice. */
    private var sessionClosed = false

    /** Set once the current attempt reported `Complete`, `Failed` or `Cancelled`. */
    private var terminal = false

    /**
     * Set once `PairingAbort(USER_REJECTED_SAS)` has been recorded, so it goes out at most once.
     *
     * Only a reject that was actually recorded latches this: a reject the session answers with
     * false completed nothing, so no abort will ever be written for it, and [onCleared] must still
     * release the session rather than leave it running with no screen.
     */
    private var abortRequested = false

    /** Set once the user has left, so a second back press neither re-aborts nor re-closes. */
    private var exitRequested = false

    /**
     * Attach a screen for [pairingUrl], starting the session if this is a new attempt.
     *
     * Called from a `LaunchedEffect` keyed on the URL, so a re-created composition (rotation) calls
     * it again with the same URL: an attempt that is still running is left untouched, which is what
     * keeps the desktop's pairing alive across a configuration change. An attempt the user has
     * already left is not reused, even if its abort has not been reported back yet.
     */
    fun beginPairing(pairingUrl: PairingUrl) {
        if (pairingUrl == this.pairingUrl && !sessionClosed && !terminal && !exitRequested) return
        startAttempt(pairingUrl)
    }

    /** Retry from the failure screen: a fresh session for the same QR code. */
    fun retry() {
        pairingUrl?.let { startAttempt(it) }
    }

    fun approveSas() {
        session?.approveSas()
    }

    /** The user says the SAS differs. The abort goes out; the screen stays on its failure view. */
    fun rejectSas() {
        abort()
    }

    /** Record that the screen went away, for the reason in [reason]. */
    fun leave(reason: PairingExit) {
        when (reason) {
            // The composition went away but the ViewModel did not: the session keeps running and
            // the desktop is left waiting for the user, not for a packet.
            PairingExit.ScreenDisposed -> return
            PairingExit.UserRequested -> Unit
        }
        if (exitRequested) return
        exitRequested = true
        if (_update.value is PairingUpdate.AwaitingSas) {
            // Leaving an unanswered SAS is the rejection the protocol describes. Closing the
            // session instead would leave the desktop waiting out its own deadline.
            abort()
        } else {
            // Nothing was keyed yet (or the attempt is over), so there is nothing to tell the
            // desktop: release the transports and let the screen go.
            releaseSession()
        }
    }

    /**
     * Release the attempt when the owner is really going away — unless a `PairingAbort` is still
     * being written.
     *
     * The abort is written inside the session's own coroutine, so releasing the attempt here (which
     * closes the session and cancels [attemptScope]) would cut the packet before the transport
     * write: "back during the SAS, then immediately navigate Home or swipe the app away" would then
     * leave the desktop waiting out its deadline. A terminal update is only reported *after* the
     * abort has gone out, so `abortRequested && !terminal` is exactly the window where the write is
     * still in flight; the session releases its own sockets and keys when it returns.
     *
     * A pairing that has already started persisting is the other such window, and [releaseSession]
     * handles it from the session's answer rather than from state here: the confirmation burst and
     * linger must still go out, or the phone stays paired while the desktop times out.
     */
    override fun onCleared() {
        if (!(abortRequested && !terminal)) releaseSession()
        scope.cancel()
    }

    private fun startAttempt(pairingUrl: PairingUrl) {
        releaseSession()
        this.pairingUrl = pairingUrl
        sessionClosed = false
        terminal = false
        abortRequested = false
        exitRequested = false
        _update.value = PairingUpdate.Connecting
        val started = sessionFactory.create(pairingUrl)
        session = started
        val attempt = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        attemptScope = attempt
        // The identity check keeps a replaced session out of this attempt's state and outcomes:
        // `close()` cancels its coroutine, but an update already in flight would otherwise still be
        // reported as though it belonged to the attempt the user is now watching.
        started.start(attempt) { update -> if (session === started) onUpdate(update) }
    }

    private fun onUpdate(update: PairingUpdate) {
        _update.value = update
        if (!update.isTerminal()) return
        terminal = true
        // Once, as an event. The retained state above is what a re-attached screen renders; it is
        // not what the host navigates on, or the previous attempt's `Complete` would answer the
        // next one (see [_outcomes]).
        _outcomes.tryEmit(update)
    }

    private fun PairingUpdate.isTerminal(): Boolean =
        this is PairingUpdate.Complete ||
            this is PairingUpdate.Failed ||
            this is PairingUpdate.Cancelled

    private fun abort() {
        if (abortRequested) return
        // Latch only a reject the session actually recorded. A `false` means a decision was already
        // taken (the user approved a moment earlier), so no abort will ever be written and the
        // release in `onCleared` must not be skipped for it.
        abortRequested = session?.rejectSas() == true
    }

    private fun releaseSession() {
        if (sessionClosed) return
        sessionClosed = true
        // A deferred close means the confirmation is still in flight: the device record is written
        // but the burst and linger that tell the desktop have not finished, so cancelling the
        // attempt scope here would cut them and leave the phone paired with a desktop that timed
        // out. The session bounds that itself and releases when it ends — after which a close
        // releases normally instead of deferring again.
        if (session?.close() != true) attemptScope?.cancel()
        attemptScope = null
    }

    companion object {
        /** The production factory: a real [PairingSession] bound to the application context. */
        fun factory(context: Context): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    val appContext = context.applicationContext ?: context
                    val sessions = PairingHandleFactory { url ->
                        RealPairingHandle(PairingSession(appContext, url))
                    }
                    return PairingViewModel(sessions) as T
                }
            }
    }
}

/** Adapts the real [PairingSession] onto [PairingHandle], so the ViewModel never names it. */
private class RealPairingHandle(private val session: PairingSession) : PairingHandle {
    override fun start(scope: CoroutineScope, onUpdate: (PairingUpdate) -> Unit) =
        session.start(scope, onUpdate)

    override fun approveSas() = session.approveSas()

    override fun rejectSas(): Boolean = session.rejectSas()

    override fun close(): Boolean = session.close()
}
