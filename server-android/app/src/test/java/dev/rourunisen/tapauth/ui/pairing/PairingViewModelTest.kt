package dev.rourunisen.tapauth.ui.pairing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import dev.rourunisen.tapauth.data.PairedDevice
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingTransport
import dev.rourunisen.tapauth.network.PairingUpdate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Drives the pairing ViewModel's state machine directly on the JVM.
 *
 * `onCleared` is reached through a real [ViewModelStore], which is what the framework calls when
 * the owner is destroyed for good. The session is a fake because the real `PairingSession` needs an
 * Android context and live UDP/BLE transports.
 *
 * What is **not** executed here is an actual configuration change: the activity is not re-created.
 * A re-created screen is stood in for by calling [PairingViewModel.beginPairing] again on the same
 * ViewModel — the only thing the screen does when it is re-created — plus [PairingViewModel.leave]
 * with [PairingExit.ScreenDisposed], which is what its `onDispose` runs.
 */
class PairingViewModelTest {

    private val url =
        PairingUrl(
            version = 2,
            sessionId = "00112233445566778899aabbccddeeff",
            publicKey = "1111111111111111111111111111111111111111111111111111111111111111",
            port = 36692,
            ipv4 = "192.168.1.20",
            ipv6 = null,
        )

    private val otherUrl = url.copy(sessionId = "ffeeddccbbaa99887766554433221100")

    /** Stands in for one `PairingSession`, recording what the ViewModel asked of it. */
    private class FakeSession : PairingHandle {
        var startCount = 0
        var approveCount = 0
        var rejectCount = 0
        var closeCount = 0
        var scope: CoroutineScope? = null

        /**
         * What `rejectSas()` reports: true while no decision is recorded yet, false once one is
         * (the real session's `CompletableDeferred.complete` returns false for the second call).
         */
        var rejectRecorded = true

        private var onUpdate: ((PairingUpdate) -> Unit)? = null

        override fun start(scope: CoroutineScope, onUpdate: (PairingUpdate) -> Unit) {
            startCount++
            this.scope = scope
            this.onUpdate = onUpdate
        }

        override fun approveSas() {
            approveCount++
        }

        override fun rejectSas(): Boolean {
            rejectCount++
            return rejectRecorded
        }

        override fun close() {
            closeCount++
        }

        /** Report an update the way the real session does, from the main thread. */
        fun emit(update: PairingUpdate) {
            onUpdate?.invoke(update)
        }
    }

    private class FakeFactory : PairingHandleFactory {
        val sessions = mutableListOf<FakeSession>()

        override fun create(pairingUrl: PairingUrl): PairingHandle =
            FakeSession().also { sessions += it }

        val current: FakeSession
            get() = sessions.last()
    }

    private class Harness {
        val factory = FakeFactory()
        private val store = ViewModelStore()

        val viewModel: PairingViewModel =
            ViewModelProvider(
                    store,
                    object : ViewModelProvider.Factory {
                        @Suppress("UNCHECKED_CAST")
                        override fun <T : ViewModel> create(modelClass: Class<T>): T =
                            PairingViewModel(factory, CoroutineScope(Job())) as T
                    },
                )
                .get(PairingViewModel::class.java)

        /** What the framework does when the owner is destroyed: `onCleared` on every ViewModel. */
        fun destroy() = store.clear()
    }

    /** A completed pairing's device record; value-equal, so a re-created one compares equal. */
    private fun device(name: String) =
        PairedDevice(
            deviceId = "id-$name",
            publicKey = ByteArray(32) { 1 },
            csk = ByteArray(32) { 2 },
            displayName = name,
            pairedAt = 1_700_000_000_000L,
        )

    /**
     * Collects the terminal outcomes the ViewModel emits while [block] runs.
     *
     * The collector is started undispatched so it is subscribed before [block] runs — `replay = 0`
     * means an outcome emitted with no subscriber is deliberately dropped — and `yield()` lets the
     * emission's resumption reach it before it is cancelled.
     */
    private fun PairingViewModel.outcomesWhile(block: () -> Unit): List<PairingUpdate> =
        runBlocking {
            val collected = mutableListOf<PairingUpdate>()
            val collector =
                launch(start = CoroutineStart.UNDISPATCHED) { outcomes.collect { collected += it } }
            block()
            yield()
            collector.cancelAndJoin()
            collected
        }

    @Test
    fun aFreshSessionReportsItsCompletionExactlyOnce() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current

        val outcomes =
            harness.viewModel.outcomesWhile {
                session.emit(PairingUpdate.Connecting)
                session.emit(PairingUpdate.Confirming(PairingTransport.UDP))
                session.emit(PairingUpdate.Complete(device("desktop-a")))
            }

        assertEquals(listOf<PairingUpdate>(PairingUpdate.Complete(device("desktop-a"))), outcomes)
    }

    @Test
    fun failureAndCancellationAreReportedAsOutcomesToo() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val failed =
            harness.viewModel.outcomesWhile {
                harness.factory.current.emit(PairingUpdate.Failed("The pairing session expired"))
            }
        assertEquals(
            listOf<PairingUpdate>(PairingUpdate.Failed("The pairing session expired")),
            failed,
        )

        harness.viewModel.retry()
        val cancelled =
            harness.viewModel.outcomesWhile {
                harness.factory.current.emit(PairingUpdate.Cancelled)
            }
        assertEquals(listOf<PairingUpdate>(PairingUpdate.Cancelled), cancelled)
    }

    /**
     * The defect this pins down: pair device A, land on Home, then scan device B's QR. The
     * completed attempt stays in the retained state (the success view renders from it), so a screen
     * that derived its navigation from that state answered the *new* attempt with A's `Complete`
     * and went back to Home before B's `Connecting` arrived — B's session then ran with no screen,
     * never showing its SAS while the desktop waited out its deadline.
     */
    @Test
    fun aNewPairingAfterACompletedOneReceivesNoStaleOutcome() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.viewModel.outcomesWhile {
            harness.factory.current.emit(PairingUpdate.Complete(device("desktop-a")))
        }
        assertTrue(harness.viewModel.update.value is PairingUpdate.Complete)

        val stale = harness.viewModel.outcomesWhile { harness.viewModel.beginPairing(otherUrl) }
        assertEquals(emptyList<PairingUpdate>(), stale)

        val fresh =
            harness.viewModel.outcomesWhile {
                harness.factory.current.emit(PairingUpdate.Complete(device("desktop-b")))
            }
        assertEquals(listOf<PairingUpdate>(PairingUpdate.Complete(device("desktop-b"))), fresh)
    }

    @Test
    fun aReattachedScreenIsNotToldAboutTheAttemptItDidNotWitness() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        // The rotation: the composition is disposed and a new one re-attaches to the same attempt.
        harness.viewModel.leave(PairingExit.ScreenDisposed)
        val reattached = harness.viewModel.outcomesWhile { harness.viewModel.beginPairing(url) }

        assertEquals(emptyList<PairingUpdate>(), reattached)
        assertEquals(1, harness.factory.sessions.size)
        assertEquals(
            PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP),
            harness.viewModel.update.value,
        )

        // The attempt's own outcome is still reported once, after the re-attach.
        val outcome =
            harness.viewModel.outcomesWhile {
                session.emit(PairingUpdate.Complete(device("desktop-a")))
            }
        assertEquals(listOf<PairingUpdate>(PairingUpdate.Complete(device("desktop-a"))), outcome)
    }

    @Test
    fun aReplacedSessionCannotReportItsOutcomeIntoTheNextAttempt() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val replaced = harness.factory.current

        harness.viewModel.beginPairing(otherUrl)
        val current = harness.factory.current

        // `close()` cancels the replaced session's coroutine, but an update already in flight can
        // still be delivered; it must not become the current attempt's state or outcome.
        val leaked =
            harness.viewModel.outcomesWhile {
                replaced.emit(PairingUpdate.Complete(device("desktop-a")))
            }
        assertEquals(emptyList<PairingUpdate>(), leaked)
        assertEquals(PairingUpdate.Connecting, harness.viewModel.update.value)

        val own =
            harness.viewModel.outcomesWhile {
                current.emit(PairingUpdate.Complete(device("desktop-b")))
            }
        assertEquals(listOf<PairingUpdate>(PairingUpdate.Complete(device("desktop-b"))), own)
    }

    @Test
    fun reCreatedScreenReattachesToTheRunningSasSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.factory.current.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        // The composition is disposed by the rotation and then re-created: both paths run.
        harness.viewModel.leave(PairingExit.ScreenDisposed)
        harness.viewModel.beginPairing(url)

        assertEquals(1, harness.factory.sessions.size)
        assertEquals(1, harness.factory.current.startCount)
        assertEquals(0, harness.factory.current.closeCount)
        assertEquals(0, harness.factory.current.rejectCount)
        assertEquals(
            PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP),
            harness.viewModel.update.value,
        )
    }

    @Test
    fun destroyingTheViewModelAfterARotationReleasesTheSessionWithoutAborting() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.BLE))
        harness.viewModel.leave(PairingExit.ScreenDisposed)
        harness.viewModel.beginPairing(url)

        harness.destroy()

        assertEquals(1, session.closeCount)
        assertEquals(0, session.rejectCount)
        assertFalse(session.scope!!.isActive)
    }

    @Test
    fun backPressDuringTheSasAbortsOnceAndDestroyingDoesNotAbortAgain() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.leave(PairingExit.UserRequested)
        harness.viewModel.leave(PairingExit.UserRequested)

        // The session is deliberately left open: the abort is written by its own coroutine.
        assertEquals(1, session.rejectCount)
        assertEquals(0, session.closeCount)

        harness.destroy()

        assertEquals(1, session.rejectCount)
        // The abort is still being written, so destroying the ViewModel must not cut it: the
        // session keeps running on the attempt's own scope and releases its own transports when
        // the abort lands.
        assertEquals(0, session.closeCount)
        assertTrue(session.scope!!.isActive)
    }

    /**
     * The defect this pins down: the user taps "Yes, they match" and then presses back. The reject
     * that the back press sends finds the approval already recorded, so the session completes
     * nothing and will never write an abort — but the ViewModel used to latch "abort requested"
     * anyway, and `onCleared` then skipped the release. The activity was destroyed, the session
     * kept running, and `Confirming` could still finish headlessly: the device persisted and the
     * desktop told the pairing succeeded while the UI was gone.
     */
    @Test
    fun approveThenBackWithAnUnrecordedRejectReleasesTheSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.approveSas()
        // The approval is already recorded, so the reject the back press sends is a no-op.
        session.rejectRecorded = false
        harness.viewModel.leave(PairingExit.UserRequested)

        // Nothing is being written, so the exit path does not close the session either.
        assertEquals(1, session.rejectCount)
        assertEquals(0, session.closeCount)

        harness.destroy()

        // No abort will ever land, so keeping the session alive would only let it complete with no
        // screen attached: it has to be released here.
        assertEquals(1, session.rejectCount)
        assertEquals(1, session.closeCount)
        assertFalse(session.scope!!.isActive)
    }

    @Test
    fun destroyingTheViewModelAfterTheAbortLandedReleasesTheSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.leave(PairingExit.UserRequested)
        // The session wrote the abort and reported its outcome.
        session.emit(PairingUpdate.Cancelled)

        harness.destroy()

        assertEquals(1, session.rejectCount)
        assertEquals(1, session.closeCount)
        assertFalse(session.scope!!.isActive)
    }

    @Test
    fun cancelButtonThenBackPressBeforeTheAbortLandsAbortsOnce() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.rejectSas() // "No, Cancel"
        // Back pressed before the session has reported that the abort went out: the SAS is still
        // up, so the exit path looks abortable too and must not ask for a second abort.
        harness.viewModel.leave(PairingExit.UserRequested)

        assertEquals(1, session.rejectCount)
        assertEquals(0, session.closeCount)

        harness.destroy()

        assertEquals(1, session.rejectCount)
        assertEquals(0, session.closeCount)
        assertTrue(session.scope!!.isActive)
    }

    @Test
    fun backPressBeforeTheSasClosesTheSessionWithoutAborting() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.Connecting)

        harness.viewModel.leave(PairingExit.UserRequested)

        assertEquals(0, session.rejectCount)
        assertEquals(1, session.closeCount)
    }

    @Test
    fun scanningTheSameQrAgainAfterAFailureStartsANewSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.factory.current.emit(PairingUpdate.Failed("No response from the desktop"))

        harness.viewModel.beginPairing(url)

        assertEquals(2, harness.factory.sessions.size)
        assertEquals(1, harness.factory.sessions[0].closeCount)
        assertEquals(PairingUpdate.Connecting, harness.viewModel.update.value)
    }

    @Test
    fun retryReplacesTheFailedSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.factory.current.emit(PairingUpdate.Failed("No response from the desktop"))

        harness.viewModel.retry()

        assertEquals(2, harness.factory.sessions.size)
        assertEquals(1, harness.factory.sessions[0].closeCount)
        assertEquals(0, harness.factory.sessions[1].closeCount)
        assertEquals(PairingUpdate.Connecting, harness.viewModel.update.value)
    }

    @Test
    fun aDifferentQrCodeReplacesTheRunningSessionWithoutAborting() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.factory.current.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.beginPairing(otherUrl)

        assertEquals(2, harness.factory.sessions.size)
        assertEquals(1, harness.factory.sessions[0].closeCount)
        assertEquals(0, harness.factory.sessions[0].rejectCount)
    }

    @Test
    fun returningToTheSameQrAfterABackPressStartsANewSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        harness.factory.current.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))
        // The abort was asked for, but the session has not reported it back yet.
        harness.viewModel.leave(PairingExit.UserRequested)

        harness.viewModel.beginPairing(url)

        assertEquals(2, harness.factory.sessions.size)
        assertEquals(1, harness.factory.sessions[0].closeCount)
        assertEquals(PairingUpdate.Connecting, harness.viewModel.update.value)
    }

    @Test
    fun approvingTheSasIsForwardedToTheSession() {
        val harness = Harness()
        harness.viewModel.beginPairing(url)
        val session = harness.factory.current
        session.emit(PairingUpdate.AwaitingSas("123-456", PairingTransport.UDP))

        harness.viewModel.approveSas()

        assertEquals(1, session.approveCount)
        assertEquals(0, session.rejectCount)
    }
}
