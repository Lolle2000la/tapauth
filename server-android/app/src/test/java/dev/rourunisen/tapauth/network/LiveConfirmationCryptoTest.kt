package dev.rourunisen.tapauth.network

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [LiveConfirmationCrypto]'s one non-delegating behaviour: concluding a session that a concurrent
 * release already closed.
 *
 * The generated UniFFI object is ref-counted and `close()` drops the last reference, after which
 * every call throws `IllegalStateException("… object has already been destroyed")`. `libshared.so`
 * cannot be loaded by `./gradlew test`, so [RefCountedSession] stands in for that wrapper — the one
 * collaborator here that is a fake. What it models is the wrapper's documented lifetime, not the
 * crypto: `close()` is terminal and a later call throws.
 *
 * The interleaving itself is not reproduced — the adapter's `conclude` is called with the session
 * already closed, which is the *outcome* of the race (the adapter resolved the session before the
 * release closed it). Reproducing the interleaving would need the real wrapper and two threads.
 */
class LiveConfirmationCryptoTest {

    /** The generated object's ref-counted lifetime, reduced to what `conclude()` observes. */
    private class RefCountedSession {
        private val closed = AtomicBoolean(false)
        var concludeCalls = 0

        fun conclude() {
            if (closed.get()) {
                throw IllegalStateException("PairingSession object has already been destroyed")
            }
            concludeCalls++
        }

        fun close() {
            closed.set(true)
        }
    }

    private fun cryptoOver(session: RefCountedSession) =
        LiveConfirmationCrypto(
            buildConfirmation = { CONFIRMATION },
            decryptIsConfirmClient = { false },
            concludeSession = { session.conclude() },
        )

    private fun phase(crypto: PairingConfirmationCrypto) =
        PairingConfirmPhase(
            crypto = crypto,
            frameReader = PairingFrameReader(sliceMs = 1L, nowMs = { 0L }),
            // No linger: these tests are about the conclusion that follows it.
            completion = PairingCompletion(lingerMs = 0L, nowMs = { 0L }, sliceMs = 1L),
            belongsToSession = { true },
        )

    private class RecordingLink : PairingLink {
        val sends = mutableListOf<ByteArray>()

        override suspend fun send(packet: ByteArray): Boolean {
            sends += packet
            return true
        }

        override suspend fun receive(timeoutMs: Long): ByteArray? = null

        override fun close() = Unit
    }

    /**
     * A live session is concluded, a released one is not called again, and neither case throws.
     *
     * The defect this catches: the adapter's `conclude()` delegating straight into the generated
     * object, so a conclusion that reaches it after `close()` raises the destroyed-object
     * `IllegalStateException` the contract says cannot happen.
     */
    @Test
    fun concludingAfterTheReleaseNeitherThrowsNorConcludesAgain() {
        val session = RefCountedSession()
        val crypto = cryptoOver(session)

        crypto.conclude()
        assertEquals("A live session must be concluded", 1, session.concludeCalls)

        session.close()
        crypto.conclude()
        assertEquals("A released session must not be concluded again", 1, session.concludeCalls)
    }

    /**
     * The device is still reported when the release closed the session before the confirmation's
     * `finally` ran: the pairing succeeded, so the outcome must not be replaced by an exception.
     *
     * The defect this catches: the destroyed-object exception escaping `PairingConfirmPhase.finish`
     * through the `finally`, which discards the persisted device and (in `runSession`) reports
     * [PairingUpdate.Failed] for a pairing that in fact completed.
     */
    @Test
    fun aReleaseRacingTheConclusionKeepsTheReportedDevice() = runBlocking {
        val session = RefCountedSession()
        val link = RecordingLink()

        val device =
            phase(cryptoOver(session))
                .finish(
                    link = link,
                    csk = CSK,
                    burstDelaysMs = listOf(0L),
                    persist = {
                        // The release got there first and closed the object under the phase.
                        session.close()
                        "paired-device"
                    },
                    beginCommit = { true },
                )

        assertEquals(
            "The completed pairing must still be reported",
            "paired-device",
            device?.persisted,
        )
        assertTrue(
            "The burst was accepted, so the desktop was told",
            device!!.proofDelivered,
        )
        assertEquals("The burst must still have gone out", 1, link.sends.size)
        assertEquals("The destroyed session must not be concluded", 0, session.concludeCalls)
    }

    /**
     * The close-won path reports "nothing persisted" instead of throwing: `finish` returns null and
     * the `finally` finds the session already destroyed.
     *
     * The defect this catches: exactly the reported failure — a cancelled pairing (a back press or
     * a released ViewModel during the end of the handshake) surfacing as [PairingUpdate.Failed]
     * because the exception replaced the intended `null`.
     */
    @Test
    fun aCloseThatWonTheBoundaryStillReportsNoDevice() = runBlocking {
        val session = RefCountedSession()
        val link = RecordingLink()
        var persists = 0

        val device =
            phase(cryptoOver(session))
                .finish(
                    link = link,
                    csk = CSK,
                    burstDelaysMs = listOf(0L),
                    persist = {
                        persists += 1
                        "paired-device"
                    },
                    // The release won the boundary and closed the object first.
                    beginCommit = {
                        session.close()
                        false
                    },
                )

        assertNull("A cancelled pairing must report no device", device)
        assertEquals("Nothing may be persisted", 0, persists)
        assertEquals("Nothing may be sent", 0, link.sends.size)
    }

    private companion object {
        val CSK = ByteArray(32) { 0x0C }

        val CONFIRMATION = byteArrayOf(0xC0.toByte(), 0x0F)
    }
}
