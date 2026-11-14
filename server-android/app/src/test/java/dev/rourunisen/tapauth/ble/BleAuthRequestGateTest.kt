package dev.rourunisen.tapauth.ble

import dev.rourunisen.tapauth.service.ReplayMitigationCache
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Ordering of the duplicate-in-flight check against the replay cache.
 *
 * The replay check is the real [ReplayMitigationCache] (fixed clock), not a stub: it is the
 * collaborator that decides "replay" in production. [replayChecks] only counts that the gate
 * consulted it, which is what separates a duplicate that never reached the cache from one that did.
 */
class BleAuthRequestGateTest {

    private var nowSeconds = 1_700_000_000L
    private var nowMillis = 1_000_000L

    private val replayChecks = AtomicInteger(0)
    private val replayCache = ReplayMitigationCache { nowSeconds }

    private val gate =
        BleAuthRequestGate(
            isReplay = { challenge, timestampUnixSeconds ->
                replayChecks.incrementAndGet()
                replayCache.isReplay(challenge, timestampUnixSeconds)
            },
            elapsedMillis = { nowMillis },
        )

    private val challenge = ByteArray(32) { (it + 1).toByte() }
    private val otherChallenge = ByteArray(32) { (it + 101).toByte() }
    private val peer = "AA:BB:CC:DD:EE:01"
    private val otherPeer = "AA:BB:CC:DD:EE:02"

    @Test
    fun firstArrivalIsProcessed() {
        val verdict = gate.evaluate(challenge, nowSeconds, peer)

        assertEquals(BleAuthRequestGate.Verdict.PROCESS, verdict)
        assertEquals(1, replayChecks.get())
        assertEquals(1, gate.inFlightCount)
    }

    @Test
    fun duplicateFromSamePeerNeverReachesTheReplayCache() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))

        // The copy that races the initial read, or the re-notification of the same request.
        val duplicate = gate.evaluate(challenge, nowSeconds, peer)

        assertEquals(BleAuthRequestGate.Verdict.DUPLICATE_IN_FLIGHT, duplicate)
        assertEquals(
            "the duplicate must not be consulted by the replay cache",
            1,
            replayChecks.get(),
        )
        // Proves the old behaviour was a disconnect: the cache *would* call these bytes a replay.
        assertTrue(replayCache.isReplay(challenge, nowSeconds))
        assertEquals(1, gate.inFlightCount)
    }

    @Test
    fun foreignPeerWithTheSameBytesStillReachesTheReplayCache() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))

        // Another device replaying the captured packet: not a duplicate, so it must be rejected by
        // the replay cache exactly as before (the caller then disconnects it).
        val replayed = gate.evaluate(challenge, nowSeconds, otherPeer)

        assertEquals(BleAuthRequestGate.Verdict.REPLAY, replayed)
        assertEquals(
            "the foreign replay must be consulted by the replay cache",
            2,
            replayChecks.get(),
        )
    }

    @Test
    fun concludeLetsTheChallengeReachTheReplayCacheAgain() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))

        // The authentication concluded (grant sent / denial / cancel / timeout).
        gate.conclude(challenge)
        assertEquals(0, gate.inFlightCount)

        // The same bytes afterwards are a replay again, not a duplicate in flight.
        assertEquals(
            BleAuthRequestGate.Verdict.REPLAY,
            gate.evaluate(challenge, nowSeconds, peer),
        )
        assertEquals(2, replayChecks.get())
    }

    @Test
    fun linkLossThatHasNotReachedTheGraceKeepsTheClaimSoTheReconnectIsADuplicate() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))

        // The GATT link dropped and the Client reconnected retransmitting the same request. The
        // service deliberately does not touch the gate on a disconnect, so the claim is still here,
        // and the arrival must be answered as a duplicate WITHOUT the replay cache ever being asked
        // (its answer would be "replay", and the service disconnects on that, killing the prompt).
        nowMillis += 1_000L

        assertEquals(
            BleAuthRequestGate.Verdict.DUPLICATE_IN_FLIGHT,
            gate.evaluate(challenge, nowSeconds, peer),
        )
        assertEquals(
            "a reconnect inside the grace must not reach the replay cache",
            1,
            replayChecks.get(),
        )
        assertEquals(1, gate.inFlightCount)
    }

    /**
     * `concludePeer` is the release the service runs at the end of the reconnection grace, and only
     * when the device did not come back — not the `STATE_DISCONNECTED` handler it used to run it
     * from. It removes exactly that peer's claims, so an abandoned link leaks nothing while another
     * peer's in-flight prompt keeps its claim.
     */
    @Test
    fun concludePeerAtGraceExpiryReleasesOnlyThatPeersChallenges() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))
        assertEquals(
            BleAuthRequestGate.Verdict.PROCESS,
            gate.evaluate(otherChallenge, nowSeconds, otherPeer),
        )

        gate.concludePeer(peer)

        assertEquals(1, gate.inFlightCount)
        // The abandoned request is concluded: nothing is held for it any more, so the next arrival
        // is decided by the replay cache again, exactly as for a request whose answer was sent.
        assertEquals(
            BleAuthRequestGate.Verdict.REPLAY,
            gate.evaluate(challenge, nowSeconds, peer),
        )
        assertEquals(
            BleAuthRequestGate.Verdict.DUPLICATE_IN_FLIGHT,
            gate.evaluate(otherChallenge, nowSeconds, otherPeer),
        )
        assertEquals("only the released peer's claim may be gone", 1, gate.inFlightCount)
    }

    @Test
    fun staleInFlightEntryIsPruned() {
        assertEquals(BleAuthRequestGate.Verdict.PROCESS, gate.evaluate(challenge, nowSeconds, peer))

        // A link that never reported its disconnect: after the TTL the entry is dropped instead of
        // being held for the lifetime of the process.
        nowMillis += 600_001L

        assertEquals(
            BleAuthRequestGate.Verdict.REPLAY,
            gate.evaluate(challenge, nowSeconds, peer),
        )
        assertEquals(2, replayChecks.get())
    }

    @Test
    fun racingDuplicatesProduceExactlyOneProcessing() {
        val threads = 8
        val start = CountDownLatch(1)
        val verdicts = java.util.Collections.synchronizedList(mutableListOf<Any>())
        val pool = Executors.newFixedThreadPool(threads)
        try {
            repeat(threads) {
                pool.execute {
                    start.await()
                    verdicts.add(gate.evaluate(challenge, nowSeconds, peer))
                }
            }
            start.countDown()
            pool.shutdown()
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }

        assertEquals(threads, verdicts.size)
        assertEquals(
            "exactly one arrival may be processed",
            1,
            verdicts.count { it == BleAuthRequestGate.Verdict.PROCESS },
        )
        assertEquals(
            "every other arrival is a duplicate in flight",
            threads - 1,
            verdicts.count { it == BleAuthRequestGate.Verdict.DUPLICATE_IN_FLIGHT },
        )
        assertEquals("only the winner may reach the replay cache", 1, replayChecks.get())
    }
}
