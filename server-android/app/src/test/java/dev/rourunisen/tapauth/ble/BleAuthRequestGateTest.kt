package dev.rourunisen.tapauth.ble

import dev.rourunisen.tapauth.service.ReplayMitigationCache
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Ordering of the ladder [BleAuthRequestGate.decide] answers: the transport claim, then the
 * duplicate-in-flight check, then the replay cache.
 *
 * The replay check is the real [ReplayMitigationCache] (fixed clock), not a stub: it is the
 * collaborator that decides "replay" in production. [replayChecks] only counts that the gate
 * consulted it, which is what separates a duplicate that never reached the cache from one that did,
 * and [steps] records the order the two collaborators were asked in.
 */
class BleAuthRequestGateTest {

    private var nowSeconds = 1_700_000_000L
    private var nowMillis = 1_000_000L

    private val replayChecks = AtomicInteger(0)

    /**
     * Which collaborator was asked, in order: "claim" for the transport lock, "replay" for the
     * cache.
     */
    private val steps = java.util.Collections.synchronizedList(mutableListOf<String>())
    private val replayCache = ReplayMitigationCache { nowSeconds }

    private val gate =
        BleAuthRequestGate(
            isReplay = { challenge, timestampUnixSeconds ->
                steps.add("replay")
                replayChecks.incrementAndGet()
                replayCache.isReplay(challenge, timestampUnixSeconds)
            },
            elapsedMillis = { nowMillis },
        )

    private val challenge = ByteArray(32) { (it + 1).toByte() }
    private val otherChallenge = ByteArray(32) { (it + 101).toByte() }
    private val peer = "AA:BB:CC:DD:EE:01"
    private val otherPeer = "AA:BB:CC:DD:EE:02"

    /** The transport lock's answer, recorded so the ladder's first rung is observable. */
    private fun claimsTransport(granted: Boolean): () -> Boolean = {
        steps.add("claim")
        granted
    }

    /** The collaborator calls recorded since the last read, oldest first. */
    private fun takenSteps(): List<String> {
        val taken = synchronized(steps) { steps.toList() }
        steps.clear()
        return taken
    }

    @Test
    fun firstArrivalIsProcessed() {
        val decision = gate.decide(challenge, nowSeconds, peer, claimsTransport(true))

        assertEquals(BleAuthRequestGate.Decision.Process, decision)
        assertEquals(1, replayChecks.get())
        assertEquals(1, gate.inFlightCount)
    }

    @Test
    fun duplicateFromSamePeerNeverReachesTheReplayCache() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // The copy that races the initial read, or the re-notification of the same request.
        val duplicate = gate.decide(challenge, nowSeconds, peer, claimsTransport(true))

        assertEquals(BleAuthRequestGate.Decision.Duplicate, duplicate)
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
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // Another device replaying the captured packet: not a duplicate, so it must be rejected by
        // the replay cache exactly as before (the caller then disconnects it).
        val replayed = gate.decide(challenge, nowSeconds, otherPeer, claimsTransport(true))

        assertEquals(BleAuthRequestGate.Decision.Replay, replayed)
        assertEquals(
            "the foreign replay must be consulted by the replay cache",
            2,
            replayChecks.get(),
        )
    }

    @Test
    fun concludeLetsTheChallengeReachTheReplayCacheAgain() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // The authentication concluded (grant sent / denial / cancel / timeout).
        gate.conclude(challenge)
        assertEquals(0, gate.inFlightCount)

        // The same bytes afterwards are a replay again, not a duplicate in flight.
        assertEquals(
            BleAuthRequestGate.Decision.Replay,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(2, replayChecks.get())
    }

    /**
     * The gate retains the peer's claim across the grace window, so a repeat of the same challenge
     * inside that window is a duplicate in flight rather than a replay.
     *
     * This pins the gate only: it says nothing about *when* the service releases a peer. That the
     * `STATE_DISCONNECTED` handler leaves `releaseForRetry` alone (and runs it only once the grace
     * has expired without a reconnect) cannot be observed from here — `BluetoothGatt` is a
     * framework class — so it is pinned by the source guard in `BleGattServiceWiringTest`.
     */
    @Test
    fun theClaimSurvivesTheGraceWindowSoARepeatInsideItIsADuplicate() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // The GATT link dropped and the Client reconnected retransmitting the same request. The
        // service deliberately does not touch the gate on a disconnect, so the claim is still here,
        // and the arrival must be answered as a duplicate WITHOUT the replay cache ever being asked
        // (its answer would be "replay", and the service disconnects on that, killing the prompt).
        nowMillis += 1_000L

        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(
            "a reconnect inside the grace must not reach the replay cache",
            1,
            replayChecks.get(),
        )
        assertEquals(1, gate.inFlightCount)
    }

    /**
     * `releaseForRetry` is the release the service runs at the end of the disconnect grace, and
     * only when the device did not come back. It must not conclude a challenge: the reconnect it
     * waited for is scan-driven and can outlast any constant, so the retransmission that finally
     * arrives has to stay a duplicate in flight — a concluded claim would send it to the replay
     * cache, whose "replay" answer makes the service tear the new link down, and the Desktop's
     * window would then time out with no way back.
     */
    @Test
    fun releaseForRetryKeepsTheClaimSoTheArrivalOnTheReconnectedLinkIsADuplicate() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(otherChallenge, nowSeconds, otherPeer, claimsTransport(true)),
        )

        // The grace expired with nothing on this peer's link left to answer.
        gate.releaseForRetry(peer)

        assertTrue(
            "the claim has to stay, it is only released for a retry",
            gate.holdsClaimFor(peer),
        )
        assertTrue(gate.wasReleasedForRetry(challenge))
        assertFalse(
            "another peer's claim is not this release's to mark",
            gate.wasReleasedForRetry(otherChallenge),
        )
        assertEquals("no claim may be concluded by the grace", 2, gate.inFlightCount)

        // The retransmission from the same peer on the reconnected link: still a duplicate, and the
        // replay cache — whose answer for these bytes is "replay" — is never asked.
        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(
            "a released claim must not be swallowed as a replay",
            2,
            replayChecks.get(),
        )

        // And the other peer's open prompt is untouched by that release.
        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(otherChallenge, nowSeconds, otherPeer, claimsTransport(true)),
        )
        assertFalse(gate.wasReleasedForRetry(otherChallenge))
        assertEquals(2, replayChecks.get())
    }

    /**
     * An answer being *built* is not the Client receiving it: the grant or denial is recorded
     * before the write, and that write fails on the handle the link died under. Concluding a claim
     * whose prompt the user answered therefore discards a completed approval and hands the
     * retransmission that finally arrives to the replay cache — which answers "replay", disconnects
     * the fresh link, and leaves the Desktop with no way back for the rest of its window. So the
     * release covers an answered claim exactly like an unanswered one.
     */
    @Test
    fun anAnsweredChallengeIsReleasedForRetrySoTheRetransmissionAfterALostAnswerIsNotAReplay() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // The user approved while the link was down: the answer was recorded, never written.
        gate.releaseForRetry(peer)

        assertTrue("the claim must survive an answered prompt too", gate.holdsClaimFor(peer))
        assertTrue(gate.wasReleasedForRetry(challenge))
        assertEquals("the release concludes nothing", 1, gate.inFlightCount)

        // The Client reconnected and retransmits the challenge it never got the verdict for.
        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals("a lost answer must not be swallowed as a replay", 1, replayChecks.get())
    }

    /**
     * `retryStarted` consumes the release, so exactly one fresh prompt follows each release and the
     * arrival after that is a plain duplicate of the prompt it raised.
     */
    @Test
    fun retryStartedConsumesTheRelease() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        gate.releaseForRetry(peer)
        assertTrue(gate.wasReleasedForRetry(challenge))

        gate.retryStarted(challenge)

        assertFalse(
            "the retry the release announced is being raised",
            gate.wasReleasedForRetry(challenge),
        )
        assertTrue("the claim the retry feeds on is still held", gate.holdsClaimFor(peer))
        // A second copy is a duplicate of the prompt the retry just raised, and the gate is not
        // consulted about a retry it already granted.
        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals("a retried challenge never reaches the replay cache", 1, replayChecks.get())
        assertEquals(1, gate.inFlightCount)
    }

    @Test
    fun staleInFlightEntryIsPruned() {
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )

        // A link that never reported its disconnect: after the TTL the entry is dropped instead of
        // being held for the lifetime of the process.
        nowMillis += 600_001L

        assertEquals(
            BleAuthRequestGate.Decision.Replay,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(2, replayChecks.get())
    }

    /**
     * The four verdicts one challenge can reach, in the order the ladder answers them, with the
     * collaborators each rung asked.
     *
     * A verdict-only test cannot see a reordering: every rung has a different result, so a
     * duplicate checked after the replay cache still returns "replay" — and the service disconnects
     * on that, killing the prompt the gate exists to protect. The recorded `[claim, replay]`
     * sequence is what makes the order observable, so each step asserts both the verdict and what
     * was consulted to reach it.
     */
    @Test
    fun theLadderIsClaimedThenDuplicateThenReplayThenProcess() {
        // 1. Another transport owns the challenge: the claim refuses it, and nothing below it runs.
        assertEquals(
            BleAuthRequestGate.Decision.Claimed,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(false)),
        )
        assertEquals(listOf("claim"), takenSteps())
        assertEquals("a claimed challenge must not reach the replay cache", 0, replayChecks.get())
        assertEquals("a claimed challenge is not ours to hold", 0, gate.inFlightCount)

        // 2. Ours, and fresh: the rung that asks the replay cache and answers Process.
        assertEquals(
            BleAuthRequestGate.Decision.Process,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(listOf("claim", "replay"), takenSteps())
        assertEquals(1, gate.inFlightCount)

        // 3. Same peer, same challenge, in flight: a duplicate, decided without the replay cache —
        // one "replay" step fewer than the rung above, which is the difference the gate exists for.
        assertEquals(
            BleAuthRequestGate.Decision.Duplicate,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(listOf("claim"), takenSteps())
        assertEquals(
            "the duplicate must not be consulted by the replay cache",
            1,
            replayChecks.get(),
        )

        // 4. The prompt concluded, so the same bytes are the replay cache's business again.
        gate.conclude(challenge)
        assertEquals(
            BleAuthRequestGate.Decision.Replay,
            gate.decide(challenge, nowSeconds, peer, claimsTransport(true)),
        )
        assertEquals(listOf("claim", "replay"), takenSteps())
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
                    verdicts.add(gate.decide(challenge, nowSeconds, peer, claimsTransport(true)))
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
            verdicts.count { it == BleAuthRequestGate.Decision.Process },
        )
        assertEquals(
            "every other arrival is a duplicate in flight",
            threads - 1,
            verdicts.count { it == BleAuthRequestGate.Decision.Duplicate },
        )
        assertEquals("only the winner may reach the replay cache", 1, replayChecks.get())
    }
}
