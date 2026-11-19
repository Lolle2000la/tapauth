package dev.rourunisen.tapauth.service

import java.util.Collections
import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The properties of [PendingRequestRegistry], the one owning structure for pending prompts.
 *
 * Every test drives the registry through its public reads and releases only, and never names a
 * private field: the point of the structure is that the challenge view, the BLE-device view and the
 * TTL sweep are *derived* from the one map, so "every view misses after a release" is the assertion
 * that catches a removal path which forgets to clean up a second structure.
 *
 * No `Context`, no `NotificationManager`, no sleeping: the registry takes `now` and its scheduler
 * as parameters, and the prompt it stores is this file's own [FakePrompt] - which is only possible
 * because the registry is generic over [PendingPrompt] instead of holding the shell's record.
 * Comparing challenge bytes by content is the other half of that: `unitTests.isReturnDefaultValues
 * = true` makes `Base64.encodeToString` return null and `SystemClock.elapsedRealtime` return 0.
 */
class PendingRequestRegistryTest {

    private var clock = 0L

    /** The delays the registry asked for, in order; the real one sleeps on `Dispatchers.IO`. */
    private val scheduled = mutableListOf<Long>()

    private val registry =
        PendingRequestRegistry<FakePrompt>(
            clock = { clock },
            scheduleExpiry = { scheduled += it },
        )

    @Test
    fun aReleasedUdpRequestIsInvisibleToEveryLookup() {
        val answers = Recorder()
        val challenge = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        assertEquals(
            PendingRequestRegistry.Registration.Registered,
            registry.register(pending("udp-1", challenge, callback = answers.callback)),
        )
        val deadline = registry.find("udp-1")!!.deadlineMs
        assertEquals(setOf("udp-1"), registry.activeIds())

        val released = registry.release("udp-1")

        assertEquals("udp-1", released?.requestId)
        assertTrue(registry.activeIds().isEmpty())
        assertFalse(registry.has("udp-1"))
        assertNull(registry.find("udp-1"))
        // The challenge view must not still answer for it: a forgotten index entry is what makes
        // the user's Cancel on the phone stop working for that prompt.
        assertTrue(registry.releaseByChallenge(challenge).isEmpty())
        // A UDP prompt has no BLE address, and the derived device view must not invent one.
        assertTrue(registry.releaseByBleDevice(ADDRESS_A).isEmpty())
        // The leaked-prompt property: a sweep after the deadline must not find it again and must
        // not hand a second caller the entry to deliver a second callback for.
        clock = deadline + 1
        assertTrue(registry.releaseExpired().isEmpty())

        // The claim the shell won is the only thing that carries the callback.
        released!!.callback(true, challenge, false)
        assertEquals(1, answers.count)
    }

    @Test
    fun cancellingAChallengeReleasesTheBleRequestOutOfTheDeviceViewToo() {
        val answers = Recorder()
        val challenge = byteArrayOf(0x11, 0x22)
        assertEquals(
            PendingRequestRegistry.Registration.Registered,
            registry.register(
                pending(
                    "ble-1",
                    challenge,
                    bleDeviceAddress = ADDRESS_A,
                    callback = answers.callback,
                ),
            ),
        )

        // What `cancelRequestsByChallenge` does with the claim it wins: answer as *cancelled*, not
        // as an explicit denial, so the client is not told the user refused.
        registry.releaseByChallenge(challenge).forEach { it.callback(false, null, false) }

        assertEquals(1, answers.count)
        val delivery = answers.only
        assertEquals(false, delivery.first)
        assertNull(delivery.second)
        assertEquals(false, delivery.third)
        // Releasing the link afterwards must find nothing, and stay a no-op on the second call:
        // a device view that still held the id would ring the callback twice.
        assertTrue(registry.releaseByBleDevice(ADDRESS_A).isEmpty())
        assertTrue(registry.releaseByBleDevice(ADDRESS_A).isEmpty())
        assertTrue(registry.activeIds().isEmpty())
        assertEquals(1, answers.count)
    }

    @Test
    fun theDeadlineSweepReleasesOnlyTheDuePromptAndReleasesItOnce() {
        val early = Recorder()
        val late = Recorder()
        // Two prompts, two deadlines: a sweep releases exactly the entries whose own deadline has
        // passed, which is why the deadline belongs to the entry instead of to a coroutine.
        registry.register(
            pending("early", byteArrayOf(0x31), timeoutMs = 1_000L, callback = early.callback),
        )
        registry.register(
            pending("late", byteArrayOf(0x32), timeoutMs = 5_000L, callback = late.callback),
        )

        assertEquals("nothing is due before the first deadline", emptyList<String>(), sweep(999L))
        assertEquals(listOf("early"), sweep(1_000L))
        assertEquals(
            "a second sweep at the same instant is a no-op",
            emptyList<String>(),
            sweep(1_000L),
        )
        assertEquals("and so is one later in the same window", emptyList<String>(), sweep(1_001L))
        assertEquals(1, early.count)
        assertEquals(0, late.count)
        assertEquals(setOf("late"), registry.activeIds())

        assertEquals(listOf("late"), sweep(5_000L))
        assertTrue(registry.activeIds().isEmpty())
        assertEquals(1, late.count)
        assertEquals("no prompt times out twice", 1, early.count)
    }

    @Test
    fun twoPromptsWithTheSameChallengeOnDifferentDevicesDoNotCollide() {
        val challenge = byteArrayOf(0x42, 0x42)
        val onA = Recorder()
        val onB = Recorder()
        registry.register(
            pending("a", challenge, bleDeviceAddress = ADDRESS_A, callback = onA.callback),
        )
        registry.register(
            pending("b", challenge, bleDeviceAddress = ADDRESS_B, callback = onB.callback),
        )

        // Removing one leaves the other: the shared challenge bytes still resolve to the survivor.
        assertEquals("a", registry.release("a")?.requestId)
        assertEquals(setOf("b"), registry.activeIds())
        assertEquals(listOf("b"), registry.releaseByChallenge(challenge).map { it.requestId })
        assertEquals(
            "removing a device's last prompt empties its view",
            emptyList<String>(),
            registry.releaseByBleDevice(ADDRESS_A).map { it.requestId },
        )

        // And a disconnect releases only the entries that arrived on that link, even though both
        // carry the same challenge.
        registry.register(
            pending("c", challenge, bleDeviceAddress = ADDRESS_A, callback = onA.callback),
        )
        registry.register(
            pending("d", challenge, bleDeviceAddress = ADDRESS_B, callback = onB.callback),
        )
        assertEquals(listOf("c"), registry.releaseByBleDevice(ADDRESS_A).map { it.requestId })
        assertEquals(setOf("d"), registry.activeIds())
        assertEquals(listOf("d"), registry.releaseByChallenge(challenge).map { it.requestId })
        assertTrue(registry.activeIds().isEmpty())
    }

    @Test
    fun aCancelledChallengeIsUnanswerableForExactlyTheCancelWindow() {
        val challenge = byteArrayOf(0x55, 0x66)
        clock = 1_000L
        registry.markCancelled(challenge)

        // Registration consults exactly this after inserting, so "true" is "the submit is rolled
        // back": the callback is answered as cancelled and nothing is left pending.
        assertTrue(registry.isCancelled(challenge))

        // The window is inclusive at its own boundary and gone one millisecond later — an expired
        // record must never keep a later request with the same bytes unanswerable.
        clock = 1_000L + PendingRequestRegistry.CANCEL_TTL_MS
        assertTrue(registry.isCancelled(challenge))
        clock = 1_000L + PendingRequestRegistry.CANCEL_TTL_MS + 1
        assertFalse(registry.isCancelled(challenge))

        assertEquals(
            PendingRequestRegistry.Registration.Registered,
            registry.register(pending("after-the-window", challenge)),
        )
        assertEquals(setOf("after-the-window"), registry.activeIds())
        // The pruned record cannot come back into force on a later read.
        assertFalse(registry.isCancelled(challenge))
    }

    @Test
    fun aChallengeCancelledBeforeRegistrationIsRefusedAndLeavesNothingPending() {
        val challenge = byteArrayOf(0x61, 0x62)
        clock = 2_000L
        registry.markCancelled(challenge)

        // The plain refusal, with the cancel already recorded and no canceller racing: the entry is
        // stored, the re-check refuses it, and the rollback leaves nothing behind. (The *ordering*
        // of the check against the insert is what `theCancelCheckRunsWhileTheEntryIsAlreadyStored`
        // pins; this test would also pass against a check-then-insert implementation.)
        assertEquals(
            PendingRequestRegistry.Registration.RefusedCancelled,
            registry.register(pending("late", challenge)),
        )

        assertTrue(registry.activeIds().isEmpty())
        assertFalse(registry.has("late"))
        assertNull(registry.find("late"))
        assertEquals("a refused registration arms no sweep", emptyList<Long>(), scheduled)

        // The honest converse: past the window the same bytes register normally, and the sweep is
        // armed for that entry only.
        clock = 2_000L + PendingRequestRegistry.CANCEL_TTL_MS + 1
        assertEquals(
            PendingRequestRegistry.Registration.Registered,
            registry.register(pending("late", challenge)),
        )
        assertEquals(setOf("late"), registry.activeIds())
        assertEquals(1, scheduled.size)
    }

    @Test
    fun theCancelCheckRunsWhileTheEntryIsAlreadyStored() {
        val challenge = byteArrayOf(0x63, 0x64)
        clock = 3_000L
        registry.markCancelled(challenge)

        // The cancelled-challenge check is interior to `register`, and the fake's `challenge`
        // getter
        // is read only for it, so this records what the registry had already done with the id at
        // the
        // instant it asked. A check-then-insert implementation asks while the map is still empty,
        // which is exactly the window a cancel can slip through.
        val storedWhenChecked = mutableListOf<Boolean>()
        val probe =
            FakePrompt(
                requestId = "probe",
                bytes = challenge,
                bleDeviceAddress = null,
                deadlineMs = clock + 1_000L,
                onChallengeRead = { storedWhenChecked += registry.has("probe") },
            )

        val outcome = registry.register(probe)

        // The *last* read is the one the refusal turns on, so extra reads are tolerated: an
        // implementation that caches the bytes first or logs them reads them more than once, but
        // only a check-then-insert implementation makes its deciding read while the map is empty.
        assertTrue("the cancel check must read the challenge", storedWhenChecked.isNotEmpty())
        assertEquals("the deciding read happens after the insert", true, storedWhenChecked.last())
        assertEquals(PendingRequestRegistry.Registration.RefusedCancelled, outcome)
        assertTrue(registry.activeIds().isEmpty())
        assertEquals("the rolled-back entry arms no sweep", emptyList<Long>(), scheduled)
    }

    @Test
    fun aClaimThatWinsDuringRegistrationIsNotAnsweredTwice() {
        val bytes = byteArrayOf(0x65, 0x66)
        clock = 4_000L
        val answers = Recorder()
        val claimedBy = mutableListOf<String>()

        // Plays the canceller's scan between the insert and the check: it marks the challenge and
        // claims the entry, delivering the one answer this request is owed.
        val probe =
            FakePrompt(
                requestId = "raced",
                bytes = bytes,
                bleDeviceAddress = ADDRESS_A,
                deadlineMs = clock + 1_000L,
                callback = answers.callback,
                onChallengeRead = {
                    registry.markCancelled(bytes)
                    registry.release("raced")?.let { claimed ->
                        claimedBy += claimed.requestId
                        claimed.callback(false, null, false)
                    }
                },
            )

        val outcome = registry.register(probe)

        // The canceller answered it, so the shell must not answer it again: a second
        // `(false, null, false)` is a duplicate denial on the wire and, on BLE, a second
        // `disconnectGatt`/`releaseLock` for one request.
        assertEquals(PendingRequestRegistry.Registration.AlreadyClaimed, outcome)
        assertEquals(listOf("raced"), claimedBy)
        assertEquals("exactly one answer for the request", 1, answers.count)
        assertTrue(registry.activeIds().isEmpty())
        assertEquals("nothing is armed for an entry nobody owns", emptyList<Long>(), scheduled)
    }

    @Test
    fun registrationArmsTheSweepAtTheEntrysOwnDeadline() {
        clock = 1_000L

        registry.register(pending("prompt", byteArrayOf(0x51), timeoutMs = 5_000L))

        // The wait is exactly `deadline - now`: shorter releases a live prompt, longer leaves it
        // answerable past its deadline.
        assertEquals(listOf(5_000L), scheduled)

        // A deadline already behind the clock still gets a real wait. `delay(0)` returns at once
        // and a negative delay is not a wait at all, so either would leave a permanent prompt.
        clock = 20_000L
        registry.register(pending("overdue", byteArrayOf(0x52), timeoutMs = 0L))
        assertEquals(listOf(5_000L, 1L), scheduled)
    }

    @Test
    fun aSecondClaimOfTheSameRequestReleasesNothing() {
        val answers = Recorder()
        val challenge = byteArrayOf(0x77)
        registry.register(pending("once", challenge, callback = answers.callback))

        val winners = Collections.synchronizedList(mutableListOf<String>())
        val start = CountDownLatch(1)
        val racers =
            (1..2).map {
                Thread {
                    start.await()
                    val claimed = registry.release("once")
                    if (claimed != null) {
                        winners += claimed.requestId
                        claimed.callback(false, null, false)
                    }
                }
            }
        racers.forEach { it.start() }
        start.countDown()
        racers.forEach { it.join() }

        // Two removal paths can race for real: the E2E app opens BiometricPromptActivity directly
        // *and* broadcasts to a running MainActivity, so the same answer arrives twice.
        assertEquals("only one claim may win", 1, winners.size)
        assertEquals("exactly one callback", 1, answers.count)
        assertTrue(registry.activeIds().isEmpty())

        // The deterministic form of the same race: the loser is a silent no-op.
        assertNull(registry.release("once"))
        assertEquals(1, answers.count)
    }

    @Test
    fun everyRemovalPathLeavesNoViewBehindAndDeliversExactlyOneCallback() {
        val challenge = byteArrayOf(0x71, 0x72)

        // Each path gets its own fresh request and asserts the same invariant, because the
        // invariant must hold because the views are derived — not because that path remembered to
        // clean each one.
        fun assertReleasesEverything(name: String, release: (String) -> List<FakePrompt>) {
            val answers = Recorder()
            val id = "via-$name"
            registry.register(
                pending(id, challenge, bleDeviceAddress = ADDRESS_A, callback = answers.callback),
            )

            val claimed = release(id)
            claimed.forEach { it.callback(false, null, false) }

            assertEquals("$name claimed the wrong entry", listOf(id), claimed.map { it.requestId })
            assertTrue("$name left the id pending", registry.activeIds().isEmpty())
            assertEquals(
                "$name left the challenge answerable",
                emptyList<String>(),
                registry.releaseByChallenge(challenge).map { it.requestId },
            )
            assertEquals(
                "$name left the device view populated",
                emptyList<String>(),
                registry.releaseByBleDevice(ADDRESS_A).map { it.requestId },
            )
            assertEquals("$name delivered one callback", 1, answers.count)

            // The by-id view agrees it is gone, and nothing delivers a second callback.
            assertNull(registry.release(id))
            assertEquals(1, answers.count)
        }

        assertReleasesEverything("response") { listOfNotNull(registry.release(it)) }
        assertReleasesEverything("timeout") { id ->
            registry.releaseExpired(now = registry.find(id)!!.deadlineMs)
        }
        assertReleasesEverything("cancel-by-challenge") { registry.releaseByChallenge(challenge) }
        assertReleasesEverything("ble-disconnect") { registry.releaseByBleDevice(ADDRESS_A) }
    }

    @Test
    fun theSweepReleasesADuePromptWithNoExplicitNow() {
        val answers = Recorder()
        val challenge = byteArrayOf(0x81.toByte(), 0x82.toByte())
        registry.register(
            pending("due", challenge, timeoutMs = 1_000L, callback = answers.callback),
        )
        val deadline = registry.find("due")!!.deadlineMs

        // The production sweep calls this with no argument (`armExpiry`), so the default `now` is
        // the whole timeout path: a default that never reaches the entry's deadline would leave
        // every prompt permanent with the rest of the suite still green.
        clock = deadline + 1
        val released = registry.releaseExpired()
        released.forEach { it.callback(false, null, false) }

        assertEquals(listOf("due"), released.map { it.requestId })
        assertEquals("the due prompt is answered once", 1, answers.count)
        assertTrue("a second no-argument sweep finds nothing", registry.releaseExpired().isEmpty())
        assertEquals(1, answers.count)
        assertTrue(registry.activeIds().isEmpty())
    }

    @Test
    fun theDeviceViewDoesNotHandBackAReleasedPrompt() {
        registry.register(pending("a", byteArrayOf(0x01), bleDeviceAddress = ADDRESS_A))
        registry.register(pending("b", byteArrayOf(0x02), bleDeviceAddress = ADDRESS_A))

        assertEquals("a", registry.release("a")?.requestId)
        assertEquals(setOf("b"), registry.activeIds())

        // What this observes: the device view releases the survivor and only the survivor, so a
        // released prompt is never handed back (and its callback is never delivered twice). The
        // structural guarantee behind it is that there is no second index to go stale - a stale
        // secondary index would pass this, because `claim` filters it by identity.
        assertEquals(listOf("b"), registry.releaseByBleDevice(ADDRESS_A).map { it.requestId })
        assertTrue(registry.activeIds().isEmpty())
    }

    /** One sweep, with the side effects that ride the claim, as the shell's scheduler runs them. */
    private fun sweep(now: Long): List<String> =
        registry.releaseExpired(now).map { request ->
            request.callback(false, null, false)
            request.requestId
        }

    private fun pending(
        id: String,
        challenge: ByteArray,
        bleDeviceAddress: String? = null,
        timeoutMs: Long = SESSION_TIMEOUT_MS,
        callback: (Boolean, ByteArray?, Boolean) -> Unit = { _, _, _ -> },
    ): FakePrompt = FakePrompt(id, challenge, bleDeviceAddress, clock + timeoutMs, callback)

    /**
     * This file's prompt: the three views' keys, a deadline, and the callback the shell would
     * deliver on release. No Android type anywhere, which is what makes the suite a plain JVM one.
     */
    private class FakePrompt(
        override val requestId: String,
        private val bytes: ByteArray,
        override val bleDeviceAddress: String?,
        override val deadlineMs: Long,
        val callback: (Boolean, ByteArray?, Boolean) -> Unit = { _, _, _ -> },
        /**
         * Run on every read of [challenge]. The registry reads it exactly once per [register], in
         * its cancelled-challenge check, which makes this the seam a test can use to observe the
         * registry's state at that instant - or to play the canceller that claims the entry between
         * the insert and that check.
         */
        val onChallengeRead: () -> Unit = {},
    ) : PendingPrompt {
        override val challenge: ByteArray
            get() {
                onChallengeRead()
                return bytes
            }
    }

    /** What each release delivered, so the assertions can count deliveries, not claims. */
    private class Recorder {
        private val deliveries =
            Collections.synchronizedList(mutableListOf<Triple<Boolean, ByteArray?, Boolean>>())

        val callback: (Boolean, ByteArray?, Boolean) -> Unit = { approved, challenge, denial ->
            deliveries += Triple(approved, challenge, denial)
        }

        val count: Int
            get() = deliveries.size

        val only: Triple<Boolean, ByteArray?, Boolean>
            get() = deliveries.single()
    }

    private companion object {
        const val ADDRESS_A = "AA:BB:CC:DD:EE:01"
        const val ADDRESS_B = "AA:BB:CC:DD:EE:02"

        /** Far beyond any test's `now`, so only the deadline tests ever reach it. */
        const val SESSION_TIMEOUT_MS = 120_000L
    }
}
