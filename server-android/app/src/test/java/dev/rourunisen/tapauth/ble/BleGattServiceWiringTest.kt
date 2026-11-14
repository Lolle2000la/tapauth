package dev.rourunisen.tapauth.ble

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `BleGattService` wiring that no JVM test can execute, pinned by reading the production
 * source.
 *
 * `BleGattService` is an Android `Service` whose callbacks take a framework `BluetoothGatt`, so
 * neither the `STATE_DISCONNECTED` handler nor the response-delivery loop can be constructed off a
 * device. That leaves two real defects with no failing test anywhere: re-adding
 * `authRequestGate.concludePeer(deviceAddress)` to the disconnect handler (a reconnect inside the
 * grace would then reach the replay cache, be called a replay and tear the new link down, killing
 * the prompt), and dropping the confirmation from the retirement call (every loop end — including a
 * link that died mid-delivery — would retire the held bytes and the re-delivery path becomes dead
 * code). A source guard is the only executable statement of those contracts a unit test can make:
 * it is deliberately a parse of the shipped call sites, in the spirit of
 * `client-pam/src/source_guards.rs`, and it does not replace the instrumentation suite that
 * exercises the behaviour.
 *
 * A failure here means the rule moved or changed shape: re-read `BleGattService.kt`, then fix
 * whichever side is wrong. The file is found by walking up from the test's working directory
 * (`server-android/app`); when it cannot be found the test fails rather than skips, because a
 * silently skipped guard is exactly the defect this class exists to prevent.
 */
class BleGattServiceWiringTest {

    private val source = serviceSource()

    @Test
    fun theDisconnectHandlerDoesNotReleaseThePeersClaims() {
        val branch = disconnectBranchUpToItsGraceCoroutine()

        // The claim has to outlive the link: the Client reconnects retransmitting the same
        // challenge, and that arrival is answered as a duplicate in flight only while the claim is
        // still held. Released here, it reaches the replay cache, which answers "replay" and
        // disconnects the new link — the prompt dies with it.
        assertFalse(
            "STATE_DISCONNECTED must not call authRequestGate.concludePeer before the grace " +
                "has expired; found it in:\n$branch",
            branch.contains(CONCLUDE_PEER),
        )
    }

    @Test
    fun theGateIsReleasedOnceAndOnlyInsideTheGraceExpiryBlock() {
        assertEquals(
            "the peer's claims are released at exactly one place: the grace-expiry release",
            1,
            source.split(CONCLUDE_PEER).size - 1,
        )

        // …and that place must be inside the coroutine that waits out the grace first, so a link
        // that stays down leaves nothing held and a link that comes back leaves its claim alone.
        val launch = source.indexOf(SERVICE_SCOPE_LAUNCH, source.indexOf(DISCONNECTED_ARM))
        assertTrue("the disconnect branch must start its grace coroutine", launch >= 0)
        val graceWait = source.indexOf(GRACE_WAIT, launch)
        assertTrue("the grace coroutine must await $GRACE_WAIT", graceWait > launch)
        val graceBlockEnd = source.indexOf(GRACE_BLOCK_END, graceWait)
        assertTrue(
            "the grace block is delimited by `$GRACE_BLOCK_END`; re-read BleGattService.kt",
            graceBlockEnd > graceWait,
        )
        val conclude = source.indexOf(CONCLUDE_PEER)
        assertTrue(
            "authRequestGate.concludePeer must run after $GRACE_WAIT, inside the grace-expiry " +
                "block (offset $conclude not in $graceWait..$graceBlockEnd)",
            conclude > graceWait && conclude < graceBlockEnd,
        )
        // Outside that block the release would be unconditional on a reconnect having happened,
        // which is the disconnect-handler bug the first test refuses.
        assertTrue(
            "the release must stay inside the disconnect branch's grace coroutine",
            conclude < source.indexOf(CLOSED_HANDLE_TOMBSTONE, launch),
        )
    }

    @Test
    fun theDeliveryLoopRetiresAnAnswerOnlyWithTheConfirmation() {
        assertEquals(
            "the held answer is retired at exactly one call site",
            1,
            source.split(FINISH_CALL).size - 1,
        )

        val call = source.indexOf(FINISH_CALL)
        val arguments = source.substring(call, source.indexOf(')', call))
        assertTrue(
            "the retirement must be passed the loop's confirmation, or a loop that ended without " +
                "one (link died, window elapsed, re-delivery cancelled it) drops bytes the Client " +
                "still needs and the re-delivery path can never run; call site: $arguments",
            Regex("\\bconfirmed\\b").containsMatchIn(arguments.substringAfter(FINISH_CALL)),
        )
    }

    @Test
    fun theAnswerIsAimedAtTheChallengesLiveHandle() {
        assertEquals(
            "an answer is recorded at exactly one call site",
            1,
            source.split(RECORD_CALL).size - 1,
        )

        val call = source.indexOf(RECORD_CALL)
        val arguments = source.substring(call, source.indexOf(')', call))
        // The handle its callback captured is already closed once the prompt outlived a drop, so it
        // cannot be the only aim: the live handle has to be resolved from the challenge-tracked map
        // at record time. Passing a bare null here compiles and leaves every handoff test green,
        // while the approval is again written to the dead handle and lost.
        assertTrue(
            "the record call must resolve the challenge's live handle, not only pass the captured " +
                "one; call site: $arguments",
            arguments.contains(LIVE_HANDLE_HELPER),
        )
    }

    /** `STATE_DISCONNECTED` up to the grace coroutine it starts, i.e. the pre-teardown body. */
    private fun disconnectBranchUpToItsGraceCoroutine(): String {
        val start = source.indexOf(DISCONNECTED_ARM)
        assertTrue("`$DISCONNECTED_ARM` must open the disconnect branch", start >= 0)
        val launch = source.indexOf(SERVICE_SCOPE_LAUNCH, start)
        assertTrue("the disconnect branch must start a coroutine", launch > start)
        return source.substring(start, launch)
    }

    private fun serviceSource(): String {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val file = File(directory, SERVICE_SOURCE_PATH)
            if (file.isFile) return file.readText()
            directory = directory.parentFile
        }
        throw AssertionError(
            "$SERVICE_SOURCE_PATH was not found above ${File("").absolutePath}; the disconnect " +
                "handler and delivery loop cannot be guarded from this working directory",
        )
    }

    private companion object {
        const val SERVICE_SOURCE_PATH =
            "app/src/main/java/dev/rourunisen/tapauth/ble/BleGattService.kt"

        /** The `when (newState)` arm; unique because the status check only compares against it. */
        const val DISCONNECTED_ARM = "BluetoothProfile.STATE_DISCONNECTED -> {"
        const val SERVICE_SCOPE_LAUNCH = "serviceScope.launch {"
        const val GRACE_WAIT = "delay(BLE_DISCONNECT_CANCEL_GRACE_MS)"
        const val CONCLUDE_PEER = "authRequestGate.concludePeer("

        /** The first line after the grace coroutine, where the torn-down handle is tombstoned. */
        const val GRACE_BLOCK_END = "// The handle is closed below"
        const val CLOSED_HANDLE_TOMBSTONE = "gattConnections.computeIfAbsent(gatt)"
        const val FINISH_CALL = "pendingResponses.finish("
        const val RECORD_CALL = "pendingResponses.record("
        const val LIVE_HANDLE_HELPER = "liveHandleFor("
    }
}
