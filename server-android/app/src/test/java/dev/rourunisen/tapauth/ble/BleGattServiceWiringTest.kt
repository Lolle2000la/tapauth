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

        // Same defect class, one registry over: the answer held for the peer is the other thing a
        // reconnect needs. Dropped at teardown, the Client's retransmission has no bytes to be
        // re-delivered and the prompt stands on a live link with nothing left to send.
        for (dropped in DROPPING_HELD_STATE) {
            assertFalse(
                "STATE_DISCONNECTED must not drop held response state before the grace has " +
                    "expired (`$dropped`), or the Client's retransmission cannot be answered:\n" +
                    branch,
                branch.contains(dropped),
            )
        }
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
        // The `if` is the invariant, not the wait: above it the release also fires for a device
        // that *did* reconnect inside the grace, whose next retransmission then reaches the replay
        // cache and gets the fresh link torn down — the original bug, one indentation level out.
        val reconnectCheck = source.indexOf(RECONNECT_CHECK, graceWait)
        assertTrue(
            "the release must sit inside the reconnect check `$RECONNECT_CHECK` that follows " +
                "$GRACE_WAIT (offset $reconnectCheck not in $graceWait..$graceBlockEnd)",
            reconnectCheck > graceWait && reconnectCheck < graceBlockEnd,
        )
        assertTrue(
            "authRequestGate.concludePeer must be inside `$RECONNECT_CHECK`: released above it, a " +
                "device that reconnected inside the grace loses its claim and its retransmission " +
                "is answered as a replay (release at $conclude, check at $reconnectCheck)",
            conclude > reconnectCheck && conclude < graceBlockEnd,
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
        val arguments = source.substring(call + FINISH_CALL.length, source.indexOf(')', call))
        // The pair is what matters, not a mention of `confirmed`: a bare `\bconfirmed\b` match also
        // accepted `!confirmed`, which retires the held bytes on link loss and keeps them after the
        // Client confirmed — both halves of the contract inverted, with every test green.
        assertEquals(
            "the retirement must be passed the loop's confirmation, or a loop that ended without " +
                "one (link died, window elapsed, re-delivery cancelled it) drops bytes the Client " +
                "still needs and the re-delivery path can never run; call site: $arguments",
            CONFIRMED_ARGUMENTS,
            arguments.normalized(),
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

        // The record alone settles nothing: the bytes still have to be written somewhere. Aiming
        // the write at the captured handle records the answer against the live one and writes it
        // to the dead one, so every handoff test stays green and the approval is lost again.
        val write = source.indexOf(DELIVER_RESPONSE_CALL, call)
        assertTrue(
            "the record must be followed by `$DELIVER_RESPONSE_CALL…` that writes the bytes",
            write > call,
        )
        val aim = source.substring(write + DELIVER_RESPONSE_CALL.length, source.indexOf(',', write))
        assertEquals(
            "the write after the record must aim at the same live handle (`$HANDLE_AIM`); a first " +
                "argument of `gatt` writes the answer to the captured — possibly closed — handle, " +
                "so the record points at a link that never receives it; call site: " +
                source.substring(write, source.indexOf(')', write)),
            HANDLE_AIM,
            aim.normalized(),
        )
    }

    /** Whitespace and line breaks only, so the shape is compared and not the formatting. */
    private fun String.normalized(): String = replace(Regex("\\s+"), " ").trim()

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

        /** The reconnect test the grace-expiry release has to stay inside. */
        const val RECONNECT_CHECK = "if (!connectingOrConnectedDevices.contains(deviceAddress))"

        /** Ways to drop held response state; only the grace expiry may use them. */
        val DROPPING_HELD_STATE = listOf("abandonPeer(", "clear(")

        /** The first line after the grace coroutine, where the torn-down handle is tombstoned. */
        const val GRACE_BLOCK_END = "// The handle is closed below"
        const val CLOSED_HANDLE_TOMBSTONE = "gattConnections.computeIfAbsent(gatt)"
        const val FINISH_CALL = "pendingResponses.finish("
        const val CONFIRMED_ARGUMENTS = "delivery, confirmed"
        const val RECORD_CALL = "pendingResponses.record("
        const val LIVE_HANDLE_HELPER = "liveHandleFor("
        const val DELIVER_RESPONSE_CALL = "deliverResponse("

        /** The handle the write after the record has to be aimed at. */
        const val HANDLE_AIM = "delivery?.handle ?: gatt"
    }
}
