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
 * device. That leaves real defects with no failing test anywhere: re-adding
 * `authRequestGate.releaseForRetry(deviceAddress)` to the disconnect handler (a reconnect inside
 * the grace would then reach the replay cache, be called a replay and tear the new link down,
 * killing the prompt), and dropping the confirmation from the retirement call (every loop end —
 * including a link that died mid-delivery — would retire the held bytes and the re-delivery path
 * becomes dead code). The same holds for the effect each outcome of `BleAuthRequestGate.decide` and
 * of `BleDisconnectGrace` maps to here: a `disconnect` added to the duplicate arm, or a `return`
 * before the prompt a released challenge has to be re-offered at, compiles and keeps every gate,
 * grace and handoff test green. The same holds for the receipt log line, which carries the caller's
 * own `username` and `hostname`: whether they are wrapped in `scrubLogValue` is a property of one
 * `Log.d` argument, which no JVM test can read back. A source guard is the only executable
 * statement of those contracts a unit test can make: it is deliberately a parse of the shipped call
 * sites, in the spirit of `client-pam/src/source_guards.rs`, and it does not replace the
 * instrumentation suite that exercises the behaviour.
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
            "STATE_DISCONNECTED must not call authRequestGate.releaseForRetry before the " +
                "grace has expired; found it in:\n$branch",
            branch.contains(RELEASE_CALL),
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

    /**
     * The peer's claim is released at exactly one place, and that place is the `ReleaseAndCancel`
     * arm of the decision the grace coroutine asks after it has waited out the grace.
     *
     * Each half is a defect of its own: a release that runs before the wait, or in the branch
     * rather than in the coroutine, drops a claim whose peer is merely reconnecting; a release
     * outside the decision's arm fires for a device that did come back; and a release that is
     * missing entirely leaves an unanswered prompt alive behind a dead link. The decision itself
     * has to be asked once and after the wait, or it is being asked with facts that cannot be true
     * yet.
     */
    @Test
    fun theGateIsReleasedOnceAndOnlyInsideTheGraceExpiryArm() {
        assertEquals(
            "the peer's claims are released at exactly one place: the grace-expiry release",
            1,
            source.split(RELEASE_CALL).size - 1,
        )
        assertEquals(
            "the disconnect branch must ask the grace decision exactly once",
            1,
            source.split(GRACE_DECISION).size - 1,
        )

        val start = source.indexOf(DISCONNECTED_ARM)
        val launch = source.indexOf(SERVICE_SCOPE_LAUNCH, start)
        assertTrue("the disconnect branch must start its grace coroutine", launch >= 0)
        val graceWait = source.indexOf(GRACE_WAIT, launch)
        assertTrue("the grace coroutine must await $GRACE_WAIT", graceWait > launch)
        val graceBlockEnd = source.indexOf(GRACE_BLOCK_END, graceWait)
        assertTrue(
            "the grace block is delimited by `$GRACE_BLOCK_END`; re-read BleGattService.kt",
            graceBlockEnd > graceWait,
        )

        val decision = source.indexOf(GRACE_DECISION)
        assertTrue(
            "`$GRACE_DECISION` must run after $GRACE_WAIT, inside the grace-expiry block " +
                "(offset $decision not in $graceWait..$graceBlockEnd)",
            decision > graceWait && decision < graceBlockEnd,
        )

        // The `when` on that decision is the invariant: above it the release also fires for a
        // device that *did* reconnect inside the grace, whose next retransmission then reaches the
        // replay cache and gets the fresh link torn down — the original bug, one indentation level
        // out.
        val release = source.indexOf(RELEASE_CALL)
        assertTrue(
            "`$RELEASE_CALL` must run after `$GRACE_DECISION` (offset $release vs $decision)",
            release > decision,
        )
        val arm = source.indexOf(RELEASE_ARM, decision)
        assertTrue(
            "the release must sit inside the `$RELEASE_ARM` arm of the decision (offset $arm not " +
                "after the decision at $decision)",
            arm > decision && arm < graceBlockEnd,
        )
        // The arm is bounded by its own `when`: the next `BleDisconnectGrace.Outcome.` label is not
        // a bound at all here (this is the only one in the file), so a release moved into the
        // `else ->` or hoisted just after the `when` would still satisfy a block-wide bound.
        val armEnd = source.indexOf(OUTCOME_ELSE, arm + RELEASE_ARM.length)
        assertTrue(
            "the `$RELEASE_ARM` arm must be closed by `$OUTCOME_ELSE` (offset $armEnd not in " +
                "$arm..$graceBlockEnd)",
            armEnd > arm && armEnd < graceBlockEnd,
        )
        assertTrue(
            "`$RELEASE_CALL` must be inside `$RELEASE_ARM` (offset $release not in $arm..$armEnd); " +
                "released anywhere else — the `else ->` of that `when`, or just after it — a device " +
                "that reconnected inside the grace loses its claim and its retransmission is " +
                "answered as a replay",
            release > arm && release < armEnd,
        )

        // Outside that block the release would be unconditional on a reconnect having happened,
        // which is the disconnect-handler bug the first test refuses.
        assertTrue(
            "the release must stay inside the disconnect branch's grace coroutine",
            release < source.indexOf(CLOSED_HANDLE_TOMBSTONE, launch),
        )

        // …and it is the arm's LAST effect. Marking the release first lets a retransmission that
        // lands before the cancel below be answered as a retry: the fresh prompt it registers is
        // then claimed and cancelled by that call, so the challenge keeps no prompt, no mark and
        // no disconnect, and every later copy of it is a silent duplicate.
        val abandoned = source.indexOf(ABANDON_PEER_CALL, arm)
        assertTrue(
            "`$ABANDON_PEER_CALL` must run before the release inside `$RELEASE_ARM` (offset " +
                "$abandoned vs $release)",
            abandoned > arm && abandoned < release,
        )
        val cancelled = source.indexOf(CANCEL_BY_DISCONNECTION_CALL, arm)
        assertTrue(
            "`$CANCEL_BY_DISCONNECTION_CALL` must run before the release inside `$RELEASE_ARM` " +
                "(offset $cancelled vs $release)",
            cancelled > arm && cancelled < release,
        )
    }

    /**
     * The facts the grace decision is asked with come from the service's own registries, and
     * nothing else in the suite binds them: `BleDisconnectGraceTest` proves the rule *given* the
     * facts, so a `reconnected = false` literal here compiles and keeps every test green while each
     * expiry releases a peer whose link is up — the original bug, one call site up. `claimHeld` has
     * the mirror-image failure: a literal `false` makes the expiry do nothing at all, so an
     * unanswered prompt outlives its link forever. And a `disconnectedAtMillis = null` makes every
     * expiry `KeepWaiting` — no cancel, no release, an orphaned prompt — while the other two read
     * perfectly, so the drop time has to be pinned to the measured reading as well.
     */
    @Test
    fun theGraceDecisionIsAskedWithTheServicesOwnLiveFacts() {
        val launch = source.indexOf(SERVICE_SCOPE_LAUNCH, source.indexOf(DISCONNECTED_ARM))
        assertTrue("the disconnect branch must start its grace coroutine", launch >= 0)
        val graceWait = source.indexOf(GRACE_WAIT, launch)
        assertTrue("the grace coroutine must await $GRACE_WAIT", graceWait > launch)
        val decision = source.indexOf(GRACE_DECISION, graceWait)
        assertTrue(
            "`$GRACE_DECISION` must be asked after $GRACE_WAIT (offset $decision vs $graceWait), " +
                "or the facts it is given are from before the grace began",
            decision > graceWait,
        )

        val facts = argumentsOf(LINK_FACTS_CALL)
        assertTrue(
            "the decision must be told whether the peer still holds a claim, from the gate " +
                "(`$CLAIM_HELD_ARGUMENT`); facts: $facts",
            facts.contains(CLAIM_HELD_ARGUMENT),
        )
        assertTrue(
            "the decision must be told whether the peer is connected again, from the connection " +
                "registry (`$RECONNECTED_ARGUMENT`); facts: $facts",
            facts.contains(RECONNECTED_ARGUMENT),
        )
        assertTrue(
            "the decision must be given the drop time the grace is measured from " +
                "(`$DISCONNECTED_AT_ARGUMENT`); a literal null there makes every expiry wait " +
                "forever; facts: $facts",
            facts.contains(DISCONNECTED_AT_ARGUMENT),
        )
    }

    @Test
    fun theTornDownHandlesStateIsDroppedOnceTheGraceHasPassed() {
        val launch = source.indexOf(SERVICE_SCOPE_LAUNCH, source.indexOf(DISCONNECTED_ARM))
        assertTrue("the disconnect branch must start its grace coroutine", launch >= 0)
        val graceWait = source.indexOf(GRACE_WAIT, launch)
        assertTrue("the grace coroutine must await $GRACE_WAIT", graceWait > launch)
        val graceBlockEnd = source.indexOf(GRACE_BLOCK_END, graceWait)
        val forget = source.indexOf(FORGET_CALL, launch)

        // The dead handle's state has to go, or a tombstone is kept per reconnection for the life
        // of the service. The grace coroutine is where it may go: dropped in the disconnect branch
        // it would leave a link that merely dropped (and its in-flight answer) without the state
        // the operations still queued on it look up.
        assertTrue(
            "`$FORGET_CALL` must run after $GRACE_WAIT (offset $forget not in " +
                "$graceWait..$graceBlockEnd)",
            forget > graceWait && forget < graceBlockEnd,
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

    /**
     * The BLE prompt path runs the process's one post-authentication limiter, after the request has
     * been authenticated and after the gate admitted it, and before any prompt exists.
     *
     * Nothing else on this path throttles: with the call gone the BLE transport answers every fresh
     * request with a prompt, so a Client that keeps sending them is throttled on UDP and not here
     * (the defect this guard existed for). No JVM test can observe that — `handleAuthRequest` runs
     * inside an Android `Service` on a framework `BluetoothGatt` — and the behavioural half
     * (`BlePromptRateLimitTest`) drives the same limiter with the same key material, so a schedule
     * change fails there while a missing, moved or mis-keyed call fails here.
     */
    @Test
    fun thePromptPathRunsTheOneSharedRateLimiter() {
        assertEquals(
            "the prompt path must run exactly one admission check",
            1,
            source.split(ADMIT_CALL).size - 1,
        )

        val admit = source.indexOf(ADMIT_CALL)

        // After authentication: the check must sit below the signature-verifying parse, so an
        // unverified request cannot spend a paired Client's budget.
        val verified = source.indexOf(VERIFIED_REQUEST_CALL)
        assertTrue(
            "`$ADMIT_CALL` must follow `$VERIFIED_REQUEST_CALL` (offset $admit vs $verified)",
            verified >= 0 && admit > verified,
        )

        // After the gate's Process outcome: Claimed (another transport owns the challenge),
        // Duplicate (a retransmission of the request the user is already answering) and Replay all
        // return above it, so none of them spends burst allowance.
        val process = source.indexOf(PROCESS_ARM)
        assertTrue(
            "`$ADMIT_CALL` must follow the gate's `$PROCESS_ARM` arm (offset $admit vs $process), " +
                "so only an arrival that would raise a prompt is charged for one",
            process >= 0 && admit > process,
        )

        // And before the prompt: the check is only worth anything above the prompt it refuses.
        val submit = source.indexOf("submitRequest(", admit)
        assertTrue(
            "`$ADMIT_CALL` must precede `submitRequest(` (offset $admit vs $submit)",
            submit > admit,
        )

        // Keyed on the paired Client's public key and the verified bytes — never on the temporal
        // identifier (one value per Client per 60 s window, so keying there would throttle a
        // Client's own second request) and never on a peer address.
        val end = source.indexOf(')', admit)
        assertTrue("`$ADMIT_CALL` must be a complete call", end > admit)
        val arguments = source.substring(admit, end).normalized()
        assertTrue(
            "the admission check must be keyed on the paired Client's public key; call: $arguments",
            arguments.contains(PAIRED_KEY_ARGUMENT),
        )
        assertTrue(
            "the admission check must hash the verified WrapperMessage; call: $arguments",
            arguments.contains(WRAPPER_ARGUMENT),
        )
        for (spoofable in UNKEYED_ARGUMENTS) {
            assertFalse(
                "the admission check must not key on `$spoofable`; call: $arguments",
                arguments.contains(spoofable),
            )
        }

        // A refusal has to end the arrival: a refused request that still leaves the link up makes
        // the Client wait out its own deadline on a prompt that was never raised.
        val refusal = source.substring(admit, submit)
        assertTrue("a refused request must be logged:\n$refusal", refusal.contains("Log.w("))
        assertTrue(
            "a refused request must drop the link it arrived on:\n$refusal",
            refusal.contains("disconnectGatt(gatt)"),
        )
        assertTrue("a refused request must return:\n$refusal", refusal.contains("return"))
    }

    /** Whitespace and line breaks only, so the shape is compared and not the formatting. */
    private fun String.normalized(): String = replace(Regex("\\s+"), " ").trim()

    /**
     * The service performs one effect per outcome of `BleAuthRequestGate.decide` — and, inside the
     * duplicate arm, per outcome of `BleDisconnectGrace` — and the ordering that produces the
     * outcome is not here to be re-edited.
     *
     * The two halves are what the JVM tests either side cannot state: `BleAuthRequestGateTest`
     * knows the gate answers `Replay` for a foreign peer but not that the service disconnects it
     * (the property the gate exists to preserve), and neither `BleResponseHandoffTest` nor
     * `BleDisconnectGraceTest` runs the duplicate arm at all. Adding a `disconnect` to the
     * duplicate path compiles, keeps every gate and handoff test green, and tears down the link
     * whose prompt the user is answering — the original defect. So does returning from the arm
     * before the prompt a released challenge has to be re-offered at: the release then swallows the
     * very retransmission it exists to recover.
     */
    @Test
    fun theDecisionIsMappedToOneEffectPerOutcome() {
        assertEquals(
            "the ladder must be asked exactly once, by the service's one `decide` call",
            1,
            source.split(DECIDE_CALL).size - 1,
        )

        val duplicate = decisionArm("Duplicate")
        assertTrue(
            "the Duplicate arm must ask what the duplicate means before acting on it:\n$duplicate",
            duplicate.contains(ON_DUPLICATE_CALL),
        )
        assertTrue(
            "the Duplicate arm must re-deliver the held answer on the handle the Client " +
                "reconnected on:\n$duplicate",
            duplicate.contains(REDELIVER_CALL),
        )
        // A prompt the grace released is gone, so its challenge is re-offered: without the fall-
        // through, the arriving copy is a silent duplicate and the Desktop waits out its window for
        // a prompt nobody ever sees.
        assertTrue(
            "the Duplicate arm must mark the arrival it must re-offer as a retry:\n$duplicate",
            duplicate.contains(RETRY_FLAG_SET),
        )
        for (effect in DISCONNECT_EFFECTS) {
            assertFalse(
                "the Duplicate arm must not disconnect the link the prompt still needs " +
                    "(`$effect`):\n$duplicate",
                duplicate.contains(effect),
            )
        }
        // And the retry has to reach the prompt: the arm falls through to the shared rate limiter
        // and the prompt, exactly like the Process outcome.
        val retry = outcomeArm("Retry")
        assertTrue(
            "the Retry arm must mark the arrival it re-offers:\n$retry",
            retry.contains(RETRY_FLAG_SET),
        )
        assertFalse(
            "the Retry arm must fall through to the prompt, not end the arrival:\n$retry",
            retry.contains("return"),
        )
        // The release is consumed only once the limiter admitted the retry and the prompt is about
        // to be registered: consumed up in the arm, a rate-limited or throwing retry would leave
        // the challenge with no prompt, no mark and no disconnect, and every later copy of it a
        // silent duplicate.
        assertFalse(
            "the release must not be consumed before the rate limiter sees the retry:\n$retry",
            retry.contains(RETRY_STARTED_CALL),
        )
        val started = source.indexOf(RETRY_STARTED_CALL)
        assertTrue(
            "`$RETRY_STARTED_CALL` must follow `$ADMIT_CALL` (offset $started vs " +
                "$ADMIT_CALL at ${source.indexOf(ADMIT_CALL)})",
            started > source.indexOf(ADMIT_CALL),
        )
        val submit = source.indexOf(SUBMIT_CALL, source.indexOf(ADMIT_CALL))
        assertTrue(
            "`$RETRY_STARTED_CALL` must precede `$SUBMIT_CALL` (offset $started vs $submit), or the " +
                "prompt it belongs to is registered before the mark is cleared",
            submit > started,
        )

        // A different peer replaying the same captured bytes is decided as Replay, and that
        // arrival still has to lose its link.
        val replay = decisionArm("Replay")
        assertTrue(
            "the Replay arm must disconnect the replaying peer:\n$replay",
            replay.contains("gatt.disconnect()"),
        )

        // A challenge another transport owns has nothing left to do on this link.
        val claimed = decisionArm("Claimed")
        assertTrue(
            "the Claimed arm must disconnect the link:\n$claimed",
            claimed.contains("disconnectGatt(gatt)"),
        )
    }

    /**
     * The receipt log line is the only place this service puts the caller's own `username` and
     * `hostname` into logcat. Both are the desktop's strings — Rust caps the username's length but
     * sanitizes neither — so an unwrapped one can carry a newline and forge an extra logcat line.
     * `scrubLogValue` is what removes that, and dropping it compiles, logs and is caught by
     * nothing: the line is a `Log.d` argument, which a JVM test cannot read back.
     */
    @Test
    fun theReceiptLogLineScrubsTheCallerStrings() {
        val start = source.indexOf(RECEIPT_LOG_MARKER)
        assertTrue(
            "the verified-request log line (`$RECEIPT_LOG_MARKER…`) must still exist; re-read " +
                "BleGattService.kt if it moved",
            start >= 0,
        )
        val lineEnd = source.indexOf('\n', start)
        val line = source.substring(start, if (lineEnd >= 0) lineEnd else source.length)

        for (scrubbed in SCRUBBED_RECEIPT_FIELDS) {
            assertTrue(
                "the receipt log line must log `$scrubbed`, not the raw caller string; line: $line",
                line.contains(scrubbed),
            )
        }
        for (raw in RAW_RECEIPT_FIELDS) {
            assertFalse(
                "the receipt log line must not interpolate `$raw` directly — a newline in the " +
                    "desktop's value would forge a logcat line; line: $line",
                line.contains(raw),
            )
        }
    }

    /**
     * The body of one `when (decision)` arm: from its label to the next arm's label.
     *
     * The done-with-decision check above the `when` mentions a variant too, so the label has to be
     * matched with its arrow — a bare variant name would read that comparison as the first arm.
     */
    private fun decisionArm(variant: String): String {
        val label = DECISION_PREFIX + variant + " ->"
        val start = source.indexOf(label)
        assertTrue("`$label` must be an arm of the decision's `when`", start >= 0)
        val next = source.indexOf(DECISION_PREFIX, start + label.length)
        val end = if (next >= 0) next else source.length
        return source.substring(start, end)
    }

    /**
     * The body of one `BleDisconnectGrace.Outcome` arm of the duplicate branch's `when`: from its
     * label to the `else ->` that closes the `when`.
     */
    private fun outcomeArm(variant: String): String {
        val label = OUTCOME_PREFIX + variant + " ->"
        val start = source.indexOf(label)
        assertTrue("`$label` must be an arm of the duplicate's `when`", start >= 0)
        val end = source.indexOf(OUTCOME_ELSE, start + label.length)
        assertTrue("`$label` must be followed by `$OUTCOME_ELSE`", end > start)
        return source.substring(start, end)
    }

    /**
     * The argument list of the first `call` in the source — from the call's own `(` to its matching
     * `)` — with whitespace and line breaks collapsed, so the shape is compared and not the
     * formatting.
     */
    private fun argumentsOf(call: String): String {
        val start = source.indexOf(call)
        assertTrue("`$call` must exist in BleGattService.kt", start >= 0)
        var depth = 0
        var index = start + call.length - 1
        while (index < source.length) {
            when (source[index]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return source.substring(start, index + 1).normalized()
                }
            }
            index++
        }
        throw AssertionError("`$call` is never closed in BleGattService.kt")
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

        /** The one expiry release; it may only run inside the grace expiry's own arm. */
        const val RELEASE_CALL = "authRequestGate.releaseForRetry("

        /** The question the grace coroutine asks once the wait is over. */
        const val GRACE_DECISION = "disconnectGrace.onGraceExpired("

        /** The facts that question is given, and the three it has to be built from. */
        const val LINK_FACTS_CALL = "BleDisconnectGrace.LinkFacts("
        const val CLAIM_HELD_ARGUMENT = "claimHeld = authRequestGate.holdsClaimFor(deviceAddress)"
        const val RECONNECTED_ARGUMENT =
            "reconnected = connectingOrConnectedDevices.contains(deviceAddress)"
        const val DISCONNECTED_AT_ARGUMENT = "disconnectedAtMillis = disconnectedAtMillis"

        /** The one arm of that decision that may release anything. */
        const val RELEASE_ARM = "BleDisconnectGrace.Outcome.ReleaseAndCancel ->"

        /** The effects the release arm has to run before it marks the release. */
        const val ABANDON_PEER_CALL = "pendingResponses.abandonPeer("
        const val CANCEL_BY_DISCONNECTION_CALL = "cancelRequestsByBleDisconnection("

        /** The variant prefix of each `BleDisconnectGrace.Outcome` arm. */
        const val OUTCOME_PREFIX = "BleDisconnectGrace.Outcome."

        /** How the duplicate branch's `when` ends, i.e. where the last arm's body stops. */
        const val OUTCOME_ELSE = "else ->"

        /** Ways to drop held state; only the grace expiry may use them. */
        val DROPPING_HELD_STATE = listOf(RELEASE_CALL, "abandonPeer(", "clear(")

        /** The first line after the grace coroutine, where the torn-down handle is tombstoned. */
        const val GRACE_BLOCK_END = "// The handle is closed below"
        const val CLOSED_HANDLE_TOMBSTONE = "gattConnections.markTornDown(gatt)"
        const val FORGET_CALL = "gattConnections.forget(gatt)"
        const val FINISH_CALL = "pendingResponses.finish("
        const val CONFIRMED_ARGUMENTS = "delivery, confirmed"
        const val RECORD_CALL = "pendingResponses.record("
        const val LIVE_HANDLE_HELPER = "liveHandleFor("
        const val DELIVER_RESPONSE_CALL = "deliverResponse("

        /** The handle the write after the record has to be aimed at. */
        const val HANDLE_AIM = "delivery?.handle ?: gatt"

        /** The verified-request log line this service logs the caller's fields on. */
        const val RECEIPT_LOG_MARKER = "Parsed and verified BLE request: "

        /**
         * The one call that asks `BleAuthRequestGate` for the verdict; more than one re-decides it.
         */
        const val DECIDE_CALL = "authRequestGate.decide("

        /** The variant prefix of each `when (decision)` arm. */
        const val DECISION_PREFIX = "BleAuthRequestGate.Decision."

        /** What the Duplicate arm does instead of disconnecting: write the held answer again. */
        const val REDELIVER_CALL = "redeliverPendingResponse("

        /**
         * What the Duplicate arm asks about the arriving copy, how it flags one it must re-offer,
         * and where the release that flag announced is consumed.
         */
        const val ON_DUPLICATE_CALL = "disconnectGrace.onDuplicate("
        const val RETRY_FLAG_SET = "retryingReleasedChallenge = true"
        const val RETRY_STARTED_CALL = "authRequestGate.retryStarted("
        const val SUBMIT_CALL = "submitRequest("

        /** The effects that end a link, which the Duplicate arm must not perform. */
        val DISCONNECT_EFFECTS = listOf("disconnectGatt(", "gatt.disconnect()")

        /** What the receipt line must log: the two caller strings, scrubbed. */
        val SCRUBBED_RECEIPT_FIELDS =
            listOf(
                "username=\${scrubLogValue(authRequest.username)}",
                "hostname=\${scrubLogValue(authRequest.hostname)}",
            )

        /** The one post-authentication admission check the prompt path runs. */
        const val ADMIT_CALL = "shouldAcceptAuthenticatedRequest("

        /** The signature-verifying parse that must precede it. */
        const val VERIFIED_REQUEST_CALL = "parseAndVerifyAuthRequest("

        /** The gate outcome that raises a prompt, and so the one the check follows. */
        const val PROCESS_ARM = "BleAuthRequestGate.Decision.Process -> Unit"

        /** The key material the check is keyed on: the pairing, not anything per-request. */
        const val PAIRED_KEY_ARGUMENT = "matchedDevice.publicKey"

        /** The request identifier the check hashes: the verified WrapperMessage. */
        const val WRAPPER_ARGUMENT = "wrapperMessageBytes"

        /** Identifiers that rotate or are chosen by the peer, so they must not key the limiter. */
        val UNKEYED_ARGUMENTS =
            listOf("temporalId", "gatt.device.address", "bleDeviceAddress", "challenge")

        /** The same two fields logged raw — a newline in either forges a logcat line. */
        val RAW_RECEIPT_FIELDS =
            listOf(
                "username=\${authRequest.username}",
                "hostname=\${authRequest.hostname}",
            )
    }
}
