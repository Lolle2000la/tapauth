package dev.rourunisen.tapauth.ble

import dev.rourunisen.tapauth.service.RequestRateLimiter
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The BLE prompt path's post-authentication rate limit.
 *
 * `BleGattService.handleAuthRequest` takes a framework `BluetoothGatt` and runs inside an Android
 * `Service`, so no JVM test can execute it (see `BleGattServiceWiringTest` for why that class reads
 * the production source). This class pins the two halves the call site cannot state on its own:
 *
 * - the decision it makes, driven through the limiter exactly as the call site passes it — the
 *   paired Client's Ed25519 public key and the verified `WrapperMessage` — so the schedule it
 *   throttles on is UDP's schedule and not a second one;
 * - that both services reach that limiter through the one shared instance, because a per-transport
 *   instance is a per-transport budget and the bypass again.
 *
 * `BleGattServiceWiringTest.thePromptPathRunsTheOneSharedRateLimiter` pins where the call sits, and
 * fails if it is removed — no JVM test can observe a call site inside the service directly.
 */
class BlePromptRateLimitTest {

    private var now = 10_000L
    private lateinit var limiter: RequestRateLimiter
    private var requestCounter = 0

    private val clientPublicKey = ByteArray(32) { 0x11 }
    private val otherClientPublicKey = ByteArray(32) { 0x22 }

    @Before
    fun setUp() {
        now = 10_000L
        requestCounter = 0
        limiter = RequestRateLimiter(timeProvider = { now })
    }

    /**
     * A request this Client has not sent before.
     *
     * A new authentication always carries a new challenge, so a fresh request is new
     * `WrapperMessage` bytes. A retransmission of one request repeats its bytes, and the limiter
     * de-duplicates those instead of counting them — which is why they are not what this class
     * feeds it.
     */
    private fun freshRequest(): ByteArray = byteArrayOf(REQUEST_TAG, requestCounter++.toByte())

    /**
     * A Client that sends four distinct requests inside one burst window is throttled, and it stays
     * throttled through the escalation until one full 5 s cooldown has passed — after which the
     * request is admitted and the burst allowance is re-armed.
     *
     * The admission at the end is what a limiter that simply refuses from the fourth request on (or
     * that never re-arms the burst) would fail: this path had no limiter at all before the check
     * existed, which is the bypass this class pins.
     */
    @Test
    fun aClientThatKeepsSendingBleRequestsIsThrottledOnTheUdpSchedule() {
        // Burst allowance: the first three distinct requests of the burst window are admitted.
        assertTrue(
            "request 1",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 200
        assertTrue(
            "request 2",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 200
        assertTrue(
            "request 3",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )

        // The fourth is refused: the burst allowance is spent, and the refusal starts a 2 s
        // cooldown (1 s, doubled by the refusal itself).
        now += 200
        assertFalse(
            "request 4 (200 ms after request 3) must be throttled",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )

        // Every further refusal doubles the cooldown: 1 s after this one is not enough (it is 2 s
        // now), nor 2 s after the next (4 s), nor 4 s after the one after that (capped at 5 s).
        now += 1000
        assertFalse(
            "a request 1 s after the first refusal must still be throttled (the cooldown is 2 s)",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 2000
        assertFalse(
            "a request 2 s after the second refusal must still be throttled (the cooldown is 4 s)",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 4000
        assertFalse(
            "a request 4 s after the third refusal must still be throttled (the cooldown is capped " +
                "at 5 s, not doubled again)",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )

        // One full 5 s cooldown admits the request, and the admission re-arms the burst allowance:
        // the two requests after it are back inside a fresh burst window.
        now += 5000
        assertTrue(
            "a request after the full 5 s cooldown must be admitted",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 100
        assertTrue(
            "the admission after the cooldown must re-arm the burst allowance",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
        now += 100
        assertTrue(
            "the burst allowance must allow three requests again",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
    }

    /**
     * Each refusal's cooldown is exactly 2 s, then 4 s, then the 5 s cap, measured from the refusal
     * a millisecond at a time: 1 ms before the boundary the request is still refused, at the
     * boundary it is admitted.
     *
     * The numbers are the point — this is `RequestRateLimiter`'s schedule, the one the UDP path
     * runs (`INITIAL_BACKOFF_SECONDS` = 1 s, doubled per refusal, `MAX_BACKOFF_SECONDS` = 5 s,
     * `BURST_MAX` = 3, `BURST_WINDOW_MS` = 2 s). A limiter with the right shape and the wrong
     * numbers — a 2 s initial backoff, a 10 s cap, a burst of four — passes the escalation test
     * above and fails here.
     */
    @Test
    fun theCooldownAfterEachRefusalIsExactlyTheUdpOne() {
        for ((refusals, cooldownMs) in listOf(1 to 2_000L, 2 to 4_000L, 3 to 5_000L)) {
            assertFalse(
                "after $refusals refusal(s), a request ${cooldownMs - 1} ms after the last one " +
                    "must still be throttled",
                verdictAfterRefusals(refusals, cooldownMs - 1),
            )
            assertTrue(
                "after $refusals refusal(s), a request $cooldownMs ms after the last one must be " +
                    "admitted",
                verdictAfterRefusals(refusals, cooldownMs),
            )
        }
    }

    /**
     * A fresh limiter whose single Client spends the burst allowance, is refused [refusals] times —
     * each knock landing 1 ms before the cooldown it has to sit out — and then sends one more
     * request [waitMs] after the last refusal. Returns whether that last request was admitted.
     */
    private fun verdictAfterRefusals(refusals: Int, waitMs: Long): Boolean {
        var clock = 10_000L
        val limiter = RequestRateLimiter(timeProvider = { clock })
        val cooldowns = listOf(2_000L, 4_000L, 5_000L)

        repeat(3) {
            assertTrue(
                "the burst allowance must admit request ${it + 1}",
                limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
            )
            clock += 200
        }
        repeat(refusals) { knock ->
            assertFalse(
                "knock ${knock + 1} must be refused",
                limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
            )
            if (knock < refusals - 1) clock += cooldowns[knock] - 1
        }

        clock += waitMs
        return limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest())
    }

    /**
     * A hot Client does not spend a fresh Client's budget.
     *
     * This is what catches a limiter keyed on anything shared — a constant, a global counter, the
     * transport, the process — instead of on the paired Client's public key: with one bucket for
     * everybody, the fresh key's first request arrives inside the hot key's cooldown and is
     * refused.
     */
    @Test
    fun aSecondClientIsAdmittedWhileAnotherClientsBackoffIsRunning() {
        assertTrue(limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()))
        now += 200
        assertTrue(limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()))
        now += 200
        assertTrue(limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()))
        now += 200
        assertFalse(
            "the hot Client's fourth request must be throttled",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )

        now += 100
        assertTrue(
            "a second Client's first request, inside the first Client's cooldown, must be admitted",
            limiter.shouldAcceptAuthenticatedRequest(otherClientPublicKey, freshRequest()),
        )

        now += 100
        assertFalse(
            "the second Client's admission must not have cleared the first Client's cooldown",
            limiter.shouldAcceptAuthenticatedRequest(clientPublicKey, freshRequest()),
        )
    }

    /**
     * Both transports reach the limiter through its one shared instance.
     *
     * The two call sites live in separate Android services that never see each other, so the only
     * thing that can make them share a budget is [RequestRateLimiter.getInstance]. A limiter
     * constructed in either file is that transport's own state: the schedule would still match, and
     * a Client that alternates transports would get a fresh bucket from each — the bypass this
     * class exists to prevent, one instance per transport.
     */
    @Test
    fun bothTransportsUseTheOneSharedLimiter() {
        for (path in LIMITER_CALL_SITES) {
            val source = sourceOf(path)
            assertTrue(
                "$path must reach the limiter through RequestRateLimiter.getInstance(), so both " +
                    "transports share one budget",
                source.contains(SHARED_ACCESSOR),
            )
            assertFalse(
                "$path must not construct a RequestRateLimiter of its own: that transport would " +
                    "then have its own schedule state",
                source.contains(CONSTRUCTOR_CALL),
            )
        }
    }

    private fun sourceOf(relativePath: String): String {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val file = File(directory, relativePath)
            if (file.isFile) return file.readText()
            directory = directory.parentFile
        }
        throw AssertionError(
            "$relativePath was not found above ${File("").absolutePath}; the limiter call sites " +
                "cannot be guarded from this working directory",
        )
    }

    private companion object {
        /** Marks a distinct request; the second byte makes each one unique. */
        const val REQUEST_TAG: Byte = 0x0A

        /** The two post-authentication paths, each of which must call the shared limiter. */
        val LIMITER_CALL_SITES =
            listOf(
                "app/src/main/java/dev/rourunisen/tapauth/ble/BleGattService.kt",
                "app/src/main/java/dev/rourunisen/tapauth/service/AuthenticationService.kt",
            )

        const val SHARED_ACCESSOR = "RequestRateLimiter.getInstance()"
        const val CONSTRUCTOR_CALL = "RequestRateLimiter()"
    }
}
