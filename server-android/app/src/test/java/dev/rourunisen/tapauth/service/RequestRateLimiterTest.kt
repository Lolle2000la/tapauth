package dev.rourunisen.tapauth.service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RequestRateLimiterTest {

    private var currentTimeMs: Long = 10000L
    private lateinit var rateLimiter: RequestRateLimiter
    private val clientKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    private val otherClientKey = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

    @Before
    fun setUp() {
        currentTimeMs = 10000L
        rateLimiter = RequestRateLimiter(timeProvider = { currentTimeMs })
    }

    @Test
    fun testBurstToleranceAllowsThreeRequestsInTwoSeconds() {
        // First 3 distinct requests within 2 seconds should all be accepted
        assertTrue(
            "Request 1 should be accepted",
            rateLimiter.shouldAcceptRequest(clientKey, "req-1"),
        )
        currentTimeMs += 200
        assertTrue(
            "Request 2 should be accepted",
            rateLimiter.shouldAcceptRequest(clientKey, "req-2"),
        )
        currentTimeMs += 200
        assertTrue(
            "Request 3 should be accepted",
            rateLimiter.shouldAcceptRequest(clientKey, "req-3"),
        )

        // 4th distinct request within burst window exceeds BURST_MAX (3) -> rejected
        currentTimeMs += 200
        assertFalse(
            "Request 4 should be rate limited",
            rateLimiter.shouldAcceptRequest(clientKey, "req-4"),
        )
    }

    @Test
    fun testEscalatingBackoffDoublesOnRejection() {
        // Exhaust burst allowance
        rateLimiter.shouldAcceptRequest(clientKey, "req-1")
        rateLimiter.shouldAcceptRequest(clientKey, "req-2")
        rateLimiter.shouldAcceptRequest(clientKey, "req-3")

        // 1st rejection triggers initial backoff (1s)
        currentTimeMs += 100
        assertFalse(
            "Request 4 should be rejected",
            rateLimiter.shouldAcceptRequest(clientKey, "req-4"),
        )

        // Attempting again before 1s has elapsed triggers 2nd rejection -> backoff doubles to 2s
        currentTimeMs += 500 // 600ms total elapsed (< 1s)
        assertFalse(
            "Request 5 should be rejected and double backoff to 2s",
            rateLimiter.shouldAcceptRequest(clientKey, "req-5"),
        )

        // Attempting again before 2s has elapsed triggers 3rd rejection -> backoff doubles to 4s
        currentTimeMs += 1000 // 1.5s since req-5 (< 2s backoff)
        assertFalse(
            "Request 6 should be rejected and double backoff to 4s",
            rateLimiter.shouldAcceptRequest(clientKey, "req-6"),
        )

        // Attempting again before 4s has elapsed -> backoff caps at MAX_BACKOFF_SECONDS (5s)
        currentTimeMs += 1000
        assertFalse(
            "Request 7 should be rejected and capped at 5s backoff",
            rateLimiter.shouldAcceptRequest(clientKey, "req-7"),
        )

        // Waiting the full 5s backoff window allows recovery
        currentTimeMs += 5100
        assertTrue(
            "Request 8 should be accepted after cooldown expires",
            rateLimiter.shouldAcceptRequest(clientKey, "req-8"),
        )
    }

    @Test
    fun testDeduplicationAllowsRetransmissionsWithoutPenalty() {
        // First request is accepted
        assertTrue(rateLimiter.shouldAcceptRequest(clientKey, "req-duplicate-1"))

        // Duplicate arrives immediately (e.g. over UDP + BLE simultaneously) -> returned as
        // accepted
        currentTimeMs += 50
        assertTrue(
            "Duplicate within dedup window should be accepted",
            rateLimiter.shouldAcceptRequest(clientKey, "req-duplicate-1"),
        )

        currentTimeMs += 100
        assertTrue(
            "3rd duplicate within dedup window should be accepted",
            rateLimiter.shouldAcceptRequest(clientKey, "req-duplicate-1"),
        )

        // Distinct requests still have burst allowance
        assertTrue(rateLimiter.shouldAcceptRequest(clientKey, "req-duplicate-2"))
        assertTrue(rateLimiter.shouldAcceptRequest(clientKey, "req-duplicate-3"))
    }

    @Test
    fun testIndependentRateLimitingPerClient() {
        // Exhaust client 1
        rateLimiter.shouldAcceptRequest(clientKey, "c1-1")
        rateLimiter.shouldAcceptRequest(clientKey, "c1-2")
        rateLimiter.shouldAcceptRequest(clientKey, "c1-3")
        assertFalse(rateLimiter.shouldAcceptRequest(clientKey, "c1-4"))

        // Other client should still be accepted independently
        assertTrue(
            "Other client should have independent rate limit",
            rateLimiter.shouldAcceptRequest(otherClientKey, "c2-1"),
        )
        assertTrue(rateLimiter.shouldAcceptRequest(otherClientKey, "c2-2"))
        assertTrue(rateLimiter.shouldAcceptRequest(otherClientKey, "c2-3"))
    }

    @Test
    fun testResetClientClearsBackoffState() {
        // Exhaust client
        rateLimiter.shouldAcceptRequest(clientKey, "req-1")
        rateLimiter.shouldAcceptRequest(clientKey, "req-2")
        rateLimiter.shouldAcceptRequest(clientKey, "req-3")
        assertFalse(rateLimiter.shouldAcceptRequest(clientKey, "req-4"))

        // Reset on authentication completion
        rateLimiter.resetClient(clientKey)

        // New request should immediately succeed
        assertTrue(
            "Client should be accepted immediately after reset",
            rateLimiter.shouldAcceptRequest(clientKey, "req-after-reset"),
        )
    }

    @Test
    fun testCleanupRemovesExpiredEntries() {
        rateLimiter.shouldAcceptRequest(clientKey, "req-1")
        // Advance past 5-minute cleanup window
        currentTimeMs += 350_000L
        rateLimiter.cleanup()

        // Cleaned up client starts fresh
        assertTrue(rateLimiter.shouldAcceptRequest(clientKey, "req-fresh"))
    }
}
