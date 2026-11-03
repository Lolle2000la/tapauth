package dev.rourunisen.tapauth.service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReplayMitigationCacheTest {

    // Fixed clock so the 60-second window boundary is deterministic. With a real
    // wall clock a second can tick between building a timestamp and `isReplay`
    // reading "now", making the delta exactly 60 (the check is `> 60`) and the
    // +61s case flaky. See ReplayMitigationCache's nowSecondsProvider.
    private var now = 1_700_000_000L

    private lateinit var cache: ReplayMitigationCache

    @Before
    fun setUp() {
        cache = ReplayMitigationCache { now }
        cache.clear()
    }

    @Test
    fun testValidChallengeAndTimestampAccepted() {
        val challenge = ByteArray(32) { (it + 1).toByte() }

        // Challenge with current timestamp should be accepted (isReplay == false)
        val isReplay = cache.isReplay(challenge, now)
        assertFalse("Fresh challenge with valid timestamp should not be a replay", isReplay)
    }

    @Test
    fun testReplayedChallengeNonceRejected() {
        val challenge = ByteArray(32) { (it + 10).toByte() }

        // First presentation accepted
        assertFalse(cache.isReplay(challenge, now))

        // Immediate replay of same challenge nonce within window -> rejected (isReplay == true)
        assertTrue(
            "Duplicate challenge nonce must be detected as replay",
            cache.isReplay(challenge, now),
        )
    }

    @Test
    fun testStaleTimestampRejectedOutsideSixtySecondWindow() {
        val challenge1 = ByteArray(32) { (it + 20).toByte() }
        val challenge2 = ByteArray(32) { (it + 30).toByte() }

        // Timestamp 61 seconds in the past -> rejected (isReplay == true)
        assertTrue(
            "Timestamp >60s in the past must be rejected",
            cache.isReplay(challenge1, now - 61),
        )

        // Timestamp 61 seconds in the future -> rejected (isReplay == true)
        assertTrue(
            "Timestamp >60s in the future must be rejected",
            cache.isReplay(challenge2, now + 61),
        )
    }

    @Test
    fun testTimestampWithinSixtySecondWindowAccepted() {
        val challenge1 = ByteArray(32) { (it + 40).toByte() }
        val challenge2 = ByteArray(32) { (it + 50).toByte() }

        // Exactly at the 60s boundary -> still accepted (the check is `> 60`)
        assertFalse(cache.isReplay(challenge1, now - 60))
        assertFalse(cache.isReplay(challenge2, now + 60))
    }

    @Test
    fun testClearResetsCache() {
        val challenge = ByteArray(32) { (it + 60).toByte() }

        assertFalse(cache.isReplay(challenge, now))
        assertTrue(cache.isReplay(challenge, now))

        cache.clear()

        // After clearing cache, the challenge should be accepted again
        assertFalse(
            "Challenge should be accepted after cache clear",
            cache.isReplay(challenge, now),
        )
    }
}
