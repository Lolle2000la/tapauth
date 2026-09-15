package dev.rourunisen.tapauth.service

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ReplayMitigationCacheTest {

    private lateinit var cache: ReplayMitigationCache

    @Before
    fun setUp() {
        cache = ReplayMitigationCache()
        cache.clear()
    }

    @Test
    fun testValidChallengeAndTimestampAccepted() {
        val challenge = ByteArray(32) { (it + 1).toByte() }
        val nowSeconds = System.currentTimeMillis() / 1000

        // Challenge with current timestamp should be accepted (isReplay == false)
        val isReplay = cache.isReplay(challenge, nowSeconds)
        assertFalse("Fresh challenge with valid timestamp should not be a replay", isReplay)
    }

    @Test
    fun testReplayedChallengeNonceRejected() {
        val challenge = ByteArray(32) { (it + 10).toByte() }
        val nowSeconds = System.currentTimeMillis() / 1000

        // First presentation accepted
        assertFalse(cache.isReplay(challenge, nowSeconds))

        // Immediate replay of same challenge nonce within window -> rejected (isReplay == true)
        assertTrue(
            "Duplicate challenge nonce must be detected as replay",
            cache.isReplay(challenge, nowSeconds),
        )
    }

    @Test
    fun testStaleTimestampRejectedOutsideSixtySecondWindow() {
        val challenge1 = ByteArray(32) { (it + 20).toByte() }
        val challenge2 = ByteArray(32) { (it + 30).toByte() }
        val nowSeconds = System.currentTimeMillis() / 1000

        // Timestamp >60s in the past -> rejected (isReplay == true)
        val stalePast = nowSeconds - 70
        assertTrue(
            "Timestamp >60s in the past must be rejected",
            cache.isReplay(challenge1, stalePast),
        )

        // Timestamp >60s in the future -> rejected (isReplay == true)
        val staleFuture = nowSeconds + 70
        assertTrue(
            "Timestamp >60s in the future must be rejected",
            cache.isReplay(challenge2, staleFuture),
        )
    }

    @Test
    fun testTimestampWithinSixtySecondWindowAccepted() {
        val challenge1 = ByteArray(32) { (it + 40).toByte() }
        val challenge2 = ByteArray(32) { (it + 50).toByte() }
        val nowSeconds = System.currentTimeMillis() / 1000

        // Timestamp safely within 60s window (30s past/future) -> accepted
        assertFalse(cache.isReplay(challenge1, nowSeconds - 30))
        assertFalse(cache.isReplay(challenge2, nowSeconds + 30))
    }

    @Test
    fun testClearResetsCache() {
        val challenge = ByteArray(32) { (it + 60).toByte() }
        val nowSeconds = System.currentTimeMillis() / 1000

        assertFalse(cache.isReplay(challenge, nowSeconds))
        assertTrue(cache.isReplay(challenge, nowSeconds))

        cache.clear()

        // After clearing cache, the challenge should be accepted again
        assertFalse(
            "Challenge should be accepted after cache clear",
            cache.isReplay(challenge, nowSeconds),
        )
    }
}
