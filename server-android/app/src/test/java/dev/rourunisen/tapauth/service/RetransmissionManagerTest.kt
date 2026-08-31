package dev.rourunisen.tapauth.service

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RetransmissionManagerTest {

    private lateinit var retransmissionManager: RetransmissionManager

    @Before
    fun setUp() {
        retransmissionManager = RetransmissionManager()
        retransmissionManager.stopAll()
    }

    @Test
    fun testBleRetransmissionStopsOnGrantConfirmation() = runBlocking {
        val challenge = ByteArray(32) { (it + 1).toByte() }
        val responseData = ByteArray(64) { 0x42 }
        var sendCount = 0

        val scope = CoroutineScope(Dispatchers.Default + Job())

        val request =
            RetransmissionManager.BleRetransmissionRequest(
                challenge = challenge,
                responseData = responseData,
                sendCallback = {
                    sendCount++
                },
            )

        retransmissionManager.startBleRetransmission(scope, request)
        assertEquals(
            "Active retransmissions should be 1",
            1,
            retransmissionManager.getStats()["active_retransmissions"],
        )

        // Wait briefly for initial send
        delay(100)
        assertTrue("Expected at least 1 send", sendCount >= 1)

        // Stop retransmission when GrantConfirmation is received
        val initialCount = sendCount
        retransmissionManager.stopRetransmission(challenge)
        assertEquals(
            "Active retransmissions should be 0",
            0,
            retransmissionManager.getStats()["active_retransmissions"],
        )

        // Wait longer -> no further sends should occur
        delay(600)
        assertEquals("No further sends after stopRetransmission", initialCount, sendCount)
    }

    @Test
    fun testStopAllCancelsAllActiveRetransmissions() = runBlocking {
        val challenge1 = ByteArray(32) { 1 }
        val challenge2 = ByteArray(32) { 2 }
        val scope = CoroutineScope(Dispatchers.Default + Job())

        val request1 =
            RetransmissionManager.BleRetransmissionRequest(
                challenge = challenge1,
                responseData = ByteArray(16),
                sendCallback = {},
            )
        val request2 =
            RetransmissionManager.BleRetransmissionRequest(
                challenge = challenge2,
                responseData = ByteArray(16),
                sendCallback = {},
            )

        retransmissionManager.startBleRetransmission(scope, request1)
        retransmissionManager.startBleRetransmission(scope, request2)
        assertEquals(2, retransmissionManager.getStats()["active_retransmissions"])

        retransmissionManager.stopAll()
        assertEquals(0, retransmissionManager.getStats()["active_retransmissions"])
    }
}
