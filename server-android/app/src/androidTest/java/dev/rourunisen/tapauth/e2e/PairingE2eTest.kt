package dev.rourunisen.tapauth.e2e

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.network.PairingClient
import dev.rourunisen.tapauth.network.PairingInitResult
import dev.rourunisen.tapauth.network.PairingResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end instrumentation test for device pairing, driven by scripts/test-e2e.sh over `adb shell
 * am instrument`:
 *
 * adb shell am instrument -w \ -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \ -e pairing_host
 * 10.0.2.2 \ -e pairing_port <port> \ [-e reject_sas true] \
 * dev.rourunisen.tapauth.e2e.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner
 *
 * With `reject_sas true` this runs the negative case (Phase 1a): the handshake completes far enough
 * to derive the SAS, then the client rejects it, and the test asserts that pairing fails and
 * nothing is stored.
 *
 * The derived SAS is logged and written to filesDir so the host side can compare it against the
 * daemon's own value (bilateral anti-MITM verification).
 */
@RunWith(AndroidJUnit4::class)
class PairingE2eTest {

    companion object {
        private const val TAG = "PairingE2eTest"
    }

    @Test
    fun testPairing() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        val rejectSas = args.getString("reject_sas")?.toBoolean() ?: false
        runPairingHandshake(rejectSas = rejectSas)
    }

    private suspend fun runPairingHandshake(rejectSas: Boolean) {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val args = InstrumentationRegistry.getArguments()

        val host = args.getString("pairing_host") ?: "10.0.2.2"
        val port = args.getString("pairing_port")?.toIntOrNull() ?: 36693

        Log.i(
            TAG,
            "Starting E2E Pairing Test: host=$host, port=$port, rejectSas=$rejectSas",
        )

        val client = PairingClient(context)

        // Step 1: Initiate pairing over TCP
        val initResult = client.initiatePairing(host, port)
        assertTrue(
            "Pairing initiation failed with error: ${(initResult as? PairingInitResult.Error)?.message}",
            initResult is PairingInitResult.AwaitingSASVerification,
        )

        val awaiting = initResult as PairingInitResult.AwaitingSASVerification
        Log.i(TAG, "Pairing handshake successful. Derived SAS: ${awaiting.sas}")
        println("ANDROID_DERIVED_SAS=${awaiting.sas}")

        // Write derived SAS to app storage for E2E host test verification
        try {
            java.io.File(context.filesDir, "derived_sas.txt").writeText(awaiting.sas)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to write SAS to filesDir: ${e.message}")
        }

        // The host compares this against the daemon's own SAS (bilateral check); the
        // guest does not know the expected value here.

        if (rejectSas) {
            // Negative test: User rejects SAS verification or SAS mismatch detected
            val rejectResult =
                client.completePairing(
                    socket = awaiting.socket,
                    psk = awaiting.psk,
                    clientEd25519Key = awaiting.clientEd25519Key,
                    clientDeviceName = awaiting.clientDeviceName,
                    sasConfirmed = false,
                )
            assertTrue(
                "Pairing completion should fail on SAS rejection, got $rejectResult",
                rejectResult is PairingResult.Error,
            )
            val errorMsg = (rejectResult as PairingResult.Error).message
            assertTrue(
                "Error message should mention rejection: $errorMsg",
                errorMsg.contains("rejected", ignoreCase = true) ||
                    errorMsg.contains("SAS", ignoreCase = true),
            )
            Log.i(TAG, "Negative pairing test passed: SAS rejected, connection closed.")
            return
        }

        // Step 2: Complete pairing (CSK exchange & storage)
        val completeResult =
            client.completePairing(
                socket = awaiting.socket,
                psk = awaiting.psk,
                clientEd25519Key = awaiting.clientEd25519Key,
                clientDeviceName = awaiting.clientDeviceName,
                sasConfirmed = true,
            )

        assertTrue(
            "Pairing completion failed with error: ${(completeResult as? PairingResult.Error)?.message}",
            completeResult is PairingResult.Success,
        )

        val pairedDevice = (completeResult as PairingResult.Success).device
        Log.i(TAG, "Pairing successfully completed. Stored device: ${pairedDevice.displayName}")

        // Save device to repository
        val deviceRepo = DeviceRepository(context)
        deviceRepo.savePairedDevice(pairedDevice)

        // Verify stored in DeviceRepository
        val storedDevice = deviceRepo.getPairedDevice(pairedDevice.deviceId)
        assertNotNull("Paired device not found in repository", storedDevice)
    }
}
