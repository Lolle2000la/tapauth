package dev.rourunisen.tapauth.e2e

import android.content.Context
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.rourunisen.tapauth.ble.BleGattService
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.network.PairingClient
import dev.rourunisen.tapauth.network.PairingInitResult
import dev.rourunisen.tapauth.network.PairingResult
import dev.rourunisen.tapauth.service.AuthenticationService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end instrumentation test for device pairing.
 *
 * Can be executed via adb: adb shell am instrument -w \ -e class
 * dev.rourunisen.tapauth.e2e.PairingE2eTest \ -e pairing_host 10.0.2.2 \ -e pairing_port 36693 \ -e
 * expected_sas 123456 \
 * dev.rourunisen.tapauth.debug.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner
 */
@RunWith(AndroidJUnit4::class)
class PairingE2eTest {

    companion object {
        private const val TAG = "PairingE2eTest"
    }

    @Test
    fun testRealDevicePairing() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val args = InstrumentationRegistry.getArguments()

        val host = args.getString("pairing_host") ?: "10.0.2.2"
        val port = args.getString("pairing_port")?.toIntOrNull() ?: 36693
        val expectedSas = args.getString("expected_sas")
        val startServices = args.getString("start_services")?.toBoolean() ?: true

        Log.i(TAG, "Starting E2E Pairing Test: host=$host, port=$port, expectedSas=$expectedSas")

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

        // Step 2: If expected SAS provided, verify match
        if (!expectedSas.isNullOrEmpty()) {
            assertEquals("SAS mismatch between desktop and Android", expectedSas, awaiting.sas)
        }

        // Step 3: Complete pairing (CSK exchange & storage)
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

        // Step 4: Start background services for subsequent auth testing if requested
        if (startServices) {
            Log.i(TAG, "Starting AuthenticationService and BleGattService...")
            AuthenticationService.start(context)
            BleGattService.start(context)
        }
    }
}
