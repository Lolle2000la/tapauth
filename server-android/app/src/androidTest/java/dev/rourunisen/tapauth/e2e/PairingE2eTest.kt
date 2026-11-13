package dev.rourunisen.tapauth.e2e

import android.content.Context
import android.os.Bundle
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.rourunisen.tapauth.data.DeviceRepository
import dev.rourunisen.tapauth.data.PairedDevice
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.network.PairingSession
import dev.rourunisen.tapauth.network.PairingUpdate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end instrumentation test for device pairing, driven by scripts/test-e2e.sh over `adb shell
 * am instrument`:
 *
 * adb shell am instrument -w \ -e class dev.rourunisen.tapauth.e2e.PairingE2eTest \ -e pairing_url
 * "tapauth://pair?v=2&sid=...&pk=...&p=...&ip4=..." \ [-e reject_sas true] \
 * dev.rourunisen.tapauth.e2e.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner
 *
 * `pairing_url` is the preferred extra: it carries the QR `sid` and `pk` the v2 handshake needs.
 * When it is absent the test falls back to `pairing_host` + `pairing_port`, the legacy harness path
 * with no QR session id or client ephemeral key (the session is built with `qrPublicKey = null`).
 *
 * With `reject_sas true` this runs the negative case (Phase 1a): the flow progresses far enough to
 * derive the SAS, then the test rejects it, asserts the rejection is reported, and asserts nothing
 * was stored.
 *
 * The derived SAS is logged, printed and written to filesDir so the host side can compare it
 * against the daemon's own value (bilateral anti-MITM verification).
 *
 * Every wait is bounded (30 s for the SAS, 60 s for the outcome) so a stuck handshake fails the
 * test with a descriptive assertion instead of hanging the E2E harness.
 */
@RunWith(AndroidJUnit4::class)
class PairingE2eTest {

    companion object {
        private const val TAG = "PairingE2eTest"

        private const val SAS_TIMEOUT_MS = 30_000L
        private const val OUTCOME_TIMEOUT_MS = 60_000L

        /** `00` × 16 — the legacy `pairing_host`/`pairing_port` path carries no QR session id. */
        private const val LEGACY_SESSION_ID = "00000000000000000000000000000000"

        /** `00` × 32 — the legacy path carries no QR client ephemeral X25519 public key. */
        private const val LEGACY_PUBLIC_KEY =
            "0000000000000000000000000000000000000000000000000000000000000000"
    }

    @Test
    fun testPairing() {
        runBlocking { runPairingFlow() }
    }

    private suspend fun runPairingFlow() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val args = InstrumentationRegistry.getArguments()
        val rejectSas = args.getString("reject_sas")?.toBoolean() ?: false
        val expectedUser = args.getString("pairing_username")?.takeIf { it.isNotBlank() }

        val pairingUrl = resolvePairingUrl(args)
        val fromQrExtra = !args.getString("pairing_url").isNullOrBlank()

        Log.i(
            TAG,
            "Starting E2E pairing: v=${pairingUrl.version}, p=${pairingUrl.port}, " +
                "ip4=${pairingUrl.ipv4}, ip6=${pairingUrl.ipv6}, " +
                "sid=${pairingUrl.sessionId}, fromQrExtra=$fromQrExtra, rejectSas=$rejectSas",
        )

        val repository = DeviceRepository(context)
        val devicesBefore = repository.getAllPairedDevices().map { it.deviceId }.toSet()

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        // The session may report from whichever dispatcher its transports run on, so updates are
        // handed over through a channel rather than a variable shared with the test thread.
        val updates = Channel<PairingUpdate>(Channel.UNLIMITED)
        val session =
            PairingSession(
                context = context,
                pairingUrl = pairingUrl,
                clientDeviceName = "tapauth-e2e",
                // The legacy host/port path has no QR key to pin, so the session must accept the
                // peer key it is given instead of comparing it against an all-zero one.
                qrPublicKey = if (fromQrExtra) pairingUrl.publicKeyBytes() else null,
            )

        try {
            session.start(scope) { update -> updates.trySend(update) }

            val awaitingUpdate =
                awaitUpdate(updates, SAS_TIMEOUT_MS, "the derived SAS") {
                    it is PairingUpdate.AwaitingSas
                }
            val awaiting = awaitingUpdate as PairingUpdate.AwaitingSas

            publishSas(context, awaiting.sas)
            Log.i(TAG, "SAS reached the phone over ${awaiting.transport}")

            if (rejectSas) {
                session.rejectSas()
                val outcome =
                    awaitUpdate(updates, OUTCOME_TIMEOUT_MS, "the rejected-SAS outcome") {
                        it is PairingUpdate.Cancelled ||
                            (it is PairingUpdate.Failed && mentionsSasRejection(it.message))
                    }
                Log.i(TAG, "Negative pairing test outcome: $outcome")

                val added =
                    repository.getAllPairedDevices().filter { it.deviceId !in devicesBefore }
                assertEquals(
                    "Rejecting the SAS must not persist a device, but these appeared: " +
                        added.map { it.deviceId },
                    emptyList<PairedDevice>(),
                    added,
                )
                Log.i(TAG, "Negative pairing test passed: SAS rejected, no device stored.")
                return
            }

            session.approveSas()
            val completeUpdate =
                awaitUpdate(updates, OUTCOME_TIMEOUT_MS, "pairing completion") {
                    it is PairingUpdate.Complete
                }
            val complete = completeUpdate as PairingUpdate.Complete

            val device = complete.device
            assertEquals("A v2 pairing must record protocolVersion 2", 2, device.protocolVersion)
            assertTrue(
                "The paired device must allow at least the pairing user, got ${device.allowedUsers}",
                device.allowedUsers.isNotEmpty(),
            )
            expectedUser?.let { user ->
                assertTrue(
                    "allowedUsers ${device.allowedUsers} must contain the pairing user $user",
                    device.allowedUsers.contains(user),
                )
            }
            assertEquals("The provisioned CSK must be 32 bytes", 32, device.csk.size)

            // Re-read through the repository: the session is supposed to persist the device itself.
            val persisted = repository.getPairedDevice(device.deviceId)
            assertNotNull(
                "PairingSession reported Complete but ${device.deviceId} is not in the repository",
                persisted,
            )
            val stored = requireNotNull(persisted)
            assertEquals(
                "The persisted device must keep protocolVersion 2",
                2,
                stored.protocolVersion,
            )
            assertEquals(
                "The persisted device must keep the negotiated allowed users",
                device.allowedUsers,
                stored.allowedUsers,
            )
            assertArrayEquals(
                "The persisted device must keep the provisioned CSK",
                device.csk,
                stored.csk,
            )
            Log.i(
                TAG,
                "Pairing completed and persisted: ${stored.deviceId} (${stored.displayName}), " +
                    "users=${stored.allowedUsers}",
            )
        } finally {
            session.close()
            updates.close()
            scope.cancel()
        }
    }

    /**
     * Build the pairing target from the extras.
     *
     * `pairing_url` wins when present. A QR carrying no UDP endpoint at all (`p`, `ip4` and `ip6`
     * all absent) is a legitimate BLE-only pairing and is accepted as parsed. The `pairing_host` /
     * `pairing_port` fallback is the legacy harness path: no QR session id, no QR client key.
     */
    private fun resolvePairingUrl(args: Bundle): PairingUrl {
        val raw = args.getString("pairing_url")?.trim()
        if (!raw.isNullOrEmpty()) {
            val parsed = PairingUrl.parse(raw)
            if (parsed == null) {
                throw AssertionError(
                    "pairing_url extra is not a well-formed v2 pairing URL " +
                        "(expected tapauth://pair?v=2&sid=<32 hex>&pk=<64 hex>[&p=…&ip4=…&ip6=…]): " +
                        raw,
                )
            }
            return parsed
        }

        val host = args.getString("pairing_host") ?: "10.0.2.2"
        val port = args.getString("pairing_port")?.toIntOrNull() ?: 36693
        Log.i(TAG, "No pairing_url extra; using legacy host/port path: host=$host, port=$port")
        return PairingUrl(
            version = 2,
            sessionId = LEGACY_SESSION_ID,
            publicKey = LEGACY_PUBLIC_KEY,
            port = port,
            ipv4 = host,
            ipv6 = null,
        )
    }

    /**
     * Publish the observables scripts/test-e2e.sh collects: stdout (`ANDROID_DERIVED_SAS=`), the
     * `Derived SAS:` logcat line, and `filesDir/derived_sas.txt`.
     */
    private fun publishSas(context: Context, sas: String) {
        Log.i(TAG, "Derived SAS: $sas")
        Log.i(TAG, "ANDROID_DERIVED_SAS=$sas")
        println("ANDROID_DERIVED_SAS=$sas")
        try {
            java.io.File(context.filesDir, "derived_sas.txt").writeText(sas)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to write SAS to filesDir: ${e.message}")
        }
    }

    /**
     * Wait for the first update [accept] matches.
     *
     * A terminal `Failed`/`Cancelled` arrives before the awaited update means the run is over, so
     * it fails immediately with the reported reason; the deadline fails the test with the
     * description of what never arrived rather than blocking the harness.
     */
    private suspend fun awaitUpdate(
        updates: ReceiveChannel<PairingUpdate>,
        timeoutMs: Long,
        description: String,
        accept: (PairingUpdate) -> Boolean,
    ): PairingUpdate {
        try {
            return withTimeout(timeoutMs) {
                var matched: PairingUpdate? = null
                while (matched == null) {
                    val update = updates.receive()
                    Log.i(TAG, "PairingUpdate: $update")
                    when {
                        accept(update) -> matched = update
                        update is PairingUpdate.Failed ->
                            throw AssertionError(
                                "Pairing failed while waiting for $description: ${update.message}",
                            )
                        update is PairingUpdate.Cancelled ->
                            throw AssertionError(
                                "Pairing was cancelled while waiting for $description",
                            )
                    }
                }
                requireNotNull(matched)
            }
        } catch (e: TimeoutCancellationException) {
            throw AssertionError("Timed out after ${timeoutMs}ms waiting for $description")
        }
    }

    private fun mentionsSasRejection(message: String): Boolean =
        message.contains("reject", ignoreCase = true) ||
            message.contains("SAS", ignoreCase = true) ||
            message.contains("abort", ignoreCase = true)
}
