package dev.rourunisen.tapauth.network

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.rourunisen.tapauth.BuildConfig
import dev.rourunisen.tapauth.service.AuthenticationService
import dev.rourunisen.tapauth.service.ServiceStatusManager
import dev.rourunisen.tapauth.service.TransportLockManager
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * One-time **connected** test proving the custom TapAuth discovery multicast groups round-trip on
 * real hardware over both IPv4 and IPv6, plus the power-management lifecycle of the UDP transport.
 *
 * The round-trip tests are intentionally self-contained (send + receive on the device, using the
 * same `MulticastSocket` join/send calls as `AuthenticationService`) so they need no host helper
 * and can be driven from one `adb` invocation:
 * ```
 * ./gradlew assembleE2e assembleE2eAndroidTest -Pandroid.injected.build.abi=arm64-v8a
 * adb install -r app/build/outputs/apk/e2e/app-e2e.apk
 * adb install -r app/build/outputs/apk/androidTest/e2e/app-e2e-androidTest.apk
 * adb shell am instrument -w \
 *   -e class dev.rourunisen.tapauth.network.MulticastReachabilityTest \
 *   dev.rourunisen.tapauth.e2e.test/dev.rourunisen.tapauth.crypto.TapAuthTestRunner
 * ```
 *
 * This is deliberately **not** wired into CI: hosted runners have no real radio, and the CI
 * instrumentation run is filtered to `TapAuthCryptoTest`. Treat it as a repeatable manual check.
 *
 * The group addresses MUST match `IPV4_MULTICAST_ADDR` / `IPV6_MULTICAST_ADDR` in
 * `shared/src/network.rs` (and the constants in `AuthenticationService`):
 * - IPv4 `239.255.26.44` (IPv4 Local Scope, RFC 2365)
 * - IPv6 `ff12::fdec:fc27` (transient link-local, IANA private-use group ID, RFC 10028)
 */
@RunWith(AndroidJUnit4::class)
class MulticastReachabilityTest {
    private val ipv4Group = "239.255.26.44"
    private val ipv6Group = "ff12::fdec:fc27"

    /** Interfaces the product would also consider: up, multicast-capable, not loopback. */
    private fun multicastInterfaces(): List<NetworkInterface> =
        NetworkInterface.getNetworkInterfaces().toList().filter {
            it.isUp && it.supportsMulticast() && !it.isLoopback
        }

    /** Prefer Wi-Fi (the realistic transport), then any interface that has `family`. */
    private fun pickInterface(v4: Boolean): NetworkInterface? {
        val candidates =
            multicastInterfaces().filter { iface ->
                iface.inetAddresses.toList().any { addr ->
                    if (v4) addr is Inet4Address else addr is Inet6Address
                }
            }
        return candidates.firstOrNull { it.name == "wlan0" } ?: candidates.firstOrNull()
    }

    /**
     * Android requires a held `WifiManager.MulticastLock` for a real Wi-Fi interface to receive
     * multicast (the emulator never exercises this). Hold it for the duration of the round trip.
     */
    private fun withMulticastLock(block: () -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val lock =
            wifi?.createMulticastLock("TapAuthMulticastTest")?.apply {
                setReferenceCounted(false)
                acquire()
            }
        try {
            block()
        } finally {
            if (lock?.isHeld == true) lock.release()
        }
    }

    private fun roundTrip(label: String, group: InetAddress, iface: NetworkInterface) {
        val socket = MulticastSocket(0)
        try {
            // NOTE: Java's MulticastSocket.setLoopbackMode(true) *disables* loopback, so pass
            // false to keep it enabled for this same-host send/receive check.
            socket.loopbackMode = false
            socket.networkInterface = iface
            socket.timeToLive = 1
            socket.joinGroup(InetSocketAddress(group, 0), iface)

            val port = socket.localPort
            val payload = "tapauth-$label-${System.nanoTime()}".toByteArray()
            socket.send(DatagramPacket(payload, payload.size, group, port))

            socket.soTimeout = 5000
            val received = DatagramPacket(ByteArray(2048), 2048)
            try {
                socket.receive(received)
            } catch (e: SocketTimeoutException) {
                fail(
                    "$label: no multicast datagram received on ${iface.name} " +
                        "(${group.hostAddress}, port $port) within 5s. The socket joined the " +
                        "group and sent to it, but loopback delivery did not arrive."
                )
                return
            }

            assertArrayEquals(
                "$label: received payload mismatch",
                payload,
                received.data.copyOf(received.length),
            )
            println(
                "$label OK: sent+received ${payload.size} bytes via ${group.hostAddress} on ${iface.name}"
            )
        } finally {
            socket.close()
        }
    }

    @Test
    fun ipv4DiscoveryGroupRoundTrips() {
        val iface = pickInterface(v4 = true)
        assumeTrue("device has no IPv4 multicast interface", iface != null)
        assertNotNull(iface)
        withMulticastLock { roundTrip("IPv4", InetAddress.getByName(ipv4Group), iface!!) }
    }

    @Test
    fun ipv6DiscoveryGroupRoundTrips() {
        val iface = pickInterface(v4 = false)
        assumeTrue("device has no IPv6 multicast interface", iface != null)
        assertNotNull(iface)
        withMulticastLock { roundTrip("IPv6", InetAddress.getByName(ipv6Group), iface!!) }
    }

    /**
     * The Wi-Fi multicast lock must track explicit acquire/release and must not be reference
     * counted, otherwise repeated screen/network transitions could leak it and keep the radio out
     * of power save while the device is locked.
     */
    @Test
    fun multicastLockTracksExplicitAcquireAndRelease() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue(
            "device has no Wi-Fi service",
            context.getSystemService(Context.WIFI_SERVICE) is WifiManager,
        )

        val manager = TransportLockManager(context)
        manager.releaseMulticastLock()
        assertFalse("lock must not be held before acquire", manager.isMulticastHeld)

        manager.acquireMulticastLock()
        assertTrue("lock must be held after acquire", manager.isMulticastHeld)

        // setReferenceCounted(false): a redundant acquire must not add a reference...
        manager.acquireMulticastLock()
        assertTrue("lock must remain held after a redundant acquire", manager.isMulticastHeld)
        // ...so a single release drops it.
        manager.releaseMulticastLock()
        assertFalse("one release must drop a non-reference-counted lock", manager.isMulticastHeld)

        // A redundant release must be a safe no-op (never an underflow/crash).
        manager.releaseMulticastLock()
        assertFalse(manager.isMulticastHeld)
    }

    private fun sendLifecycle(context: Context, start: Boolean) {
        val intent =
            Intent(AuthenticationService.ACTION_TEST_UDP_LIFECYCLE).apply {
                setPackage(context.packageName)
                putExtra(AuthenticationService.EXTRA_TEST_UDP_START, start)
            }
        context.sendBroadcast(intent)
    }

    private fun awaitUdpRunning(expected: Boolean, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (ServiceStatusManager.udpRunning.value == expected) return true
            Thread.sleep(100)
        }
        return ServiceStatusManager.udpRunning.value == expected
    }

    /**
     * Re-sends the control action until the expected transport state is observed. The service
     * registers its receiver asynchronously after `startForegroundService()`, so the first action
     * can race ahead of registration. Both start and stop are idempotent, so re-sending is safe.
     */
    private fun driveLifecycleUntil(
        context: Context,
        start: Boolean,
        expected: Boolean,
        timeoutMs: Long,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            sendLifecycle(context, start)
            val stepDeadline = System.currentTimeMillis() + 1_000
            while (System.currentTimeMillis() < stepDeadline) {
                if (ServiceStatusManager.udpRunning.value == expected) return true
                Thread.sleep(50)
            }
        }
        return ServiceStatusManager.udpRunning.value == expected
    }

    /**
     * Drives the exact `startUdpTransport()` / `stopUdpTransport()` paths used by
     * `ACTION_USER_PRESENT` / `ACTION_SCREEN_OFF` and asserts the socket is bound on unlock and
     * unbound on screen-off.
     *
     * Protected system broadcasts cannot be injected from instrumentation, so the service exposes
     * an E2E-build-only control action (`ACTION_TEST_UDP_LIFECYCLE`) that routes to the same
     * methods.
     */
    @Test
    fun udpTransportBindsOnUnlockAndUnbindsOnScreenOff() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assumeTrue("control action is only registered in the e2e build", BuildConfig.E2E_TESTING)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Some OEM builds block `adb shell pm grant` (the shell user lacks
            // GRANT_RUNTIME_PERMISSIONS), so try the instrumentation path before giving up.
            if (
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS,
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                try {
                    instrumentation.uiAutomation.grantRuntimePermission(
                        context.packageName,
                        Manifest.permission.POST_NOTIFICATIONS,
                    )
                    println("Granted POST_NOTIFICATIONS via UiAutomation")
                } catch (t: Throwable) {
                    println("UiAutomation POST_NOTIFICATIONS grant failed: ${t.message}")
                }
            }
            assumeTrue(
                "POST_NOTIFICATIONS not granted; foreground service would stop itself",
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS,
                ) == PackageManager.PERMISSION_GRANTED,
            )
        }

        // Clean slate: make sure no previous run left the transport up.
        context.stopService(Intent(context, AuthenticationService::class.java))
        awaitUdpRunning(expected = false, timeoutMs = 5_000)

        val serviceIntent = Intent(context, AuthenticationService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        } catch (e: Exception) {
            assumeTrue(
                "foreground service start not permitted in this environment: ${e.message}",
                false,
            )
            return
        }

        // Unlock path -> socket binds.
        assertTrue(
            "UDP socket did not bind after simulated unlock (udpRunning=" +
                "${ServiceStatusManager.udpRunning.value})",
            driveLifecycleUntil(context, start = true, expected = true, timeoutMs = 15_000),
        )

        // Screen-off path -> socket unbinds.
        assertTrue(
            "UDP socket did not unbind after simulated screen-off (udpRunning=" +
                "${ServiceStatusManager.udpRunning.value})",
            driveLifecycleUntil(context, start = false, expected = false, timeoutMs = 15_000),
        )
    }
}
