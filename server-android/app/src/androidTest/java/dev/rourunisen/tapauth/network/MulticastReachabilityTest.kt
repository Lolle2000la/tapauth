package dev.rourunisen.tapauth.network

import android.content.Context
import android.net.wifi.WifiManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.net.DatagramPacket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * One-time **connected** test proving the custom TapAuth discovery multicast groups round-trip on
 * real hardware over both IPv4 and IPv6.
 *
 * It is intentionally self-contained (send + receive on the device, using the same
 * `MulticastSocket` join/send calls as `AuthenticationService`) so it needs no host helper and can
 * be driven from one `adb` invocation:
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
}
