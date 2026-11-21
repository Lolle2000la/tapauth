package dev.rourunisen.tapauth.network

import dev.rourunisen.tapauth.data.PairingUrl
import java.io.IOException
import java.net.InetSocketAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The UDP pairing transport's `open()` contract.
 *
 * These tests construct [PairingUrl] directly instead of going through [PairingUrl.parse], so they
 * pin `open()`'s own behaviour on whatever endpoints it is handed, not the QR grammar: `::zz` is an
 * address `PairingUrl.parse` refuses as a non-literal, and here it stands in for any endpoint that
 * cannot be resolved. `open()` must report that instead of handing back a socket that can never
 * send: the session's UDP candidate would otherwise sit on its 30 s response deadline with nothing
 * to send to.
 */
class PairingClientTest {

    private fun url(ipv4: String? = null, ipv6: String? = null) =
        PairingUrl(
            version = 2,
            sessionId = "00112233445566778899aabbccddeeff",
            publicKey = "ab".repeat(32),
            port = 36692,
            ipv4 = ipv4,
            ipv6 = ipv6,
        )

    /**
     * `::zz` is rejected as an address literal without a DNS lookup, so this stays hermetic.
     *
     * The defect this catches: `open()` succeeding with zero resolved targets, which leaves the
     * session sending to nobody until its 30 s deadline expires.
     */
    @Test
    fun openThrowsWhenNoEndpointResolves() {
        val client = PairingClient(url(ipv6 = "::zz"))

        val thrown = assertThrows(IOException::class.java) { client.open() }

        assertTrue(
            "The failure must name the unresolvable endpoint, got '${thrown.message}'",
            thrown.message?.contains("::zz") == true,
        )
    }

    /**
     * A send with no socket bound goes nowhere, and must say so.
     *
     * The defect this catches: the transport claiming delivery for a frame it never wrote. That is
     * what `send` returning `Unit` forced every caller to do, and it turned `proofDelivered` into a
     * constant `true`: a phone whose completion proof never left still reported a successful
     * pairing and never reached the undelivered outcome. The mapping has to answer `false` for the
     * states where `send` is a no-op.
     */
    @Test
    fun aSendWithNoBoundSocketIsReportedAsUndelivered() {
        val client = PairingClient(url(ipv4 = "127.0.0.1"))

        assertFalse(
            "No socket is bound before open(), so nothing can have been sent",
            client.send(byteArrayOf(1, 2, 3)),
        )
    }

    /**
     * The same after `close()`: the socket is gone, so the frame went nowhere.
     *
     * The defect this catches: a `send` that answers from state captured at construction (or from
     * the resolved target list) instead of from the live socket — it would report the burst as
     * delivered after the session's epilogue closed the transport, which is exactly the window a
     * deferred close leaves open.
     */
    @Test
    fun aSendAfterCloseIsReportedAsUndelivered() {
        val client = PairingClient(url(ipv4 = "127.0.0.1"))
        client.open()
        client.close()

        assertFalse(
            "The socket is closed, so nothing was sent",
            client.send(byteArrayOf(1, 2, 3)),
        )
    }

    /**
     * The positive control for the mapping: on a bound socket with a resolved endpoint the datagram
     * is written, and that is what "delivered" means here.
     *
     * Loopback only, one datagram, no listener: the send is the assertion (a local UDP send to an
     * unbound port succeeds; the ICMP error surfaces on a *later* operation, which this test does
     * not perform). Its content matches the KS test `openBindsWhenAnEndpointResolves` makes.
     *
     * The defect this catches: an over-corrected `send` that answers `false` unconditionally, which
     * would make every pairing warn about an undelivered proof it did deliver.
     */
    @Test
    fun aSendToAResolvedEndpointIsReportedAsDelivered() {
        val client = PairingClient(url(ipv4 = "127.0.0.1"))
        try {
            client.open()

            assertTrue(
                "The datagram was written to the resolved target",
                client.send(byteArrayOf(1, 2, 3)),
            )
        } finally {
            client.close()
        }
    }

    /**
     * A QR with no `p` has no endpoint to send to, whatever the socket state: the pairing port is
     * optional in the grammar (a BLE-only session), so `send` must not claim a delivery it cannot
     * address.
     *
     * The defect this catches: dropping the `pairingUrl.port ?: return false` guard, so a port-less
     * session reports its burst as sent to port 0/none.
     */
    @Test
    fun aQrWithNoPortIsReportedAsUndelivered() {
        val client = PairingClient(url(ipv4 = "127.0.0.1").copy(port = null))
        try {
            client.open()

            assertFalse(
                "There is no port to send to",
                client.send(byteArrayOf(1, 2, 3)),
            )
        } finally {
            client.close()
        }
    }

    /**
     * The positive control: a resolvable endpoint must leave an actually bound socket behind.
     *
     * `send()` cannot stand in for this — it is best-effort and swallows an `IOException` — so the
     * assertions are on the socket's own state. This fails for an `open()` whose body was deleted
     * (no socket), one that resolved its targets without binding (port 0 / not bound), and one that
     * bound a socket but discarded it instead of keeping it for `send()`/`receive()`.
     */
    @Test
    fun openBindsWhenAnEndpointResolves() {
        val client = PairingClient(url(ipv4 = "127.0.0.1"))
        try {
            client.open()

            val bound = checkNotNull(client.boundSocket) { "open() must keep the bound socket" }
            assertTrue("open() must bind its socket", bound.isBound)
            val local = bound.localSocketAddress as InetSocketAddress
            assertNotEquals("open() must bind a real ephemeral port", 0, local.port)
            assertEquals(
                "the local endpoint must report the same port as the socket",
                bound.localPort,
                local.port,
            )

            client.send(byteArrayOf(1, 2, 3))
        } finally {
            client.close()
        }
        // Idempotent, as the session's epilogue relies on.
        client.close()
        assertFalse("close() must drop the socket", client.boundSocket?.isBound ?: false)
    }
}
