package dev.rourunisen.tapauth.network

import dev.rourunisen.tapauth.data.PairingUrl
import java.io.IOException
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The UDP pairing transport's `open()` contract.
 *
 * The QR code's `ip4`/`ip6` are not validated as IP literals by [PairingUrl.parse], so a QR that
 * names something unresolvable resolves to zero targets. `open()` must report that instead of
 * handing back a socket that can never send: the session's UDP candidate would otherwise sit on its
 * 30 s response deadline with nothing to send to.
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

    /** The positive control: a resolvable endpoint must still open and send. */
    @Test
    fun openBindsWhenAnEndpointResolves() {
        val client = PairingClient(url(ipv4 = "127.0.0.1"))
        try {
            client.open()
            client.send(byteArrayOf(1, 2, 3))
        } finally {
            client.close()
        }
        // Idempotent, as the session's epilogue relies on.
        client.close()
    }
}
