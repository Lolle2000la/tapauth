package dev.rourunisen.tapauth.network

import android.util.Log
import dev.rourunisen.tapauth.data.PairingUrl
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Ephemeral UDP transport for protocol v2 pairing
 * (`docs/design-documents/protocol/initial-key-exchange.md`).
 *
 * The Linux Client binds an ephemeral dual-stack UDP socket and encodes its port plus reachable
 * addresses into the QR code, so this transport needs no listener of its own: it binds `[::]:0`,
 * resolves the QR's `ip4`/`ip6` at `p`, and sends whole serialized `PairingPacket` frames there.
 * One datagram carries exactly one `PairingPacket`; there is no length prefix or framing.
 *
 * Packets sourced from loopback or from an unexpected address are deliberately **not** filtered:
 * QEMU SLIRP delivers the Client's replies from `10.0.2.2`, and the daemon may answer from any
 * local address of a multi-homed host. Authentication of the peer is the handshake's job (QR `pk`
 * pinning plus Ed25519 signatures plus the SAS), never the address's.
 *
 * This class performs blocking socket work, so [send] should be invoked off the main thread; the
 * suspend members move themselves to [Dispatchers.IO].
 */
class PairingClient(private val pairingUrl: PairingUrl) {

    companion object {
        private const val TAG = "PairingClient"

        /**
         * Receive buffer size. A serialized `PairingPacket` is at most a few hundred bytes
         * (`PairingPacket` is bounded at ~300 B by the BLE GATT budget), so this only has to be
         * larger than any single pairing datagram.
         */
        private const val MAX_DATAGRAM_BYTES = 2048
    }

    private var socket: DatagramSocket? = null

    /** Addresses resolved from the QR code's `ip4`/`ip6`, filled in by [open]. */
    private val targets = mutableListOf<InetAddress>()

    /**
     * Bind an ephemeral dual-stack UDP socket and resolve the QR's endpoints.
     *
     * The socket is created unbindable-by-constructor (`DatagramSocket(null)`) and then bound to
     * port 0 of the wildcard address, so the OS picks a free ephemeral port and a dual-stack
     * platform accepts both address families.
     *
     * @throws IOException if the socket cannot be bound
     */
    fun open() {
        val bound = DatagramSocket(null)
        try {
            bound.bind(InetSocketAddress(0))
            val resolved = resolveTargets()
            targets.clear()
            targets.addAll(resolved)
        } catch (e: IOException) {
            bound.close()
            throw e
        }
        socket = bound
        Log.d(
            TAG,
            "UDP pairing socket bound to port ${bound.localPort}, ${targets.size} endpoint(s)",
        )
    }

    /**
     * Send one serialized `PairingPacket` to every reachable QR endpoint at the QR's port.
     *
     * Best effort: a send failure to one address never stops the others, and a closed socket is a
     * no-op. Call off the main thread.
     */
    fun send(packetBytes: ByteArray) {
        val bound = socket ?: return
        val port = pairingUrl.port ?: return
        for (target in targets) {
            val datagram = DatagramPacket(packetBytes, packetBytes.size, target, port)
            try {
                bound.send(datagram)
            } catch (e: IOException) {
                Log.d(TAG, "Sending ${packetBytes.size} B to $target:$port failed: ${e.message}")
            }
        }
    }

    /**
     * Wait up to [timeoutMs] for one datagram.
     *
     * @return the received payload, or null on timeout, on a closed socket, or after [close]
     */
    suspend fun receive(timeoutMs: Long): ByteArray? =
        withContext(Dispatchers.IO) {
            val bound = socket ?: return@withContext null
            val buffer = ByteArray(MAX_DATAGRAM_BYTES)
            val datagram = DatagramPacket(buffer, buffer.size)
            try {
                bound.soTimeout = timeoutMs.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
                bound.receive(datagram)
                datagram.data.copyOfRange(datagram.offset, datagram.offset + datagram.length)
            } catch (e: SocketTimeoutException) {
                null
            } catch (e: IOException) {
                // Expected when close() races a pending receive; also covers a concurrently
                // changed soTimeout.
                Log.d(TAG, "Receive stopped: ${e.message}")
                null
            }
        }

    /** Close the socket. Idempotent. */
    fun close() {
        val bound = socket ?: return
        socket = null
        bound.close()
    }

    private fun resolveTargets(): List<InetAddress> {
        val resolved = mutableListOf<InetAddress>()
        for (host in listOfNotNull(pairingUrl.ipv4, pairingUrl.ipv6)) {
            try {
                val address = InetAddress.getByName(host)
                if (resolved.none { it == address }) resolved.add(address)
            } catch (e: IOException) {
                Log.w(TAG, "Cannot resolve QR endpoint '$host': ${e.message}")
            }
        }
        return resolved
    }
}
