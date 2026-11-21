package dev.rourunisen.tapauth.network

import android.util.Log
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.service.scrubLogValue
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

    /**
     * The socket [open] bound, or null before [open] and after [close].
     *
     * Exposed so a test can observe the binding itself: [send]'s answer says whether a datagram was
     * handed to a target, which is not the same as proving *which* socket bound *which* port — a
     * send that fails on every target answers the same as an unbound one.
     */
    internal val boundSocket: DatagramSocket?
        get() = socket

    /** Addresses resolved from the QR code's `ip4`/`ip6`, filled in by [open]. */
    private val targets = mutableListOf<InetAddress>()

    /**
     * Bind an ephemeral dual-stack UDP socket and resolve the QR's endpoints.
     *
     * The socket is created unbindable-by-constructor (`DatagramSocket(null)`) and then bound to
     * port 0 of the wildcard address, so the OS picks a free ephemeral port and a dual-stack
     * platform accepts both address families.
     *
     * A QR whose `ip4`/`ip6` resolve to nothing is a failure here, not a silent no-op: [send] can
     * only reach the addresses in [targets], so an empty list means nothing can ever arrive and the
     * pairing would otherwise burn its whole 30 s response deadline before giving up.
     *
     * @throws IOException if the socket cannot be bound, or if no QR endpoint resolves
     */
    fun open() {
        val bound = DatagramSocket(null)
        try {
            bound.bind(InetSocketAddress(0))
            val resolved = resolveTargets()
            if (resolved.isEmpty()) {
                throw IOException(
                    "No QR endpoint resolved (ip4=${pairingUrl.ipv4}, ip6=${pairingUrl.ipv6})",
                )
            }
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
     * Best effort in the *other* direction: a send failure to one address never stops the others.
     *
     * @return whether the transport accepted the datagram — true when at least one target's `send`
     *   returned without throwing, false when there is no bound socket, no QR port, no resolved
     *   target, or every target's send failed. This is the only delivery signal a UDP pairing has:
     *   there is no acknowledgement, so `true` means "handed to the socket", not "the desktop got
     *   it". It answers `false` for the states that make a send a no-op, which is what lets the
     *   completion report an undelivered proof instead of a silent success.
     */
    fun send(packetBytes: ByteArray): Boolean {
        val bound = socket ?: return false
        val port = pairingUrl.port ?: return false
        var sent = false
        for (target in targets) {
            val datagram = DatagramPacket(packetBytes, packetBytes.size, target, port)
            try {
                bound.send(datagram)
                sent = true
            } catch (e: IOException) {
                Log.d(TAG, "Sending ${packetBytes.size} B to $target:$port failed: ${e.message}")
            }
        }
        return sent
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
                Log.w(TAG, "Cannot resolve QR endpoint '${scrubLogValue(host)}': ${e.message}")
            }
        }
        return resolved
    }
}
