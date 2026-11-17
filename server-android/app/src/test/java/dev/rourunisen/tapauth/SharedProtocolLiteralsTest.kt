package dev.rourunisen.tapauth

import dev.rourunisen.tapauth.ble.BleGattService
import dev.rourunisen.tapauth.data.AppConfiguration
import dev.rourunisen.tapauth.network.BlePairingClient
import dev.rourunisen.tapauth.service.AuthenticationService
import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The literals Android copies from the specification, the design documents and the Rust side.
 *
 * None of them is computed or negotiated — a UUID, a port, a multicast group, a buffer bound — so
 * when one drifts nothing fails at compile time and nothing fails here either unless a test states
 * the value. The failure it produces instead is silent and remote: the phone subscribes to a
 * characteristic the daemon does not serve (pairing hangs until the SAS prompt expires), the phone
 * multicasts to a group the daemon never joined (authentication never rings), or the phone requests
 * an MTU that no longer covers the payload Rust will hand it.
 *
 * Each case is pinned at *both* ends: the Kotlin constant against a literal, and that literal
 * against the document or the Rust declaration that is supposed to agree with it. A rewrite of
 * either side that this cannot parse fails loudly rather than skipping, because a silently skipped
 * cross-check is the drift it exists to catch.
 */
class SharedProtocolLiteralsTest {

    /**
     * `docs/design-documents/protocol/ble-gatt-specification.md` is the specification both sides
     * are written against: one static service and four characteristics under it (§2).
     *
     * The defect this catches: a transcription slip in any of the five, which compiles, passes
     * every behavioural test that is written against the same constant, and only shows up as a link
     * that silently never matches on a real device.
     */
    @Test
    fun theGattTableMatchesTheDesignDocument() {
        val served =
            listOf(
                BleGattService.SERVICE_UUID,
                BleGattService.CLIENT_COMMAND_CHAR_UUID,
                BleGattService.SERVER_RESPONSE_CHAR_UUID,
                BleGattService.CLIENT_CONFIRMATION_CHAR_UUID,
            )
        val documented =
            listOf(
                "b4ad84c0-2adb-4876-8315-b39d983b2bde",
                "caf54438-9d78-4697-8886-0a4cfa87ba8d",
                "ca6238be-c194-49b7-855b-58f41d3da626",
                "ace3e9ad-5f0d-48bf-825a-5b7f4dc49cdf",
            )
        assertEquals(
            "BleGattService must serve the service and the three authentication characteristics " +
                "the specification names",
            documented,
            served.map { it.toString() },
        )

        // The pairing side opens its own connection to the *same* service, and writes the pairing
        // channel: a client that scanned for one service and wrote another characteristic would
        // never complete a pairing.
        assertEquals(
            "BlePairingClient must scan for the same service BleGattService serves",
            "b4ad84c0-2adb-4876-8315-b39d983b2bde",
            BlePairingClient.SERVICE_UUID.toString(),
        )
        assertEquals(
            "BlePairingClient must write the pairing channel characteristic",
            "d9e8f1a2-3b4c-4d5e-8f60-7a8b9c0d1e2f",
            BlePairingClient.PAIRING_CHAR_UUID.toString(),
        )

        val doc = repositoryFile(BLE_SPECIFICATION)
        for (uuid in documented + BlePairingClient.PAIRING_CHAR_UUID.toString()) {
            assertTrue(
                "$BLE_SPECIFICATION must name the UUID Android uses ($uuid): the phone and the " +
                    "daemon are specified against this document, not against each other",
                doc.contains(uuid),
            )
        }
    }

    /**
     * `pairing_adv_id` is a 10-byte truncation, and both sides have to truncate at the same length
     * or the phone's hardware `ScanFilter` matches a value the daemon never advertises.
     *
     * The defect this catches: a length changed on one side only (the Rust field is `[u8; 10]`,
     * `shared/src/protocol/pairing/wire.rs`), which leaves the phone scanning for a ten-byte prefix
     * of a longer or shorter identifier.
     */
    @Test
    fun thePairingAdvertisementIdMatchesTheRustArray() {
        assertEquals(
            "ADV_ID_BYTES must stay 10: the advertise side and the scan filter both derive it from " +
                "the Rust [u8; N] field",
            10,
            BlePairingClient.ADV_ID_BYTES,
        )
        assertEquals(
            "BlePairingClient must truncate to the length of the Rust `pairing_adv_id` array",
            BlePairingClient.ADV_ID_BYTES,
            capture(PAIRING_ADV_ID_FIELD, PAIRING_WIRE_RS),
        )
        assertTrue(
            "AGENTS.md documents the advertisement id as 10 bytes",
            repositoryFile("AGENTS.md").contains("10-byte `pairing_adv_id`"),
        )
    }

    /**
     * The daemon's default port, as `config.toml.example` documents it to an administrator.
     *
     * The defect this catches: the phone binding one port while the shipped default (and every
     * administrator's config) names another — authentication then multicasts to a port nothing is
     * listening on.
     */
    @Test
    fun theDefaultUdpPortMatchesTheDocumentedDefault() {
        val documented =
            Regex("""(?m)^\s*udp_port\s*=\s*(\d+)\s*$""")
                .find(repositoryFile(CONFIG_EXAMPLE))
                ?.groupValues
                ?.get(1)
                ?.toInt()
                ?: throw AssertionError(
                    "Could not parse `udp_port = <n>` out of $CONFIG_EXAMPLE; re-read that file " +
                        "and update this test",
                )

        assertEquals(
            "AppConfiguration must default to the port the daemon's example config documents",
            documented,
            AppConfiguration.DEFAULT_UDP_PORT,
        )
        assertEquals("the documented default port", 36692, documented)
    }

    /**
     * Discovery groups: the phone joins the two the daemon multicasts to, and AGENTS.md names both.
     *
     * The defect this catches: a group edited on one side, so the phone's multicast lock is taken
     * on a group the daemon never sends to and no authentication request is ever received.
     */
    @Test
    fun theMulticastGroupsMatchTheDocumentedGroups() {
        // Compared as addresses, not as strings: the JDK's textual form of an IPv6 address is
        // formatted on its own terms (`ff12:0:0:0:0:fdec:fc27`), so the bytes are what must agree.
        assertEquals(
            "the IPv4 discovery group",
            InetAddress.getByName("239.255.26.44"),
            AuthenticationService.IPV4_MULTICAST_GROUP,
        )
        assertEquals(
            "the IPv6 discovery group",
            InetAddress.getByName("ff12::fdec:fc27"),
            AuthenticationService.IPV6_MULTICAST_GROUP,
        )

        val agents = repositoryFile("AGENTS.md")
        assertTrue(
            "AGENTS.md must document the IPv4 group the phone joins",
            agents.contains("239.255.26.44"),
        )
        assertTrue(
            "AGENTS.md must document the IPv6 group the phone joins",
            agents.contains("ff12::fdec:fc27"),
        )
    }

    /**
     * The MTU Android requests and the payload ceiling Rust enforces are one budget: a single ATT
     * PDU carries `MTU - 5` bytes of payload, so a 512-byte ceiling needs an MTU of 517.
     *
     * The defect this catches: the two numbers drifting apart — a ceiling raised past the MTU would
     * make Rust hand Android frames the stack must fragment or truncate, and a lowered one silently
     * refuses frames the desktop believes are deliverable. Because both are checked here and again
     * in `shared/src/models.rs` (`test_gatt_payload_fits_the_negotiated_mtu`), neither side can
     * move alone.
     */
    @Test
    fun theRequestedMtuCoversTheRustPayloadCeiling() {
        val payloadCeiling = capture(MAX_GATT_PAYLOAD, MODELS_RS)

        assertEquals("the Rust GATT payload ceiling", 512, payloadCeiling)
        assertEquals(
            "BleGattService must request the MTU this payload needs",
            payloadCeiling + ATT_HEADER_BYTES,
            BleGattService.GATT_REQUESTED_MTU,
        )
        assertEquals(
            "BlePairingClient must request the same MTU: both transports carry the same frames",
            BleGattService.GATT_REQUESTED_MTU,
            BlePairingClient.TARGET_MTU,
        )
        assertEquals("the ATT MTU both sides negotiate", 517, BleGattService.GATT_REQUESTED_MTU)
    }

    /** The first capture group of [pattern] in a repository file, as an `Int`. */
    private fun capture(pattern: Regex, path: String): Int =
        pattern.find(repositoryFile(path))?.groupValues?.get(1)?.toInt()
            ?: throw AssertionError(
                "Could not parse ${pattern.pattern} out of $path; re-read that file and update " +
                    "this test",
            )

    /**
     * A repository file, located by walking up from this module's working directory
     * (`server-android/app`), the way `PairingCompletionTest` reads the daemon's pairing worker.
     */
    private fun repositoryFile(relativePath: String): String {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val file = File(directory, relativePath)
            if (file.isFile) return file.readText()
            directory = directory.parentFile
        }
        throw AssertionError(
            "$relativePath was not found above ${File("").absolutePath}; the literal it pins " +
                "cannot be cross-checked from this working directory",
        )
    }

    private companion object {
        const val BLE_SPECIFICATION = "docs/design-documents/protocol/ble-gatt-specification.md"

        const val CONFIG_EXAMPLE = "config.toml.example"

        const val MODELS_RS = "shared/src/models.rs"

        const val PAIRING_WIRE_RS = "shared/src/protocol/pairing/wire.rs"

        /** `pub const MAX_GATT_PAYLOAD_BYTES: usize = 512;` */
        val MAX_GATT_PAYLOAD = Regex("""MAX_GATT_PAYLOAD_BYTES\s*:\s*usize\s*=\s*(\d+)""")

        /** `pub pairing_adv_id: [u8; 10]` */
        val PAIRING_ADV_ID_FIELD = Regex("""pairing_adv_id\s*:\s*\[u8;\s*(\d+)\s*]""")

        /** The ATT framing a single PDU spends before its payload (opcode + attribute handle). */
        const val ATT_HEADER_BYTES = 5
    }
}
