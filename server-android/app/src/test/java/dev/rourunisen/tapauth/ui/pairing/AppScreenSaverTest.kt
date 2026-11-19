package dev.rourunisen.tapauth.ui.pairing

import androidx.compose.runtime.saveable.SaverScope
import dev.rourunisen.tapauth.AppScreen
import dev.rourunisen.tapauth.data.PairingUrl
import dev.rourunisen.tapauth.ui.navigation.AppScreenSaver
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Round-trips [AppScreenSaver], the piece a configuration change depends on.
 *
 * What a rotation actually runs is `rememberSaveable`, which needs a composition and is not
 * exercised here; what *is* exercised is the saver it delegates to, through the same `Saver` API
 * Compose calls: `save` produces the persisted form and `restore` rebuilds the screen from it. A
 * field dropped from either half fails these tests — and in production would turn every rotation
 * into a fresh handshake (no `sessionId`/`publicKey`) or a pairing with no endpoint to reach (no
 * `port`/`ip4`/`ip6`).
 */
class AppScreenSaverTest {

    private val scope = SaverScope { true }

    private fun save(screen: AppScreen): Any? = with(AppScreenSaver) { scope.save(screen) }

    private fun roundTrip(screen: AppScreen): AppScreen? {
        val saved = save(screen) ?: return null
        return AppScreenSaver.restore(saved)
    }

    private val fullUrl =
        PairingUrl(
            version = 2,
            sessionId = "00112233445566778899aabbccddeeff",
            publicKey = "1111111111111111111111111111111111111111111111111111111111111111",
            port = 36692,
            ipv4 = "192.168.1.20",
            ipv6 = "fd00::1",
        )

    @Test
    fun aPairingScreenWithANetworkEndpointRoundTrips() {
        assertEquals(AppScreen.Pairing(fullUrl), roundTrip(AppScreen.Pairing(fullUrl)))
    }

    @Test
    fun aPairingScreenWithoutAnyEndpointRoundTrips() {
        val bleOnly = fullUrl.copy(port = null, ipv4 = null, ipv6 = null)

        assertEquals(AppScreen.Pairing(bleOnly), roundTrip(AppScreen.Pairing(bleOnly)))
    }

    @Test
    fun aPairingScreenWithOnlyAnIpv6EndpointRoundTrips() {
        val ipv6Only = fullUrl.copy(port = 40000, ipv4 = null, ipv6 = "fd00::1")

        assertEquals(AppScreen.Pairing(ipv6Only), roundTrip(AppScreen.Pairing(ipv6Only)))
    }

    @Test
    fun theSavedFormKeepsEveryPairingFieldInOrder() {
        val saved = save(AppScreen.Pairing(fullUrl))

        assertEquals(
            listOf(
                "pairing",
                "2",
                "00112233445566778899aabbccddeeff",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "36692",
                "192.168.1.20",
                "fd00::1",
            ),
            saved,
        )
    }

    @Test
    fun everyOtherScreenRoundTrips() {
        val screens =
            listOf(AppScreen.Home, AppScreen.Scanner, AppScreen.DeviceList, AppScreen.Settings)

        for (screen in screens) {
            assertEquals(screen, roundTrip(screen))
        }
    }

    @Test
    fun aPairingRecordWithMissingFieldsRestoresToNothing() {
        // One field short of the seven a `Pairing` screen saves: restoring a half-read screen would
        // put the user on a pairing with an empty session id, so the saver refuses it instead.
        assertNull(
            AppScreenSaver.restore(listOf("pairing", "2", "00112233445566778899aabbccddeeff")),
        )
    }
}
