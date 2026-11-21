package dev.rourunisen.tapauth.ui.navigation

import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import dev.rourunisen.tapauth.AppScreen
import dev.rourunisen.tapauth.data.PairingUrl

/** Screen tags for [AppScreenSaver]; the saved form is a plain `List<String>`. */
private const val SAVED_HOME = "home"

private const val SAVED_SCANNER = "scanner"

private const val SAVED_PAIRING = "pairing"

private const val SAVED_DEVICE_LIST = "devices"

private const val SAVED_SETTINGS = "settings"

/** Elements of a saved [AppScreen.Pairing]: tag, version, session id, key, port, IPv4, IPv6. */
private const val SAVED_PAIRING_FIELDS = 7

/**
 * Saves the current screen across a configuration change, so a rotation keeps the user where they
 * were instead of dropping them back to [AppScreen.Home].
 *
 * [AppScreen.Pairing] carries a [PairingUrl], which is not `Parcelable`; it is saved field by field
 * and rebuilt on restore. Absent optional fields (`p`, `ip4`, `ip6`) are saved as empty strings.
 *
 * Every field matters: a dropped `sessionId` or `publicKey` would make the restored screen start a
 * fresh handshake against the desktop's live one, and a dropped `port`/`ip4`/`ip6` would silently
 * turn a network pairing into a BLE-only attempt. [AppScreenSaverTest] round-trips all of them.
 */
internal object AppScreenSaver :
    Saver<AppScreen, Any> by listSaver(
        save = { screen ->
            when (screen) {
                AppScreen.Home -> listOf(SAVED_HOME)
                AppScreen.Scanner -> listOf(SAVED_SCANNER)
                AppScreen.DeviceList -> listOf(SAVED_DEVICE_LIST)
                AppScreen.Settings -> listOf(SAVED_SETTINGS)
                is AppScreen.Pairing ->
                    listOf(
                        SAVED_PAIRING,
                        screen.url.version.toString(),
                        screen.url.sessionId,
                        screen.url.publicKey,
                        screen.url.port?.toString().orEmpty(),
                        screen.url.ipv4.orEmpty(),
                        screen.url.ipv6.orEmpty(),
                    )
            }
        },
        restore = { saved ->
            when (saved.firstOrNull()) {
                SAVED_SCANNER -> AppScreen.Scanner
                SAVED_DEVICE_LIST -> AppScreen.DeviceList
                SAVED_SETTINGS -> AppScreen.Settings
                SAVED_PAIRING -> restorePairingScreen(saved)
                else -> AppScreen.Home
            }
        },
    )

/** Rebuilds a saved [AppScreen.Pairing]; null (restore failed) falls back to [AppScreen.Home]. */
private fun restorePairingScreen(saved: List<String>): AppScreen? {
    if (saved.size != SAVED_PAIRING_FIELDS) return null
    val version = saved[1].toIntOrNull() ?: return null
    return AppScreen.Pairing(
        PairingUrl(
            version = version,
            sessionId = saved[2],
            publicKey = saved[3],
            port = saved[4].toIntOrNull(),
            ipv4 = saved[5].ifEmpty { null },
            ipv6 = saved[6].ifEmpty { null },
        ),
    )
}
