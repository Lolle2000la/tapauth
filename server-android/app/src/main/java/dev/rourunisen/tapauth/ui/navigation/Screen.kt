package dev.rourunisen.tapauth.ui.navigation

sealed class Screen(val route: String) {
    object Home : Screen("home")

    object QRScanner : Screen("qr_scanner")

    object PairedDevices : Screen("paired_devices")

    object Settings : Screen("settings")

    object Pairing : Screen("pairing/{ipAddress}/{port}/{publicKey}") {
        fun createRoute(ipAddress: String, port: Int, publicKey: String): String {
            return "pairing/$ipAddress/$port/$publicKey"
        }
    }
}
