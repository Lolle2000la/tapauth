package dev.rourunisen.tapauth.crypto

import android.app.Application
import android.content.Context
import androidx.test.runner.AndroidJUnitRunner

/**
 * Custom test runner that uses TestTapAuthApplication instead of the production TapAuthApplication.
 * This prevents services from starting during tests.
 */
class TapAuthTestRunner : AndroidJUnitRunner() {
    override fun newApplication(
        cl: ClassLoader?,
        className: String?,
        context: Context?,
    ): Application {
        return super.newApplication(cl, TestTapAuthApplication::class.java.name, context)
    }
}
