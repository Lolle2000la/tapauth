import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.spotless)
    id("kotlin-parcelize")
    id("net.mullvad.rust-android")
}

// Dynamic ABI filtering: when Android Studio deploys to a specific device/emulator
// it injects the target ABI via this property, so we only build that one.
val injectedAbi = project.findProperty("android.injected.build.abi") as? String
val nativeTargets =
    if (!injectedAbi.isNullOrEmpty()) {
        injectedAbi
            .split(",")
            .mapNotNull { abi ->
                when (abi.trim()) {
                    "arm64-v8a" -> "arm64"
                    "armeabi-v7a" -> "arm"
                    "x86_64" -> "x86_64"
                    "x86" -> "x86"
                    else -> null
                }
            }
            .distinct()
    } else {
        listOf("arm", "arm64", "x86", "x86_64")
    }

cargo {
    module = "../../shared"
    libname = "shared"
    targets = nativeTargets
    targetDirectory = "../../target"
    extraCargoBuildArguments = listOf("--features", "jni")
}

// Select profile based on whether any Release task is in the graph
gradle.taskGraph.whenReady {
    val isReleaseBuild = allTasks.any { it.name.contains("Release", ignoreCase = true) }
    cargo.profile = if (isReleaseBuild) "release" else "debug"
}

tasks.named("preBuild") { dependsOn("cargoBuild") }

android {
    namespace = "dev.rourunisen.tapauth"
    compileSdk { version = release(36) }

    // Dynamically resolve NDK path from environment when available
    // (e.g. CI/CD runners, direct NDK installations).
    // Falls back to ndkVersion-based lookup from the Android SDK when not set.
    System.getenv("ANDROID_NDK_HOME")?.let { ndkPath = it }
        ?: System.getenv("ANDROID_NDK_ROOT")?.let { ndkPath = it }

    // CI release signing: configure from environment if a keystore is provided
    val keystoreB64: String? = System.getenv("ANDROID_KEYSTORE_B64")
    if (!keystoreB64.isNullOrEmpty()) {
        signingConfigs {
            create("ciRelease") {
                storeFile = rootProject.file("release.keystore")
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS") ?: "tapauth"
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD") ?: storePassword
            }
        }
    }

    defaultConfig {
        applicationId = "dev.rourunisen.tapauth"
        minSdk = 24
        targetSdk = 36
        versionCode = (System.getenv("VERSION_CODE")?.toIntOrNull() ?: 1)
        versionName = (System.getenv("VERSION_NAME") ?: "1.0")
        ndkVersion = "30.0.14904198"

        testInstrumentationRunner = "dev.rourunisen.tapauth.crypto.TapAuthTestRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Apply CI signing config when available
            val ciReleaseSigning = signingConfigs.findByName("ciRelease")
            if (ciReleaseSigning != null) {
                signingConfig = ciReleaseSigning
            }
        }
        debug {
            // Use different application ID suffix for debug builds
            // This allows side-by-side installation with release builds
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"

            resValue("string", "app_name", "TapAuth (Debug)")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        resValues = true
    }
}

dependencies {
    // Core Android
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)

    // Compose
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)

    // Coroutines
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)

    // Biometric
    implementation(libs.androidx.biometric)

    // Camera & QR Scanning
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)

    // Permissions
    implementation(libs.accompanist.permissions)

    // WorkManager
    implementation(libs.androidx.work.runtime.ktx)

    // JSON parsing
    implementation(libs.gson)

    // Testing
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}

spotless {
    kotlin {
        target("src/**/*.kt")
        ktfmt().kotlinlangStyle()
        trimTrailingWhitespace()
        endWithNewline()
    }
    kotlinGradle {
        target("*.gradle.kts")
        ktfmt().kotlinlangStyle()
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_11) } }
