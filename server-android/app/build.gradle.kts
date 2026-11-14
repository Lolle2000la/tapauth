import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

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

// Detect release profile at configuration time so cargoBuild tasks see it
cargo.profile =
    if (gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }) "release"
    else "debug"

tasks.named("preBuild") { dependsOn("cargoBuild") }

// ---------------------------------------------------------------------------
// UniFFI Kotlin bindings
// ---------------------------------------------------------------------------
// The Rust↔Kotlin surface is declared once, by the `#[uniffi::export]` items in
// `shared/src/ffi.rs`. The Kotlin half is generated from the metadata compiled
// into `libshared.so` instead of being committed, so the declarations are the
// only source of truth.
//
// `cargoBuild` (the aggregate task, depended on by `preBuild` above) has
// already produced that library with the `jni` feature; the task registered
// below only turns it into Kotlin. The aggregate task is the dependency on
// purpose: Android Studio injects `android.injected.build.abi` on deploy, which
// narrows `cargo.targets` (above) to a single ABI, so a per-ABI task such as
// `cargoBuildArm64` may not exist in the graph at all.
//
// The bindgen runs in the cargo workspace root because UniFFI library mode
// resolves `shared/uniffi.toml` relative to the crate it finds in the
// workspace.
val uniffiOutDir = layout.buildDirectory.dir("generated/uniffi")
val rustJniLibsDir = layout.buildDirectory.dir("rustJniLibs/android")
val cargoWorkspaceRoot = rootProject.projectDir.parentFile

android {
    namespace = "dev.rourunisen.tapauth"
    compileSdk { version = release(37) }

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
        targetSdk = 37
        versionCode = (System.getenv("VERSION_CODE")?.toIntOrNull() ?: 1)
        versionName = (System.getenv("VERSION_NAME") ?: "1.0")
        ndkVersion = "30.0.14904198"

        testInstrumentationRunner = "dev.rourunisen.tapauth.crypto.TapAuthTestRunner"

        manifestPlaceholders["appName"] = "TapAuth"
    }

    // Intentional: unit tests (./gradlew test) and instrumented tests
    // (connectedE2eAndroidTest) both run against the e2e variant. This is fine
    // today because no unit-testable logic reads BuildConfig.E2E_TESTING — the
    // unit tests are pure logic (rate limiter, replay cache, retransmission).
    // Two caveats to keep in mind:
    //   1. If you add a test that branches on E2E_TESTING, it would silently
    //      test e2e behavior, not production behavior — revisit this setting.
    //   2. Unit tests also run with unitTests.isReturnDefaultValues = true
    //      (below), a slightly more permissive environment than production.
    testBuildType = "e2e"

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
            buildConfigField("Boolean", "E2E_TESTING", "false")
        }
        debug {
            // Use different application ID suffix for debug builds
            // This allows side-by-side installation with release builds
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"

            manifestPlaceholders["appName"] = "TapAuth (Debug)"
            buildConfigField("Boolean", "E2E_TESTING", "false")
        }
        create("e2e") {
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            applicationIdSuffix = ".e2e"
            versionNameSuffix = "-e2e"

            manifestPlaceholders["appName"] = "TapAuth (E2E)"
            buildConfigField("Boolean", "E2E_TESTING", "true")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        resValues = true
        buildConfig = true
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    // The generated UniFFI bindings are a normal Kotlin source root of the
    // `main` source set, so every variant (debug, release, e2e) and every
    // consumer of `main` (unit test, instrumented test) sees them.
    //
    // Passed as a File, not the Provider: AGP 9 rejects Provider instances in
    // the SourceSet API ("You cannot add Provider instances to the Android
    // SourceSet API"), because it cannot tell generated from static sources.
    // The task dependency that a Provider would have carried implicitly is
    // declared explicitly next to the task registration below.
    sourceSets.getByName("main").kotlin.srcDir(uniffiOutDir.get().asFile)
}

val generateUniffiBindings =
    tasks.register<Exec>("generateUniffiBindings") {
        group = "rust"
        description = "Generates the Kotlin bindings for the UniFFI surface in shared/src/ffi.rs."

        dependsOn("cargoBuild")

        // Resolved at configuration time: execution-time access to the project
        // is not allowed under the configuration cache this build enables.
        val jniLibsRoot = rustJniLibsDir.get().asFile
        val outDir = uniffiOutDir.get().asFile
        val cargoManifest = File(cargoWorkspaceRoot, "shared/Cargo.toml")
        val uniffiConfig = File(cargoWorkspaceRoot, "shared/uniffi.toml")
        val workspaceRoot = cargoWorkspaceRoot

        // The library tree, not a single ABI: which ABIs exist depends on the
        // injected-ABI filter above. UniFFI metadata is architecture-agnostic,
        // so any one of them carries the whole surface.
        inputs.files(fileTree(jniLibsRoot) { include("*/libshared.so") })
        inputs.file(cargoManifest)
        inputs.file(uniffiConfig)
        outputs.dir(outDir)

        doFirst {
            val abiDirs =
                jniLibsRoot.listFiles()?.filter { it.isDirectory }?.sortedBy { it.name }.orEmpty()
            val library =
                abiDirs.map { File(it, "libshared.so") }.firstOrNull { it.isFile }
                    ?: throw GradleException(
                        "generateUniffiBindings: no native library carrying UniFFI metadata found. " +
                            "Expected one of " +
                            listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64").joinToString(", ") {
                                "$it/libshared.so"
                            } +
                            " under ${jniLibsRoot.path}; that directory contains " +
                            if (abiDirs.isEmpty()) {
                                "nothing (it does not exist)."
                            } else {
                                "only ${abiDirs.joinToString(", ") { it.name }}."
                            } +
                            " Run `:app:cargoBuild` first, or check `cargo.targets` in app/build.gradle.kts.",
                    )

            outDir.mkdirs()
            commandLine(
                "cargo",
                "run",
                "--manifest-path",
                cargoManifest.path,
                "--features",
                "cli,jni",
                "--bin",
                "uniffi-bindgen",
                "--",
                "generate",
                library.path,
                "--language",
                "kotlin",
                "--out-dir",
                outDir.path,
                "--no-format",
            )
        }

        workingDir(workspaceRoot)
    }

// Ordering, not just build-config wiring: `preBuild` covers assemble/package,
// and every Kotlin compile (including the unit-test and instrumented-test
// compiles, which do not run `preBuild`) needs the sources on disk first.
tasks.named("preBuild") { dependsOn(generateUniffiBindings) }

tasks.withType<KotlinCompile>().configureEach { dependsOn(generateUniffiBindings) }

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

    // UniFFI runtime. The generated bindings use JNA's direct mapping
    // (`com.sun.jna.*` plus `Native.register(..., "shared")`), so JNA ships the
    // `libjnidispatch.so` that does the symbol lookup. The `@aar` is required:
    // the plain jar has no `jni/` payload, so the dispatcher would not be
    // packaged and the bindings would fail to load at runtime.
    //
    // KEEP RULES — not needed today (`release` has isMinifyEnabled = false).
    // If minification is ever enabled, R8 must retain `com.sun.jna.**` (JNA
    // resolves its own structure/class names reflectively) and the generated
    // `dev.rourunisen.tapauth.crypto` package (the bindings reflect over their
    // own signatures and are only reachable through `Native.register`). Do not
    // enable minification for this migration otherwise.
    implementation("net.java.dev.jna:jna:5.19.1@aar")

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

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}
