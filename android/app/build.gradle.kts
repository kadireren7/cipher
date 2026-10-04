plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ktlint)
}

val repoRoot = rootProject.projectDir.parentFile
val generatedKotlin = layout.buildDirectory.dir("generated/uniffi/kotlin")

android {
    namespace = "app.cipher.messenger"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.cipher.messenger"
        minSdk = 30 // Android 11: per-use biometric+credential keys, TLS 1.3 in the platform stack
        targetSdk = 35
        versionCode = 1
        versionName = "0.2.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    signingConfigs {
        // Debug builds only use the SDK debug keystore. A release signing config is supplied by CI/the maintainer through
        // environment variables; nothing signing-related is committed.
        create("release") {
            val ks = System.getenv("CIPHER_RELEASE_KEYSTORE")
            if (ks != null) {
                storeFile = file(ks)
                storePassword = System.getenv("CIPHER_RELEASE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("CIPHER_RELEASE_KEY_ALIAS")
                keyPassword = System.getenv("CIPHER_RELEASE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            // Emulators have no hardware-backed keystore: debug builds may accept a software-backed key, and say so on screen.
            buildConfigField("boolean", "ALLOW_SOFTWARE_KEYSTORE", "true")
            buildConfigField("String", "DEFAULT_RELAY_URL", "\"https://10.0.2.2:8443\"")
            buildConfigField("String", "DEFAULT_INVITE", "\"\"")
            applicationIdSuffix = ".debug"
            isDebuggable = true
        }
        release {
            // Production: never accepts a software keystore, no default relay/invite baked in, minified, not debuggable.
            buildConfigField("boolean", "ALLOW_SOFTWARE_KEYSTORE", "false")
            buildConfigField("String", "DEFAULT_RELAY_URL", "\"\"")
            buildConfigField("String", "DEFAULT_INVITE", "\"\"")
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (System.getenv("CIPHER_RELEASE_KEYSTORE") != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/versions/**")
        jniLibs.useLegacyPackaging = false
    }
    sourceSets["main"].java.srcDir(generatedKotlin)
    testOptions { unitTests.isReturnDefaultValues = true }
    lint {
        abortOnError = true
        warningsAsErrors = false
        checkReleaseBuilds = true
        lintConfig = file("lint.xml")
    }
}

// --- FFI: generate the Kotlin bindings from the Rust library (so they can never drift from the Rust API). ---
val generateUniffi by tasks.registering(Exec::class) {
    group = "cipher"
    description = "Generate Kotlin bindings for cipher-ffi (UniFFI)."
    workingDir = repoRoot
    val out = generatedKotlin.get().asFile
    inputs.files(fileTree("$repoRoot/crates/cipher-ffi/src"))
    outputs.dir(out)
    environment("PATH", "${System.getProperty("user.home")}/.cargo/bin:${System.getenv("PATH")}")
    commandLine(
        "bash",
        "-c",
        "cargo build -p cipher-ffi --features cli --locked && " +
            "cargo run -q -p cipher-ffi --features cli --locked --bin uniffi-bindgen -- generate " +
            "--library target/debug/libcipher_ffi.so --language kotlin --out-dir '${out.absolutePath}' --no-format",
    )
}
// --- Rust security core for Android (arm64-v8a + x86_64), built from source on every build. ---
val rustJniLibs = layout.buildDirectory.dir("rustJniLibs")
val buildRustLibs by tasks.registering(Exec::class) {
    group = "cipher"
    description = "Cross-compile cipher-ffi for Android with cargo-ndk."
    workingDir = repoRoot
    inputs.files(fileTree("$repoRoot/crates"), file("$repoRoot/Cargo.lock"), file("$repoRoot/Cargo.toml"))
    outputs.dir(rustJniLibs)
    val ndk = System.getenv("ANDROID_NDK_HOME") ?: "${System.getenv("ANDROID_HOME") ?: ""}/ndk/27.2.12479018"
    environment("ANDROID_NDK_HOME", ndk)
    environment("PATH", "${System.getProperty("user.home")}/.cargo/bin:${System.getenv("PATH")}")
    // Reproducibility / privacy: keep the builder's home directory and checkout path out of the native library (panic locations, DWARF).
    environment(
        "RUSTFLAGS",
        "--remap-path-prefix=${System.getProperty("user.home")}=/build/home --remap-path-prefix=$repoRoot=/build/src",
    )
    commandLine(
        "cargo", "ndk", "-t", "arm64-v8a", "-t", "x86_64", "-o", rustJniLibs.get().asFile.absolutePath,
        "build", "--profile", "android-release", "-p", "cipher-ffi", "--locked",
    )
}
android.sourceSets["main"].jniLibs.srcDir(rustJniLibs)
tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach { dependsOn(buildRustLibs) }

tasks.matching { it.name.startsWith("preBuild") || it.name.startsWith("runKtlint") || it.name.startsWith("ktlint") }.configureEach {
    dependsOn(generateUniffi)
}

// Debug builds trust a throwaway test CA (via <debug-overrides>); make sure it exists before resources are processed.
val ensureTestCa by tasks.registering(Exec::class) {
    group = "cipher"
    workingDir = repoRoot
    commandLine("bash", "scripts/make-test-ca.sh")
}
tasks.matching {
    it.name.matches(Regex("(merge|process|generate|package).*Debug.*Resources|mergeDebugResources|processDebugResources"))
}.configureEach { dependsOn(ensureTestCa) }

ktlint {
    android.set(true)
    ignoreFailures.set(false)
    filter { exclude { it.file.path.contains("generated") } }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.androidx.core)
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.okhttp)
    implementation(libs.zxing.core)
    implementation(libs.kotlinx.coroutines.android)
    // UniFFI's Kotlin bindings load the Rust library through JNA (the AAR bundles the Android native stubs).
    implementation("${libs.jna.get()}@aar")

    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(libs.compose.ui.test.junit4)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
