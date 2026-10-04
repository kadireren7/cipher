package app.cipher.messenger.data

import android.app.Application
import android.net.ConnectivityManager
import androidx.fragment.app.FragmentActivity
import app.cipher.messenger.BuildConfig
import app.cipher.messenger.net.OkHttpCallbacks
import app.cipher.messenger.net.RouteConfig
import app.cipher.messenger.net.RouteStatus
import app.cipher.messenger.net.RouteTracker
import app.cipher.messenger.net.SocksEndpoint
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.io.File
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import uniffi.cipher_ffi.CipherEngine
import uniffi.cipher_ffi.DeviceEventFfi
import uniffi.cipher_ffi.EngineSettings

/**
 * Owns the Rust engine and serialises every call onto ONE thread (the Rust side also serialises, but keeping UI/main-thread
 * work off the FFI avoids ANRs and keeps the BiometricPrompt callback — which blocks the engine thread — off the UI thread).
 *
 * Non-secret configuration lives in plain files under the no-backup directory: the relay URL and the chosen lock timeout.
 * Nothing secret is stored here; keys and data live in the Rust vault.
 */
class EngineHost(private val app: Application, private val activityProvider: () -> FragmentActivity?) {
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "cipher-engine") }
    val dispatcher: CoroutineDispatcher = executor.asCoroutineDispatcher()

    private val configDir = File(app.noBackupFilesDir, "config").apply { mkdirs() }
    private val relayFile = File(configDir, "relay.url")
    private val timeoutFile = File(configDir, "lock_timeout_secs")

    @Volatile private var engine: CipherEngine? = null
    val routeConfig = RouteConfig(configDir)
    private val routeTracker = RouteTracker(
        nowMs = { System.currentTimeMillis() },
        deviceOnline = {
            val cm = app.getSystemService(ConnectivityManager::class.java)
            cm?.activeNetwork != null
        },
    )

    @Volatile private var http = OkHttpCallbacks(routeConfig, routeTracker)

    /** What the user is told about the route (PRIV-013): PROTECTED only while a request really completed through the privacy route. */
    fun routeStatus(): RouteStatus = routeTracker.status()

    fun socksEndpoint(): SocksEndpoint = routeConfig.socks()

    /** Changes the local SOCKS endpoint; the engine is rebuilt so the new route applies to every later request. */
    fun configureSocks(e: SocksEndpoint) {
        http.cancelAll()
        routeConfig.setSocks(e)
        http = OkHttpCallbacks(routeConfig, routeTracker)
        engine = null
    }

    fun relayUrl(): String? = relayFile.takeIf { it.exists() }?.readText()?.trim()?.takeIf { it.startsWith("https://") }

    fun lockTimeoutSecs(): Int = timeoutFile.takeIf { it.exists() }?.readText()?.trim()?.toIntOrNull()?.coerceIn(15, 3600) ?: 60

    fun setLockTimeoutSecs(secs: Int) {
        timeoutFile.writeText(secs.coerceIn(15, 3600).toString())
    }

    /** DEBUG BUILDS ONLY: skip per-use biometric auth for emulators that have no secure lock screen. Dead code in release. */
    private fun requireUserAuth(): Boolean = !(BuildConfig.DEBUG && File(configDir, "debug_no_user_auth").exists())

    /** The user's unlock-mode choice made at onboarding ("biometric" or "pin"). Not secret. */
    fun unlockMode(): String = File(configDir, "unlock_mode").takeIf { it.exists() }?.readText()?.trim() ?: "biometric"

    fun setUnlockMode(mode: String) {
        File(configDir, "unlock_mode").writeText(mode)
    }

    /** Non-secret marker: onboarding finished (the Rust status cannot report an identity while the vault is locked). */
    fun onboardingComplete(): Boolean = File(configDir, "onboarding_done").exists()

    /** Non-secret marker: the last unlock was refused because the storage was older than the recorded generation (rollback). */
    fun markRolledBack() {
        File(configDir, "rolled_back").writeText("1")
    }

    fun wasRolledBack(): Boolean = File(configDir, "rolled_back").exists()

    fun markOnboardingComplete() {
        File(configDir, "onboarding_done").writeText("1")
    }

    /**
     * USER-INITIATED ONLY (explicit confirmation in Settings or after the OS invalidated the keys): removes this device's vault,
     * configuration and Keystore keys so onboarding can start over. This is never triggered automatically (no wipe-on-failure).
     */
    suspend fun resetLocalData() = withContext(dispatcher) {
        engine = null
        File(app.noBackupFilesDir, "cipher").deleteRecursively()
        configDir.listFiles()?.forEach { it.delete() }
        runCatching {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            ks.aliases().toList().filter { it.startsWith("cipher.") }.forEach { ks.deleteEntry(it) } // vault keys AND the rollback counter
        }
    }

    fun configureRelay(url: String) {
        require(url.startsWith("https://")) { "https required" }
        relayFile.writeText(url.trim())
        engine = null
    }

    private fun build(): CipherEngine {
        val url = relayUrl() ?: error("relay not configured")
        val settings = EngineSettings(
            dataDir = File(app.noBackupFilesDir, "cipher").apply { mkdirs() }.absolutePath,
            relayUrl = url,
            allowSoftwareKeystore = BuildConfig.ALLOW_SOFTWARE_KEYSTORE,
            inactivityTimeoutSecs = lockTimeoutSecs().toULong(),
            requireUserAuth = requireUserAuth(),
            extraSourceDir = null,
        )
        return CipherEngine(settings, AndroidKeystoreCallbacks(app, BiometricGate(activityProvider)), http)
    }

    val isConfigured: Boolean get() = relayUrl() != null

    suspend fun <T> call(block: (CipherEngine) -> T): T = withContext(dispatcher) {
        val e = engine ?: build().also { engine = it }
        block(e)
    }

    /** Fire-and-forget lifecycle notifications, ordered with every other engine call. */
    private fun post(block: (CipherEngine) -> Unit) {
        executor.execute {
            val e = engine ?: return@execute
            runCatching { block(e) }
        }
    }

    /**
     * FR-11: lock requests must not wait behind a running operation (the engine thread is single-threaded). Signal the engine and cancel
     * the network FIRST, on the calling thread; the ordered lock then follows.
     */
    fun signalLockNow() {
        engine?.requestLock()
        http.cancelAll()
    }

    fun onBackground() {
        signalLockNow()
        post { it.onBackground() }
    }

    fun onForeground() = post { it.onForeground() }

    fun onScreenOff() {
        signalLockNow()
        post { it.onDeviceEvent(DeviceEventFfi.SCREEN_LOCKED) }
    }
}
