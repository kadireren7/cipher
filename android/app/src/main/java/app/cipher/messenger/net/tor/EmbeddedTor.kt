package app.cipher.messenger.net.tor

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.io.File
import org.torproject.jni.TorService

/**
 * Starts and stops the embedded Tor daemon ([CipherTorService], `:tor` process), chooses how it connects ([TorMode]) and reports its bootstrap
 * progress. App process only.
 *
 * Lifecycle (Android background limits): Tor runs while Cipher is in the foreground and for [GRACE_MS] after it leaves it, then it is stopped. Cipher
 * never holds a wake lock, never asks for a battery exemption and never runs a foreground service to keep Tor alive: with the app in the background
 * messages wait (encrypted) on the relay and in the outbox, exactly as without push (docs/NOTIFICATIONS.md).
 *
 * Censorship: in [TorMode.AUTO] (the default) a direct attempt that makes no real progress is replaced by one through the built-in bridges
 * (snowflake, obfs4), and the outcome is remembered so the next start goes the working way at once ([TorPlan]).
 *
 * Fail closed: this class only decides whether and how the daemon runs. The route is still the one fixed loopback SOCKS port; when the daemon is not
 * up the connection to that port is refused and every request fails with `RouteUnavailable`. No other route exists.
 */
class EmbeddedTor(private val context: Context, private val bridgesFile: File) {
    private val handler = Handler(Looper.getMainLooper())
    private val stopLater = Runnable { stop() }
    private val modeFile = File(bridgesFile.parentFile, "tor.mode")
    private val autoBridgesFile = File(bridgesFile.parentFile, "tor.auto_bridges")

    @Volatile private var running = false

    @Volatile private var attemptStartedAt = 0L

    @Volatile private var attemptUsesBridges = false

    private val supervisor = object : Runnable {
        override fun run() {
            if (!running) return
            if (mode() == TorMode.AUTO) {
                val p = progress()
                if (p == 100 && attemptUsesBridges != autoUsesBridges()) setAutoUsesBridges(attemptUsesBridges)
                TorPlan.autoSwitch(attemptUsesBridges, p, SystemClock.elapsedRealtime() - attemptStartedAt)?.let { useBridges ->
                    setAutoUsesBridges(useBridges)
                    restart()
                    return
                }
            }
            handler.postDelayed(this, 2_000)
        }
    }

    /** Bootstrap percentage (0..100) while the daemon is alive and reporting, null otherwise. */
    fun progress(nowMs: Long = System.currentTimeMillis()): Int? =
        TorProgress.decode(runCatching { CipherTorService.stateFile(context).readText() }.getOrNull(), nowMs)

    /** True while the running attempt goes through bridges (built-in or the user's), for the UI. */
    fun usingBridges(): Boolean = running && attemptUsesBridges

    fun mode(): TorMode = TorMode.parse(runCatching { modeFile.readText() }.getOrNull())

    fun setMode(mode: TorMode) {
        modeFile.parentFile?.mkdirs()
        modeFile.writeText(mode.name)
        if (running) restart()
    }

    fun bridges(): List<String> = runCatching { TorConfig.parseBridges(bridgesFile.readText()) }.getOrNull() ?: emptyList()

    /** Stores a validated bridge list (empty = no bridges). Returns false, changing nothing, if any line is not a supported bridge. */
    fun setBridges(block: String): Boolean {
        val parsed = TorConfig.parseBridges(block) ?: return false
        bridgesFile.parentFile?.mkdirs()
        bridgesFile.writeText(parsed.joinToString("\n"))
        if (running) restart()
        return true
    }

    /** Saves the user's bridges and switches to them in one step (an empty list keeps the built-in bridges as the custom fallback). */
    fun useCustomBridges(block: String): Boolean {
        val parsed = TorConfig.parseBridges(block) ?: return false
        bridgesFile.parentFile?.mkdirs()
        bridgesFile.writeText(parsed.joinToString("\n"))
        setMode(if (parsed.isEmpty()) TorMode.BUILTIN_BRIDGES else TorMode.CUSTOM_BRIDGES)
        if (!running) start()
        return true
    }

    private fun autoUsesBridges(): Boolean = autoBridgesFile.exists()

    private fun setAutoUsesBridges(v: Boolean) {
        runCatching { if (v) autoBridgesFile.writeText("1") else autoBridgesFile.delete() }
    }

    @Synchronized
    fun start() {
        handler.removeCallbacks(stopLater)
        if (running) return
        val plan = TorPlan.bridgesFor(mode(), bridges(), autoUsesBridges())
        CipherTorService.planFile(context).writeText(plan.joinToString("\n"))
        // The service writes the real torrc (it knows the transport helpers' ports); this one is only a safe direct default.
        val torrc = TorService.getTorrc(context)
        torrc.parentFile?.mkdirs()
        torrc.writeText(TorConfig.torrc(emptyList()))
        running = true
        attemptUsesBridges = plan.isNotEmpty()
        attemptStartedAt = SystemClock.elapsedRealtime()
        context.startService(Intent(context, CipherTorService::class.java).setAction(TorService.ACTION_START))
        handler.removeCallbacks(supervisor)
        handler.postDelayed(supervisor, 2_000)
    }

    @Synchronized
    fun stop() {
        handler.removeCallbacks(stopLater)
        handler.removeCallbacks(supervisor)
        if (!running) return
        running = false
        context.stopService(Intent(context, CipherTorService::class.java))
    }

    /** Stops and starts again with the current mode (also the "Try again" action when Tor does not connect). */
    fun restart() {
        stop()
        handler.postDelayed({ start() }, 1_500)
    }

    /** The app left the foreground: keep Tor for a short grace period (an upload or a quick app switch), then stop it. */
    fun onBackground() {
        handler.removeCallbacks(stopLater)
        handler.postDelayed(stopLater, GRACE_MS)
    }

    companion object {
        const val GRACE_MS = 5 * 60_000L
    }
}
