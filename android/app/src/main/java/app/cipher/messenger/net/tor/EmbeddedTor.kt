package app.cipher.messenger.net.tor

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import java.io.File
import org.torproject.jni.TorService

/**
 * Starts and stops the embedded Tor daemon ([CipherTorService], `:tor` process) and reports its bootstrap progress. App process only.
 *
 * Lifecycle (Android background limits): Tor runs while Cipher is in the foreground and for [GRACE_MS] after it leaves it, then it is stopped. Cipher
 * never holds a wake lock, never asks for a battery exemption and never runs a foreground service to keep Tor alive: with the app in the background
 * messages wait (encrypted) on the relay and in the outbox, exactly as without push (docs/NOTIFICATIONS.md).
 *
 * Fail closed: this class only decides whether the daemon runs. The route is still the one fixed loopback SOCKS port; when the daemon is not up the
 * connection to that port is refused and every request fails with `RouteUnavailable`. No other route exists.
 */
class EmbeddedTor(private val context: Context, private val bridgesFile: File) {
    private val handler = Handler(Looper.getMainLooper())
    private val stopLater = Runnable { stop() }

    @Volatile private var running = false

    /** Bootstrap percentage (0..100) while the daemon is alive and reporting, null otherwise. */
    fun progress(nowMs: Long = System.currentTimeMillis()): Int? =
        TorProgress.decode(runCatching { CipherTorService.stateFile(context).readText() }.getOrNull(), nowMs)

    fun bridges(): List<String> = runCatching { TorConfig.parseBridges(bridgesFile.readText()) }.getOrNull() ?: emptyList()

    /** Stores a validated bridge list (empty = no bridges). Returns false, changing nothing, if any line is not a plain bridge. */
    fun setBridges(block: String): Boolean {
        val parsed = TorConfig.parseBridges(block) ?: return false
        bridgesFile.parentFile?.mkdirs()
        bridgesFile.writeText(parsed.joinToString("\n"))
        if (running) restart()
        return true
    }

    @Synchronized
    fun start() {
        handler.removeCallbacks(stopLater)
        if (running) return
        val torrc = TorService.getTorrc(context)
        torrc.parentFile?.mkdirs()
        torrc.writeText(TorConfig.torrc(bridges()))
        running = true
        context.startService(Intent(context, CipherTorService::class.java).setAction(TorService.ACTION_START))
    }

    @Synchronized
    fun stop() {
        handler.removeCallbacks(stopLater)
        if (!running) return
        running = false
        context.stopService(Intent(context, CipherTorService::class.java))
    }

    private fun restart() {
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
