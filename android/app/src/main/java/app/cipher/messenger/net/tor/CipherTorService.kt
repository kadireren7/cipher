package app.cipher.messenger.net.tor

import android.content.Context
import android.content.Intent
import java.io.File
import org.torproject.jni.TorService

/**
 * The embedded Tor daemon, in its own `:tor` process (declared in the manifest, not exported). The C Tor code therefore never shares an address
 * space with the vault, the engine or the keys; the app talks to it only through the loopback SOCKS port and a one-line progress file.
 *
 * This subclass adds exactly one thing to the library's [TorService]: it reports the bootstrap percentage. It reads it from the daemon's own control
 * connection (which only exists inside this process) and writes it, with a timestamp, to a private file the app polls. Nothing else leaves the process:
 * no log lines, no addresses, no circuit information.
 */
class CipherTorService : TorService() {
    @Volatile private var reporting = false

    private var reporter: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val result = super.onStartCommand(intent, flags, startId)
        startReporter()
        return result
    }

    private fun startReporter() {
        if (reporting) return
        reporting = true
        reporter = Thread({
            while (reporting) {
                val progress = try {
                    TorProgress.fromBootstrapInfo(getInfo("status/bootstrap-phase"))
                } catch (_: Exception) {
                    null // the control connection is not up yet, or the daemon is stopping
                }
                if (progress != null) writeState(this, TorProgress.encode(progress, System.currentTimeMillis()))
                try {
                    Thread.sleep(1_000)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "cipher-tor-progress").apply {
            isDaemon = true
            start()
        }
    }

    override fun onDestroy() {
        reporting = false
        reporter?.interrupt()
        runCatching { stateFile(this).delete() }
        super.onDestroy()
    }

    companion object {
        /** In the no-backup directory: shared by both processes of this app (same uid), invisible to every other app. */
        fun stateFile(context: Context): File = File(File(context.noBackupFilesDir, "tor").apply { mkdirs() }, "bootstrap")

        /** Atomic replace, so the reader never sees a half-written line. */
        private fun writeState(context: Context, line: String) {
            val target = stateFile(context)
            val tmp = File(target.parentFile, "bootstrap.tmp")
            tmp.writeText(line)
            if (!tmp.renameTo(target)) tmp.delete()
        }
    }
}
