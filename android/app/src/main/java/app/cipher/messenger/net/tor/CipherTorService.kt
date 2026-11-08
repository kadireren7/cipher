package app.cipher.messenger.net.tor

import IPtProxy.Controller
import IPtProxy.IPtProxy
import IPtProxy.OnTransportEvents
import android.content.Context
import android.content.Intent
import app.cipher.messenger.BuildConfig
import java.io.File
import org.torproject.jni.TorService

/**
 * The embedded Tor daemon, in its own `:tor` process (declared in the manifest, not exported). The C Tor code therefore never shares an address
 * space with the vault, the engine or the keys; the app talks to it only through the loopback SOCKS port and two small private files.
 *
 * What this subclass adds to the library's [TorService]:
 *  1. Before the daemon starts it reads the attempt's bridge list ([planFile], written by the app), starts the pluggable-transport helpers those
 *     bridges need (IPtProxy: obfs4/webtunnel/snowflake, also in this process), and writes the torrc with their loopback ports.
 *  2. It reports the bootstrap percentage, read from the daemon's own control connection, to [stateFile] which the app polls.
 * Nothing else leaves the process: no log lines, no addresses, no circuit information.
 */
class CipherTorService : TorService() {
    @Volatile private var reporting = false

    private var reporter: Thread? = null

    override fun onCreate() {
        // Must happen before super.onCreate(): that is where the library starts the daemon thread, which reads the torrc.
        // If the helpers cannot be prepared, fall back to a direct torrc (Automatic mode then reports no progress and tries again).
        runCatching { prepareTorrc() }.onFailure { runCatching { writeTorrc(this, emptyList(), emptyMap()) } }
        super.onCreate()
    }

    private fun prepareTorrc() {
        val bridges = readPlan(this)
        val needed = bridges.mapNotNull { TorConfig.transportOf(it) }.toSet()
        val ports = if (needed.isEmpty()) {
            stopTransports()
            emptyMap()
        } else {
            startTransports(this, needed)
        }
        writeTorrc(this, bridges, ports)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val result = super.onStartCommand(intent, flags, startId)
        startReporter()
        return result
    }

    private fun startReporter() {
        if (reporting) return
        reporting = true
        reporter = Thread({
            var last: Int? = null
            while (reporting) {
                val progress = try {
                    TorProgress.fromBootstrapInfo(getInfo("status/bootstrap-phase"))
                } catch (_: Exception) {
                    null // the control connection is not up yet, or the daemon is stopping
                }
                // Before the control connection answers, report "alive, 0%" so the app can tell a starting daemon from a dead one.
                // A transient control-channel hiccup after that keeps the last known value instead of dropping back to 0.
                if (progress != null) last = progress
                writeState(this, TorProgress.encode(last ?: 0, System.currentTimeMillis()))
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
        stopTransports()
    }

    companion object {
        private fun torDir(context: Context): File = File(context.noBackupFilesDir, "tor").apply { mkdirs() }

        /** In the no-backup directory: shared by both processes of this app (same uid), invisible to every other app. */
        fun stateFile(context: Context): File = File(torDir(context), "bootstrap")

        /** Bridge lines for the next start (one per line, already validated by the app); empty or missing = direct connection. */
        fun planFile(context: Context): File = File(torDir(context), "plan")

        private fun readPlan(context: Context): List<String> =
            runCatching { planFile(context).readLines() }.getOrDefault(emptyList()).mapNotNull { TorConfig.parseBridge(it) }.take(
                TorConfig.MAX_BRIDGES * 2
            )

        private fun writeTorrc(context: Context, bridges: List<String>, ports: Map<String, Int>) {
            val torrc = TorService.getTorrc(context)
            torrc.parentFile?.mkdirs()
            val debugLog = if (BuildConfig.DEBUG) File(torDir(context), "tor.log").path else null
            torrc.writeText(TorConfig.torrc(bridges, debugLog, ports))
        }

        /** Atomic replace, so the reader never sees a half-written line. */
        private fun writeState(context: Context, line: String) {
            val target = stateFile(context)
            val tmp = File(target.parentFile, "bootstrap.tmp")
            tmp.writeText(line)
            if (!tmp.renameTo(target)) tmp.delete()
        }

        // One helper controller per :tor process; the daemon can be stopped and started again in the same process.
        private var controller: Controller? = null
        private val running = mutableSetOf<String>()

        @Synchronized
        private fun startTransports(context: Context, needed: Set<String>): Map<String, Int> {
            val c = controller ?: Controller(
                File(torDir(context), "pt").apply { mkdirs() }.path,
                BuildConfig.DEBUG, // debug builds write the helpers' own log (ipt.log) next to tor.log
                false, // never log addresses
                "INFO",
                object : OnTransportEvents {
                    override fun connected(transport: String?) {}

                    override fun error(transport: String?, e: Exception?) {}

                    override fun stopped(transport: String?, e: Exception?) {}
                },
            ).also { controller = it }
            if (IPtProxy.Snowflake in needed) {
                c.snowflakeBrokerUrl = BuiltinBridges.SNOWFLAKE_BROKER
                c.snowflakeFrontDomains = BuiltinBridges.SNOWFLAKE_FRONTS
                c.snowflakeIceServers = BuiltinBridges.SNOWFLAKE_ICE
            }
            (running - needed).forEach { runCatching { c.stop(it) } }
            running.retainAll(needed)
            val ports = mutableMapOf<String, Int>()
            for (t in needed) {
                try {
                    if (t !in running) {
                        c.start(t, "")
                        running += t
                    }
                    c.port(t).toInt().takeIf { it in 1..65535 }?.let { ports[t] = it }
                } catch (_: Exception) {
                    // this transport's bridges are left out of the torrc (TorConfig.torrc drops bridges without a helper port)
                }
            }
            return ports
        }

        @Synchronized
        private fun stopTransports() {
            val c = controller ?: return
            running.forEach { runCatching { c.stop(it) } }
            running.clear()
        }
    }
}
