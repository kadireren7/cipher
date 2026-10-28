package app.cipher.messenger.net.tor

/**
 * Embedded Tor configuration. Pure Kotlin so it is unit-testable on the JVM.
 *
 * The daemon is the Guardian Project packaging of the C Tor client (`info.guardianproject:tor-android`), run in its own `:tor` process. Cipher does
 * not implement any anonymity protocol. What this file decides is what the daemon is allowed to be: a client only (never a relay or an exit), with
 * ONE SOCKS listener on the loopback address and nothing else (no DNS port, no HTTP tunnel, no transparent proxy).
 */
object TorConfig {
    /** Loopback only. Deliberately not Orbot's 9050/9150, so the embedded daemon and an external one never collide. */
    const val SOCKS_PORT = 19050

    /**
     * The address the daemon listens on AND the app dials, from one constant so they can never disagree. IPv4 on purpose: the JVM's own
     * "loopback address" can be ::1 on Android, where the daemon is not listening, and the connection would be refused.
     */
    const val SOCKS_HOST = "127.0.0.1"

    /** The control channel is a private socket inside the app's own data directory; no TCP ControlPort is ever opened. */
    fun torrc(bridges: List<String>): String = buildString {
        appendLine("SocksPort $SOCKS_HOST:$SOCKS_PORT IsolateSOCKSAuth")
        appendLine("ClientOnly 1")
        // The library's own defaults also open an HTTP tunnel on 127.0.0.1:8118. Cipher does not use it and no other app on the phone may borrow
        // our Tor, so it is switched off explicitly (a value in the torrc overrides the defaults file).
        appendLine("HTTPTunnelPort 0")
        appendLine("SafeLogging 1")
        appendLine("AvoidDiskWrites 1")
        if (bridges.isNotEmpty()) {
            appendLine("UseBridges 1")
            bridges.forEach { appendLine("Bridge $it") }
        }
    }

    private const val IPV4 = """(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"""
    private const val IPV6 = """\[[0-9A-Fa-f:]{2,39}]"""
    private val PLAIN_BRIDGE = Regex("""^(?:$IPV4|$IPV6):(?:[1-9]\d{0,4})(?: [0-9A-Fa-f]{40})?$""")

    /** Maximum number of bridge lines; more is never useful and only grows the attack surface of the config. */
    const val MAX_BRIDGES = 8

    /**
     * Only PLAIN bridges (`IP:port [FINGERPRINT]`) are accepted. Pluggable transports (obfs4, snowflake, webtunnel) need a separate transport
     * binary that is not shipped, so they are refused instead of being silently ignored. The match is whole-string and single-line: a bridge can
     * never smuggle a second torrc directive (for example a ControlPort) into the file.
     */
    fun parseBridge(line: String): String? {
        val t = line.trim()
        if (t.any { it == '\n' || it == '\r' || it == '\u0000' }) return null
        if (!PLAIN_BRIDGE.matches(t)) return null
        val port = t.substringBefore(' ').substringAfterLast(':').toIntOrNull() ?: return null
        return t.takeIf { port in 1..65535 }
    }

    /** Parses a user-entered block (one bridge per line); null if ANY line is invalid, so nothing is half-applied. */
    fun parseBridges(block: String): List<String>? {
        val lines = block.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.size > MAX_BRIDGES) return null
        val out = lines.map { parseBridge(it) ?: return null }
        return out.distinct()
    }
}

/** Bootstrap progress as the daemon reports it, plus the tiny line protocol used to hand it from the `:tor` process to the app. */
object TorProgress {
    private val PROGRESS = Regex("""PROGRESS=(\d{1,3})""")

    /** `NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY="..."` -> 45; null if the text carries no progress. */
    fun fromBootstrapInfo(
        info: String?
    ): Int? = info?.let { PROGRESS.find(it)?.groupValues?.get(1)?.toIntOrNull() }?.takeIf { it in 0..100 }

    /** `<progress> <epochMillis>` on one line. The timestamp lets the reader tell a live daemon from a stale file left by a dead one. */
    fun encode(progress: Int, nowMs: Long): String = "${progress.coerceIn(0, 100)} $nowMs"

    /** Progress if the line is well-formed AND fresh; null otherwise (daemon not running, or not reporting any more). */
    fun decode(line: String?, nowMs: Long, maxAgeMs: Long = 8_000): Int? {
        val parts = line?.trim()?.split(' ') ?: return null
        if (parts.size != 2) return null
        val p = parts[0].toIntOrNull()?.takeIf { it in 0..100 } ?: return null
        val at = parts[1].toLongOrNull() ?: return null
        return p.takeIf { nowMs - at in -1_000..maxAgeMs }
    }
}
