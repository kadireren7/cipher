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

    /** Loopback address the pluggable-transport helpers listen on (inside the :tor process). */
    private const val PT_HOST = "127.0.0.1"

    /**
     * The control channel is a private socket inside the app's own data directory; no TCP ControlPort is ever opened.
     *
     * [transportPorts] maps a pluggable transport name (obfs4, webtunnel, snowflake, meek_lite) to the loopback SOCKS port its helper listens on. A
     * bridge whose transport has no helper port is left out instead of being written as a line Tor cannot use (Tor would refuse to start).
     */
    fun torrc(bridges: List<String>, debugLogFile: String? = null, transportPorts: Map<String, Int> = emptyMap()): String = buildString {
        appendLine("SocksPort $SOCKS_HOST:$SOCKS_PORT IsolateSOCKSAuth")
        appendLine("ClientOnly 1")
        // The library's own defaults also open an HTTP tunnel on 127.0.0.1:8118. Cipher does not use it and no other app on the phone may borrow
        // our Tor, so it is switched off explicitly (a value in the torrc overrides the defaults file).
        appendLine("HTTPTunnelPort 0")
        appendLine("SafeLogging 1")
        appendLine("AvoidDiskWrites 1")
        // Debug builds only (the caller passes null in release): Tor's own notices to a private file, for diagnosing a device. SafeLogging stays on.
        if (debugLogFile != null && debugLogFile.none { it == '\n' || it == '\r' }) appendLine("Log notice file $debugLogFile")
        val ports = transportPorts.filter { (name, port) -> name in TRANSPORTS && port in 1..65535 }
        val usable = bridges.filter { b -> transportOf(b)?.let { it in ports } ?: true }
        if (usable.isNotEmpty()) {
            appendLine("UseBridges 1")
            usable.mapNotNull {
                transportOf(it)
            }.distinct().forEach { t -> appendLine("ClientTransportPlugin $t socks5 $PT_HOST:${ports.getValue(t)}") }
            usable.forEach { appendLine("Bridge $it") }
        }
    }

    /** Pluggable transports the shipped helper (IPtProxy: lyrebird + snowflake) provides. */
    val TRANSPORTS = setOf("obfs4", "webtunnel", "snowflake", "meek_lite")

    /** The transport a bridge line needs, or null for a plain bridge. */
    fun transportOf(line: String): String? = line.substringBefore(' ').takeIf { it in TRANSPORTS }

    private const val IPV4 = """(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"""
    private const val IPV6 = """\[[0-9A-Fa-f:]{2,39}]"""
    private const val ADDR = """(?:$IPV4|$IPV6):(?:[1-9]\d{0,4})"""
    private val PLAIN_BRIDGE = Regex("""^$ADDR(?: [0-9A-Fa-f]{40})?$""")

    /**
     * `transport IP:port [FINGERPRINT] key=value ...`. Values use a restricted character set (no spaces, quotes, `#` or control characters) and the
     * match is whole-string, so a bridge stays ONE torrc line and can never carry a second directive.
     */
    private val TRANSPORT_BRIDGE =
        Regex(
            """^(?:obfs4|webtunnel|snowflake|meek_lite) $ADDR(?: [0-9A-Fa-f]{40})?(?: [A-Za-z0-9_-]{1,32}=[A-Za-z0-9+/=:,._~%?&@-]{1,1024})*$"""
        )

    /** Maximum number of bridge lines; more is never useful and only grows the attack surface of the config. */
    const val MAX_BRIDGES = 8

    /**
     * Accepts plain bridges (`IP:port [FINGERPRINT]`) and pluggable-transport bridges as bridges.torproject.org hands them out (obfs4, webtunnel,
     * snowflake, meek_lite), with or without a leading `Bridge `. Anything else is refused, never silently ignored. Single-line, whole-string match.
     */
    fun parseBridge(line: String): String? {
        if (line.any { it == '\n' || it == '\r' || it == '\u0000' }) return null
        val t = line.replace('\t', ' ').trim().removePrefix("Bridge ").trim().replace(Regex(" {2,}"), " ")
        if (!PLAIN_BRIDGE.matches(t) && !TRANSPORT_BRIDGE.matches(t)) return null
        val addr = if (transportOf(t) != null) t.split(' ')[1] else t.substringBefore(' ')
        val port = addr.substringAfterLast(':').toIntOrNull() ?: return null
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

/**
 * How the embedded daemon reaches the Tor network.
 *
 * [AUTO] is the default: it tries a direct connection first and, if the network blocks it (no real progress within [TorPlan.DIRECT_PATIENCE_MS]),
 * switches to the built-in bridges by itself and remembers that choice. Many networks (for example ISPs that filter Tor with DPI) never let a plain
 * Tor connection finish its handshake, which used to look like "Connecting to Tor 0%" forever.
 */
enum class TorMode {
    AUTO,
    DIRECT,
    BUILTIN_BRIDGES,
    CUSTOM_BRIDGES;

    companion object {
        fun parse(s: String?): TorMode = entries.firstOrNull { it.name == s?.trim() } ?: AUTO
    }
}

/**
 * The public default bridges that Tor Browser ships (tor-browser-build `pt_config.json`, fetched 2026-11-08). Snowflake first: it goes through a
 * CDN and WebRTC peers, so it works on most filtered networks; the obfs4 bridges are the fallback. Tor uses whichever answers.
 */
object BuiltinBridges {
    private const val SNOWFLAKE_ARGS =
        "url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com " +
            "ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478," +
            "stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 " +
            "utls-imitate=hellorandomizedalpn"

    /** Broker settings the snowflake helper also gets directly (in case a helper version ignores the per-bridge arguments). */
    const val SNOWFLAKE_BROKER = "https://1098762253.rsc.cdn77.org/"
    const val SNOWFLAKE_FRONTS = "app.datapacket.com,www.datapacket.com"
    const val SNOWFLAKE_ICE =
        "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478," +
            "stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478"

    val SNOWFLAKE = listOf(
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 $SNOWFLAKE_ARGS",
        "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA $SNOWFLAKE_ARGS",
    )

    val OBFS4 = listOf(
        "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
        "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
        "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
        "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
        "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
        "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
    )

    val ALL: List<String> = SNOWFLAKE + OBFS4
}

/**
 * Pure decision logic for [TorMode.AUTO] (unit-tested). An attempt is either direct (no bridges) or through the built-in bridges.
 */
object TorPlan {
    /** A direct attempt that has not reached [DIRECT_MIN_PROGRESS] after this long is treated as blocked. */
    const val DIRECT_PATIENCE_MS = 40_000L

    /** Bootstrap 0-15% is "connecting / handshaking with the first relay"; a DPI block stalls exactly there. */
    const val DIRECT_MIN_PROGRESS = 20

    /**
     * Bridges (snowflake in particular: it waits for a volunteer proxy, measured from 10 s to 3 min on the same network) are slower to start. A
     * bridge attempt still below [DIRECT_MIN_PROGRESS] after this long makes the next attempt direct again...
     */
    const val BRIDGE_PATIENCE_MS = 150_000L

    /** ...and one that is making progress gets until this before it is abandoned. */
    const val BRIDGE_MAX_MS = 300_000L

    /** Bridge lines for one attempt: empty means a direct connection. */
    fun bridgesFor(mode: TorMode, custom: List<String>, autoUsesBridges: Boolean): List<String> = when (mode) {
        TorMode.DIRECT -> emptyList()
        TorMode.BUILTIN_BRIDGES -> BuiltinBridges.ALL
        TorMode.CUSTOM_BRIDGES -> custom.ifEmpty { BuiltinBridges.ALL }
        TorMode.AUTO -> if (autoUsesBridges) BuiltinBridges.ALL else emptyList()
    }

    /**
     * In AUTO, whether the running attempt should be abandoned for the other kind. Returns the new value of "auto uses bridges", or null to keep
     * waiting. [progress] is null while the daemon has not reported yet.
     */
    fun autoSwitch(usingBridges: Boolean, progress: Int?, elapsedMs: Long): Boolean? {
        val p = progress ?: 0
        if (p >= 100) return null
        return when {
            !usingBridges && elapsedMs >= DIRECT_PATIENCE_MS && p < DIRECT_MIN_PROGRESS -> true
            usingBridges && elapsedMs >= BRIDGE_PATIENCE_MS && p < DIRECT_MIN_PROGRESS -> false
            usingBridges && elapsedMs >= BRIDGE_MAX_MS -> false
            else -> null
        }
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
