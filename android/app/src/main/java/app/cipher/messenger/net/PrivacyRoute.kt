package app.cipher.messenger.net

import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.net.UnknownHostException
import okhttp3.Dns

/**
 * Privacy route (docs/ADR-PRIVACY-TRANSPORT.md): every request to the relay goes through a local SOCKS5 endpoint (Tor — Orbot or an embedded
 * tor — or a compatible proxy). Cipher does NOT implement any anonymity protocol; the proxy is an established, separate component. It is not a
 * trust boundary for message content: everything crossing it is already E2EE ciphertext inside TLS 1.3 to the relay.
 *
 * Fail closed: if the proxy cannot be used the call FAILS ([uniffi.cipher_ffi.HttpFault.RouteUnavailable]) and the encrypted message stays in the
 * outbox. There is no fallback to a direct connection anywhere in this class or in the release build.
 */
data class SocksEndpoint(val ip: String, val port: Int) {
    init {
        require(isIpLiteral(ip)) { "the proxy must be an IP literal (no DNS lookup for the proxy itself)" }
        require(port in 1..65535) { "port" }
    }

    /** Never resolves anything: [ip] is a validated literal. */
    fun toProxy(): Proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(InetAddress.getByName(ip), port))

    override fun toString(): String = "$ip:$port"

    companion object {
        private val V4 = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")

        fun isIpLiteral(s: String): Boolean = V4.matches(s) || s == "::1"

        fun parse(text: String): SocksEndpoint? {
            val i = text.trim().lastIndexOf(':')
            if (i <= 0) return null
            val port = text.substring(i + 1).toIntOrNull() ?: return null
            return runCatching { SocksEndpoint(text.substring(0, i).trim(), port) }.getOrNull()
        }

        /** Orbot / tor default: the loopback address (taken from the JVM, so no developer-style literal sits in the release dex) and port 9050. */
        val DEFAULT = SocksEndpoint(InetAddress.getLoopbackAddress().hostAddress ?: "::1", 9050)
    }
}

/** No name is ever resolved on the device: with a SOCKS proxy OkHttp hands the HOSTNAME to the proxy (remote resolution). This is the backstop. */
object NoDns : Dns {
    override fun lookup(hostname: String): List<InetAddress> =
        throw UnknownHostException("local DNS is disabled: names are resolved by the privacy route")
}

/** One fixed proxy, no system proxy selection, and no DIRECT entry. */
class FixedProxySelector(private val proxy: Proxy) : ProxySelector() {
    override fun select(uri: URI?): List<Proxy> = listOf(proxy)

    override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: java.io.IOException?) = Unit
}

enum class RouteStatus { OFFLINE, CONNECTING, PROTECTED, UNAVAILABLE }

/**
 * What the user is told (PRIV-013): PROTECTED only while a request has actually completed THROUGH the privacy route recently. E2EE being active is
 * never enough.
 */
class RouteTracker(
    private val nowMs: () -> Long,
    private val deviceOnline: () -> Boolean,
    private val freshMs: Long = 120_000,
) {
    @Volatile private var lastOk = Long.MIN_VALUE

    @Volatile private var lastFail = Long.MIN_VALUE

    fun recordSuccess() {
        lastOk = nowMs()
    }

    fun recordFailure() {
        lastFail = nowMs()
    }

    fun status(): RouteStatus {
        val now = nowMs()
        if (lastOk != Long.MIN_VALUE && now - lastOk <= freshMs && lastFail <= lastOk) return RouteStatus.PROTECTED
        if (!deviceOnline()) return RouteStatus.OFFLINE
        if (lastFail != Long.MIN_VALUE && lastFail > lastOk) return RouteStatus.UNAVAILABLE
        return RouteStatus.CONNECTING
    }
}

/** Non-secret route configuration, in the no-backup config directory. */
class RouteConfig(private val dir: File) {
    private val socksFile = File(dir, "route.socks")

    fun socks(): SocksEndpoint = socksFile.takeIf { it.exists() }?.readText()?.let { SocksEndpoint.parse(it) } ?: SocksEndpoint.DEFAULT

    fun setSocks(e: SocksEndpoint) {
        socksFile.writeText(e.toString())
    }

    /** True ONLY in a debug build that also carries the opt-in marker file; always false in release ([DirectDevRoute] is a stub there). */
    fun directDevRoute(): Boolean = DirectDevRoute.enabled(dir)
}
