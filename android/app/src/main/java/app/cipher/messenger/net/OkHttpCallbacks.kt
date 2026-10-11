package app.cipher.messenger.net

import app.cipher.messenger.BuildConfig
import java.io.File
import java.io.IOException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.TlsVersion
import uniffi.cipher_ffi.HttpCallbacks
import uniffi.cipher_ffi.HttpFault
import uniffi.cipher_ffi.HttpReply

/**
 * Privacy-preserving network diagnostics (debug builds only; release builds log nothing). One line per HTTP call: a per-process sequence number, a coarse
 * kind (`api` or `blob`, never a path, id or host), the method, the byte count, the duration, the outcome class and the number of consecutive failures of
 * that kind. No bodies, keys, identities, tokens or URLs. Retries are visible as consecutive `fail` lines with a growing `failsInRow`.
 */
internal object NetDiag {
    private val seq = java.util.concurrent.atomic.AtomicLong()
    private val failsInRow = java.util.concurrent.ConcurrentHashMap<String, Int>()

    fun kind(pathAndQuery: String) = if (pathAndQuery.startsWith("/v1/blobs")) "blob" else "api"

    fun <T> track(kind: String, method: String, bytes: Long, timeoutS: Long, block: () -> T): T {
        val id = seq.incrementAndGet()
        val t0 = System.nanoTime()
        var outcome = "ok"
        try {
            return block()
        } catch (e: HttpFault) {
            outcome = e.javaClass.simpleName.lowercase()
            throw e
        } catch (e: Throwable) {
            outcome = "error"
            throw e
        } finally {
            val ms = (System.nanoTime() - t0) / 1_000_000
            val n = if (outcome == "ok") 0.also { failsInRow[kind] = 0 } else failsInRow.merge(kind, 1, Int::plus) ?: 1
            if (BuildConfig.DEBUG) {
                android.util.Log.i("CipherNet", "req=$id kind=$kind method=$method bytes=$bytes limitS=$timeoutS ms=$ms " +
                        "outcome=$outcome failsInRow=$n")
            }
        }
    }

    /**
     * Whole-call deadline: 120 s for the connection (a Tor rendezvous can take that long) plus the time the body needs at a floor of 8 KB/s, at most 5 minutes.
     * A congested circuit that trickles bytes never trips the 60 s read/write idle timeouts, so without this a 700 KB upload could hold a call for minutes.
     */
    fun callLimitSeconds(bytes: Long): Long = (120 + bytes / 8_192).coerceIn(120, 300)
}

/**
 * The only network stack. Policy, all enforced by construction:
 *  - TLS 1.3 ONLY (`ConnectionSpec` below); cleartext is not in the connection-spec list, so `http://` cannot even be attempted;
 *  - platform trust anchors only. The single exception is [PinnedTls] (certificate-pinned relays, e.g. onion services): there the server key must hash
 *    to the pin from the invitation; for every other host the platform trust manager decides. No HostnameVerifier, no "accept invalid certificate" path;
 *  - HTTP/1.1, no redirects (a relay never legitimately redirects; following one could leak signed headers);
 *  - optional SPKI certificate pinning (`pins`), empty by default (SECURITY TODO ST-002: needs the operator's pin + backup pin).
 *
 * Bodies are protocol ciphertext or signed requests produced by the Rust core; this class never sees plaintext or keys.
 */
class OkHttpCallbacks(
    private val route: RouteConfig,
    private val tracker: RouteTracker,
    pins: List<Pair<String, String>> = emptyList(),
    private val pinnedTls: PinnedTls = PinnedTls(),
) : HttpCallbacks {
    private val tls13Only: ConnectionSpec = ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
        .tlsVersions(TlsVersion.TLS_1_3)
        .build()

    private val client: OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(pinnedTls.socketFactory, pinnedTls.trustManager)
        .connectionSpecs(listOf(tls13Only))
        .protocols(listOf(Protocol.HTTP_1_1))
        .followRedirects(false)
        .followSslRedirects(false)
        // Through the SOCKS proxy the handshake includes building a Tor circuit (onion services: rendezvous). Typical 10-30 s; CI logs show Tor itself abandoning
        // stalled circuits after ~60 s and retrying, so a shorter limit would cut off a retry that is about to succeed. Still fail-closed: no fallback route.
        .connectTimeout(if (route.directDevRoute()) 10 else 120, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.MINUTES)
        .apply {
            if (route.directDevRoute()) {
                DirectDevRoute.configure(this) // debug builds with the explicit marker only
            } else {
                // PRIVACY ROUTE (the only route in release): fixed SOCKS5 proxy, hostnames are resolved by the proxy, no DIRECT, no fallback.
                val proxy = route.socks().toProxy()
                proxy(proxy)
                proxySelector(FixedProxySelector(proxy))
                dns(NoDns)
            }
        }
        .apply {
            if (pins.isNotEmpty()) {
                val b = CertificatePinner.Builder()
                pins.forEach { (host, pin) -> b.add(host, pin) }
                certificatePinner(b.build())
            }
        }
        .build()

    /** The core asks that `baseUrl` be authenticated by this key (SHA-256 of its SubjectPublicKeyInfo, unpadded base64url) instead of by a CA chain. */
    override fun pinRelay(baseUrl: String, spkiSha256B64: String) {
        val pin = try {
            java.util.Base64.getUrlDecoder().decode(spkiSha256B64)
        } catch (e: IllegalArgumentException) {
            throw HttpFault.Tls()
        }
        if (!pinnedTls.pins.register(baseUrl, pin)) throw HttpFault.Tls() // malformed, or the host is already pinned to a DIFFERENT key
    }

    /** Cancels every running and queued call (used when the app is about to lock: an in-flight transfer must not keep keys alive). */
    fun cancelAll() = client.dispatcher.cancelAll()

    private fun request(base: String, path: String, auth: String?, method: String, body: RequestBody?): Request {
        require(base.startsWith("https://")) { "https required" }
        val b = Request.Builder().url(base + path)
        if (auth != null) b.header("Authorization", auth)
        return b.method(method, body).build()
    }

    private fun fault(e: IOException): HttpFault {
        tracker.recordFailure()
        return when (e) {
            is SSLException -> HttpFault.Tls()
            // The proxy refused/was unreachable, or spoke malformed SOCKS: the privacy route is unavailable. The message stays queued; nothing else is tried.
            is java.net.ConnectException, is java.net.NoRouteToHostException, is java.net.SocketException -> HttpFault.RouteUnavailable()
            is SocketTimeoutException -> HttpFault.Timeout()
            is java.net.UnknownHostException -> HttpFault.Network()
            else -> HttpFault.Io()
        }
    }

    /** One call with its own deadline (see [NetDiag.callLimitSeconds]); `okhttp3.Call.timeout` overrides the client-wide 5 minutes for this call only. */
    private fun call(req: Request, bytes: Long): okhttp3.Call =
        client.newCall(req).also { it.timeout().timeout(NetDiag.callLimitSeconds(bytes), TimeUnit.SECONDS) }

    override fun execute(baseUrl: String, method: String, pathAndQuery: String, authorization: String?, body: ByteArray): HttpReply {
        val rb = if (method == "GET") null else body.toRequestBody("application/octet-stream".toMediaType())
        return NetDiag.track(NetDiag.kind(pathAndQuery), method, body.size.toLong(), NetDiag.callLimitSeconds(body.size.toLong())) {
            try {
                call(request(baseUrl, pathAndQuery, authorization, method, rb), body.size.toLong()).execute().use { r ->
                    val bytes = r.body.bytes()
                    tracker.recordSuccess()
                    HttpReply(status = r.code.toUShort(), body = bytes)
                }
            } catch (e: IOException) {
                throw fault(e)
            } catch (e: IllegalArgumentException) {
                throw HttpFault.Io()
            }
        }
    }

    override fun uploadFile(baseUrl: String, pathAndQuery: String, authorization: String?, filePath: String): HttpReply {
        val file = File(filePath)
        val size = file.length()
        return NetDiag.track("blob", "POST", size, NetDiag.callLimitSeconds(size)) {
            try {
                val rb = file.asRequestBody("application/octet-stream".toMediaType())
                call(request(baseUrl, pathAndQuery, authorization, "POST", rb), size).execute().use { r ->
                    tracker.recordSuccess()
                    HttpReply(status = r.code.toUShort(), body = r.body.bytes())
                }
            } catch (e: IOException) {
                throw fault(e)
            } catch (e: IllegalArgumentException) {
                throw HttpFault.Io()
            }
        }
    }

    override fun downloadFile(baseUrl: String, pathAndQuery: String, authorization: String?, destPath: String, maxBytes: ULong): UShort {
        val limit = maxBytes.toLong().coerceAtLeast(0)
        return NetDiag.track("blob", "GET", limit, NetDiag.callLimitSeconds(limit)) {
            try {
                call(request(baseUrl, pathAndQuery, authorization, "GET", null), limit).execute().use { r ->
                    if (r.code == 200) {
                        var total = 0L
                        File(destPath).outputStream().use { out ->
                            r.body.byteStream().use { input ->
                                val buf = ByteArray(64 * 1024)
                                while (true) {
                                    val n = input.read(buf)
                                    if (n < 0) break
                                    total += n
                                    if (total.toULong() > maxBytes) throw HttpFault.Io() // never write more than the descriptor allows
                                    out.write(buf, 0, n)
                                }
                            }
                        }
                    }
                    tracker.recordSuccess()
                    r.code.toUShort()
                }
            } catch (e: IOException) {
                throw fault(e)
            } catch (e: IllegalArgumentException) {
                throw HttpFault.Io()
            }
        }
    }
}
