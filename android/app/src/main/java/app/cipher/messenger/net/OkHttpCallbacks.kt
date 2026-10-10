package app.cipher.messenger.net

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
        .connectTimeout(10, TimeUnit.SECONDS)
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

    override fun execute(baseUrl: String, method: String, pathAndQuery: String, authorization: String?, body: ByteArray): HttpReply {
        val rb = if (method == "GET") null else body.toRequestBody("application/octet-stream".toMediaType())
        try {
            client.newCall(request(baseUrl, pathAndQuery, authorization, method, rb)).execute().use { r ->
                val bytes = r.body.bytes()
                tracker.recordSuccess()
                return HttpReply(status = r.code.toUShort(), body = bytes)
            }
        } catch (e: IOException) {
            throw fault(e)
        } catch (e: IllegalArgumentException) {
            throw HttpFault.Io()
        }
    }

    override fun uploadFile(baseUrl: String, pathAndQuery: String, authorization: String?, filePath: String): HttpReply {
        val file = File(filePath)
        try {
            val rb = file.asRequestBody("application/octet-stream".toMediaType())
            client.newCall(request(baseUrl, pathAndQuery, authorization, "POST", rb)).execute().use { r ->
                tracker.recordSuccess()
                return HttpReply(status = r.code.toUShort(), body = r.body.bytes())
            }
        } catch (e: IOException) {
            throw fault(e)
        } catch (e: IllegalArgumentException) {
            throw HttpFault.Io()
        }
    }

    override fun downloadFile(baseUrl: String, pathAndQuery: String, authorization: String?, destPath: String, maxBytes: ULong): UShort {
        try {
            client.newCall(request(baseUrl, pathAndQuery, authorization, "GET", null)).execute().use { r ->
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
                return r.code.toUShort()
            }
        } catch (e: IOException) {
            throw fault(e)
        } catch (e: IllegalArgumentException) {
            throw HttpFault.Io()
        }
    }
}
