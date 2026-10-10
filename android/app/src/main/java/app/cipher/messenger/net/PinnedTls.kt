package app.cipher.messenger.net

import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/**
 * THE ONLY place in the app that touches TLS trust. It exists for one purpose: relays that are named by a descriptor carrying a certificate pin
 * (docs/MULTI_RELAY_PROTOCOL.md §2, docs/SELF_HOSTING.md "Trust model for onion relays"). A `.onion` relay cannot have a CA-issued certificate, so
 * for exactly those hosts the server's public key must hash to the pin that came with the invitation. Everything else is unchanged:
 *
 *  - a host WITHOUT a pin is validated by the platform's own trust manager (system trust anchors, chain, dates) — this class delegates untouched;
 *  - a host WITH a pin is accepted only if the leaf certificate is currently valid AND SHA-256(SubjectPublicKeyInfo) equals the pin; no CA chain is
 *    consulted for it. Host-name verification still runs afterwards (OkHttp's default verifier checks the certificate's SAN against the host);
 *  - a pin can be registered once per host: a second, different pin for the same host is refused (a relay cannot be re-pointed at another key);
 *  - TLS 1.3 only, no cleartext, no "trust all" path exists. The pin set is empty until the Rust core asks for a pin.
 *
 * `android_guards.rs` bans these APIs everywhere else and checks the shape of this file.
 */
class RelayPins {
    private val pins = ConcurrentHashMap<String, ByteArray>()

    /** `base` is `https://host[:port]`. Returns false (and changes nothing) if the host already has a different pin or the input is malformed. */
    fun register(base: String, spkiSha256: ByteArray): Boolean {
        if (spkiSha256.size != 32) return false
        val host = hostOf(base) ?: return false
        val prev = pins.putIfAbsent(host, spkiSha256.copyOf())
        return prev == null || MessageDigest.isEqual(prev, spkiSha256)
    }

    fun forHost(host: String?): ByteArray? = host?.lowercase()?.let { pins[it] }

    companion object {
        fun hostOf(base: String): String? {
            val rest = base.removePrefix("https://")
            if (rest == base || rest.isEmpty() || rest.any { it == '/' || it == '@' || it == '?' || it == '#' }) return null
            return rest.substringBefore(':').lowercase().ifEmpty { null }
        }
    }
}

internal class PinningTrustManager(
    private val platform: X509ExtendedTrustManager,
    private val pins: RelayPins,
) : X509ExtendedTrustManager() {

    private fun pinnedCheck(chain: Array<X509Certificate>?, pin: ByteArray) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("empty certificate chain")
        leaf.checkValidity() // throws if expired / not yet valid
        val spki = MessageDigest.getInstance("SHA-256").digest(leaf.publicKey.encoded)
        if (!MessageDigest.isEqual(spki, pin)) throw CertificateException("relay certificate does not match the pinned key")
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, socket: Socket?) {
        val host = (socket as? SSLSocket)?.handshakeSession?.peerHost
        val pin = pins.forHost(host)
        if (pin != null) pinnedCheck(chain, pin) else platform.checkServerTrusted(chain, authType, socket)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) {
        val pin = pins.forHost(engine?.handshakeSession?.peerHost)
        if (pin != null) pinnedCheck(chain, pin) else platform.checkServerTrusted(chain, authType, engine)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        // Without a socket the host is unknown: never a pinned path, so only the platform's validation can accept.
        platform.checkServerTrusted(chain, authType)
    }

    // This app never acts as a TLS server and never asks for client certificates.
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, socket: Socket?) = throw CertificateException("client auth unsupported")
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?, engine: SSLEngine?) = throw CertificateException("client auth unsupported")
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) = throw CertificateException("client auth unsupported")

    override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers
}

/** Builds the socket factory + trust manager OkHttp needs, wrapping the platform default. */
class PinnedTls(val pins: RelayPins = RelayPins()) {
    internal val trustManager: X509TrustManager
    val socketFactory: SSLSocketFactory

    init {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val platform = tmf.trustManagers.filterIsInstance<X509ExtendedTrustManager>().firstOrNull()
            ?: error("platform trust manager unavailable") // fail closed: no fallback to an accept-all manager
        trustManager = PinningTrustManager(platform, pins)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(trustManager), null)
        socketFactory = ctx.socketFactory
    }
}
