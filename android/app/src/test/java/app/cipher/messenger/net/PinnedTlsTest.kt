package app.cipher.messenger.net

import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.security.KeyStore
import java.security.MessageDigest
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlin.concurrent.thread
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.TlsVersion
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * REAL TLS 1.3 handshakes against a self-signed server, through the app's pinning component and OkHttp's default host-name verifier. The certificate is
 * generated with `keytool` at test time, so no key material is committed. Everything that must fail does so closed: there is no code path that continues.
 */
class PinnedTlsTest {
    private val dir = File.createTempFile("pin", "").apply {
        delete()
        mkdirs()
    }
    private val servers = mutableListOf<SSLServerSocket>()

    @After fun stop() {
        servers.forEach { runCatching { it.close() } }
        dir.deleteRecursively()
    }

    private class Server(val port: Int, val pin: ByteArray)

    private fun server(validityDays: Int = 2, startOffset: String = "-1d", san: String = "dns:localhost"): Server {
        val ks = File(dir, "ks-${servers.size}.p12")
        val keytool = File(System.getProperty("java.home"), "bin/keytool").absolutePath
        val p = ProcessBuilder(
            keytool, "-genkeypair", "-alias", "s", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost", "-ext", "san=$san",
            "-validity", validityDays.toString(), "-startdate", startOffset, "-storetype", "PKCS12", "-keystore", ks.absolutePath,
            "-storepass", "changeit",
        ).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertEquals(out, 0, p.waitFor())
        val store = KeyStore.getInstance("PKCS12").apply { ks.inputStream().use { load(it, "changeit".toCharArray()) } }
        val pin = MessageDigest.getInstance("SHA-256").digest(store.getCertificate("s").publicKey.encoded)
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "changeit".toCharArray()) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        val ss = ctx.serverSocketFactory.createServerSocket(0, 10, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        ss.enabledProtocols = arrayOf("TLSv1.3")
        servers += ss
        thread(isDaemon = true) {
            while (!ss.isClosed) {
                try {
                    ss.accept().use { c ->
                        val r = c.getInputStream().bufferedReader()
                        while (true) if (r.readLine().isNullOrEmpty()) break
                        c.getOutputStream().apply {
                            write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toByteArray())
                            flush()
                        }
                    }
                } catch (_: IOException) {
                }
            }
        }
        return Server(ss.localPort, pin)
    }

    private fun client(tls: PinnedTls) = OkHttpClient.Builder()
        .sslSocketFactory(tls.socketFactory, tls.trustManager)
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS).tlsVersions(TlsVersion.TLS_1_3).build()))
        .protocols(listOf(Protocol.HTTP_1_1))
        .retryOnConnectionFailure(false)
        .build()

    private fun get(c: OkHttpClient, url: String): String = c.newCall(Request.Builder().url(url).build()).execute().use { it.body.string() }

    private fun assertRefused(c: OkHttpClient, url: String, why: String) {
        try {
            get(c, url)
            fail("must be refused: $why")
        } catch (e: IOException) {
            // refused: TLS failure of some kind, never a response
        }
    }

    @Test fun theCorrectPinIsAcceptedOverRealTls13() {
        val s = server()
        val tls = PinnedTls()
        assertTrue(tls.pins.register("https://localhost:${s.port}", s.pin))
        assertEquals("ok", get(client(tls), "https://localhost:${s.port}/"))
    }

    @Test fun aWrongPinIsRefused() {
        val s = server()
        val tls = PinnedTls()
        assertTrue(tls.pins.register("https://localhost:${s.port}", ByteArray(32) { 7 }))
        assertRefused(client(tls), "https://localhost:${s.port}/", "wrong pin")
    }

    @Test fun withoutAPinASelfSignedServerIsRefusedByThePlatformTrustManager() {
        val s = server()
        assertRefused(client(PinnedTls()), "https://localhost:${s.port}/", "self-signed, no pin")
    }

    @Test fun aPinOnlyAppliesToTheRelayItWasRegisteredFor() {
        val a = server()
        val b = server()
        val tls = PinnedTls()
        assertTrue(tls.pins.register("https://localhost:${a.port}", a.pin))
        assertEquals("ok", get(client(tls), "https://localhost:${a.port}/"))
        assertRefused(client(tls), "https://localhost:${b.port}/", "a second relay on the same host has no pin")
        // and a pin copied to the wrong port does not make a different key acceptable
        assertTrue(tls.pins.register("https://localhost:${b.port}", a.pin))
        assertRefused(client(tls), "https://localhost:${b.port}/", "b's key differs from the pin registered for b")
    }

    @Test fun anExpiredCertificateIsRefusedEvenWithTheRightPin() {
        val s = server(validityDays = 1, startOffset = "-5d")
        val tls = PinnedTls()
        assertTrue(tls.pins.register("https://localhost:${s.port}", s.pin))
        assertRefused(client(tls), "https://localhost:${s.port}/", "expired")
    }

    @Test fun theHostNameIsStillVerifiedAfterAPinMatches() {
        val s = server(san = "dns:localhost") // no IP SAN
        val tls = PinnedTls()
        assertTrue(tls.pins.register("https://127.0.0.1:${s.port}", s.pin))
        assertRefused(client(tls), "https://127.0.0.1:${s.port}/", "pin matches but the certificate does not name the host")
    }

    @Test fun aRelayCannotBeRePinnedToADifferentKey() {
        val tls = PinnedTls()
        val pin = ByteArray(32) { 1 }
        assertTrue(tls.pins.register("https://relay.example.org:8443", pin))
        assertTrue("same pin again is fine", tls.pins.register("https://relay.example.org:8443", pin.copyOf()))
        assertFalse(tls.pins.register("https://relay.example.org:8443", ByteArray(32) { 2 }))
        assertFalse(tls.pins.register("https://relay.example.org:8443/x", pin))
        assertFalse(tls.pins.register("http://relay.example.org", pin))
        assertFalse(tls.pins.register("https://relay.example.org", ByteArray(31)))
        // default port is explicit 443
        assertTrue(tls.pins.register("https://other.example.org", pin))
        assertFalse(tls.pins.register("https://other.example.org:443", ByteArray(32) { 3 }))
    }
}
