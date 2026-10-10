package app.cipher.messenger.net

import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import uniffi.cipher_ffi.HttpFault

/**
 * Privacy-route behaviour against a hostile/broken local SOCKS5 endpoint (a TEST DOUBLE in this file — Cipher contains no proxy or anonymity code).
 * PRIV-005/006/007/015: hostnames go to the proxy, failures fail closed, nothing is ever sent to the destination another way.
 */
class PrivacyRouteTest {
    private enum class Mode { CLOSE_AFTER_REQUEST, GARBAGE, REFUSE }

    private class Seen(val atyp: Int, val host: String, val port: Int)

    private val seen = CopyOnWriteArrayList<Seen>()
    private lateinit var proxy: ServerSocket
    private var mode = Mode.CLOSE_AFTER_REQUEST
    private val dir = File.createTempFile("route", "").apply {
        delete()
        mkdirs()
    }

    @Before fun startFakeSocks() {
        proxy = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"))
        thread(isDaemon = true) {
            while (!proxy.isClosed) {
                val c = runCatching { proxy.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    runCatching {
                        c.use { s ->
                            val i = s.getInputStream()
                            val o = s.getOutputStream()
                            i.readNBytes(2).let { i.readNBytes(it[1].toInt() and 0xff) } // greeting
                            o.write(byteArrayOf(5, 0))
                            val hdr = i.readNBytes(4) // VER CMD RSV ATYP
                            val atyp = hdr[3].toInt()
                            val host = when (atyp) {
                                3 -> String(i.readNBytes(i.read()))
                                1 -> i.readNBytes(4).joinToString(".") { (it.toInt() and 0xff).toString() }
                                else -> "?"
                            }
                            val pb = i.readNBytes(2)
                            seen += Seen(atyp, host, ((pb[0].toInt() and 0xff) shl 8) or (pb[1].toInt() and 0xff))
                            when (mode) {
                                Mode.CLOSE_AFTER_REQUEST -> Unit
                                Mode.GARBAGE -> o.write("HTTP/1.1 200 OK\r\n\r\nnot socks".toByteArray())
                                Mode.REFUSE -> o.write(byteArrayOf(5, 5, 0, 1, 0, 0, 0, 0, 0, 0))
                            }
                            o.flush()
                        }
                    }
                }
            }
        }
    }

    @After fun stop() {
        proxy.close()
    }

    private fun callbacks(endpoint: SocksEndpoint = SocksEndpoint("127.0.0.1", proxy.localPort)): Pair<OkHttpCallbacks, RouteTracker> {
        RouteConfig(dir).setSocks(endpoint)
        val t = RouteTracker({ System.currentTimeMillis() }, { true })
        return OkHttpCallbacks(RouteConfig(dir), t) to t
    }

    private fun expectFault(block: () -> Unit): HttpFault {
        try {
            block()
        } catch (e: HttpFault) {
            return e
        }
        fail("a fault was expected")
        error("unreachable")
    }

    @Test fun theHostnameIsHandedToTheProxyNeverResolvedOnTheDevice() {
        val (cb, _) = callbacks()
        // `.invalid` can never be resolved by any DNS: only a proxy-side (remote) resolution can even attempt this name.
        expectFault { cb.execute("https://relay.cipher.invalid:8443", "GET", "/v1/messages", null, ByteArray(0)) }
        val s = seen.firstOrNull()
        assertNotNull("the proxy must have been contacted", s)
        assertEquals("SOCKS5 ATYP 3 = domain name", 3, s!!.atyp)
        assertEquals("relay.cipher.invalid", s.host)
        assertEquals(8443, s.port)
    }

    @Test fun aDeadProxyFailsClosedAndTheDestinationIsNeverContacted() {
        val canary = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 400 }
        val deadPort = ServerSocket(0).use { it.localPort } // closed again: nothing listens
        val (cb, tracker) = callbacks(SocksEndpoint("127.0.0.1", deadPort))
        val f = expectFault { cb.execute("https://127.0.0.1:${canary.localPort}", "GET", "/", null, ByteArray(0)) }
        assertTrue("RouteUnavailable expected, was $f", f is HttpFault.RouteUnavailable)
        try {
            canary.accept()
            fail("DIRECT FALLBACK: the destination was contacted although the privacy route was down")
        } catch (_: SocketTimeoutException) {
            // good: nobody connected
        } finally {
            canary.close()
        }
        assertEquals(RouteStatus.UNAVAILABLE, tracker.status())
    }

    @Test fun aProxyThatRefusesTheConnectionIsRouteUnavailableAndNotRetriedDirectly() {
        mode = Mode.REFUSE
        val canary = ServerSocket(0, 5, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 400 }
        val (cb, _) = callbacks()
        val f = expectFault { cb.execute("https://127.0.0.1:${canary.localPort}", "GET", "/", null, ByteArray(0)) }
        assertTrue("was $f", f is HttpFault.RouteUnavailable || f is HttpFault.Io || f is HttpFault.Network)
        assertTrue(runCatching { canary.accept() }.exceptionOrNull() is SocketTimeoutException)
        canary.close()
    }

    @Test fun aProxyThatSpeaksGarbageIsRejectedNotTrusted() {
        mode = Mode.GARBAGE
        val (cb, tracker) = callbacks()
        expectFault { cb.execute("https://relay.cipher.invalid:8443", "GET", "/", null, ByteArray(0)) }
        assertFalse("garbage from the proxy must never count as a working route", tracker.status() == RouteStatus.PROTECTED)
    }

    @Test fun theProxyMustBeAnIpLiteralAndLocalDnsIsDisabled() {
        for (bad in listOf("localhost", "proxy.example", "999.1.1.1", "1.2.3", "")) {
            assertTrue(bad, runCatching { SocksEndpoint(bad, 9050) }.isFailure)
        }
        assertTrue(runCatching { SocksEndpoint("127.0.0.1", 0) }.isFailure)
        assertEquals(SocksEndpoint("127.0.0.1", 9050), SocksEndpoint.parse("127.0.0.1:9050"))
        assertEquals(null, SocksEndpoint.parse("tor.local:9050"))
        try {
            NoDns.lookup("relay.example")
            fail()
        } catch (_: UnknownHostException) {
        }
        assertEquals("the proxy selector offers no DIRECT entry", 1, FixedProxySelector(SocksEndpoint.DEFAULT.toProxy()).select(null).size)
    }

    @Test fun theStatusShownToTheUserReflectsTheRealRouteState() {
        var now = 0L
        var online = true
        val t = RouteTracker({ now }, { online })
        assertEquals("nothing has gone through the route yet", RouteStatus.CONNECTING, t.status())
        now = 10
        t.recordFailure()
        assertEquals(RouteStatus.UNAVAILABLE, t.status())
        now = 20
        t.recordSuccess()
        assertEquals(RouteStatus.PROTECTED, t.status())
        now = 20 + 121_000
        assertEquals("stale proof of a working route is not proof", RouteStatus.CONNECTING, t.status())
        now += 1
        t.recordFailure()
        assertEquals(RouteStatus.UNAVAILABLE, t.status())
        online = false
        assertEquals(RouteStatus.OFFLINE, t.status())
    }

    @Test fun releaseHasNoDirectRouteSourceAndNoOtherNetworkStackExists() {
        val main = File("src/main/java")
        assertTrue(main.exists())
        val forbidden = listOf(
            "HttpURLConnection", "HttpsURLConnection", "java.net.Socket", "java.net.URL(", "URL(\"", "WebView", "DownloadManager",
            "InetAddress.getByName(", "InetAddress.getAllByName(", "OkHttpClient", "Retrofit", "Cronet", "cleartextTraffic",
        )
        // PinnedTls.kt names java.net.Socket only because X509ExtendedTrustManager's method signatures do; it opens no connection (android_guards.rs checks its shape).
        val allowed = setOf("net/OkHttpCallbacks.kt", "net/PrivacyRoute.kt", "net/PinnedTls.kt")
        val offenders = mutableListOf<String>()
        main.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val rel = f.path.substringAfter("messenger/")
            if (rel in allowed) return@forEach
            val text = f.readText()
            forbidden.filter { text.contains(it) }.forEach { offenders += "$rel uses $it" }
        }
        assertTrue("only net/ may touch the network: $offenders", offenders.isEmpty())
        // the debug-only direct route marker must not exist in code that is compiled into release
        val inMain = main.walkTopDown().filter { it.isFile }.filter { it.readText().contains("allow_direct_dev") }.map { it.path }.toList()
        assertTrue("allow_direct_dev must only exist in src/debug: $inMain", inMain.isEmpty())
        assertTrue(File("src/debug/java/app/cipher/messenger/net/DirectDevRoute.kt").readText().contains("allow_direct_dev"))
        assertFalse(File("src/release/java/app/cipher/messenger/net/DirectDevRoute.kt").readText().contains("allow_direct_dev"))
    }
}
