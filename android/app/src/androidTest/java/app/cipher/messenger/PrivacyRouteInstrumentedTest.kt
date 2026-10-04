package app.cipher.messenger

import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import app.cipher.messenger.net.RouteStatus
import app.cipher.messenger.net.SocksEndpoint
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.cipher_ffi.HttpFault

/**
 * The real OkHttp/Android SOCKS path against a SOCKS5 endpoint started by the tester (`scripts/dev-socks-proxy.py`, a TEST DOUBLE — not Tor).
 * Skipped unless `socks` and `relayUrl` instrumentation arguments are given. `relayUrl` must use a NAME that the emulator cannot resolve
 * (the proxy maps it), so success proves the hostname was resolved by the proxy and not on the device.
 */
class PrivacyRouteInstrumentedTest {
    private val args = InstrumentationRegistry.getArguments()
    private val ctx get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun probe(): ByteArray {
        val cap = "0".repeat(32)
        val id = "1".repeat(32)
        return """{"deliveries":[{"cap":"$cap","message_id":"$id","ciphertext":"AAAA"}]}""".toByteArray()
    }

    @Test fun theRelayNameIsResolvedByTheProxyAndTlsSucceedsThroughIt() {
        val socks = args.getString("socks")
        val relay = args.getString("relayUrl")
        assumeTrue("socks/relayUrl arguments not provided", socks != null && relay != null)
        val (cb, tracker) = TestRoutes.socks(ctx, SocksEndpoint.parse(socks!!)!!)
        val r = cb.execute(relay!!, "POST", "/v1/deliver", null, probe())
        assertEquals(200, r.status.toInt())
        assertTrue(String(r.body).contains("invalid"))
        assertEquals(RouteStatus.PROTECTED, tracker.status())
    }

    /** CONTROL for the source-address measurement: the debug-only direct route (not available in release builds). */
    @Test fun theDirectDevControlReachesTheRelayWithoutAProxy() {
        val relay = args.getString("directRelayUrl")
        assumeTrue("directRelayUrl not provided", relay != null)
        val r = TestRoutes.direct(ctx).execute(relay!!, "POST", "/v1/deliver", null, probe())
        assertEquals(200, r.status.toInt())
    }

    @Test fun aDeadRouteFailsClosedEvenThoughTheRelayIsReachableDirectly() {
        val relay = args.getString("directRelayUrl") // the SAME relay, reachable without a proxy (e.g. https://10.0.2.2:8443)
        assumeTrue("directRelayUrl not provided", relay != null)
        val (cb, tracker) = TestRoutes.socks(ctx, SocksEndpoint("10.0.2.2", 9)) // nothing listens there
        try {
            cb.execute(relay!!, "POST", "/v1/deliver", null, probe())
            fail("DIRECT FALLBACK: a request was answered although the privacy route is dead")
        } catch (e: HttpFault) {
            assertTrue("was $e", e is HttpFault.RouteUnavailable || e is HttpFault.Timeout || e is HttpFault.Network)
        }
        assertEquals(RouteStatus.UNAVAILABLE, tracker.status())
    }

    /** Measurement, not a pass/fail test: request round-trip over the direct dev route vs through the SOCKS test double (NOT real Tor latency). */
    @Test fun probeLatencyDirectVersusThroughTheProxy() {
        val socks = args.getString("socks")
        val relay = args.getString("relayUrl")
        val direct = args.getString("directRelayUrl")
        assumeTrue("socks/relayUrl/directRelayUrl not provided", socks != null && relay != null && direct != null)
        fun sample(cb: app.cipher.messenger.net.OkHttpCallbacks, url: String): List<Long> {
            repeat(5) { cb.execute(url, "POST", "/v1/deliver", null, probe()) }
            return (1..30).map {
                val t = System.nanoTime()
                cb.execute(url, "POST", "/v1/deliver", null, probe())
                (System.nanoTime() - t) / 1_000_000
            }.sorted()
        }
        val d = sample(TestRoutes.direct(ctx), direct!!)
        val p = sample(TestRoutes.socks(ctx, SocksEndpoint.parse(socks!!)!!).first, relay!!)
        val dm = "median=${d[d.size / 2]} p90=${d[(d.size * 9) / 10]}"
        val pm = "median=${p[p.size / 2]} p90=${p[(p.size * 9) / 10]}"
        println("LATENCY_MS direct $dm  socks-test-double $pm")
    }

    /** Measurement: time to first response on a FRESH client (TCP + SOCKS handshake + TLS 1.3) for each route. */
    @Test fun probeConnectionSetupDirectVersusThroughTheProxy() {
        val socks = args.getString("socks")
        val relay = args.getString("relayUrl")
        val direct = args.getString("directRelayUrl")
        assumeTrue("socks/relayUrl/directRelayUrl not provided", socks != null && relay != null && direct != null)
        val d = (1..10).map {
            val cb = TestRoutes.direct(ctx)
            val t = System.nanoTime()
            cb.execute(direct!!, "POST", "/v1/deliver", null, probe())
            (System.nanoTime() - t) / 1_000_000
        }.sorted()
        val p = (1..10).map {
            val cb = TestRoutes.socks(ctx, SocksEndpoint.parse(socks!!)!!).first
            val t = System.nanoTime()
            cb.execute(relay!!, "POST", "/v1/deliver", null, probe())
            (System.nanoTime() - t) / 1_000_000
        }.sorted()
        println("SETUP_MS direct median=${d[d.size / 2]}  socks-test-double median=${p[p.size / 2]}")
    }
}
