package app.cipher.messenger

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.cipher_ffi.HttpFault

/**
 * Network attacks against the app's REAL transport, from the emulator, against `scripts/adversarial-tls-servers.py` on the host
 * (reachable as 10.0.2.2). The tests are skipped (not failed) when those servers are not running.
 * What it proves: TLS 1.3 only (no downgrade), no invalid/expired/wrong-host/untrusted-CA certificates (what a MITM proxy presents),
 * no redirect following, no plain HTTP ever. What it does NOT prove: pinning (none shipped), behaviour on OEM TLS stacks.
 */
@RunWith(AndroidJUnit4::class)
class NetworkAttackInstrumentedTest {
    private val http = run {
        // Optional: run every attack THROUGH a SOCKS5 privacy route (-e socks 10.0.2.2:1081) to show a substituted destination cannot downgrade TLS.
        val inst = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        val socks = androidx.test.platform.app.InstrumentationRegistry.getArguments().getString("socks")
        if (socks != null) {
            TestRoutes.socks(inst.targetContext, app.cipher.messenger.net.SocksEndpoint.parse(socks)!!).first
        } else {
            TestRoutes.direct(inst.targetContext)
        }
    }
    private val host = "10.0.2.2"

    private fun get(port: Int, path: String = "/") = http.execute("https://$host:$port", "GET", path, null, ByteArray(0))

    @Before fun requireAdversarialServers() {
        val up = runCatching { get(9501).status.toInt() == 200 }.getOrDefault(false)
        assumeTrue("start scripts/adversarial-tls-servers.py to run the network attack tests", up)
    }

    private fun plainHits(): Int = String(get(9501, "/hits?port=9507").body).trim().toInt()

    private fun assertTlsRefused(port: Int, why: String) {
        try {
            get(port)
            fail("the client accepted: $why")
        } catch (e: HttpFault) {
            assertTrue("$why must fail as a TLS error, was ${e::class.simpleName}", e is HttpFault.Tls)
        }
    }

    @Test fun theClientNegotiatesTls13EvenWhenTheServerAlsoOffersTls12() {
        assertEquals("TLSv1.3", String(get(9501, "/version").body).trim())
    }

    @Test fun aTls12OnlyServerIsRefusedNoDowngrade() = assertTlsRefused(9502, "a TLS 1.2-only server (downgrade)")

    @Test fun anExpiredCertificateIsRefused() = assertTlsRefused(9503, "an expired certificate")

    @Test fun aCertificateForTheWrongHostnameIsRefused() = assertTlsRefused(9504, "a certificate for another hostname")

    @Test fun aCertificateFromAnUntrustedCaIsRefusedLikeAMitmProxy() = assertTlsRefused(9505, "a certificate from an untrusted CA")

    @Test fun aRedirectToPlainHttpIsNeverFollowed() {
        val before = plainHits()
        val reply = get(9506)
        assertEquals("the 302 is returned to the caller, not followed", 302, reply.status.toInt())
        assertEquals("no connection to the plain-HTTP server was made", before, plainHits())
    }

    @Test fun plainHttpUrlsAreRefusedBeforeAnyConnection() {
        val before = plainHits()
        try {
            http.execute("http://$host:9507", "GET", "/", null, ByteArray(0))
            fail("http:// was accepted")
        } catch (_: HttpFault) {
        }
        assertEquals(before, plainHits())
    }
}
