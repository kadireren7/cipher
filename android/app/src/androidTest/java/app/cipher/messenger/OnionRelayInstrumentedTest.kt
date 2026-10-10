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
 * The Android HTTP/TLS stack (OkHttp + PinnedTls + the SOCKS privacy route) against a REAL onion service reached through a REAL Tor client.
 * Arguments (given by scripts/android-e2e-multirelay.py in Tor mode): socks=<ip:port of the Tor SocksPort>, onionUrl=https://<id>.onion:<port>, onionPin=<SPKI sha256>.
 * Skipped without them. Honest scope: emulator, software Keystore; the Tor client runs on the host, not in the app (the app is the SOCKS client, as with Orbot).
 */
class OnionRelayInstrumentedTest {
    private val args = InstrumentationRegistry.getArguments()
    private val ctx get() = ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun probe(): ByteArray {
        val cap = "0".repeat(32)
        val id = "1".repeat(32)
        return """{"deliveries":[{"cap":"$cap","message_id":"$id","ciphertext":"AAAA"}]}""".toByteArray()
    }

    private fun params(): Triple<SocksEndpoint, String, String> {
        val socks = args.getString("socks")
        val url = args.getString("onionUrl")
        val pin = args.getString("onionPin")
        assumeTrue("onion arguments not provided", socks != null && url != null && pin != null)
        return Triple(SocksEndpoint.parse(socks!!)!!, url!!, pin!!)
    }

    /** First connection to a hidden service can take a while (descriptor fetch + rendezvous): retry on transport errors only, never on a TLS refusal. */
    private fun <T> eventually(what: String, block: () -> T): T {
        var last: Throwable? = null
        repeat(8) {
            try {
                return block()
            } catch (e: HttpFault.Tls) {
                throw e
            } catch (e: HttpFault) {
                last = e
                Thread.sleep(10_000)
            }
        }
        throw AssertionError("$what: onion service unreachable through Tor after retries: $last")
    }

    @Test fun theCorrectPinIsAcceptedAndTheRouteIsReportedProtected() {
        val (socks, url, pin) = params()
        val (cb, tracker) = TestRoutes.socks(ctx, socks)
        cb.pinRelay(url, pin)
        val r = eventually("pinned request") { cb.execute(url, "POST", "/v1/deliver", null, probe()) }
        assertEquals(200, r.status.toInt())
        assertTrue(String(r.body).contains("invalid"))
        assertEquals(RouteStatus.PROTECTED, tracker.status())
    }

    @Test fun aWrongPinIsRefusedFailClosed() {
        val (socks, url, pin) = params()
        // reachable first, so a refusal below is the pin and not a dead circuit
        val (ok, _) = TestRoutes.socks(ctx, socks)
        ok.pinRelay(url, pin)
        eventually("reachability") { ok.execute(url, "POST", "/v1/deliver", null, probe()) }
        val wrong = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
        val (cb, _) = TestRoutes.socks(ctx, socks)
        cb.pinRelay(url, wrong)
        try {
            cb.execute(url, "POST", "/v1/deliver", null, probe())
            fail("a relay presenting a key that does not match the pin was accepted")
        } catch (e: HttpFault.Tls) {
            // expected: fail closed
        }
    }

    @Test fun aSelfSignedOnionRelayWithoutAnyPinIsRefused() {
        val (socks, url, pin) = params()
        val (ok, _) = TestRoutes.socks(ctx, socks)
        ok.pinRelay(url, pin)
        eventually("reachability") { ok.execute(url, "POST", "/v1/deliver", null, probe()) }
        // no pin registered: the platform CA validation applies and must reject a self-signed certificate
        val (cb, _) = TestRoutes.socks(ctx, socks)
        try {
            cb.execute(url, "POST", "/v1/deliver", null, probe())
            fail("a self-signed certificate was accepted without a pin")
        } catch (e: HttpFault.Tls) {
            // expected
        }
    }
}
