package app.cipher.messenger.net

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Kotlin relay-address rules must match the Rust `RelayDescriptor` (https only, canonical, onion => pin). */
class RelayAddressTest {
    private val pinBytes = ByteArray(32) { it.toByte() }
    private val pinUrlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(pinBytes)
    private val pinStd = Base64.getEncoder().encodeToString(pinBytes)
    private val onion = "https://46qfvf5rr4gulgasuzud7la5izd4fjm555gvynfnuipkwtwhz7shbcad.onion"

    private fun ok(url: String, pin: String? = null) = (RelayAddress.parse(url, pin) as RelayAddress.Result.Ok).address
    private fun bad(url: String, pin: String? = null) = RelayAddress.parse(url, pin) is RelayAddress.Result.Bad

    @Test fun canonicalisesHostAndKeepsPort() {
        assertEquals("https://relay.example.org:8443", ok("  https://Relay.Example.org:8443/ ").url)
        assertNull(ok("https://relay.example.org").pinB64)
    }

    @Test fun refusesEverythingThatIsNotPlainHttpsHostPort() {
        listOf(
            "http://relay.example.org", "relay.example.org", "https://", "https://u@relay.example.org", "https://relay.example.org/p",
            "https://relay.example.org?x=1", "https://relay.example.org#f", "https://relay.example.org:0",
            "https://relay.example.org:99999",
            "https://relay.example.org:", "https://re lay.example.org", "https://relay..example.org", "https://-relay.example.org",
            "https://relay.example.org%2f", "https://rélay.example.org", "https://a.example.orghttps://b.example.org",
            "ftp://relay.example.org",
        ).forEach { assertTrue("must refuse $it", bad(it)) }
    }

    @Test fun onionServersRequireAPinAndClearnetServersMayHaveOne() {
        assertTrue(bad(onion))
        assertTrue(bad(onion, "   "))
        assertEquals(pinUrlSafe, ok(onion, pinStd).pinB64)
        assertTrue(ok(onion, pinStd).isOnion)
        assertEquals(pinUrlSafe, ok("https://relay.example.org", pinStd).pinB64)
    }

    @Test fun acceptsEveryPinSpellingOperatorsSeeAndNormalisesThem() {
        val hex = pinBytes.joinToString("") { "%02x".format(it) }
        listOf(
            pinStd,
            pinUrlSafe,
            "sha256/$pinStd",
            "sha256//$pinStd",
            "SHA256/$pinUrlSafe",
            hex,
            hex.uppercase(),
            "  sha256/$pinStd  "
        ).forEach {
            assertEquals("spelling: $it", pinUrlSafe, RelayAddress.normalisePin(it))
        }
    }

    @Test fun rejectsPinsThatAreNotExactlyAThirtyTwoByteHash() {
        listOf(
            "", "AAAA", "not base64!!",
            pinUrlSafe.dropLast(
                2
            ),
            pinUrlSafe + "AA", "sha256/",
            "zz".repeat(
                32
            ),
            Base64.getEncoder().encodeToString(ByteArray(31)), Base64.getEncoder().encodeToString(ByteArray(33))
        )
            .forEach { assertNull("must reject '$it'", RelayAddress.normalisePin(it)) }
        assertTrue(bad("https://relay.example.org", "garbage"))
    }
}
