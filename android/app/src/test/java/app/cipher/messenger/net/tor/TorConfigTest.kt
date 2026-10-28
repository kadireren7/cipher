package app.cipher.messenger.net.tor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigTest {
    @Test fun theDaemonIsAClientWithOneLoopbackSocksListenerAndNothingElse() {
        val rc = TorConfig.torrc(emptyList())
        assertTrue(rc.contains("SocksPort ${TorConfig.SOCKS_HOST}:${TorConfig.SOCKS_PORT} IsolateSOCKSAuth"))
        assertEquals("the app dials exactly where the daemon listens", "127.0.0.1", TorConfig.SOCKS_HOST)
        assertTrue("never a relay or an exit", rc.contains("ClientOnly 1"))
        assertTrue("the library's default HTTP tunnel is switched off", rc.lines().contains("HTTPTunnelPort 0"))
        // Nothing that opens another listener, resolves names for the device, or exposes the control channel.
        val forbiddenDirectives = listOf(
            "0.0.0.0",
            "DNSPort",
            "TransPort",
            "ControlPort",
            "ORPort",
            "ExitRelay",
            "AutomapHosts",
            "SocksPolicy accept *"
        )
        for (forbidden in forbiddenDirectives) {
            assertFalse("torrc must not contain $forbidden", rc.contains(forbidden))
        }
        assertEquals("exactly one SocksPort line", 1, rc.lines().count { it.startsWith("SocksPort") })
        assertFalse("no bridge lines unless the user added them", rc.contains("Bridge"))
    }

    @Test fun bridgesAreOnlyEmittedWhenGivenAndEnableUseBridges() {
        val rc = TorConfig.torrc(listOf("192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567"))
        assertTrue(rc.contains("UseBridges 1"))
        assertTrue(rc.contains("Bridge 192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567"))
    }

    @Test fun plainBridgesAreAccepted() {
        assertEquals("192.0.2.7:443", TorConfig.parseBridge("192.0.2.7:443"))
        assertEquals(
            "192.0.2.7:9001 0123456789abcdef0123456789abcdef01234567",
            TorConfig.parseBridge("  192.0.2.7:9001 0123456789abcdef0123456789abcdef01234567  ")
        )
        assertEquals("[2001:db8::1]:443", TorConfig.parseBridge("[2001:db8::1]:443"))
    }

    @Test fun aBridgeCanNeverSmuggleAnotherTorrcDirective() {
        for (bad in listOf(
            "192.0.2.7:443\nControlPort 9051",
            "192.0.2.7:443\rHTTPTunnelPort 8118",
            "192.0.2.7:443 \u0000",
            "obfs4 192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0", // pluggable transport: refused, not ignored
            "192.0.2.7:443 ; ControlPort 9051",
            "192.0.2.7:0",
            "192.0.2.7:70000",
            "192.0.2.7",
            "999.1.1.1:443",
            "example.org:443", // a name would need local DNS
            "192.0.2.7:443 0123", // short fingerprint
            "",
        )) {
            assertNull("must be refused: ${bad.replace("\n", "\\n")}", TorConfig.parseBridge(bad))
        }
    }

    @Test fun aBlockIsAllOrNothing() {
        assertEquals(
            listOf("192.0.2.7:443", "198.51.100.9:9001"),
            TorConfig.parseBridges("192.0.2.7:443\n\n198.51.100.9:9001\n192.0.2.7:443")
        )
        assertNull("one bad line rejects the whole block", TorConfig.parseBridges("192.0.2.7:443\nControlPort 9051"))
        assertNull("too many lines", TorConfig.parseBridges((1..(TorConfig.MAX_BRIDGES + 1)).joinToString("\n") { "192.0.2.$it:443" }))
        assertEquals(emptyList<String>(), TorConfig.parseBridges("  \n "))
    }

    @Test fun bootstrapProgressIsParsedFromTheDaemonsOwnWords() {
        assertEquals(
            45,
            TorProgress.fromBootstrapInfo("NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"")
        )
        assertEquals(100, TorProgress.fromBootstrapInfo("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\""))
        assertNull(TorProgress.fromBootstrapInfo("NOTICE BOOTSTRAP PROGRESS=250 TAG=x"))
        assertNull(TorProgress.fromBootstrapInfo("garbage"))
        assertNull(TorProgress.fromBootstrapInfo(null))
    }

    @Test fun aStaleOrMalformedProgressFileIsNotProgress() {
        val now = 1_000_000L
        assertEquals(60, TorProgress.decode(TorProgress.encode(60, now - 2_000), now))
        assertNull("a file left by a dead daemon", TorProgress.decode(TorProgress.encode(60, now - 60_000), now))
        assertNull(TorProgress.decode("60", now))
        assertNull(TorProgress.decode("abc 123", now))
        assertNull(TorProgress.decode("101 $now", now))
        assertNull(TorProgress.decode(null, now))
    }
}
