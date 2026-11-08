package app.cipher.messenger.net.tor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TorConfigTest {
    @Test fun theDebugLogLineExistsOnlyWhenAFileIsGivenAndNeverCarriesAnotherDirective() {
        assertFalse("release passes no log file", TorConfig.torrc(emptyList()).contains("Log "))
        assertTrue(TorConfig.torrc(emptyList(), "/data/x/tor.log").lines().contains("Log notice file /data/x/tor.log"))
        val smuggled = TorConfig.torrc(emptyList(), "/x\nControlPort 9051")
        assertFalse("a newline cannot smuggle a second directive", smuggled.contains("ControlPort"))
    }

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
            "obfs4 192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0\nControlPort 9051",
            "obfs4 192.0.2.7:443 cert=a\"b",
            "obfs4 192.0.2.7:443 cert=abc #comment",
            "meek 192.0.2.7:443", // unknown transport
            "conjure 192.0.2.7:443",
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

    @Test fun pluggableTransportBridgesAreAcceptedAsTorProjectHandsThemOut() {
        val obfs4 = "obfs4 192.0.2.7:443 0123456789ABCDEF0123456789ABCDEF01234567 " +
            "cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kT iat-mode=0"
        assertEquals(obfs4, TorConfig.parseBridge(obfs4))
        assertEquals(
            "a torrc-style 'Bridge ' prefix and tabs are tolerated",
            obfs4,
            TorConfig.parseBridge("Bridge  $obfs4".replace(" cert", "\tcert"))
        )
        val webtunnel = "webtunnel [2001:db8:1::2]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/abc ver=0.0.1"
        assertEquals(webtunnel, TorConfig.parseBridge(webtunnel))
        assertEquals("webtunnel", TorConfig.transportOf(webtunnel))
        assertNull(TorConfig.transportOf("192.0.2.7:443"))
    }

    @Test fun everyBuiltInBridgeIsValidAndNeedsAShippedTransport() {
        assertTrue(BuiltinBridges.ALL.size in 2..TorConfig.MAX_BRIDGES * 2)
        for (b in BuiltinBridges.ALL) {
            assertEquals(b, TorConfig.parseBridge(b))
            assertTrue(TorConfig.transportOf(b) in setOf("snowflake", "obfs4"))
        }
    }

    @Test fun transportBridgesGetTheirHelperPortAndBridgesWithoutAHelperAreLeftOut() {
        val rc = TorConfig.torrc(BuiltinBridges.ALL + "192.0.2.7:443", transportPorts = mapOf("snowflake" to 40001, "obfs4" to 40002))
        assertTrue(rc.lines().contains("ClientTransportPlugin snowflake socks5 127.0.0.1:40001"))
        assertTrue(rc.lines().contains("ClientTransportPlugin obfs4 socks5 127.0.0.1:40002"))
        assertEquals(BuiltinBridges.ALL.size + 1, rc.lines().count { it.startsWith("Bridge ") })
        assertEquals("still exactly one SocksPort", 1, rc.lines().count { it.startsWith("SocksPort") })

        val noHelper = TorConfig.torrc(BuiltinBridges.ALL, transportPorts = mapOf("snowflake" to 40001))
        assertFalse("obfs4 bridges without a helper are not written", noHelper.contains("Bridge obfs4"))
        assertTrue(noHelper.contains("Bridge snowflake"))

        val none = TorConfig.torrc(BuiltinBridges.OBFS4, transportPorts = mapOf("obfs4" to 0))
        assertFalse("an invalid port is no port: no bridges, no UseBridges", none.contains("UseBridges"))
    }

    @Test fun modesChooseTheBridgesOfAnAttempt() {
        assertTrue(TorPlan.bridgesFor(TorMode.DIRECT, listOf("192.0.2.7:443"), true).isEmpty())
        assertTrue(TorPlan.bridgesFor(TorMode.AUTO, emptyList(), false).isEmpty())
        assertEquals(BuiltinBridges.ALL, TorPlan.bridgesFor(TorMode.AUTO, emptyList(), true))
        assertEquals(BuiltinBridges.ALL, TorPlan.bridgesFor(TorMode.BUILTIN_BRIDGES, listOf("192.0.2.7:443"), false))
        assertEquals(listOf("192.0.2.7:443"), TorPlan.bridgesFor(TorMode.CUSTOM_BRIDGES, listOf("192.0.2.7:443"), false))
        assertEquals("unknown or missing mode is Automatic", TorMode.AUTO, TorMode.parse(null))
        assertEquals(TorMode.AUTO, TorMode.parse("garbage"))
        assertEquals(TorMode.CUSTOM_BRIDGES, TorMode.parse("CUSTOM_BRIDGES\n"))
    }

    @Test fun automaticSwitchesToBridgesWhenADirectAttemptStallsAndBackWhenBridgesNeverFinish() {
        assertNull("too early", TorPlan.autoSwitch(false, 5, TorPlan.DIRECT_PATIENCE_MS - 1))
        assertEquals("stalled at the handshake (DPI)", true, TorPlan.autoSwitch(false, 10, TorPlan.DIRECT_PATIENCE_MS))
        assertEquals("never reported", true, TorPlan.autoSwitch(false, null, TorPlan.DIRECT_PATIENCE_MS))
        assertNull("real progress: keep waiting", TorPlan.autoSwitch(false, 50, TorPlan.DIRECT_PATIENCE_MS * 3))
        assertNull("done", TorPlan.autoSwitch(true, 100, TorPlan.BRIDGE_PATIENCE_MS * 2))
        assertNull(TorPlan.autoSwitch(true, 10, TorPlan.BRIDGE_PATIENCE_MS - 1))
        assertEquals("bridges never got past the first hop", false, TorPlan.autoSwitch(true, 10, TorPlan.BRIDGE_PATIENCE_MS))
        assertNull("bridges are making progress: keep them", TorPlan.autoSwitch(true, 40, TorPlan.BRIDGE_PATIENCE_MS))
        assertEquals(false, TorPlan.autoSwitch(true, 40, TorPlan.BRIDGE_MAX_MS))
    }
}
