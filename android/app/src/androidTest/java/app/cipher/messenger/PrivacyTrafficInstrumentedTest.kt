package app.cipher.messenger

import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import app.cipher.messenger.net.SocksEndpoint
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.io.File
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.cipher_ffi.CipherEngine
import uniffi.cipher_ffi.EngineSettings
import uniffi.cipher_ffi.NetworkProfileFfi

/**
 * Traffic-shape experiment on the real Android stack: a real engine ticks per its network profile through a SOCKS5 test double that records what a
 * link observer sees (time, direction, bytes). Message sends are scheduled; their times are printed (`SEND_AT <epoch ms>`) so the host can test
 * whether an observer could tell when the user sent. Arguments: socks, relayUrl, invite, peerCipherId, profile, durationSecs, sendEverySecs.
 * Skipped unless given. This is a measurement tool, not a pass/fail security test.
 */
class PrivacyTrafficInstrumentedTest {
    private val args = InstrumentationRegistry.getArguments()

    @Test fun runTheProfileAndPrintTheSendSchedule() {
        val socks = args.getString("socks")
        val relay = args.getString("relayUrl")
        val invite = args.getString("invite")
        val peer = args.getString("peerCipherId")
        val profile = args.getString("profile")
        assumeTrue("traffic experiment arguments not provided", listOf(socks, relay, invite, peer, profile).all { it != null })
        val duration = (args.getString("durationSecs") ?: "360").toInt()
        val every = (args.getString("sendEverySecs") ?: "37").toInt()
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val dir = File(ctx.cacheDir, "traffic-${System.nanoTime()}").apply { mkdirs() }
        val route = TestRoutes.socks(ctx, SocksEndpoint.parse(socks!!)!!).first
        val engine = CipherEngine(
            EngineSettings(
                dataDir = dir.absolutePath,
                relayUrl = relay!!,
                allowSoftwareKeystore = BuildConfig.ALLOW_SOFTWARE_KEYSTORE,
                inactivityTimeoutSecs = 3600uL,
                requireUserAuth = false,
                extraSourceDir = null,
            ),
            AndroidKeystoreCallbacks(ctx, BiometricGate { null }),
            route,
        )
        try {
            engine.provisionVaultPinOnly("739104")
            engine.createIdentity(invite!!)
            val contact = engine.addContactByCipherId(peer!!, "Peer")
            val conv = engine.createConversation(contact.accountId)
            engine.setSettings(
                engine.getSettings().copy(
                    networkProfile = if (profile == "enhanced") NetworkProfileFfi.ENHANCED else NetworkProfileFfi.STANDARD,
                ),
            )
            println("EXPERIMENT_START ${System.currentTimeMillis()} profile=$profile")
            val start = System.currentTimeMillis()
            var nextTick = start
            var nextSend = start + 20_000
            while (System.currentTimeMillis() - start < duration * 1000L) {
                val now = System.currentTimeMillis()
                if (now >= nextSend) {
                    println("SEND_AT $now")
                    runCatching { engine.sendText(conv, "traffic-experiment-$now", null) }
                    nextSend = now + every * 1000L
                }
                if (now >= nextTick) {
                    nextTick = now + runCatching { engine.networkTick().nextDelayMs.toLong() }.getOrDefault(4_000L)
                }
                Thread.sleep(200)
            }
            println("EXPERIMENT_END ${System.currentTimeMillis()}")
        } finally {
            runCatching { engine.lockVault() }
            dir.deleteRecursively()
            runCatching {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                ks.aliases().toList().filter { it.startsWith("cipher.") }.forEach { ks.deleteEntry(it) }
            }
        }
    }
}
