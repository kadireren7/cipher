package app.cipher.messenger

import android.os.Bundle
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import app.cipher.messenger.net.OkHttpCallbacks
import app.cipher.messenger.net.SocksEndpoint
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.CipherEngine
import uniffi.cipher_ffi.DeliveryStateFfi
import uniffi.cipher_ffi.EngineSettings

/**
 * Two INDEPENDENT relays, the REAL app stack (native core + Android Keystore + OkHttp/TLS 1.3 + PinnedTls) on an emulator, and a headless peer on the
 * OTHER relay. Driven phase by phase by `scripts/android-e2e-multirelay.py` (each phase is a separate instrumentation run = a separate app process,
 * so persistence across process restarts is exercised too). Skipped unless `phase` is given.
 *
 * Honest scope: an emulator Keystore is software-backed and the route is the debug direct route; no Tor, no physical device.
 */
class MultiRelayE2EInstrumentedTest {
    private val args = InstrumentationRegistry.getArguments()
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val dir = File(ctx.filesDir, "mr-e2e")
    private val pin = "739104"

    private fun status(vararg kv: Pair<String, String>) {
        val b = Bundle()
        kv.forEach { b.putString(it.first, it.second) }
        InstrumentationRegistry.getInstrumentation().sendStatus(0, b)
    }

    private fun engine(): Pair<CipherEngine, OkHttpCallbacks> {
        val url = args.getString("relayUrl")!!
        // `socks` given = the REAL privacy route (SOCKS5 to a real Tor client; relays are onion services); otherwise the debug direct route.
        val http = args.getString("socks")?.let { TestRoutes.socks(ctx, SocksEndpoint.parse(it)!!).first } ?: TestRoutes.direct(ctx)
        args.getString("ownPin")?.let { http.pinRelay(url, it) }
        val e = CipherEngine(
            EngineSettings(
                dataDir = dir.absolutePath,
                relayUrl = url,
                allowSoftwareKeystore = BuildConfig.ALLOW_SOFTWARE_KEYSTORE,
                inactivityTimeoutSecs = 3600uL,
                requireUserAuth = false,
                extraSourceDir = dir.absolutePath,
            ),
            AndroidKeystoreCallbacks(ctx, BiometricGate { null }),
            http,
        )
        return e to http
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun texts(e: CipherEngine, conv: String): List<String> =
        e.getHistory(conv, null, 200u).items.reversed().filter { it.attachment == null }.map { it.text }

    private fun waitFor(what: String, seconds: Int = 90, cond: () -> Boolean) {
        val end = System.currentTimeMillis() + seconds * 1000L * (if (args.getString("socks") != null) 4 else 1) // Tor circuits are slow
        while (System.currentTimeMillis() < end) {
            if (cond()) return
            Thread.sleep(1000)
        }
        throw AssertionError("timed out waiting for: $what")
    }

    @Test fun phase() {
        val phase = args.getString("phase")
        assumeTrue("no phase given", phase != null && args.getString("relayUrl") != null)
        when (phase) {
            "init" -> init()
            "connect" -> connect()
            "read" -> read()
            "final" -> final()
            "recv" -> recv()
            "send" -> send()
            "settle" -> settle()
            else -> throw AssertionError("unknown phase $phase")
        }
    }

    /** Fresh app data, an account on relay A, and a contact card for it. */
    private fun init() {
        dir.deleteRecursively()
        dir.mkdirs()
        // a previous run's vault keys would make provisioning fail: start from a clean Keystore (test data only)
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList().filter { it.startsWith("cipher.") }.forEach { ks.deleteEntry(it) }
        val (e, _) = engine()
        e.provisionVaultPinOnly(pin)
        val me = e.createIdentity(args.getString("invite")!!)
        e.setOwnRelay(args.getString("relayUrl")!!, args.getString("ownPin"))
        status("account" to me.accountId, "card" to e.createContactCard(7u))
    }

    /** New process: unlock, add the peer's card (from ANOTHER relay), start the conversation, send the first message. */
    private fun connect() {
        val (e, _) = engine()
        e.unlockVaultWithPin(pin)
        e.setOwnRelay(args.getString("relayUrl")!!, args.getString("ownPin"))
        val bob = e.addContactByCard(args.getString("peerCard")!!, "Bob", true)
        val conv = e.createConversation(bob.accountId)
        val m = e.sendText(conv, "app-hello-1", null)
        assertTrue(m.state == DeliveryStateFfi.SENT || m.state == DeliveryStateFfi.PENDING)
        // The foreground app syncs continuously; a few ticks here hand our own mailbox capability to the peer (the app's side of the introduction).
        repeat(3) { e.sync() }
        status("conv" to conv, "bobAccount" to bob.accountId)
    }

    /** New process again: messages Bob sent while the app was not running must be here, in order; open his attachment; send ours. */
    private fun read() {
        val (e, _) = engine()
        e.unlockVaultWithPin(pin)
        e.setOwnRelay(args.getString("relayUrl")!!, args.getString("ownPin"))
        val conv = args.getString("conv")!!
        val expect = args.getString("expectTexts")!!.split(",")
        waitFor("offline messages in order $expect") {
            e.sync()
            texts(e, conv).filter { it in expect } == expect
        }
        val wantSha = args.getString("expectSha")!!
        val att = e.getHistory(conv, null, 200u).items.first { it.attachment != null && !it.outgoing }
        assertEquals(args.getString("expectName"), att.attachment!!.filename)
        assertEquals("attachment from the other relay is intact", wantSha, sha(e.openAttachment(conv, att.id, false, null)))
        // our reply: text + an encrypted attachment toward a user on ANOTHER relay
        e.sendText(conv, "app-reply-2", null)
        val bytes = ByteArray(700_000) { (it * 31 + 7).toByte() }
        val f = File(dir, "from-app.bin").apply { writeBytes(bytes) }
        val sent = e.sendAttachment(
            conv, f.absolutePath, "application/octet-stream", "from-app.bin", AttachmentKindFfi.FILE, "", null, null, null, null,
        )
        f.delete()
        assertTrue(sent.attachment != null)
        // the sender can still open its own copy (it lives on the sender's relay)
        assertEquals(sha(bytes), sha(e.openAttachment(conv, sent.id, false, null)))
        e.flushOutbox()
        status("sentSha" to sha(bytes), "sentName" to "from-app.bin")
    }

    /** New process: Bob has read everything and sent receipts; the app must show its messages as DELIVERED (end-to-end receipts, not relay acks). */
    private fun final() {
        val (e, _) = engine()
        e.unlockVaultWithPin(pin)
        e.setOwnRelay(args.getString("relayUrl")!!, args.getString("ownPin"))
        val conv = args.getString("conv")!!
        waitFor("end-to-end receipts") {
            e.sync()
            e.getHistory(conv, null, 200u).items.filter { it.outgoing }.all { it.state == DeliveryStateFfi.DELIVERED }
        }
        val out = e.getHistory(conv, null, 200u).items.filter { it.outgoing }
        assertTrue("app sent at least 3 messages", out.size >= 3)
        status("delivered" to out.size.toString())
        e.lockVault()
    }

    private fun unlocked(): CipherEngine {
        val (e, _) = engine()
        e.unlockVaultWithPin(pin)
        e.setOwnRelay(args.getString("relayUrl")!!, args.getString("ownPin"))
        return e
    }

    /** Resilience: a new process; the listed incoming texts (sent while this app was offline or while a relay was down) must all be here, in order. */
    private fun recv() {
        val e = unlocked()
        val conv = args.getString("conv")!!
        val expect = args.getString("expectTexts")!!.split(",")
        waitFor("texts in order $expect", 120) {
            runCatching { e.sync() }
            texts(e, conv).filter { it in expect } == expect
        }
        e.lockVault()
    }

    /**
     * Resilience: send while a relay may be DOWN. Never throws for a network failure of the text (it must be queued); for the attachment either the call
     * fails and leaves NO message behind, or the message is queued and settles later. Reports which, so the driver can check exactly-once delivery.
     */
    private fun send() {
        val e = unlocked()
        val conv = args.getString("conv")!!
        val before = e.getHistory(conv, null, 200u).items.count { it.outgoing && it.attachment != null }
        args.getString("text")?.let { e.sendText(conv, it, null) }
        var failed = false
        var sentSha = ""
        args.getString("fileKb")?.let { kb ->
            val bytes = ByteArray(kb.toInt() * 1024) { (it * 13 + 5).toByte() }
            val f = File(dir, args.getString("fileName")!!).apply { writeBytes(bytes) }
            try {
                e.sendAttachment(conv, f.absolutePath, "application/octet-stream", args.getString("fileName")!!, AttachmentKindFfi.FILE, "", null, null, null, null)
                sentSha = sha(bytes)
            } catch (x: Exception) {
                failed = true
            } finally {
                f.delete()
            }
        }
        runCatching { e.flushOutbox() }
        val after = e.getHistory(conv, null, 200u).items.count { it.outgoing && it.attachment != null }
        if (failed) assertEquals("a failed attachment send must leave no message behind", before, after)
        val states = e.getHistory(conv, null, 200u).items.filter { it.outgoing }.joinToString(",") { it.state.name }
        status("attachFailed" to failed.toString(), "sentSha" to sentSha, "states" to states)
        e.lockVault()
    }

    /** Resilience: every message this app sent must reach DELIVERED (end-to-end receipt) once the relays are back; nothing may be FAILED. */
    private fun settle() {
        val e = unlocked()
        val conv = args.getString("conv")!!
        waitFor("all outgoing messages DELIVERED after recovery", 180) {
            runCatching { e.sync() }
            runCatching { e.flushOutbox() }
            val out = e.getHistory(conv, null, 200u).items.filter { it.outgoing }
            assertTrue("a message ended FAILED", out.none { it.state == DeliveryStateFfi.FAILED })
            out.all { it.state == DeliveryStateFfi.DELIVERED }
        }
        status("delivered" to e.getHistory(conv, null, 200u).items.count { it.outgoing }.toString())
        e.lockVault()
    }
}
