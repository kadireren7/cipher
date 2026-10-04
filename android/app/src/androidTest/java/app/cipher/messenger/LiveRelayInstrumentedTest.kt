package app.cipher.messenger

import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.CipherEngine
import uniffi.cipher_ffi.DeliveryStateFfi
import uniffi.cipher_ffi.EngineSettings

/**
 * Drives the REAL app stack (native core + Android Keystore wrapper + OkHttp transport) against a LIVE relay started by the tester.
 * Skipped unless the instrumentation arguments are given:
 *   -Pandroid.testInstrumentationRunnerArguments.relayUrl=https://10.0.2.2:8443
 *   -Pandroid.testInstrumentationRunnerArguments.invite=<registration token>
 *   -Pandroid.testInstrumentationRunnerArguments.peerCipherId=CIPH-…   (a second, already registered client)
 * Purpose (final review FR-10): the relay now authenticates uploads BEFORE reading the body, using a body hash announced in the signed
 * header. This proves the real OkHttp upload path (file body, Content-Length, `bh=`) works against the real relay.
 */
class LiveRelayInstrumentedTest {
    private val args = InstrumentationRegistry.getArguments()

    @Test fun anAttachmentUploadFromTheRealAppStackIsAcceptedByTheRealRelay() {
        val relay = args.getString("relayUrl")
        val invite = args.getString("invite")
        val peer = args.getString("peerCipherId")
        val socks = args.getString("socks") // optional: run the whole flow through a SOCKS5 privacy route
        assumeTrue("live-relay arguments not provided", relay != null && invite != null && peer != null)
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        val dir = File(ctx.cacheDir, "live-${System.nanoTime()}").apply { mkdirs() }
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
            socks?.let { TestRoutes.socks(ctx, app.cipher.messenger.net.SocksEndpoint.parse(it)!!).first } ?: TestRoutes.direct(ctx),
        )
        try {
            engine.provisionVaultPinOnly("739104")
            val me = engine.createIdentity(invite!!)
            assertNotNull(me.cipherId)
            val contact = engine.addContactByCipherId(peer!!, "Peer")
            val conv = engine.createConversation(contact.accountId)
            val text = engine.sendText(conv, "LIVE-CANARY-text-from-the-real-app-4412", null)
            assertEquals(DeliveryStateFfi.SENT, text.state)

            // A 3 MiB file with a recognisable plaintext marker, handed over as a file descriptor exactly like the picker flow.
            val file = File(dir, "live-doc.pdf")
            val marker = "LIVE-CANARY-attachment-bytes-9921".toByteArray()
            file.writeBytes(
                "%PDF-1.4\n".toByteArray() + marker + ByteArray(3 * 1024 * 1024) { (it * 7).toByte() } + "\n%%EOF\n".toByteArray()
            )
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                val m = engine.sendAttachment(
                    conv,
                    "/proc/self/fd/${pfd.fd}",
                    "application/pdf",
                    "live-doc.pdf",
                    AttachmentKindFfi.PDF,
                    "",
                    null,
                    null,
                    null,
                    null,
                )
                assertEquals("the relay accepted the upload", DeliveryStateFfi.SENT, m.state)
                assertTrue(m.attachment != null && m.attachment!!.sizeBytes >= 3uL * 1024uL * 1024uL)
            }
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
