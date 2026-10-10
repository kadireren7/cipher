package app.cipher.messenger

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.io.File
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.cipher_ffi.CipherEngine
import uniffi.cipher_ffi.CipherException
import uniffi.cipher_ffi.EngineSettings
import uniffi.cipher_ffi.HttpCallbacks
import uniffi.cipher_ffi.HttpFault
import uniffi.cipher_ffi.HttpReply
import uniffi.cipher_ffi.LockStateFfi

/**
 * The real native library (cipher-ffi) driven from Kotlin on a device/emulator, with the REAL Android Keystore wrapper and a dead
 * network. Covers the lifecycle the UI depends on: provision, lock, unlock, restart, wrong/weak/hostile PINs, rate limiting,
 * key loss, and that the vault file never holds the PIN.
 */
@RunWith(AndroidJUnit4::class)
class EngineLifecycleInstrumentedTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
    private lateinit var dir: File
    private val engines = mutableListOf<CipherEngine>()

    private object DeadHttp : HttpCallbacks {
        override fun execute(baseUrl: String, method: String, pathAndQuery: String, authorization: String?, body: ByteArray): HttpReply =
            throw HttpFault.Network()

        override fun uploadFile(baseUrl: String, pathAndQuery: String, authorization: String?, filePath: String): HttpReply =
            throw HttpFault.Network()

        override fun downloadFile(
            baseUrl: String,
            pathAndQuery: String,
            authorization: String?,
            destPath: String,
            maxBytes: ULong,
        ): UShort = throw HttpFault.Network()

        // a dead transport cannot pin: refusing is the fail-closed answer
        override fun pinRelay(baseUrl: String, spkiSha256B64: String) = throw HttpFault.Tls()
    }

    @Before fun setUp() {
        dir = File(ctx.cacheDir, "eng-${UUID.randomUUID()}").apply { mkdirs() }
        cleanAliases()
    }

    @After fun tearDown() {
        engines.forEach { runCatching { it.lockVault() } }
        dir.deleteRecursively()
        cleanAliases()
    }

    private fun cleanAliases() = runCatching {
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList().filter { it.startsWith("cipher.") }.forEach { ks.deleteEntry(it) } // vault keys and the rollback counter
    }

    private fun engine(timeoutSecs: ULong = 3600uL): CipherEngine = CipherEngine(
        EngineSettings(
            dataDir = dir.absolutePath,
            relayUrl = "https://relay.invalid",
            allowSoftwareKeystore = BuildConfig.ALLOW_SOFTWARE_KEYSTORE,
            inactivityTimeoutSecs = timeoutSecs,
            requireUserAuth = false,
            extraSourceDir = null,
        ),
        AndroidKeystoreCallbacks(ctx, BiometricGate { null }),
        DeadHttp,
    ).also { engines += it }

    private inline fun <reified T : CipherException> expect(block: () -> Unit) {
        try {
            block()
            fail("expected ${T::class.simpleName}")
        } catch (e: CipherException) {
            assertTrue("expected ${T::class.simpleName} but got ${e::class.simpleName}", e is T)
        }
    }

    @Test fun freshEngineIsUnprovisionedAndLocked() {
        val s = engine().status()
        assertFalse(s.provisioned)
        assertFalse(s.hasIdentity)
        assertTrue(s.state != LockStateFfi.UNLOCKED)
    }

    @Test fun pinOnlyProvisionLockUnlockAndRestart() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        var s = e.status()
        assertTrue(s.provisioned && s.pinOnly)
        assertEquals(LockStateFfi.UNLOCKED, s.state)

        e.lockVault()
        assertEquals(LockStateFfi.LOCKED, e.status().state)
        expect<CipherException.Locked> { e.listConversations() } // locked means no plaintext API at all
        expect<CipherException.Locked> { e.getSettings() }

        expect<CipherException.BadCredential> { e.unlockVaultWithPin("000111") }
        assertEquals(LockStateFfi.LOCKED, e.status().state)
        e.unlockVaultWithPin("739104")
        assertEquals(LockStateFfi.UNLOCKED, e.status().state)

        // "Restart": a brand-new engine over the same directory must come up provisioned and LOCKED.
        e.lockVault()
        val again = engine()
        s = again.status()
        assertTrue(s.provisioned && s.pinOnly)
        assertEquals(LockStateFfi.LOCKED, s.state)
        again.unlockVaultWithPin("739104")
        assertEquals(LockStateFfi.UNLOCKED, again.status().state)
    }

    @Test fun backgroundDropsKeysAndRequiresUnlock() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        e.onBackground()
        expect<CipherException.Locked> { e.listContacts() }
        e.onForeground()
        expect<CipherException.Locked> { e.listContacts() } // foregrounding alone never unlocks
        e.unlockVaultWithPin("739104")
        assertTrue(e.listContacts().isEmpty())
    }

    @Test fun weakAndHostilePinsAreRejectedBeforeAnythingIsCreated() {
        val e = engine()
        for (bad in listOf("", "1", "12345", "111111", "123456789".repeat(100), "\u0000\u0000\u0000\u0000\u0000\u0000")) {
            try {
                e.provisionVaultPinOnly(bad)
                fail("accepted hostile PIN of length ${bad.length}")
            } catch (_: CipherException) {
            }
            assertFalse("a rejected PIN must not leave a half-provisioned vault", e.status().provisioned)
        }
    }

    @Test fun repeatedWrongPinsAreRateLimited() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        e.lockVault()
        var limited = false
        for (i in 0 until 12) {
            try {
                e.unlockVaultWithPin("00000$i")
            } catch (x: CipherException.RateLimited) {
                limited = true
                assertTrue(x.retryAfterSecs > 0uL)
                break
            } catch (_: CipherException.BadCredential) {
            }
        }
        assertTrue("brute force was never throttled", limited)
        // Even the right PIN is refused while throttled (no oracle).
        expect<CipherException.RateLimited> { e.unlockVaultWithPin("739104") }
    }

    @Test fun vaultFileNeverContainsThePin() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        e.lockVault()
        val bytes = dir.walkTopDown().filter {
            it.isFile
        }.flatMap { it.readBytes().asSequence().windowed(6).map { w -> String(w.toByteArray(), Charsets.ISO_8859_1) } }
        assertFalse(bytes.any { it == "739104" })
    }

    @Test fun lostDeviceKeyFailsClosedAndNeverWipesTheVault() {
        val e = engine()
        e.provisionVault() // device-key vault (user auth disabled for this test)
        e.lockVault()
        val vaultFiles = dir.walkTopDown().filter { it.isFile }.map { it.length() }.sum()
        assertTrue(vaultFiles > 0)
        cleanAliases() // simulates: key invalidated / app reinstalled (the Keystore entry is gone, the file is not)
        try {
            engine().unlockVaultWithDeviceAuth()
            fail("unlocked without the hardware key")
        } catch (_: CipherException) {
        }
        assertEquals(
            "a key failure must never delete user data",
            vaultFiles,
            dir.walkTopDown().filter {
                it.isFile
            }.map { it.length() }.sum()
        )
    }

    @Test fun malformedIdentifiersAreRejectedAtTheBoundary() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        for (bad in listOf("", "xyz", "0".repeat(31), "0".repeat(33), "g".repeat(32), "../../etc/passwd", "\u0000".repeat(32))) {
            try {
                e.getConversation(bad)
                fail("accepted id '$bad'")
            } catch (_: CipherException.InvalidInput) {
            }
        }
        try {
            e.addContactByCipherId("CIPH-NOPE", "x")
            fail()
        } catch (_: CipherException) {
        }
    }

    /** FR-05 on the real stack: real native library + real Android Keystore counter. */
    @Test fun restoringAnOlderCopyOfTheVaultIsRefusedAsRolledBack() {
        val e = engine()
        e.provisionVaultPinOnly("739104")
        e.lockVault()
        val vaultFile = File(dir, "vault.db")
        val old = vaultFile.readBytes() // the attacker's copy of the files
        repeat(2) {
            val x = engine()
            x.unlockVaultWithPin("739104")
            x.lockVault()
        }
        vaultFile.writeBytes(old)
        val victim = engine()
        expect<CipherException.RolledBack> { victim.unlockVaultWithPin("739104") }
        assertEquals(LockStateFfi.INVALIDATED, victim.status().state)
        expect<CipherException.Invalidated> { victim.listConversations() }
    }
}
