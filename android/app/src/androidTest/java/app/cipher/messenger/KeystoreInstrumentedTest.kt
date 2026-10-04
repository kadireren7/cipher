package app.cipher.messenger

import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.cipher.messenger.security.AndroidKeystoreCallbacks
import app.cipher.messenger.security.BiometricGate
import java.security.KeyStore
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.cipher_ffi.KeyLevel
import uniffi.cipher_ffi.KeystoreFault
import uniffi.cipher_ffi.SecretSink

/**
 * Runs the REAL Android Keystore on whatever device/emulator executes it. Nothing here is mocked.
 *
 * Honest scope: on an emulator the Keystore is software-backed, so these tests prove the wrapper's behaviour (round trip, AAD
 * binding, tamper detection, honest level reporting, restart persistence, deletion), NOT hardware isolation. Per-use biometric
 * prompts, invalidation on enrollment change and StrongBox need a physical device and are listed as NOT TESTED in the docs.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreInstrumentedTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val aliases = mutableListOf<String>()
    private lateinit var ks: AndroidKeystoreCallbacks

    @Before fun setUp() {
        ks = AndroidKeystoreCallbacks(ctx, BiometricGate { null })
    }

    @After fun cleanUp() {
        aliases.forEach { runCatching { ks.deleteKey(it) } }
    }

    /** Kotlin-side capture of what the Keystore wrapper hands to the sink (and a reference to the very array it handed over). */
    private class CaptureSink : SecretSink {
        var handedOver: ByteArray? = null
        var copy: ByteArray? = null

        override fun put(data: ByteArray) {
            handedOver = data
            copy = data.copyOf()
        }
    }

    private fun AndroidKeystoreCallbacks.unwrapBytes(alias: String, blob: ByteArray, aad: ByteArray): ByteArray {
        val sink = CaptureSink()
        unwrapInto(alias, blob, aad, sink)
        return sink.copy ?: throw KeystoreFault.Corrupt()
    }

    private fun alias() = "cipher.test.${UUID.randomUUID()}".also { aliases += it }

    @Test fun createdKeyReportsItsRealProtectionLevelNeverHigherThanTheDeviceCanDo() {
        val a = alias()
        val level = ks.createKey(a, requireUserAuth = false, invalidateOnBiometricChange = false, preferStrongbox = true)
        assertEquals("level read back later must match the creation report", level, ks.keyProtection(a))
        val hasStrongBox = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (!hasStrongBox) assertTrue("no StrongBox on this device but reported $level", level != KeyLevel.STRONGBOX)
    }

    @Test fun wrapUnwrapRoundTripsAndBindsTheAad() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val secret = ByteArray(32) { it.toByte() }
        val aad = "cipher/test/aad".toByteArray()
        val blob = ks.wrap(a, secret.copyOf(), aad) // wrap ZEROES the array it is given (ST-027), so hand it a copy
        assertFalse("blob must not contain the plaintext", blob.toList().windowed(32).any { it == secret.toList() })
        assertArrayEquals(secret, ks.unwrapBytes(a, blob, aad))
        try {
            ks.unwrapBytes(a, blob, "other".toByteArray())
            fail("wrong AAD must not decrypt")
        } catch (_: KeystoreFault) {
        }
    }

    @Test fun wrappingIsRandomised() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val s = ByteArray(32)
        assertFalse(ks.wrap(a, s, byteArrayOf()).contentEquals(ks.wrap(a, s, byteArrayOf())))
    }

    @Test fun tamperedTruncatedAndEmptyBlobsFailClosed() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val blob = ks.wrap(a, ByteArray(32) { 7 }, byteArrayOf())
        for (i in blob.indices step 5) {
            val t = blob.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            try {
                ks.unwrapBytes(a, t, byteArrayOf())
                fail("flipped byte $i was accepted")
            } catch (_: KeystoreFault) {
            }
        }
        for (cut in listOf(0, 1, 11, 27)) {
            try {
                ks.unwrapBytes(a, blob.copyOf(cut), byteArrayOf())
                fail("truncated to $cut accepted")
            } catch (_: KeystoreFault) {
            }
        }
    }

    @Test fun missingAliasAndDuplicateCreationAreDistinctSafeFaults() {
        try {
            ks.keyProtection("cipher.test.absent.${UUID.randomUUID()}")
            fail("missing key reported a level")
        } catch (e: KeystoreFault) {
            assertTrue(e is KeystoreFault.Missing)
        }
        val a = alias()
        ks.createKey(a, false, false, false)
        try {
            ks.createKey(a, false, false, false) // never silently replace an existing key
            fail("duplicate create succeeded")
        } catch (e: KeystoreFault) {
            assertTrue(e is KeystoreFault.Unavailable)
        }
    }

    @Test fun keyMaterialIsNotExportable() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(a, null)
        assertNull("Keystore keys must not expose their bytes", key.encoded)
    }

    @Test fun keySurvivesProcessStyleRestartAndDeletionIsFinal() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val blob = ks.wrap(a, ByteArray(32) { 9 }, byteArrayOf())
        val reopened = AndroidKeystoreCallbacks(ctx, BiometricGate { null }) // a fresh instance == a restarted process
        assertArrayEquals(ByteArray(32) { 9 }, reopened.unwrapBytes(a, blob, byteArrayOf()))
        reopened.deleteKey(a)
        try {
            reopened.unwrapBytes(a, blob, byteArrayOf())
            fail("deleted key still unwrapped")
        } catch (e: KeystoreFault) {
            assertTrue(e is KeystoreFault.Missing)
        }
    }

    @Test fun aliasesDoNotShareKeys() {
        val a = alias()
        val b = alias()
        ks.createKey(a, false, false, false)
        ks.createKey(b, false, false, false)
        val blob = ks.wrap(a, ByteArray(32), byteArrayOf())
        try {
            ks.unwrapBytes(b, blob, byteArrayOf())
            fail("a different key decrypted the blob")
        } catch (_: KeystoreFault) {
        }
    }

    @Test fun capabilitiesDoNotOverclaim() {
        val caps = ks.capabilities()
        if (!ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            assertTrue(caps.bestLevel != KeyLevel.STRONGBOX)
        }
    }

    /** ST-027 mitigation: the JVM copy of the vault key is zeroed right after it was handed to Rust, and `wrap` zeroes its input. */
    @Test fun theJvmCopyOfTheKeyIsZeroedAfterUnwrapAndWrap() {
        val a = alias()
        ks.createKey(a, false, false, false)
        val secret = ByteArray(32) { (it + 1).toByte() }
        val input = secret.copyOf()
        val blob = ks.wrap(a, input, byteArrayOf())
        assertTrue("wrap must zero its plaintext argument", input.all { it == 0.toByte() })
        val sink = CaptureSink()
        ks.unwrapInto(a, blob, byteArrayOf(), sink)
        assertArrayEquals("the sink received the key", secret, sink.copy)
        assertTrue("the array handed to the sink must be zeroed afterwards", sink.handedOver!!.all { it == 0.toByte() })
    }

    /** FR-05: the generation counter is monotonic, lives in the Keystore (not in app files) and can be reset only by deleting its keys. */
    @Test fun theGenerationCounterIsMonotonicAndNeverLowers() {
        val before = ks.counterRead()
        ks.counterAdvance(before + 5uL)
        assertEquals(before + 5uL, ks.counterRead())
        ks.counterAdvance(before + 2uL) // attempt to lower: ignored
        assertEquals(before + 5uL, ks.counterRead())
        ks.counterAdvance(before + 9uL)
        assertEquals(before + 9uL, ks.counterRead())
        val ksRaw = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val gens = ksRaw.aliases().toList().filter { it.startsWith("cipher.gen.") }
        assertEquals("only the newest generation key is kept", listOf("cipher.gen.${before + 9uL}"), gens)
        gens.forEach { ksRaw.deleteEntry(it) }
        assertEquals(0uL, ks.counterRead())
    }
}
