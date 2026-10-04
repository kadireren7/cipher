package app.cipher.messenger.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import uniffi.cipher_ffi.KeyLevel
import uniffi.cipher_ffi.KeystoreCallbacks
import uniffi.cipher_ffi.KeystoreCaps
import uniffi.cipher_ffi.KeystoreFault
import uniffi.cipher_ffi.SecretSink

/**
 * Android Keystore implementation of the Rust core's `SecureKeyStore` contract.
 *
 *  - AES-256-GCM wrapping keys are generated INSIDE the Keystore and are non-exportable: this class never sees their bytes.
 *  - StrongBox is requested first; if the device has none we fall back to the TEE-backed key and REPORT the real level read back
 *    from `KeyInfo`. A software-backed key is reported as `SoftwareOrUnknown` — never as hardware.
 *  - Keys that require user authentication are used only through a BiometricPrompt CryptoObject (per use, no time window).
 *  - Errors are a closed set of `KeystoreFault`s; platform exception messages are dropped.
 *  - Nothing here logs.
 *
 * What the Rust core hands to `wrap` is a 32-byte vault key; `unwrap` returns it. That 32-byte value therefore transits JVM memory
 * for the duration of the call (and the lowering to Rust). It is never stored, logged, or passed to UI code; this is the narrowest
 * boundary Android allows because Keystore decryption necessarily returns plaintext to the app process.
 */
class AndroidKeystoreCallbacks(private val context: Context, private val gate: BiometricGate) : KeystoreCallbacks {
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun capabilities(): KeystoreCaps {
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return KeystoreCaps(
            bestLevel = if (strongBox) KeyLevel.STRONGBOX else KeyLevel.TEE,
            userAuthSupported = true,
            biometricSupported = context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) ||
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE),
        )
    }

    override fun createKey(
        alias: String,
        requireUserAuth: Boolean,
        invalidateOnBiometricChange: Boolean,
        preferStrongbox: Boolean,
    ): KeyLevel {
        try {
            if (keyStore.containsAlias(alias)) throw KeystoreFault.Unavailable()
            val canStrongBox = preferStrongbox &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            try {
                generate(alias, requireUserAuth, invalidateOnBiometricChange, strongBox = canStrongBox)
            } catch (e: StrongBoxUnavailableException) {
                // Safe fallback: TEE-backed key. The level read back below makes the downgrade visible to the core and the UI.
                generate(alias, requireUserAuth, invalidateOnBiometricChange, strongBox = false)
            }
            return levelOf(secretKey(alias))
        } catch (e: KeystoreFault) {
            throw e
        } catch (e: Exception) {
            throw map(e)
        }
    }

    private fun generate(alias: String, requireUserAuth: Boolean, invalidateOnBiometricChange: Boolean, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox) builder.setIsStrongBoxBacked(true)
        if (requireUserAuth) {
            // The key cannot be used while the device is locked; and every use needs a fresh strong-biometric or credential check.
            builder.setUnlockedDeviceRequired(true)
            builder.setUserAuthenticationRequired(true)
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
            builder.setInvalidatedByBiometricEnrollment(invalidateOnBiometricChange)
        }
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).apply { init(builder.build()) }.generateKey()
    }

    private fun secretKey(alias: String): SecretKey = try {
        keyStore.getKey(alias, null) as? SecretKey ?: throw KeystoreFault.Missing()
    } catch (e: UnrecoverableKeyException) {
        throw KeystoreFault.Invalidated()
    }

    private fun info(key: SecretKey): KeyInfo =
        SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo

    /** The level the key ACTUALLY achieved, read from the Keystore — never assumed. */
    private fun levelOf(key: SecretKey): KeyLevel {
        val i = info(key)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (i.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyLevel.TEE
                else -> KeyLevel.SOFTWARE_OR_UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (i.isInsideSecureHardware) KeyLevel.TEE else KeyLevel.SOFTWARE_OR_UNKNOWN
        }
    }

    override fun keyProtection(alias: String): KeyLevel = try {
        levelOf(secretKey(alias))
    } catch (e: KeystoreFault) {
        throw e
    } catch (e: Exception) {
        throw map(e)
    }

    /**
     * Returns iv(12) || ciphertext||tag; `aad` is authenticated and must be supplied again to unwrap.
     * `plaintext` is the 32-byte vault key (ST-027): it is ZEROED here as soon as the Keystore has used it.
     */
    override fun wrap(alias: String, plaintext: ByteArray, aad: ByteArray): ByteArray {
        try {
            val key = secretKey(alias)
            var cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
            if (info(key).isUserAuthenticationRequired) cipher = gate.authenticate(cipher)
            cipher.updateAAD(aad)
            return cipher.iv + cipher.doFinal(plaintext)
        } catch (e: KeystoreFault) {
            throw e
        } catch (e: Exception) {
            throw map(e)
        } finally {
            plaintext.fill(0)
        }
    }

    /**
     * Decrypts and hands the plaintext to [sink] (Rust memory) instead of returning it, then zeroes the JVM copy immediately.
     * Residual: JCA/Keystore-internal temporary buffers are outside our control (documented in docs/ANDROID_SECURITY.md §4).
     */
    override fun unwrapInto(alias: String, blob: ByteArray, aad: ByteArray, sink: SecretSink) {
        if (blob.size < IV_BYTES + TAG_BYTES) throw KeystoreFault.Corrupt()
        var plain: ByteArray? = null
        try {
            val key = secretKey(alias)
            val iv = blob.copyOfRange(0, IV_BYTES)
            var cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, iv))
            }
            if (info(key).isUserAuthenticationRequired) cipher = gate.authenticate(cipher)
            cipher.updateAAD(aad)
            plain = cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES)
            sink.put(plain)
        } catch (e: KeystoreFault) {
            throw e
        } catch (e: Exception) {
            throw map(e)
        } finally {
            plain?.fill(0)
        }
    }

    override fun deleteKey(alias: String) {
        try {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        } catch (e: Exception) {
            throw KeystoreFault.Unavailable()
        }
    }

    /**
     * Monotonic generation counter for local rollback detection. The value lives in the NAMES of tiny Keystore keys
     * (`cipher.gen.<n>`), i.e. in the system keystore database OUTSIDE the app's data directory, so restoring or replacing the app's files
     * cannot lower it. Honest limits: it is not hardware-protected (an attacker who can run code as the app, or root, can edit it) and
     * it does not survive an app uninstall (the vault does not either).
     */
    override fun counterRead(): ULong = try {
        generationAliases().maxOrNull()?.toULong() ?: 0uL
    } catch (e: Exception) {
        throw KeystoreFault.Unavailable()
    }

    override fun counterAdvance(to: ULong) {
        try {
            val cur = generationAliases().maxOrNull() ?: 0L
            if (to.toLong() <= cur || to > Long.MAX_VALUE.toULong()) return
            generate("$GEN_PREFIX$to", requireUserAuth = false, invalidateOnBiometricChange = false, strongBox = false)
            generationAliases().filter { it < to.toLong() }.forEach { keyStore.deleteEntry("$GEN_PREFIX$it") }
        } catch (e: Exception) {
            throw KeystoreFault.Unavailable()
        }
    }

    private fun generationAliases(): List<Long> =
        keyStore.aliases().toList().filter { it.startsWith(GEN_PREFIX) }.mapNotNull { it.removePrefix(GEN_PREFIX).toLongOrNull() }

    private fun map(e: Exception): KeystoreFault = when (e) {
        is KeyPermanentlyInvalidatedException -> KeystoreFault.Invalidated()
        is UserNotAuthenticatedException -> KeystoreFault.AuthRequired()
        is AEADBadTagException -> KeystoreFault.Corrupt()
        else -> KeystoreFault.Unavailable() // deliberately drops the platform message: it could carry details
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val GEN_PREFIX = "cipher.gen."
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BYTES = 16
    }
}
