package app.cipher.messenger.security

import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import uniffi.cipher_ffi.KeystoreFault

/**
 * Presents the system BiometricPrompt for a Keystore-bound `Cipher` (CryptoObject) and blocks the CALLING (engine) thread until
 * the user authenticates, cancels or fails. Must never be called on the main thread.
 *
 * The prompt is rendered by the OS (not capturable by apps, immune to overlay tricks) and releases the hardware key operation only
 * on a successful strong biometric or device-credential authentication. Cancelling yields `AuthCancelled`: nothing is unlocked.
 */
class BiometricGate(private val activityProvider: () -> FragmentActivity?) {
    fun authenticate(cipher: Cipher): Cipher {
        check(Looper.myLooper() != Looper.getMainLooper()) { "authenticate() must run off the main thread" }
        val activity = activityProvider() ?: throw KeystoreFault.AuthRequired()
        val latch = CountDownLatch(1)
        var outcome: Result<Cipher> = Result.failure(KeystoreFault.AuthRequired())

        activity.runOnUiThread {
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        outcome = Result.success(result.cryptoObject?.cipher ?: cipher)
                        latch.countDown()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        outcome = Result.failure(
                            when (errorCode) {
                                BiometricPrompt.ERROR_USER_CANCELED,
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                                BiometricPrompt.ERROR_CANCELED,
                                ->
                                    KeystoreFault.AuthCancelled()
                                BiometricPrompt.ERROR_NO_BIOMETRICS,
                                BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                                BiometricPrompt.ERROR_HW_NOT_PRESENT,
                                BiometricPrompt.ERROR_HW_UNAVAILABLE,
                                BiometricPrompt.ERROR_LOCKOUT,
                                BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                                -> KeystoreFault.AuthRequired()
                                else -> KeystoreFault.Unavailable()
                            },
                        )
                        latch.countDown()
                    }
                    // onAuthenticationFailed (a non-matching finger): the system keeps the prompt open; nothing to do.
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Cipher")
                .setSubtitle("Confirm it's you")
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .setConfirmationRequired(false)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
        if (!latch.await(120, TimeUnit.SECONDS)) throw KeystoreFault.AuthCancelled()
        return outcome.getOrThrow()
    }
}
