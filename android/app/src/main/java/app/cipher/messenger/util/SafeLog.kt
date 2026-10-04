package app.cipher.messenger.util

import android.util.Log

/**
 * The ONLY logging entry point. It accepts a closed set of event codes and integers: free-form strings and objects are not
 * accepted by the type system, so plaintext, ids, tokens or error details cannot be logged by accident. (Ported from the retired
 * TypeScript SafeLogger.) Release builds additionally strip all `android.util.Log` calls with R8 (see proguard-rules.pro).
 */
object SafeLog {
    enum class Code {
        APP_LOCKED,
        APP_UNLOCKED,
        UNLOCK_FAILED,
        KEY_INVALIDATED,
        IDENTITY_CHANGED,
        REPLAY_REJECTED,
        SYNC_ERROR,
        RELAY_ERROR,
        UI_ERROR,
    }

    fun event(code: Code, n: Int = 0) {
        Log.i("Cipher", "${code.name} $n")
    }
}
