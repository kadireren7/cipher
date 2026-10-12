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

    /** What kind of call a [net] line describes. Never a path, id or host. */
    enum class NetKind { API, BLOB }

    /** How a call ended. */
    enum class NetOutcome { OK, TIMEOUT, ROUTE_UNAVAILABLE, TLS, NETWORK, IO, OTHER }

    fun event(code: Code, n: Int = 0) {
        Log.i("Cipher", "${code.name} $n")
    }

    /** One line per HTTP call: closed enums plus integers only (sequence number, bytes, milliseconds, consecutive failures of that kind). */
    fun net(kind: NetKind, outcome: NetOutcome, seq: Int, bytes: Int, ms: Int, failsInRow: Int) {
        Log.i("Cipher", "NET ${kind.name} ${outcome.name} seq=$seq bytes=$bytes ms=$ms failsInRow=$failsInRow")
    }
}
