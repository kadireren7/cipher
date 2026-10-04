package app.cipher.messenger.util

import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import uniffi.cipher_ffi.CipherException

fun formatTime(ms: ULong): String {
    val d = Date(ms.toLong())
    val now = Calendar.getInstance()
    val then = Calendar.getInstance().apply { time = d }
    return when {
        now.get(Calendar.YEAR) == then.get(Calendar.YEAR) && now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR) ->
            DateFormat.getTimeInstance(DateFormat.SHORT).format(d)
        now.get(Calendar.YEAR) == then.get(Calendar.YEAR) -> java.text.SimpleDateFormat("d MMM", java.util.Locale.getDefault()).format(d)
        else -> DateFormat.getDateInstance(DateFormat.SHORT).format(d)
    }
}

fun formatSize(bytes: ULong): String {
    val b = bytes.toDouble()
    return when {
        b < 1024 -> "$bytes B"
        b < 1024 * 1024 -> String.format("%.0f KB", b / 1024)
        else -> String.format("%.1f MB", b / (1024 * 1024))
    }
}

fun formatDuration(ms: UInt?): String {
    val s = (ms ?: 0u).toInt() / 1000
    return "%d:%02d".format(s / 60, s % 60)
}

fun initials(name: String): String {
    val parts = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    return when {
        parts.isEmpty() -> "?"
        parts.size == 1 -> parts[0].take(2).uppercase()
        else -> (parts[0].take(1) + parts[1].take(1)).uppercase()
    }
}

/** Human-readable text for errors. Never includes anything the user typed or any key/ciphertext material. */
fun humanize(e: Throwable): String = when (e) {
    is CipherException.Locked -> "Cipher is locked."
    is CipherException.RolledBack ->
        "The Cipher data on this phone is older than the last state it recorded (for example restored from a copy). " +
            "Cipher refuses to use it: reusing old encryption state could expose messages. You can reset Cipher on this phone."
    is CipherException.Invalidated -> "Your secure keys were reset by Android (for example after a screen-lock or biometric change)."
    is CipherException.BadCredential -> "Wrong PIN."
    is CipherException.WeakPin -> "Choose a stronger PIN (at least 6 characters, not all the same)."
    is CipherException.RateLimited -> "Too many attempts. Try again in ${e.retryAfterSecs} s."
    is CipherException.Offline -> "Can't reach the server. Check your connection."
    is CipherException.Server -> "The server refused the request."
    is CipherException.IdentityUntrusted -> "This contact's identity could not be verified. Check their safety number."
    is CipherException.Unauthorized -> "Your role in this group does not allow that."
    is CipherException.Denied -> "Not allowed: ${e.what}."
    is CipherException.NotFound -> "Not found: ${e.what}."
    is CipherException.InvalidInput -> "Invalid input: ${e.what}."
    is CipherException.Attachment -> "Attachment problem: ${e.what}."
    is CipherException.KeyStore -> "This device cannot provide the required secure key storage."
    is CipherException.Corrupt -> "Local data is damaged or was tampered with."
    else -> "Something went wrong."
}
