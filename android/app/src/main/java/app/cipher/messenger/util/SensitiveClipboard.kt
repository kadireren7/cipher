package app.cipher.messenger.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copying plaintext to the system clipboard exposes it to other apps and keyboards, so it is opt-in per action, flagged as
 * sensitive (hides it from the clipboard preview on Android 13+), and cleared after 60 seconds if still ours.
 */
object SensitiveClipboard {
    private const val CLEAR_AFTER_MS = 60_000L
    private var token = 0L

    fun copy(context: Context, label: String, text: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        val mine = ++token
        Handler(Looper.getMainLooper()).postDelayed({
            if (mine == token) {
                if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.P
                ) {
                    cm.clearPrimaryClip()
                } else {
                    cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }, CLEAR_AFTER_MS)
    }
}
