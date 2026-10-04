package app.cipher.messenger

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity

/**
 * Base class for EVERY activity in the app (a CI guard fails the build if any manifest activity does not extend it).
 *
 * FLAG_SECURE blocks screenshots and screen recording of this window and hides its content in the Recents / app-switcher
 * thumbnail. It is set BEFORE any content is created. Limits (documented in docs/ANDROID_SECURITY.md): it does not stop another
 * camera photographing the screen, a compromised OS, or accessibility services that the user has granted.
 */
abstract class SecureActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        // Tapjacking / overlay defences: system alert windows are hidden while we are visible (API 31+, needs the normal
        // HIDE_OVERLAY_WINDOWS permission), and touches are dropped when another window obscures the view (see hardenRoot()).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            window.setHideOverlayWindows(true)
        }
        // Android 14+: only genuine accessibility TOOLS (screen readers etc.) may read this window's content; other services that merely
        // registered as accessibility services (a common malware vector) are denied. Older versions cannot make this distinction.
        if (Build.VERSION.SDK_INT >= 34) {
            window.decorView.setAccessibilityDataSensitive(android.view.View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        // No autofill service may read or fill any field of this app (typed PINs, invite codes, messages).
        window.decorView.importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    /** Call after `setContent`: ignore touches while another (possibly malicious) window is drawn over the content. */
    protected fun hardenRoot() {
        window.decorView.filterTouchesWhenObscured = true
        (findViewById<android.view.ViewGroup>(android.R.id.content)).let { content ->
            content.filterTouchesWhenObscured = true
            for (i in 0 until content.childCount) content.getChildAt(i).filterTouchesWhenObscured = true
        }
    }
}
