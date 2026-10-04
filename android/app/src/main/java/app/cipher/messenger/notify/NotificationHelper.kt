package app.cipher.messenger.notify

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import app.cipher.messenger.MainActivity
import app.cipher.messenger.R
import uniffi.cipher_ffi.isValidWakePayload

/**
 * Notifications. The text always comes from the Rust policy (`NotificationFfi`): the default mode shows only "New message".
 * Every notification is VISIBILITY_SECRET on the lock screen, with a generic public version, whatever the privacy mode.
 */
object NotificationHelper {
    const val CHANNEL = "messages"

    fun ensureChannel(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        val ch = NotificationChannel(CHANNEL, ctx.getString(R.string.channel_messages), NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = ctx.getString(R.string.channel_messages_desc)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            setShowBadge(false)
        }
        nm.createNotificationChannel(ch)
    }

    fun show(ctx: Context, title: String, body: String) {
        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val open = PendingIntent.getActivity(
            ctx,
            0,
            Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val generic = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher_fg)
            .setContentTitle(ctx.getString(R.string.notif_title))
            .setContentText(ctx.getString(R.string.notif_body))
            .build()
        val n = NotificationCompat.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher_fg)
            .setContentTitle(title)
            .setContentText(body)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPublicVersion(generic)
            .setAutoCancel(true)
            .setContentIntent(open)
            .setOnlyAlertOnce(true)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(1, n)
    }
}

/**
 * Entry point for a content-free wake-up (from FCM/UnifiedPush once a push provider is configured — see SECURITY TODO ST-017).
 * While the vault is locked the app cannot even authenticate to the relay, so a wake can only produce the generic notification.
 */
object WakeHandler {
    fun onWake(ctx: Context, payload: String, appInForeground: Boolean): Boolean {
        if (!isValidWakePayload(payload)) return false // fail closed: anything but the exact constant payload is ignored
        if (!appInForeground) NotificationHelper.show(ctx, ctx.getString(R.string.notif_title), ctx.getString(R.string.notif_body))
        return true
    }
}
