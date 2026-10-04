package app.cipher.messenger

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.cipher.messenger.data.EngineHost
import app.cipher.messenger.notify.NotificationHelper
import java.lang.ref.WeakReference

class CipherApplication : Application() {
    lateinit var host: EngineHost
        private set

    private var resumed: WeakReference<FragmentActivity>? = null

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.ensureChannel(this)
        host = EngineHost(this) { resumed?.get() }

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity is FragmentActivity) resumed = WeakReference(activity)
            }

            override fun onActivityPaused(activity: Activity) {
                if (resumed?.get() === activity) resumed = null
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        })

        // Keys are dropped the moment the app leaves the foreground; coming back requires a fresh unlock.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) = host.onBackground()

            override fun onStart(owner: LifecycleOwner) = host.onForeground()
        })

        // Device screen lock -> lock Cipher immediately.
        registerReceiver(
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == Intent.ACTION_SCREEN_OFF) host.onScreenOff()
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            Context.RECEIVER_NOT_EXPORTED,
        )
    }
}
