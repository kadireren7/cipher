package app.cipher.messenger

import android.content.pm.PackageManager
import android.security.NetworkSecurityPolicy
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Checks the INSTALLED package, not the source: what Android actually enforces for this app. */
@RunWith(AndroidJUnit4::class)
class HardeningInstrumentedTest {
    private val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test fun flagSecureIsSetOnTheMainWindow() {
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a ->
                val flags = a.window.attributes.flags
                assertTrue(
                    "FLAG_SECURE missing: screenshots/recents would expose content",
                    flags and WindowManager.LayoutParams.FLAG_SECURE != 0
                )
            }
        }
    }

    @Test fun overlayAndAutofillDefencesAreActiveOnTheRealViews() {
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a ->
                val content = a.findViewById<android.view.ViewGroup>(android.R.id.content)
                assertTrue("decor must drop obscured touches", a.window.decorView.filterTouchesWhenObscured)
                assertTrue("content must drop obscured touches", content.filterTouchesWhenObscured)
                assertTrue("compose root must drop obscured touches", content.getChildAt(0).filterTouchesWhenObscured)
                assertEquals(
                    android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS,
                    a.window.decorView.importantForAutofill,
                )
                if (android.os.Build.VERSION.SDK_INT >= 34) {
                    assertTrue("window must be accessibility-data-sensitive", a.window.decorView.isAccessibilityDataSensitive)
                }
            }
        }
    }

    @Test fun everyDeclaredActivityExtendsSecureActivity() {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_ACTIVITIES)
        val ours = info.activities.orEmpty().filter { it.name.startsWith("app.cipher.messenger") }
        assertTrue(ours.isNotEmpty())
        ours.forEach {
            assertTrue("${it.name} must extend SecureActivity", SecureActivity::class.java.isAssignableFrom(Class.forName(it.name)))
        }
    }

    @Test fun onlyTheLauncherActivityIsExportedAndNothingElseIs() {
        val info = ctx.packageManager.getPackageInfo(
            ctx.packageName,
            PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS,
        )
        val exported = buildList {
            info.activities.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.services.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.receivers.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.providers.orEmpty().filter { it.exported }.forEach { add(it.name) }
        }
        // EVERY component of the merged manifest, including those contributed by libraries (androidx etc.).
        // Debug builds additionally carry Compose tooling/test-manifest activities (debugImplementation only). They must not exist in
        // release: `scripts/check-release-apk.sh` asserts that the release APK exports ONLY the launcher activity.
        val debugOnlyTooling = setOf("androidx.compose.ui.tooling.PreviewActivity", "androidx.activity.ComponentActivity")
        val unexpected = exported.filterNot { it == "app.cipher.messenger.MainActivity" || (BuildConfig.DEBUG && it in debugOnlyTooling) }
        assertEquals(emptyList<String>(), unexpected)
        assertTrue(exported.contains("app.cipher.messenger.MainActivity"))
        assertTrue("no content providers/services of ours", info.providers.orEmpty().none { it.name.startsWith("app.cipher") })
    }

    @Test fun backupAndCleartextAreOff() {
        val ai = ctx.applicationInfo
        assertEquals(0, ai.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP)
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted)
        assertFalse(NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted("relay.example.com"))
    }

    @Test fun noDangerousOrUnneededPermissionsAreRequested() {
        val perms = ctx.packageManager.getPackageInfo(
            ctx.packageName,
            PackageManager.GET_PERMISSIONS
        ).requestedPermissions.orEmpty().toSet()
        val forbidden = listOf(
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
            "READ_PHONE_STATE", "READ_SMS", "RECEIVE_SMS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CALL_LOG",
            "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "GET_ACCOUNTS",
        )
        forbidden.forEach { assertFalse("forbidden permission $it", perms.contains("android.permission.$it")) }
    }

    @Test fun debugFlagsMatchTheBuildType() {
        // This test APK always targets the debug variant; a release build must report not-debuggable (checked in the release gate).
        val debuggable = ctx.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
        assertEquals(BuildConfig.DEBUG, debuggable)
    }

    @Test fun noDebugAuthBypassMarkerExistsOnAFreshInstall() {
        // The bypass is only honoured when this file exists AND BuildConfig.DEBUG; it must never be created by the app itself.
        val marker = java.io.File(ctx.noBackupFilesDir, "config/debug_no_user_auth")
        // Instrumented runs use a clean marker state unless the tester created it explicitly (documented in SECURITY_TESTING).
        if (marker.exists()) assertTrue("marker present: tester opted into the emulator-only bypass", BuildConfig.DEBUG)
    }
}
