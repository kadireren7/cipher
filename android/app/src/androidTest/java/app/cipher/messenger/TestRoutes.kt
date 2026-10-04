package app.cipher.messenger

import android.content.Context
import app.cipher.messenger.net.OkHttpCallbacks
import app.cipher.messenger.net.RouteConfig
import app.cipher.messenger.net.RouteTracker
import app.cipher.messenger.net.SocksEndpoint
import java.io.File

/** Test-only route builders (debug test APK). The direct route exists only because the DEBUG source set provides it and a marker file opts in. */
object TestRoutes {
    private fun tracker() = RouteTracker({ System.currentTimeMillis() }, { true })

    fun direct(ctx: Context): OkHttpCallbacks {
        val dir = File(ctx.cacheDir, "route-${System.nanoTime()}").apply { mkdirs() }
        File(dir, "allow_direct_dev").writeText("1")
        return OkHttpCallbacks(RouteConfig(dir), tracker())
    }

    fun socks(ctx: Context, endpoint: SocksEndpoint): Pair<OkHttpCallbacks, RouteTracker> {
        val dir = File(ctx.cacheDir, "route-${System.nanoTime()}").apply { mkdirs() }
        RouteConfig(dir).setSocks(endpoint)
        val t = tracker()
        return OkHttpCallbacks(RouteConfig(dir), t) to t
    }
}
