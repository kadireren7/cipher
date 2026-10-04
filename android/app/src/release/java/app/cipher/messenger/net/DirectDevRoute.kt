package app.cipher.messenger.net

import java.io.File
import okhttp3.OkHttpClient

/** RELEASE: the direct route does not exist. There is no switch, marker file or setting that can turn it on. */
object DirectDevRoute {
    @Suppress("UNUSED_PARAMETER")
    fun enabled(dir: File): Boolean = false

    @Suppress("UNUSED_PARAMETER")
    fun configure(b: OkHttpClient.Builder): Unit = throw IllegalStateException("no direct route in release builds")
}
