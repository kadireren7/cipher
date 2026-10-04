package app.cipher.messenger.net

import java.io.File
import java.net.Proxy
import okhttp3.OkHttpClient

/** DEBUG ONLY: lets developers run against a local relay without a privacy proxy, and only with an explicit marker file. Not compiled into release. */
object DirectDevRoute {
    fun enabled(dir: File): Boolean = File(dir, "allow_direct_dev").exists()

    fun configure(b: OkHttpClient.Builder) {
        b.proxy(Proxy.NO_PROXY)
    }
}
