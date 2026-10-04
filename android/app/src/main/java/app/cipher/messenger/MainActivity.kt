package app.cipher.messenger

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.cipher.messenger.media.AnonymousTempFile
import app.cipher.messenger.ui.CipherRoot

/** The single activity. All sensitive content lives inside it, and it inherits FLAG_SECURE from [SecureActivity]. */
class MainActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        AnonymousTempFile.sweep(this)
        setContent { CipherRoot() }
        hardenRoot()
    }

    override fun onStop() {
        super.onStop()
        AnonymousTempFile.sweep(this)
    }
}
