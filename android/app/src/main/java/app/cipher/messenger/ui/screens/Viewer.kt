package app.cipher.messenger.ui.screens

import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.media.MediaPlayer
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.media.AnonymousTempFile
import app.cipher.messenger.media.BytesMediaDataSource
import app.cipher.messenger.media.SafeDecode
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.util.formatSize
import app.cipher.messenger.util.humanize
import kotlinx.coroutines.delay
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.MessageFfi

private sealed interface Loaded {
    data object Loading : Loaded

    class Ready(val msg: MessageFfi, val bytes: ByteArray) : Loaded

    class Failed(val text: String) : Loaded
}

/**
 * Decrypts the attachment IN MEMORY, verifies it, and renders it without ever exporting it. There is deliberately no "save" or
 * "share" action: that would move plaintext out of the vault. The window is FLAG_SECURE (no screenshots / screen recording).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ViewerScreen(conv: String, msgId: String, vm: AppViewModel, onBack: () -> Unit) {
    var progress by remember { mutableFloatStateOf(0f) }
    val loaded by produceState<Loaded>(Loaded.Loading, conv, msgId) {
        value = try {
            val (m, bytes) = vm.host.call { e ->
                val m = e.getMessage(conv, msgId) ?: error("missing")
                val cb = object : uniffi.cipher_ffi.ProgressCallback {
                    override fun onProgress(done: ULong, total: ULong): Boolean {
                        progress = if (total == 0uL) 0f else (done.toDouble() / total.toDouble()).toFloat().coerceIn(0f, 1f)
                        return true
                    }
                }
                m to e.openAttachment(conv, msgId, false, cb)
            }
            Loaded.Ready(m, bytes)
        } catch (e: Exception) {
            Loaded.Failed(humanize(e))
        }
    }
    DisposableEffect(loaded) { onDispose { (loaded as? Loaded.Ready)?.bytes?.fill(0) } }

    Scaffold(
        containerColor = Color.Black,
        topBar = {
            TopAppBar(
                title = { Text((loaded as? Loaded.Ready)?.msg?.attachment?.filename ?: "Attachment") },
                navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) },
            )
        },
    ) { pad ->
        Box(Modifier.fillMaxSize().padding(pad), contentAlignment = Alignment.Center) {
            when (val l = loaded) {
                Loaded.Loading -> Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(12.dp))
                    LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth(0.6f))
                    Text("Decrypting…", color = Color.White, modifier = Modifier.padding(top = 8.dp))
                }
                is Loaded.Failed -> Banner("Couldn't open this attachment: ${l.text}", error = true)
                is Loaded.Ready -> when (l.msg.attachment?.kind) {
                    AttachmentKindFfi.IMAGE -> ImageView(l.bytes)
                    AttachmentKindFfi.VIDEO -> VideoView(l.bytes)
                    AttachmentKindFfi.VOICE, AttachmentKindFfi.AUDIO -> AudioView(l.bytes)
                    AttachmentKindFfi.PDF -> PdfView(l.bytes)
                    else -> Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
                        Text(l.msg.attachment?.filename ?: "File", color = Color.White, style = MaterialTheme.typography.titleMedium)
                        Text(formatSize(l.msg.attachment?.sizeBytes ?: 0uL), color = Color.LightGray)
                        Spacer(Modifier.height(12.dp))
                        Text(
                            "Cipher doesn't open unknown file types, and files never leave the encrypted store.",
                            color = Color.LightGray,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
            }
        }
    }
}

private const val MAX_PDF_PAGES = 300
private const val MAX_PDF_PAGE_HEIGHT_PX = 6000

@Composable
private fun ImageView(bytes: ByteArray) {
    val bmp = remember(bytes) { SafeDecode.bitmap(bytes, 2048) }
    if (bmp == null) {
        Text("This image can't be displayed.", color = Color.White)
    } else {
        Image(bmp.asImageBitmap(), contentDescription = "Image", contentScale = ContentScale.Fit, modifier = Modifier.fillMaxSize())
    }
}

@Composable
private fun AudioView(bytes: ByteArray) {
    var playing by remember { mutableStateOf(false) }
    var pos by remember { mutableFloatStateOf(0f) }
    // Attacker-controlled media: a malformed file must produce "can't play", never an exception inside composition (final review FR-06).
    val player = remember {
        runCatching {
            MediaPlayer().apply {
                try {
                    setDataSource(BytesMediaDataSource(bytes))
                    prepare()
                } catch (e: Throwable) {
                    release()
                    throw e
                }
            }
        }.getOrNull()
    }
    if (player == null) {
        Text("This audio can't be played.", color = Color.White)
        return
    }
    DisposableEffect(Unit) { onDispose { player.release() } }
    LaunchedEffect(playing) {
        while (playing) {
            pos = if (player.duration > 0) player.currentPosition.toFloat() / player.duration else 0f
            if (!player.isPlaying) playing = false
            delay(200)
        }
    }
    Row(Modifier.padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = {
            if (player.isPlaying) {
                player.pause()
                playing = false
            } else {
                player.start()
                playing = true
            }
        }, modifier = Modifier.size(64.dp)) {
            Icon(
                if (playing) Icons.Default.Pause else Icons.Default.PlayArrow,
                if (playing) "Pause" else "Play",
                tint = Color.White,
                modifier = Modifier.size(40.dp)
            )
        }
        LinearProgressIndicator(progress = { pos }, modifier = Modifier.fillMaxWidth().padding(start = 12.dp))
    }
}

@Composable
private fun VideoView(bytes: ByteArray) {
    val player = remember {
        runCatching {
            MediaPlayer().apply {
                try {
                    setDataSource(BytesMediaDataSource(bytes))
                } catch (e: Throwable) {
                    release()
                    throw e
                }
            }
        }.getOrNull()
    }
    if (player == null) {
        Text("This video can't be played.", color = Color.White)
        return
    }
    DisposableEffect(Unit) { onDispose { player.release() } }
    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { c ->
            SurfaceView(c).apply {
                holder.addCallback(object : SurfaceHolder.Callback {
                    override fun surfaceCreated(h: SurfaceHolder) {
                        player.setDisplay(h)
                        runCatching {
                            player.prepare()
                            player.start()
                        }
                    }

                    override fun surfaceChanged(h: SurfaceHolder, f: Int, w: Int, hh: Int) = Unit

                    override fun surfaceDestroyed(h: SurfaceHolder) {
                        player.setDisplay(null)
                    }
                })
                setOnClickListener { if (player.isPlaying) player.pause() else player.start() }
            }
        },
    )
}

@Composable
private fun PdfView(bytes: ByteArray) {
    val ctx = LocalContext.current
    val file = remember(bytes) { runCatching { AnonymousTempFile.create(ctx, bytes) }.getOrNull() }
    val renderer = remember(file) { file?.let { f -> runCatching { PdfRenderer(f.descriptor) }.getOrNull() } }
    DisposableEffect(file) {
        onDispose {
            runCatching { renderer?.close() }
            file?.close() // zero-fills, then releases the (already unlinked) file
        }
    }
    if (file == null || renderer == null) {
        Text("This PDF can't be displayed.", color = Color.White)
        return
    }
    LazyColumn(
        Modifier.fillMaxSize().background(Color(0xFF222222)),
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
    ) {
        // A hostile PDF can declare an absurd page count or page size: both are capped (FR-06).
        itemsIndexed(List(minOf(renderer.pageCount, MAX_PDF_PAGES)) { it }) { _, index ->
            val bmp by produceState<Bitmap?>(null, index) {
                value = runCatching {
                    synchronized(renderer) {
                        renderer.openPage(index).use { page ->
                            val w = 1080
                            val h = (w * page.height.toFloat() / page.width.coerceAtLeast(1)).toInt().coerceIn(1, MAX_PDF_PAGE_HEIGHT_PX)
                            Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { b ->
                                b.eraseColor(android.graphics.Color.WHITE)
                                page.render(b, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            }
                        }
                    }
                }.getOrNull()
            }
            val b = bmp
            if (b !=
                null
            ) {
                Image(
                    b.asImageBitmap(),
                    "Page ${index + 1}",
                    modifier = Modifier.fillMaxWidth().aspectRatio(
                        b.width.toFloat() / b.height
                    )
                )
            } else {
                Box(Modifier.fillMaxWidth().height(300.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            }
        }
    }
}
