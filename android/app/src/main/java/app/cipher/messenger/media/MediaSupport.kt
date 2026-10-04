package app.cipher.messenger.media

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.pdf.PdfRenderer
import android.media.MediaDataSource
import android.media.MediaMetadataRetriever
import android.media.MediaRecorder
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom
import kotlin.concurrent.thread

/** Thumbnails are generated LOCALLY, kept in memory only, and encrypted by the Rust core like any attachment. */
object ThumbnailMaker {
    private const val MAX_BYTES = 120 * 1024

    private fun jpeg(bmp: Bitmap): ByteArray {
        var q = 70
        while (true) {
            val out = ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.JPEG, q, out)
            if (out.size() <= MAX_BYTES || q <= 20) return out.toByteArray()
            q -= 15
        }
    }

    private fun scaled(src: Bitmap, max: Int = 320): Bitmap {
        val s = max.toFloat() / maxOf(src.width, src.height)
        return if (s >=
            1f
        ) {
            src
        } else {
            Bitmap.createScaledBitmap(src, (src.width * s).toInt().coerceAtLeast(1), (src.height * s).toInt().coerceAtLeast(1), true)
        }
    }

    fun forImage(ctx: Context, uri: Uri): ByteArray? = runCatching {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        ctx.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        val sample = maxOf(1, maxOf(bounds.outWidth, bounds.outHeight) / 640)
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        ctx.contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }?.let { jpeg(scaled(it)) }
    }.getOrNull()

    fun forVideo(ctx: Context, uri: Uri): ByteArray? = runCatching {
        val r = MediaMetadataRetriever()
        try {
            r.setDataSource(ctx, uri)
            r.getFrameAtTime(0)?.let { jpeg(scaled(it)) }
        } finally {
            r.release()
        }
    }.getOrNull()

    fun forPdf(ctx: Context, uri: Uri): ByteArray? = runCatching {
        ctx.contentResolver.openFileDescriptor(uri, "r")?.use { pfd ->
            PdfRenderer(pfd).use { r ->
                r.openPage(0).use { page ->
                    val w = 320
                    val h = (w * page.height.toFloat() / page.width).toInt().coerceAtLeast(1)
                    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888).also { it.eraseColor(android.graphics.Color.WHITE) }
                    page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                    jpeg(bmp)
                }
            }
        }
    }.getOrNull()
}

/** MediaPlayer data source over an in-memory byte array: decrypted audio/video never touches disk. */
class BytesMediaDataSource(private val bytes: ByteArray) : MediaDataSource() {
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int {
        if (position >= bytes.size) return -1
        val n = minOf(size, bytes.size - position.toInt())
        System.arraycopy(bytes, position.toInt(), buffer, offset, n)
        return n
    }

    override fun getSize(): Long = bytes.size.toLong()

    override fun close() = Unit
}

/**
 * PdfRenderer needs a seekable file descriptor. We write the decrypted PDF into an app-private file, open it, and UNLINK it
 * immediately: the data has no path any more and disappears when the descriptor is closed (which also overwrites it with zeros
 * first). Limits (documented): the bytes briefly exist in the page cache / storage of the app's own sandbox, which Android's
 * file-based encryption protects at rest; flash wear-levelling means we cannot promise secure erase.
 */
class AnonymousTempFile private constructor(private val raf: RandomAccessFile, private val length: Long) : AutoCloseable {
    val descriptor: ParcelFileDescriptor = ParcelFileDescriptor.dup(raf.fd)

    override fun close() {
        runCatching {
            descriptor.close()
            raf.seek(0)
            val zeros = ByteArray(64 * 1024)
            var left = length
            while (left > 0) {
                val n = minOf(left, zeros.size.toLong()).toInt()
                raf.write(zeros, 0, n)
                left -= n
            }
            raf.fd.sync()
        }
        runCatching { raf.close() }
    }

    companion object {
        fun create(ctx: Context, bytes: ByteArray): AnonymousTempFile {
            val dir = File(ctx.cacheDir, "viewer").apply { mkdirs() }
            val name = ByteArray(12).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
            val f = File(dir, "$name.bin")
            val raf = RandomAccessFile(f, "rw")
            raf.write(bytes)
            raf.fd.sync()
            f.delete() // unlink NOW: no path remains
            return AnonymousTempFile(raf, bytes.size.toLong())
        }

        /** Remove anything left by a crash. */
        fun sweep(ctx: Context) {
            File(ctx.cacheDir, "viewer").listFiles()?.forEach { it.delete() }
        }
    }
}

/**
 * Voice notes: MediaRecorder writes AAC/ADTS (a streamable format) into a pipe; a reader thread collects it in MEMORY. The recording
 * never exists as a plaintext file. Max length 5 minutes.
 */
class VoiceRecorder(private val ctx: Context) {
    private var recorder: MediaRecorder? = null
    private var pipe: Array<ParcelFileDescriptor>? = null
    private var reader: Thread? = null
    private val sink = ByteArrayOutputStream()
    private var startedAt = 0L

    fun start() {
        val p = ParcelFileDescriptor.createPipe()
        pipe = p
        val r = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(ctx)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }
        r.setAudioSource(MediaRecorder.AudioSource.MIC)
        r.setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS)
        r.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        r.setAudioEncodingBitRate(48_000)
        r.setAudioSamplingRate(32_000)
        r.setMaxDuration(5 * 60 * 1000)
        r.setOutputFile(p[1].fileDescriptor)
        r.prepare()
        sink.reset()
        reader = thread(name = "voice-reader") {
            ParcelFileDescriptor.AutoCloseInputStream(p[0]).use { input ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    synchronized(sink) { sink.write(buf, 0, n) }
                }
            }
        }
        r.start()
        recorder = r
        startedAt = System.currentTimeMillis()
    }

    /** Stops and returns (audio, durationMs); the audio only exists in memory. */
    fun stop(): Pair<ByteArray, Int>? {
        val r = recorder ?: return null
        val dur = (System.currentTimeMillis() - startedAt).toInt()
        runCatching { r.stop() }
        r.release()
        recorder = null
        runCatching { pipe?.get(1)?.close() }
        reader?.join(2000)
        pipe = null
        val bytes = synchronized(sink) { sink.toByteArray().also { sink.reset() } }
        return if (bytes.isEmpty() || dur < 500) null else bytes to dur
    }

    /** Abort and discard everything. */
    fun cancel() {
        recorder?.let {
            runCatching { it.stop() }
            it.release()
        }
        recorder = null
        runCatching { pipe?.get(1)?.close() }
        reader?.join(1000)
        pipe = null
        synchronized(sink) { sink.reset() }
    }
}

/**
 * Decoding of ATTACKER-CONTROLLED images (a contact's thumbnail or attachment). A small file can declare enormous dimensions
 * ("decompression bomb"); decoding it at full size throws OutOfMemoryError, which crashed the app every time the conversation was opened
 * (a message-triggered crash loop). The header is therefore checked first, decoding is sub-sampled to the display size, and every
 * failure — including OOM — yields `null` ("can't display"). Final-review finding FR-06.
 */
object SafeDecode {
    /** Largest SOURCE image we will even try to sub-sample (width x height). Anything bigger is refused outright. */
    const val MAX_SOURCE_PIXELS = 100_000_000L

    /** Returns the sub-sample factor for [w] x [h] so that the longest side is at most [maxDim], or null if the image is refused. */
    fun sampleSizeFor(w: Int, h: Int, maxDim: Int): Int? {
        if (w <= 0 || h <= 0 || maxDim <= 0) return null
        if (w.toLong() * h.toLong() > MAX_SOURCE_PIXELS) return null
        var sample = 1
        while (maxOf(w, h) / sample > maxDim) sample *= 2
        return sample
    }

    fun bitmap(bytes: ByteArray, maxDim: Int): Bitmap? {
        return try {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
            val sample = sampleSizeFor(bounds.outWidth, bounds.outHeight, maxDim) ?: return null
            val opts = BitmapFactory.Options().apply {
                inSampleSize = sample
                inPreferredConfig = Bitmap.Config.RGB_565 // half the memory; thumbnails and previews do not need alpha precision
            }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
        } catch (_: Throwable) {
            null // includes OutOfMemoryError
        }
    }
}
