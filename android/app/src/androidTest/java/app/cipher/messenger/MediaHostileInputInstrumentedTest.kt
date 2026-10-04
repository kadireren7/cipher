package app.cipher.messenger

import android.graphics.Bitmap
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.cipher.messenger.media.SafeDecode
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.zip.CRC32
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** FR-06: media sent by a contact is attacker-controlled. These run the REAL platform decoders on the emulator. */
@RunWith(AndroidJUnit4::class)
class MediaHostileInputInstrumentedTest {
    private fun chunk(type: String, data: ByteArray): ByteArray {
        val crc = CRC32().apply {
            update(type.toByteArray())
            update(data)
        }
        return ByteBuffer.allocate(12 + data.size)
            .putInt(data.size).put(type.toByteArray()).put(data).putInt(crc.value.toInt()).array()
    }

    /** A ~70-byte PNG whose header declares [w] x [h] pixels (a decompression-bomb header). */
    private fun pngHeaderOnly(w: Int, h: Int): ByteArray {
        val ihdr = ByteBuffer.allocate(13).putInt(w).putInt(h).put(8).put(2).put(0).put(0).put(0).array()
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A))
        out.write(chunk("IHDR", ihdr))
        out.write(chunk("IEND", ByteArray(0)))
        return out.toByteArray()
    }

    @Test fun aDecompressionBombThumbnailIsRefusedQuicklyWithoutExhaustingMemory() {
        val bomb = pngHeaderOnly(30_000, 30_000)
        assertTrue("the bomb itself is tiny", bomb.size < 200)
        val t0 = System.nanoTime()
        assertNull(SafeDecode.bitmap(bomb, 640))
        assertTrue("refusal must be fast", (System.nanoTime() - t0) / 1_000_000 < 2_000)
    }

    @Test fun garbageAndTruncatedImagesDoNotThrow() {
        assertNull(SafeDecode.bitmap(ByteArray(0), 640))
        assertNull(SafeDecode.bitmap(ByteArray(1000) { (it * 31).toByte() }, 640))
        val png = pngHeaderOnly(100, 100) // header without pixel data
        SafeDecode.bitmap(png, 640) // may be null; must not throw
    }

    @Test fun aLegitimateImageIsStillDecodedAndSubSampled() {
        val bmp = Bitmap.createBitmap(2000, 1000, Bitmap.Config.ARGB_8888).also { it.eraseColor(0xFF3366CC.toInt()) }
        val bytes = ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
        val decoded = SafeDecode.bitmap(bytes, 640)
        assertNotNull(decoded)
        assertTrue("longest side must fit the display size", maxOf(decoded!!.width, decoded.height) <= 1000)
        assertTrue(decoded.width < 2000)
    }
}
