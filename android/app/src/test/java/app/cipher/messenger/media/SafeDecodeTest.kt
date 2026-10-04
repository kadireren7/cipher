package app.cipher.messenger.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SafeDecodeTest {
    @Test fun normalImagesAreSampledDownToTheDisplaySize() {
        assertEquals(1, SafeDecode.sampleSizeFor(640, 480, 640))
        assertEquals(2, SafeDecode.sampleSizeFor(1280, 720, 640))
        assertEquals(8, SafeDecode.sampleSizeFor(4000, 3000, 640))
    }

    @Test fun decompressionBombsAndNonsenseHeadersAreRefused() {
        assertNull(SafeDecode.sampleSizeFor(30_000, 30_000, 640)) // 900 MP declared by a tiny file
        assertNull(SafeDecode.sampleSizeFor(Int.MAX_VALUE, Int.MAX_VALUE, 640)) // must not overflow into "small"
        assertNull(SafeDecode.sampleSizeFor(0, 100, 640))
        assertNull(SafeDecode.sampleSizeFor(-5, 100, 640))
        assertNull(SafeDecode.sampleSizeFor(100, 100, 0))
    }
}
