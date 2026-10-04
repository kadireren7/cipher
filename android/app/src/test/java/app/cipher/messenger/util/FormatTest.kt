package app.cipher.messenger.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.cipher_ffi.CipherException

class FormatTest {
    @Test fun sizesUseHonestUnits() {
        assertEquals("0 B", formatSize(0uL))
        assertEquals("1023 B", formatSize(1023uL))
        assertEquals("1 KB", formatSize(1024uL))
        assertEquals("1.0 MB", formatSize(1024uL * 1024uL))
    }

    @Test fun durationsAreMinutesAndSeconds() {
        assertEquals("0:00", formatDuration(null))
        assertEquals("0:01", formatDuration(1500u))
        assertEquals("1:05", formatDuration(65_000u))
    }

    @Test fun initialsAreSafeForOddNames() {
        assertEquals("?", initials(""))
        assertEquals("?", initials("   "))
        assertEquals("AL", initials("alice"))
        assertEquals("AB", initials("alice  bob carol"))
    }

    /** Error text must never echo caller-controlled values other than the closed `what` labels produced by the Rust core. */
    @Test fun humanizedErrorsAreStaticAndNeverLeakDetails() {
        val locked = humanize(CipherException.Locked())
        assertEquals("Cipher is locked.", locked)
        assertTrue(humanize(CipherException.RateLimited(30uL)).contains("30"))
        assertFalse(humanize(CipherException.Internal()).contains("panic", ignoreCase = true))
        assertEquals("Something went wrong.", humanize(IllegalStateException("secret-token-123")))
    }
}
