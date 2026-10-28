package app.cipher.messenger.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.AttachmentViewFfi
import uniffi.cipher_ffi.DeliveryStateFfi
import uniffi.cipher_ffi.MessageFfi

class ChatSearchTest {
    private fun msg(text: String, att: AttachmentViewFfi? = null, unavailable: Boolean = false) =
        MessageFfi("1", "c", false, "a", "A", 0uL, null, text, att, DeliveryStateFfi.RECEIVED, unavailable)

    @Test fun matchesTextCaseInsensitively() {
        assertTrue(ChatViewModel.matches(msg("Meet at the Station"), "station"))
        assertFalse(ChatViewModel.matches(msg("Meet at the Station"), "airport"))
    }

    @Test fun matchesAttachmentFileNames() {
        val pdf = AttachmentViewFfi(AttachmentKindFfi.PDF, "application/pdf", "Itinerary.pdf", 10uL, false, null)
        assertTrue(ChatViewModel.matches(msg("", pdf), "itinerary"))
    }

    @Test fun unavailableMessagesNeverMatch() {
        assertFalse(ChatViewModel.matches(msg("secret", unavailable = true), "secret"))
    }
}
