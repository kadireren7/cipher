package app.cipher.messenger.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class InviteFormatTest {
    private val now = 1_000_000_000L

    @Test fun automaticAdmissionOffersOnlyTheCappedChoices() {
        assertEquals(listOf(InviteFormat.HOUR_MS, InviteFormat.DAY_MS), InviteFormat.lifetimeChoices(automatic = true))
        assertEquals(listOf(1, 5), InviteFormat.usesChoices(automatic = true))
        assertTrue(InviteFormat.lifetimeChoices(automatic = true).all { it <= InviteFormat.AUTO_MAX_LIFETIME_MS })
        assertTrue(InviteFormat.usesChoices(automatic = true).all { it <= InviteFormat.AUTO_MAX_USES })
        // approval mode offers everything, including the maximum of 7 days
        assertEquals(3, InviteFormat.lifetimeChoices(automatic = false).size)
        assertEquals(7 * InviteFormat.DAY_MS, InviteFormat.lifetimeChoices(automatic = false).max())
    }

    @Test fun labelsAreHumanAndExact() {
        assertEquals("1 hour", InviteFormat.lifetimeLabel(InviteFormat.HOUR_MS))
        assertEquals("24 hours", InviteFormat.lifetimeLabel(InviteFormat.DAY_MS))
        assertEquals("7 days", InviteFormat.lifetimeLabel(7 * InviteFormat.DAY_MS))
        assertEquals("1 person", InviteFormat.usesLabel(1))
        assertEquals("5 people", InviteFormat.usesLabel(5))
    }

    @Test fun expiryIsRelativeAndNeverNegative() {
        assertEquals("expired", InviteFormat.expiry(now, now))
        assertEquals("expired", InviteFormat.expiry(now - 1, now))
        assertEquals("expires in 1 min", InviteFormat.expiry(now + 30_000, now))
        assertEquals("expires in 10 min", InviteFormat.expiry(now + 10 * 60_000, now))
        assertEquals("expires in 3 h", InviteFormat.expiry(now + 3 * InviteFormat.HOUR_MS + 5, now))
        assertEquals("expires in 2 days", InviteFormat.expiry(now + 2 * InviteFormat.DAY_MS + 5, now))
    }

    @Test fun statusSaysWhyAnInvitationIsNoLongerUsable() {
        val later = now + InviteFormat.DAY_MS
        assertEquals("revoked", InviteFormat.status(true, later, now, 0, 5))
        assertEquals("expired", InviteFormat.status(false, now - 1, now, 0, 5))
        assertEquals("used up", InviteFormat.status(false, later, now, 5, 5))
        assertEquals("expires in 2 days", InviteFormat.status(false, now + 2 * InviteFormat.DAY_MS + 5, now, 1, 5))
        assertTrue(InviteFormat.isLive(false, later, now, 4, 5))
        assertFalse(InviteFormat.isLive(true, later, now, 0, 5))
        assertFalse(InviteFormat.isLive(false, now, now, 0, 5))
        assertFalse(InviteFormat.isLive(false, later, now, 5, 5))
    }
}
