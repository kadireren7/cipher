package app.cipher.messenger.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OnboardingPlanTest {
    @Test fun aCompleteDefaultRelaySkipsTheServerStep() {
        assertTrue(OnboardingPlan.hasDefaultRelay("https://relay.example.org", "ABCD2345EFGH"))
        assertTrue(OnboardingPlan.hasDefaultRelay("https://relay.example.org:8443", "  ABCD2345  "))
    }

    @Test fun anIncompleteOrUnsafeDefaultKeepsTheServerStep() {
        assertFalse("release builds ship no default relay", OnboardingPlan.hasDefaultRelay("", ""))
        assertFalse("no invitation code", OnboardingPlan.hasDefaultRelay("https://relay.example.org", ""))
        assertFalse("invitation code too short", OnboardingPlan.hasDefaultRelay("https://relay.example.org", "short"))
        assertFalse("never cleartext", OnboardingPlan.hasDefaultRelay("http://relay.example.org", "ABCD2345EFGH"))
        assertFalse("bare scheme", OnboardingPlan.hasDefaultRelay("https://", "ABCD2345EFGH"))
        assertFalse(
            "a debug build's emulator address without an invite is not 'easy'",
            OnboardingPlan.hasDefaultRelay("https://10.0.2.2:8443", "")
        )
    }
}
