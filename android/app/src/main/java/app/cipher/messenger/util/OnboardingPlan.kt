package app.cipher.messenger.util

/**
 * Decides which first-launch path a build offers. Pure, so it is unit-testable.
 *
 * Easy path: the build carries a complete default relay (an https address and an invitation code), so the person only taps "Create my identity" and the server
 * step is skipped (it stays one tap away under "Use a different server"). Otherwise the server step is part of the flow exactly as before. A default relay is
 * a convenience, never an authority: identity and keys are created on the phone either way, and the person can pick any other relay.
 */
object OnboardingPlan {
    /** True only when the default relay is usable on its own: an https URL and an invitation code of the minimum length the relay accepts. */
    fun hasDefaultRelay(url: String, invite: String): Boolean =
        url.startsWith("https://") && url.length > "https://".length && invite.trim().length >= MIN_INVITE

    /** Where a (re)started onboarding resumes. The invitation code is deliberately never stored, so once an identity exists the creating step must not run again (ST-063). */
    enum class Resume { START, CREATE, ACKNOWLEDGE }

    fun resumeAt(relayConfigured: Boolean, vaultProvisioned: Boolean, identityExists: Boolean): Resume = when {
        identityExists -> Resume.ACKNOWLEDGE
        relayConfigured && vaultProvisioned -> Resume.CREATE
        else -> Resume.START
    }

    private const val MIN_INVITE = 8
}
