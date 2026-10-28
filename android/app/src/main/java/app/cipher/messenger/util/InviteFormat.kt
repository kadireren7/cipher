package app.cipher.messenger.util

/** Pure helpers for the invitation screens (JVM-testable). Limits mirror `cipher_wire::invite` (the core enforces them; the UI only offers valid choices). */
object InviteFormat {
    const val HOUR_MS = 3_600_000L
    const val DAY_MS = 24 * HOUR_MS
    const val AUTO_MAX_USES = 10
    const val AUTO_MAX_LIFETIME_MS = DAY_MS

    val LIFETIMES_MS: List<Long> = listOf(HOUR_MS, DAY_MS, 7 * DAY_MS)
    val USES: List<Int> = listOf(1, 5, 20)

    fun lifetimeLabel(ms: Long): String = when (ms) {
        HOUR_MS -> "1 hour"
        DAY_MS -> "24 hours"
        7 * DAY_MS -> "7 days"
        else -> "${ms / HOUR_MS} hours"
    }

    fun usesLabel(n: Int): String = if (n == 1) "1 person" else "$n people"

    /** Automatic admission is capped at 10 people and 24 hours, whatever else was chosen. */
    fun lifetimeChoices(
        automatic: Boolean
    ): List<Long> = if (automatic) LIFETIMES_MS.filter { it <= AUTO_MAX_LIFETIME_MS } else LIFETIMES_MS

    fun usesChoices(automatic: Boolean): List<Int> = if (automatic) USES.filter { it <= AUTO_MAX_USES } else USES

    /** "expires in 3 h", "expires in 2 days", "expired". */
    fun expiry(expiresMs: Long, nowMs: Long): String {
        val left = expiresMs - nowMs
        return when {
            left <= 0 -> "expired"
            left < HOUR_MS -> "expires in ${maxOf(1, left / 60_000)} min"
            left < DAY_MS -> "expires in ${left / HOUR_MS} h"
            else -> "expires in ${left / DAY_MS} days"
        }
    }

    /** True while the invitation can still admit somebody. */
    fun isLive(revoked: Boolean, expiresMs: Long, nowMs: Long, admitted: Int, maxUses: Int): Boolean =
        !revoked && expiresMs > nowMs && admitted < maxUses

    fun status(revoked: Boolean, expiresMs: Long, nowMs: Long, admitted: Int, maxUses: Int): String = when {
        revoked -> "revoked"
        expiresMs <= nowMs -> "expired"
        admitted >= maxUses -> "used up"
        else -> expiry(expiresMs, nowMs)
    }
}
