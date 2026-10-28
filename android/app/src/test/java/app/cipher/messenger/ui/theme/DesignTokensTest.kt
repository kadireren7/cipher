package app.cipher.messenger.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertTrue
import org.junit.Test

/** Text/background pairs must meet WCAG AA (4.5:1 for body text) in both themes; the design language relies on it. */
class DesignTokensTest {
    private fun contrast(a: Color, b: Color): Double {
        val la = a.luminance().toDouble()
        val lb = b.luminance().toDouble()
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    private fun check(name: String, fg: Color, bg: Color, min: Double = 4.5) {
        val c = contrast(fg, bg)
        assertTrue("$name contrast %.2f < $min".format(c), c >= min)
    }

    @Test fun darkSchemeMeetsAA() {
        val s = DarkScheme
        val c = DarkCipher
        check("dark body", s.onBackground, s.background)
        check("dark secondary text", s.onSurfaceVariant, s.background)
        check("dark secondary text on cards", s.onSurfaceVariant, s.surfaceContainer)
        check("dark primary on background", s.primary, s.background)
        check("dark button", s.onPrimary, s.primary)
        check("dark outgoing bubble", c.onBubbleOut, c.bubbleOut)
        check("dark incoming bubble", c.onBubbleIn, c.bubbleIn)
        check("dark error", s.error, s.background)
        check("dark warning banner", c.onWarningContainer, c.warningContainer)
        check("dark verified", c.verified, c.bubbleOut, 3.0) // icon only, paired with a label: 3:1 non-text contrast
    }

    @Test fun lightSchemeMeetsAA() {
        val s = LightScheme
        val c = LightCipher
        check("light body", s.onBackground, s.background)
        check("light secondary text", s.onSurfaceVariant, s.background)
        check("light secondary text on cards", s.onSurfaceVariant, s.surfaceContainer)
        check("light primary on background", s.primary, s.background)
        check("light button", s.onPrimary, s.primary)
        check("light outgoing bubble", c.onBubbleOut, c.bubbleOut)
        check("light incoming bubble", c.onBubbleIn, c.bubbleIn)
        check("light error", s.error, s.background)
        check("light warning banner", c.onWarningContainer, c.warningContainer)
        check("light verified", c.verified, c.bubbleOut, 3.0)
    }
}
