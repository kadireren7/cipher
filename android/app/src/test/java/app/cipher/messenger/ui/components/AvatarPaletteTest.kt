package app.cipher.messenger.ui.components

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertTrue
import org.junit.Test

class AvatarPaletteTest {
    private fun contrast(a: Color, b: Color): Double {
        val la = a.luminance().toDouble()
        val lb = b.luminance().toDouble()
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    @Test fun noAvatarIsGreen() {
        // Hues 70..180 degrees are yellow-green through teal: the brand has no green.
        assertTrue(avatarHues.none { it in 70f..180f })
    }

    @Test fun initialsStayReadableInBothThemes() {
        for (h in avatarHues) {
            val darkBg = Color.hsl(h, 0.16f, 0.22f)
            val darkFg = Color.hsl(h, 0.30f, 0.84f)
            val lightBg = Color.hsl(h, 0.16f, 0.87f)
            val lightFg = Color.hsl(h, 0.30f, 0.22f)
            assertTrue("dark hue $h", contrast(darkFg, darkBg) >= 4.5)
            assertTrue("light hue $h", contrast(lightFg, lightBg) >= 4.5)
        }
    }

    @Test fun thereIsEnoughVarietyToTellPeopleApart() {
        assertTrue(avatarHues.toSet().size >= 6)
    }
}
