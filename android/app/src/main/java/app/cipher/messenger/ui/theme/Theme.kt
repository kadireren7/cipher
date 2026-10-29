package app.cipher.messenger.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * Cipher design language: "ink and paper". Near-black and graphite in the dark theme, off-white and black in the light one, and ONE restrained steel-blue
 * accent. The primary action is monochrome (light on dark, black on light); the accent marks only what is selected, unread or verified.
 * Amber marks what needs attention, red what failed or is unsafe: colour carries meaning, never decoration. Corners are small and there are no shadows,
 * gradients or glows. Every pair below keeps at least 4.5:1 contrast for body text (checked by DesignTokensTest).
 */

/** Spacing scale (4 dp grid). Use these instead of ad-hoc dp literals in new code. */
object CipherSpace {
    val xxs: Dp = 2.dp
    val xs: Dp = 4.dp
    val s: Dp = 8.dp
    val m: Dp = 12.dp
    val l: Dp = 16.dp
    val xl: Dp = 24.dp
    val xxl: Dp = 32.dp

    /** Minimum touch target (Material / WCAG 2.5.8 recommends 48 dp). */
    val touch: Dp = 48.dp
}

/** Shape tokens. Bubbles keep one corner tight on the sender's side; everything else uses [control] or [surface]. */
object CipherShape {
    val bubble: Dp = 14.dp
    val bubbleTail: Dp = 4.dp
    val control = RoundedCornerShape(8.dp)
    val surface = RoundedCornerShape(10.dp)
    val field = RoundedCornerShape(12.dp)
}

/** Colours that Material 3's scheme has no slot for. */
data class CipherColors(
    /** Incoming message bubble. */
    val bubbleIn: Color,
    val onBubbleIn: Color,
    /** Outgoing message bubble. */
    val bubbleOut: Color,
    val onBubbleOut: Color,
    /** Something needs the person's attention but nothing has failed (offline, unverified). */
    val warning: Color,
    val onWarningContainer: Color,
    val warningContainer: Color,
    /** A positive, verified state. Always paired with an icon or text, never colour alone. */
    val verified: Color,
)

internal val DarkCipher = CipherColors(
    bubbleIn = Color(0xFF1C1C1F),
    onBubbleIn = Color(0xFFEDEDEF),
    bubbleOut = Color(0xFF2A3140),
    onBubbleOut = Color(0xFFEEF0F4),
    warning = Color(0xFFE2B45E),
    onWarningContainer = Color(0xFFF3DFB4),
    warningContainer = Color(0xFF33290F),
    verified = Color(0xFF8FA8C8),
)

internal val LightCipher = CipherColors(
    bubbleIn = Color(0xFFFFFFFF),
    onBubbleIn = Color(0xFF0E0E10),
    bubbleOut = Color(0xFFDDE3EC),
    onBubbleOut = Color(0xFF0E1622),
    warning = Color(0xFF8A5A00),
    onWarningContainer = Color(0xFF4A3000),
    warningContainer = Color(0xFFFBEBC8),
    verified = Color(0xFF2F5686),
)

internal val DarkScheme = darkColorScheme(
    primary = Color(0xFFEDEDEF),
    onPrimary = Color(0xFF0A0A0B),
    primaryContainer = Color(0xFF26262B),
    onPrimaryContainer = Color(0xFFEDEDEF),
    secondary = Color(0xFF8FA8C8),
    onSecondary = Color(0xFF0A0A0B),
    secondaryContainer = Color(0xFF232C3B),
    onSecondaryContainer = Color(0xFFDCE5F2),
    background = Color(0xFF0A0A0B),
    onBackground = Color(0xFFF4F4F5),
    surface = Color(0xFF0A0A0B),
    onSurface = Color(0xFFF4F4F5),
    surfaceVariant = Color(0xFF1C1C1F),
    onSurfaceVariant = Color(0xFFA1A1A8),
    surfaceContainerLowest = Color(0xFF070708),
    surfaceContainerLow = Color(0xFF101012),
    surfaceContainer = Color(0xFF151517),
    surfaceContainerHigh = Color(0xFF1C1C1F),
    surfaceContainerHighest = Color(0xFF242428),
    outline = Color(0xFF55555C),
    outlineVariant = Color(0xFF26262A),
    error = Color(0xFFF2877E),
    onError = Color(0xFF3A0904),
    errorContainer = Color(0xFF4A1914),
    onErrorContainer = Color(0xFFFFD9D5),
    tertiary = Color(0xFFE2B45E),
    onTertiary = Color(0xFF2E1F00),
)

internal val LightScheme = lightColorScheme(
    primary = Color(0xFF0E0E10),
    onPrimary = Color(0xFFF6F5F2),
    primaryContainer = Color(0xFFE7E6E1),
    onPrimaryContainer = Color(0xFF0E0E10),
    secondary = Color(0xFF3B5B82),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDDE3EC),
    onSecondaryContainer = Color(0xFF0E1622),
    background = Color(0xFFF6F5F2),
    onBackground = Color(0xFF0E0E10),
    surface = Color(0xFFF6F5F2),
    onSurface = Color(0xFF0E0E10),
    surfaceVariant = Color(0xFFEAE9E4),
    onSurfaceVariant = Color(0xFF55555C),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFFAF9F7),
    surfaceContainer = Color.White,
    surfaceContainerHigh = Color(0xFFEFEEEA),
    surfaceContainerHighest = Color(0xFFE7E6E1),
    outline = Color(0xFF8A8A91),
    outlineVariant = Color(0xFFDDDCD7),
    error = Color(0xFFB3261E),
    onError = Color.White,
    errorContainer = Color(0xFFF9DEDA),
    onErrorContainer = Color(0xFF410E0B),
    tertiary = Color(0xFF8A5A00),
    onTertiary = Color.White,
)

private val Sans = FontFamily.SansSerif

private val AppTypography = Typography(
    headlineMedium = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 28.sp,
        lineHeight = 34.sp,
        letterSpacing = (-0.4).sp
    ),
    headlineSmall = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 30.sp,
        letterSpacing = (-0.3).sp
    ),
    titleLarge = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 21.sp,
        lineHeight = 27.sp,
        letterSpacing = (-0.2).sp
    ),
    titleMedium = TextStyle(fontFamily = Sans, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
    titleSmall = TextStyle(fontFamily = Sans, fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp),
    bodyLarge = TextStyle(fontFamily = Sans, fontSize = 16.sp, lineHeight = 23.sp),
    bodyMedium = TextStyle(fontFamily = Sans, fontSize = 14.sp, lineHeight = 20.sp),
    bodySmall = TextStyle(fontFamily = Sans, fontSize = 12.sp, lineHeight = 16.sp),
    labelLarge = TextStyle(fontFamily = Sans, fontWeight = FontWeight.Medium, fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp),
    labelMedium = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.2.sp
    ),
    // 12 sp minimum: 11 sp timestamps were hard to read at default font scale.
    labelSmall = TextStyle(fontFamily = Sans, fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.2.sp),
)

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(6.dp),
    medium = RoundedCornerShape(8.dp),
    large = RoundedCornerShape(12.dp),
    extraLarge = RoundedCornerShape(16.dp),
)

private val LocalCipherColors = staticCompositionLocalOf { DarkCipher }

/** Semantic colours beyond Material's scheme: `CipherTheme.colors.bubbleOut` etc. */
object CipherTheme {
    val colors: CipherColors
        @Composable @ReadOnlyComposable
        get() = LocalCipherColors.current
}

@Composable
fun CipherTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalCipherColors provides if (dark) DarkCipher else LightCipher) {
        MaterialTheme(
            colorScheme = if (dark) DarkScheme else LightScheme,
            typography = AppTypography,
            shapes = AppShapes,
            content = content
        )
    }
}
