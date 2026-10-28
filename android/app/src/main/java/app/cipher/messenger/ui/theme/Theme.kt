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
 * Cipher design language: "quiet confidence". One restrained verdigris accent over warm neutrals (paper in light, ink in dark).
 * Colour carries meaning, never decoration: the accent marks what is yours and what is verified; amber marks what needs attention;
 * red marks what failed or is unsafe. Every pair below was chosen for at least 4.5:1 contrast for body text (checked by DesignTokensTest).
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
    val bubble: Dp = 18.dp
    val bubbleTail: Dp = 5.dp
    val control = RoundedCornerShape(12.dp)
    val surface = RoundedCornerShape(16.dp)
    val field = RoundedCornerShape(22.dp)
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

private val DarkCipher = CipherColors(
    bubbleIn = Color(0xFF1E2422),
    onBubbleIn = Color(0xFFE8ECEA),
    bubbleOut = Color(0xFF1D4A3C),
    onBubbleOut = Color(0xFFE3F5EE),
    warning = Color(0xFFE2B45E),
    onWarningContainer = Color(0xFFF3DFB4),
    warningContainer = Color(0xFF33290F),
    verified = Color(0xFF7FCBB0),
)

private val LightCipher = CipherColors(
    bubbleIn = Color(0xFFFFFFFF),
    onBubbleIn = Color(0xFF1A1F1D),
    bubbleOut = Color(0xFFD3EADF),
    onBubbleOut = Color(0xFF0B2E24),
    warning = Color(0xFF8A5A00),
    onWarningContainer = Color(0xFF4A3000),
    warningContainer = Color(0xFFFBEBC8),
    verified = Color(0xFF1F6F5A),
)

private val Dark = darkColorScheme(
    primary = Color(0xFF7FCBB0),
    onPrimary = Color(0xFF07251C),
    primaryContainer = Color(0xFF1D4A3C),
    onPrimaryContainer = Color(0xFFD6F1E7),
    secondary = Color(0xFF9DB8AE),
    onSecondary = Color(0xFF0E1A16),
    background = Color(0xFF0F1211),
    onBackground = Color(0xFFE8ECEA),
    surface = Color(0xFF0F1211),
    onSurface = Color(0xFFE8ECEA),
    surfaceVariant = Color(0xFF212826),
    onSurfaceVariant = Color(0xFF9FAAA5),
    surfaceContainerLowest = Color(0xFF0B0D0C),
    surfaceContainerLow = Color(0xFF131716),
    surfaceContainer = Color(0xFF171C1A),
    surfaceContainerHigh = Color(0xFF1E2422),
    surfaceContainerHighest = Color(0xFF262D2A),
    outline = Color(0xFF55615C),
    outlineVariant = Color(0xFF29322F),
    error = Color(0xFFF2877E),
    onError = Color(0xFF3A0904),
    errorContainer = Color(0xFF4A1914),
    onErrorContainer = Color(0xFFFFD9D5),
    tertiary = Color(0xFFE2B45E),
    onTertiary = Color(0xFF2E1F00),
)

private val Light = lightColorScheme(
    primary = Color(0xFF1F6F5A),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD3EADF),
    onPrimaryContainer = Color(0xFF0B2E24),
    secondary = Color(0xFF4A6A5F),
    onSecondary = Color.White,
    background = Color(0xFFF5F4F0),
    onBackground = Color(0xFF1A1F1D),
    surface = Color(0xFFF5F4F0),
    onSurface = Color(0xFF1A1F1D),
    surfaceVariant = Color(0xFFE9E7E0),
    onSurfaceVariant = Color(0xFF515B57),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF9F8F5),
    surfaceContainer = Color.White,
    surfaceContainerHigh = Color(0xFFEFEDE7),
    surfaceContainerHighest = Color(0xFFE6E3DB),
    outline = Color(0xFF7E8782),
    outlineVariant = Color(0xFFDAD7CE),
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
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(24.dp),
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
        MaterialTheme(colorScheme = if (dark) Dark else Light, typography = AppTypography, shapes = AppShapes, content = content)
    }
}
