package app.cipher.messenger.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// A calm blue-ink palette. Dark theme is the reference design (deep neutral surfaces, one accent); light is a clean counterpart.
private val Accent = Color(0xFF4C8DFF)
private val AccentDeep = Color(0xFF1B3A7A)

private val Dark = darkColorScheme(
    primary = Accent,
    onPrimary = Color(0xFF00203F),
    primaryContainer = AccentDeep,
    onPrimaryContainer = Color(0xFFDCE8FF),
    secondary = Color(0xFF8FB4FF),
    background = Color(0xFF0E1116),
    onBackground = Color(0xFFE6EAF0),
    surface = Color(0xFF0E1116),
    onSurface = Color(0xFFE6EAF0),
    surfaceVariant = Color(0xFF1B2129),
    onSurfaceVariant = Color(0xFFA7B0BD),
    surfaceContainer = Color(0xFF151A21),
    surfaceContainerHigh = Color(0xFF1B2129),
    outline = Color(0xFF3A4350),
    outlineVariant = Color(0xFF262D37),
    error = Color(0xFFFF6B6B),
    tertiary = Color(0xFF4CD6A0),
)

private val Light = lightColorScheme(
    primary = Color(0xFF2468E8),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD9E6FF),
    onPrimaryContainer = Color(0xFF0B2A5E),
    background = Color(0xFFF7F8FA),
    surface = Color(0xFFF7F8FA),
    surfaceVariant = Color(0xFFE9ECF1),
    surfaceContainer = Color.White,
    surfaceContainerHigh = Color(0xFFEEF1F5),
    outline = Color(0xFFB4BCC8),
    outlineVariant = Color(0xFFDDE2E9),
    tertiary = Color(0xFF0E9F6E),
)

private val AppTypography = Typography(
    titleLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp),
    titleMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
    bodyLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 16.sp, lineHeight = 22.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp, lineHeight = 20.sp),
    labelSmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 11.sp, lineHeight = 14.sp),
)

@Composable
fun CipherTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) Dark else Light, typography = AppTypography, content = content)
}
