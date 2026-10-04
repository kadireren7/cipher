package app.cipher.messenger.ui.components

import android.graphics.Bitmap
import android.graphics.Color as AColor
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Backspace
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PlatformImeOptions
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import app.cipher.messenger.util.initials
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import uniffi.cipher_ffi.TrustStateFfi

private val avatarColors = listOf(0xFF3B6FD8, 0xFF2E9E8F, 0xFF8E5CD9, 0xFFD9822B, 0xFFC94F7C, 0xFF4F8F3B, 0xFF5C6BC0).map { Color(it) }

@Composable
fun Avatar(name: String, size: Dp = 44.dp, group: Boolean = false) {
    val color = avatarColors[(name.hashCode() and 0x7fffffff) % avatarColors.size]
    Box(Modifier.size(size).clip(CircleShape).background(color), contentAlignment = Alignment.Center) {
        Text(initials(name), color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = (size.value * 0.36f).sp)
    }
}

/**
 * Every dialog in the app MUST go through this wrapper: Compose dialogs are separate windows and do not inherit the activity's
 * FLAG_SECURE, so they are created with `SecureFlagPolicy.SecureOn`. (A CI guard bans direct `AlertDialog(`/`Dialog(` elsewhere.)
 */
@Composable
fun SecureDialog(
    onDismiss: () -> Unit,
    title: String,
    text: @Composable (() -> Unit)? = null,
    confirmLabel: String = "OK",
    onConfirm: (() -> Unit)? = null,
    dismissLabel: String? = "Cancel",
    destructive: Boolean = false,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(title) },
        text = text,
        confirmButton = {
            TextButton(onClick = {
                onConfirm?.invoke()
                onDismiss()
            }) {
                Text(confirmLabel, color = if (destructive) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            }
        },
        dismissButton = dismissLabel?.let { { TextButton(onClick = onDismiss) { Text(it) } } },
    )
}

@Composable
fun TrustBadge(trust: TrustStateFfi, modifier: Modifier = Modifier) {
    val (icon, tint, label) = when (trust) {
        TrustStateFfi.VERIFIED -> Triple(Icons.Default.Verified, MaterialTheme.colorScheme.tertiary, "Verified")
        TrustStateFfi.UNVERIFIED -> Triple(Icons.Default.GppMaybe, MaterialTheme.colorScheme.onSurfaceVariant, "Not verified")
        TrustStateFfi.IDENTITY_CHANGED -> Triple(Icons.Default.ErrorOutline, MaterialTheme.colorScheme.error, "Identity changed")
    }
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(16.dp))
        Spacer(Modifier.size(4.dp))
        Text(label, color = tint, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
fun Banner(text: String, error: Boolean = false, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    Surface(
        color = if (error) MaterialTheme.colorScheme.error.copy(alpha = 0.16f) else MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            if (actionLabel != null && onAction != null) TextButton(onClick = onAction) { Text(actionLabel) }
        }
    }
}

@Composable
fun EmptyState(icon: ImageVector, title: String, text: String, modifier: Modifier = Modifier) {
    Column(
        modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(12.dp))
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(
            text,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyMedium
        )
    }
}

/** QR code rendered from `text` (our own identity payload: account id + public identity key). */
@Composable
fun QrCode(text: String, size: Dp = 240.dp, modifier: Modifier = Modifier) {
    val bmp = remember(text) { qrBitmap(text, 512) }
    Image(
        bitmap = bmp.asImageBitmap(),
        contentDescription = "QR code of your identity",
        modifier = modifier.size(size).clip(RoundedCornerShape(12.dp)).background(Color.White).padding(10.dp),
    )
}

fun qrBitmap(text: String, px: Int): Bitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, px, px, mapOf(EncodeHintType.MARGIN to 0))
    val bmp = Bitmap.createBitmap(m.width, m.height, Bitmap.Config.ARGB_8888)
    for (x in 0 until m.width) for (y in 0 until m.height) bmp.setPixel(x, y, if (m[x, y]) AColor.BLACK else AColor.WHITE)
    return bmp
}

/**
 * Numeric PIN entry WITHOUT the system keyboard: the IME (and any third-party keyboard) never sees the PIN. Digits are shown only
 * as dots. `onSubmit` receives the PIN once the user confirms with at least `minLength` digits.
 */
@Composable
fun PinPad(
    title: String,
    error: String?,
    minLength: Int = 6,
    maxLength: Int = 12,
    submitLabel: String = "Unlock",
    onSubmit: (String) -> Unit
) {
    var pin by remember { mutableStateOf("") }
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(16.dp))
        Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.height(20.dp).semantics {
                contentDescription =
                    "${pin.length} digits entered"
            }
        ) {
            repeat(pin.length.coerceAtLeast(minLength).coerceAtMost(maxLength)) { i ->
                Box(
                    Modifier.size(14.dp).clip(CircleShape).background(
                        if (i <
                            pin.length
                        ) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.outline
                        }
                    )
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            error ?: " ",
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.height(20.dp)
        )
        Spacer(Modifier.height(8.dp))
        val rows = listOf(listOf("1", "2", "3"), listOf("4", "5", "6"), listOf("7", "8", "9"))
        rows.forEach { r ->
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                r.forEach { d -> Key(d) { if (pin.length < maxLength) pin += d } }
            }
            Spacer(Modifier.height(12.dp))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            IconKey(Icons.Default.Backspace, "Delete") { if (pin.isNotEmpty()) pin = pin.dropLast(1) }
            Key("0") { if (pin.length < maxLength) pin += "0" }
            IconKey(Icons.Default.Check, submitLabel, enabled = pin.length >= minLength) {
                val p = pin
                pin = ""
                onSubmit(p)
            }
        }
    }
}

@Composable
private fun Key(label: String, onClick: () -> Unit) {
    Surface(
        shape = CircleShape,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = Modifier.size(72.dp).clip(CircleShape).clickable(onClick = onClick),
    ) { Box(contentAlignment = Alignment.Center) { Text(label, fontSize = 26.sp, fontWeight = FontWeight.Medium) } }
}

@Composable
private fun IconKey(icon: ImageVector, description: String, enabled: Boolean = true, onClick: () -> Unit) {
    Surface(
        shape = CircleShape,
        color = if (enabled) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f),
        modifier = Modifier.size(72.dp).clip(CircleShape).clickable(enabled = enabled, onClick = onClick),
    ) { Box(contentAlignment = Alignment.Center) { Icon(icon, contentDescription = description) } }
}

@Composable
fun PrimaryButton(text: String, enabled: Boolean = true, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(),
        modifier = modifier.fillMaxWidth().height(52.dp),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

@Composable
fun IconAction(icon: ImageVector, description: String, onClick: () -> Unit) {
    IconButton(onClick = onClick) { Icon(icon, contentDescription = description) }
}

/**
 * EVERY text input goes through this wrapper. Typed text (messages, names, Cipher IDs, invite codes) must not be fed to the keyboard's
 * learning/personalisation or to autofill services: autocorrect is off and the IME is asked for "incognito" mode
 * (`flagNoPersonalizedLearning` via `privateImeOptions="nm"`, honoured by Gboard and several others). This is BEST EFFORT — a third-party
 * keyboard can ignore it — and is documented as such. A static guard bans direct `OutlinedTextField(` elsewhere.
 */
@Composable
fun PrivateTextField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    label: (@Composable () -> Unit)? = null,
    placeholder: (@Composable () -> Unit)? = null,
    singleLine: Boolean = false,
    maxLines: Int = if (singleLine) 1 else Int.MAX_VALUE,
    shape: Shape = androidx.compose.material3.OutlinedTextFieldDefaults.shape,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier,
        label = label,
        placeholder = placeholder,
        singleLine = singleLine,
        maxLines = maxLines,
        shape = shape,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, platformImeOptions = PlatformImeOptions("nm")),
    )
}
