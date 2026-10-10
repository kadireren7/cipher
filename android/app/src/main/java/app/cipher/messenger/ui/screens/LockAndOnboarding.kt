package app.cipher.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.cipher.messenger.BuildConfig
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.PinPad
import app.cipher.messenger.ui.components.PrimaryButton
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.QrCode
import app.cipher.messenger.ui.components.SecureDialog
import uniffi.cipher_ffi.LockStateFfi
import uniffi.cipher_ffi.ProtectionFfi

@Composable
fun LockScreen(state: UiState, vm: AppViewModel) {
    val vault = state.vault
    val pinOnly = state.pinOnly
    var showPin by rememberSaveable { mutableStateOf(pinOnly) }
    var pinError by remember { mutableStateOf<String?>(null) }
    var autoTried by rememberSaveable { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }

    LaunchedEffect(vault?.state) {
        if (!pinOnly && !autoTried && vault?.state == LockStateFfi.LOCKED && vault.pinRetryAfterSecs == 0uL) {
            autoTried = true
            vm.unlockWithDeviceAuth()
        }
    }

    Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.verticalScroll(rememberScrollState())) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.size(72.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(34.dp))
                }
            }
            Spacer(Modifier.height(16.dp))
            Text("Cipher is locked", style = MaterialTheme.typography.titleLarge)
            Spacer(Modifier.height(4.dp))
            Text(
                "Your messages are encrypted on this device.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(24.dp))

            when {
                vault?.state == LockStateFfi.INVALIDATED -> {
                    Banner(
                        if (state.rolledBack) {
                            "The Cipher data on this phone is older than the last state it recorded — for example it was restored " +
                                "from a copy. Cipher refuses to use it, because reusing old encryption state could expose messages. " +
                                "Nothing was opened or changed."
                        } else {
                            "Android reset the keys that protect your messages " +
                                "(this happens when the screen lock or enrolled biometrics change). " +
                                "The data on this device can no longer be opened."
                        },
                        error = true,
                    )
                    Spacer(Modifier.height(12.dp))
                    PrimaryButton("Start over on this device") { confirmReset = true }
                }
                showPin -> {
                    if ((vault?.pinRetryAfterSecs ?: 0uL) > 0uL) {
                        Banner("Too many attempts. Try again in ${vault?.pinRetryAfterSecs} s.", error = true)
                    }
                    PinPad("Enter your PIN", pinError) { pin ->
                        pinError = null
                        vm.unlockWithPin(pin) { pinError = "Wrong PIN" }
                    }
                    if (!pinOnly) {
                        TextButton(onClick = {
                            showPin = false
                            vm.unlockWithDeviceAuth()
                        }) { Text("Use biometrics / screen lock") }
                    }
                }
                else -> {
                    PrimaryButton("Unlock", modifier = Modifier.padding(horizontal = 24.dp)) { vm.unlockWithDeviceAuth() }
                    if (vault?.hasPin == true) TextButton(onClick = { showPin = true }) { Text("Use PIN instead") }
                }
            }
        }
    }
    if (confirmReset) {
        SecureDialog(
            onDismiss = { confirmReset = false },
            title = "Start over?",
            text = { Text("This permanently removes Cipher's data and keys from this device. Messages cannot be recovered.") },
            confirmLabel = "Remove and start over",
            destructive = true,
            onConfirm = { vm.resetLocalData() },
        )
    }
}

private enum class Step { WELCOME, SERVER, MODE, PIN, CREATING, RECOVERY, IDENTITY }

@Composable
fun OnboardingFlow(state: UiState, vm: AppViewModel) {
    var step by rememberSaveable {
        mutableStateOf(
            if (state.relayConfigured &&
                state.vault?.provisioned == true
            ) {
                Step.CREATING
            } else {
                Step.WELCOME
            }
        )
    }
    var url by rememberSaveable { mutableStateOf(BuildConfig.DEFAULT_RELAY_URL) }
    var invite by remember { mutableStateOf(BuildConfig.DEFAULT_INVITE) }
    var relayPin by rememberSaveable { mutableStateOf("") }
    var pinOnly by rememberSaveable { mutableStateOf(false) }
    var pinFirst by remember { mutableStateOf<String?>(null) }
    var chosenPin by remember { mutableStateOf<String?>(null) }
    var pinMsg by remember { mutableStateOf<String?>(null) }
    var understood by rememberSaveable { mutableStateOf(false) }
    var createError by remember { mutableStateOf<String?>(null) }
    var attempt by remember { mutableIntStateOf(0) }

    Column(
        Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(24.dp))
        when (step) {
            Step.WELCOME -> {
                Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.size(88.dp)) {
                    Box(contentAlignment = Alignment.Center) { Icon(Icons.Default.Lock, null, modifier = Modifier.size(42.dp)) }
                }
                Spacer(Modifier.height(24.dp))
                Text("Cipher", fontSize = 34.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Private messaging. No phone number. No email.",
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(32.dp))
                Bullet("Messages are encrypted on your phone before they leave it.")
                Bullet("Servers can't read them, and your contacts are never uploaded.")
                Bullet("Your keys live in your phone's secure hardware.")
                Spacer(Modifier.height(32.dp))
                PrimaryButton("Get started") { step = Step.SERVER }
            }
            Step.SERVER -> {
                Text("Choose a server", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Cipher talks to a relay server that only passes along encrypted messages. Enter the address and invite code from whoever runs it.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                PrivateTextField(url, {
                    url = it
                }, label = { Text("Server address") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                PrivateTextField(relayPin, {
                    relayPin = it
                }, label = {
                    Text("Certificate pin (onion or self-signed servers)")
                }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                PrivateTextField(invite, {
                    invite = it
                }, label = { Text("Invite code") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Text(
                    "Connections always use TLS 1.3. Plain http:// is rejected. An onion (.onion) server needs the certificate pin from its operator; with a pin, ONLY that key is accepted.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(24.dp))
                val addr = app.cipher.messenger.net.RelayAddress.parse(url, relayPin)
                if (addr is app.cipher.messenger.net.RelayAddress.Result.Bad && url.startsWith("https://") && url.length > 12) {
                    Text(addr.reason, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
                PrimaryButton("Continue", enabled = addr is app.cipher.messenger.net.RelayAddress.Result.Ok && invite.length >= 8) {
                    vm.configureRelay(url, relayPin)
                    step = Step.MODE
                }
            }
            Step.MODE -> {
                Text("How should Cipher unlock?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(16.dp))
                ModeCard(
                    "Biometrics or screen lock, plus a backup PIN",
                    "Recommended. Your fingerprint, face or phone PIN opens Cipher. Each unlock is confirmed by your phone's secure hardware.",
                    !pinOnly,
                    Icons.Default.Fingerprint
                ) {
                    pinOnly =
                        false
                }
                Spacer(Modifier.height(12.dp))
                ModeCard(
                    "PIN only",
                    "Cipher asks for its own PIN every time. No biometric option exists for this vault.",
                    pinOnly,
                    Icons.Default.Lock
                ) {
                    pinOnly =
                        true
                }
                Spacer(Modifier.height(24.dp))
                PrimaryButton("Continue") { step = Step.PIN }
            }
            Step.PIN -> {
                Text(if (pinOnly) "Create your PIN" else "Create a backup PIN", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "At least 6 digits. Cipher stores no copy of it and cannot reset it for you.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(24.dp))
                PinPad(if (pinFirst == null) "Choose a PIN" else "Repeat the PIN", pinMsg, submitLabel = "Next") { p ->
                    if (pinFirst == null) {
                        if (p.toSet().size == 1) {
                            pinMsg = "Don't use one repeated digit"
                        } else {
                            pinFirst = p
                            pinMsg = null
                        }
                    } else if (pinFirst == p) {
                        chosenPin = p
                        pinMsg = null
                        step = Step.CREATING
                    } else {
                        pinFirst = null
                        pinMsg = "PINs didn't match. Try again."
                    }
                }
                if (!pinOnly) {
                    TextButton(onClick = {
                        chosenPin = null
                        step = Step.CREATING
                    }) { Text("Skip for now") }
                }
            }
            Step.CREATING -> {
                LaunchedEffect(attempt) {
                    createError = null
                    val provisioned = vm.state.value.vault?.provisioned == true
                    val provisionStep: (suspend () -> Boolean) = {
                        if (provisioned) {
                            true
                        } else {
                            kotlinx.coroutines.suspendCancellableCoroutine { c ->
                                val cb: (Boolean) -> Unit = { ok -> if (c.isActive) c.resume(ok) {} }
                                if (pinOnly) vm.provisionPinOnly(chosenPin ?: "", cb) else vm.provisionWithDeviceAuth(chosenPin, cb)
                            }
                        }
                    }
                    if (!provisionStep()) {
                        createError = "Couldn't set up secure storage on this device."
                        return@LaunchedEffect
                    }
                    val done = kotlinx.coroutines.suspendCancellableCoroutine { c ->
                        vm.createIdentity(invite) { ok -> if (c.isActive) c.resume(ok) {} }
                    }
                    if (done) {
                        step = Step.RECOVERY
                    } else {
                        createError =
                            "Couldn't create your identity. Check the server address and invite code."
                    }
                }
                if (createError == null) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Creating your keys…", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "They are generated on this phone and never leave it.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                } else {
                    Banner(createError ?: "", error = true)
                    PrimaryButton("Try again") { attempt++ }
                    TextButton(onClick = { step = Step.SERVER }) { Text("Change server") }
                }
            }
            Step.RECOVERY -> {
                Text("Before you continue", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(12.dp))
                Bullet("There is no account recovery. If you lose or reset this phone, your messages and identity are gone.")
                Bullet("Nothing is backed up to the cloud — on purpose.")
                Bullet(
                    "If Android resets your secure keys (for example after changing biometrics), Cipher data on this phone becomes unreadable."
                )
                Bullet("Your contacts will see a warning if your identity ever changes.")
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { understood = !understood }) {
                    Checkbox(understood, { understood = it })
                    Text("I understand")
                }
                Spacer(Modifier.height(16.dp))
                PrimaryButton("Continue", enabled = understood) { step = Step.IDENTITY }
            }
            Step.IDENTITY -> {
                val id = state.identity
                Text("Your Cipher ID", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "A random identifier — not derived from your phone number or any key. Share it or let friends scan your code.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(16.dp))
                if (id != null) {
                    QrCode(id.qrPayload, 220.dp)
                    Spacer(Modifier.height(12.dp))
                    Text(id.cipherId, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(8.dp))
                    Text("Fingerprint", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(id.fingerprint, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                }
                Spacer(Modifier.height(24.dp))
                PrimaryButton("Open Cipher") { vm.finishOnboarding() }
                if (state.vault?.protection == ProtectionFfi.SOFTWARE_OR_UNKNOWN) {
                    Spacer(Modifier.height(12.dp))
                    Banner("Debug build: this device's keys are software-backed (no hardware protection).", error = true)
                }
            }
        }
    }
}

@Composable
private fun Bullet(text: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.Top) {
        Box(Modifier.padding(top = 8.dp).size(6.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
        Spacer(Modifier.size(12.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ModeCard(
    title: String,
    text: String,
    selected: Boolean,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainer,
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable(onClick = onClick),
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.Top) {
            Icon(icon, null, modifier = Modifier.padding(top = 2.dp))
            Spacer(Modifier.size(12.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            RadioButton(selected, onClick)
        }
    }
}
