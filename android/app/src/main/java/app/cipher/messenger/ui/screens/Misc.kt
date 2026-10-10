package app.cipher.messenger.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import app.cipher.messenger.BuildConfig
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.net.RouteStatus
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.QrCode
import app.cipher.messenger.ui.components.SecureDialog
import uniffi.cipher_ffi.NetworkProfileFfi
import uniffi.cipher_ffi.PrivacyModeFfi
import uniffi.cipher_ffi.ProtectionFfi
import uniffi.cipher_ffi.SecurityEventKind
import uniffi.cipher_ffi.TrustStateFfi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Page(title: String, onBack: () -> Unit, content: @Composable () -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp)) { content() }
    }
}

@Composable
fun IdentityScreen(state: UiState, onBack: () -> Unit) {
    Page("My identity", onBack) {
        val id = state.identity
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            if (id != null) {
                QrCode(id.qrPayload, 240.dp)
                Spacer(Modifier.height(16.dp))
                Text("Cipher ID", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(id.cipherId, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                Spacer(Modifier.height(12.dp))
                Text("Fingerprint", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(id.fingerprint, textAlign = TextAlign.Center)
                Spacer(Modifier.height(16.dp))
                Banner(
                    "Anyone with your Cipher ID can send you a message request. Your ID is random: it isn't linked to your phone number, " +
                        "email or any key, and it contains no secrets.",
                )
            } else {
                Text("Unlock Cipher to see your identity.")
            }
        }
    }
}

@Composable
fun DevicesScreen(vm: AppViewModel, onBack: () -> Unit) {
    val devices by produceState<List<uniffi.cipher_ffi.DeviceFfi>?>(null) {
        value =
            runCatching { vm.host.call { it.ownDevices() } }.getOrNull()
    }
    Page("Devices", onBack) {
        Text("Devices on your Cipher identity", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        val list = devices
        if (list == null) Text("Loading…", color = MaterialTheme.colorScheme.onSurfaceVariant)
        list?.forEach { d ->
            Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(if (d.isThisDevice) "This phone" else "Another device", fontWeight = FontWeight.SemiBold)
                    Text(
                        "ID ${d.deviceId.take(8)}…",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (d.endorsedByAnotherDevice) Text("Linked", color = MaterialTheme.colorScheme.tertiary)
            }
            HorizontalDivider()
        }
        Spacer(Modifier.height(16.dp))
        Banner("Cipher currently runs on one phone per identity. Linking a second device is not available yet.")
    }
}

@Composable
fun SettingsScreen(
    state: UiState,
    vm: AppViewModel,
    onBack: () -> Unit,
    onSecurity: () -> Unit,
    onDevices: () -> Unit,
    onRelay: () -> Unit
) {
    val ctx = LocalContext.current
    val s = state.settings
    var confirmReset by remember { mutableStateOf(false) }
    var timeout by remember { mutableStateOf(vm.host.lockTimeoutSecs()) }
    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
    Page("Settings", onBack) {
        Text("Notifications", style = MaterialTheme.typography.titleMedium)
        Text(
            "Push services only ever carry an empty wake-up. What the notification shows is decided on this phone.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        if (s != null) {
            listOf(
                Triple(PrivacyModeFfi.NO_CONTENT, "Hide everything", "Just “New message”. (Default)"),
                Triple(PrivacyModeFfi.SENDER_ONLY, "Show sender only", "Only while Cipher is unlocked."),
                Triple(PrivacyModeFfi.CONTENT_WHEN_UNLOCKED, "Show sender and message", "Only while Cipher is unlocked."),
            ).forEach { (mode, title, desc) ->
                Row(
                    Modifier.fillMaxWidth().clickable {
                        vm.saveSettings(s.copy(privacyMode = mode))
                    }.padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(s.privacyMode == mode, { vm.saveSettings(s.copy(privacyMode = mode)) })
                    Column {
                        Text(title)
                        Text(desc, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                OutlinedButton(onClick = { notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS) }) { Text("Allow notifications") }
            }
            HorizontalDivider(Modifier.padding(vertical = 12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Delivery receipts")
                    Text(
                        "Tell people in 1:1 chats when their message arrived.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(s.sendReceipts, { vm.saveSettings(s.copy(sendReceipts = it)) })
            }
        }
        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        NetworkSection(state, vm)
        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        Text("Auto-lock", style = MaterialTheme.typography.titleMedium)
        Text(
            "Cipher always locks when you leave it or switch off the screen. This also locks it after inactivity.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        listOf(30 to "30 seconds", 60 to "1 minute", 300 to "5 minutes", 900 to "15 minutes").forEach { (secs, label) ->
            Row(
                Modifier.fillMaxWidth().clickable {
                    timeout = secs
                    vm.setLockTimeout(secs)
                }.padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(timeout == secs, {
                    timeout = secs
                    vm.setLockTimeout(secs)
                })
                Text(label)
            }
        }
        HorizontalDivider(Modifier.padding(vertical = 12.dp))
        OutlinedButton(onClick = onSecurity, modifier = Modifier.fillMaxWidth()) { Text("Security information") }
        OutlinedButton(onClick = onRelay, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Server and certificate") }
        OutlinedButton(onClick = onDevices, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Devices") }
        OutlinedButton(onClick = { vm.lockNow() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Lock now") }
        Spacer(Modifier.height(24.dp))
        Text("Danger zone", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
        OutlinedButton(onClick = { confirmReset = true }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Text("Remove Cipher data from this phone", color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Text(
            "Cipher ${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
    if (confirmReset) {
        SecureDialog(
            onDismiss = { confirmReset = false },
            title = "Remove all Cipher data?",
            text = { Text("Your messages, contacts, identity and keys on this phone are permanently deleted. There is no backup.") },
            confirmLabel = "Delete everything",
            destructive = true,
            onConfirm = { vm.resetLocalData() },
        )
    }
}

private fun eventText(k: SecurityEventKind): String = when (k) {
    SecurityEventKind.LOCKED -> "Cipher locked"
    SecurityEventKind.UNLOCKED -> "Cipher unlocked"
    SecurityEventKind.UNLOCK_FAILED -> "Unlock attempt failed"
    SecurityEventKind.UNLOCK_RATE_LIMITED -> "Unlock attempts were rate-limited"
    SecurityEventKind.VAULT_INVALIDATED -> "Android invalidated the secure keys"
    SecurityEventKind.PROTECTION_DOWNGRADE_ACCEPTED -> "A software-backed key was accepted (debug)"
    SecurityEventKind.IDENTITY_CHANGED -> "A contact's identity changed"
    SecurityEventKind.UNENDORSED_DEVICE -> "An unverified new device appeared for a contact"
    SecurityEventKind.DEVICE_LIST_CHANGED -> "A contact added a device"
    SecurityEventKind.REPLAY_REJECTED -> "A replayed message was rejected"
    SecurityEventKind.UNAUTHORIZED_GROUP_CHANGE -> "A group change that broke the group's rules was blocked"
    SecurityEventKind.STORAGE_CORRUPTION_DETECTED -> "Damaged local data was detected"
    SecurityEventKind.GROUP_MEMBER_REMOVED -> "A member was removed from a group; the group keys were rotated"
    SecurityEventKind.GROUP_ACCESS_REVOKED -> "You were removed from a group; its history is no longer available here"
    SecurityEventKind.REMOVED_MEMBER_MESSAGE_REJECTED -> "A message from a removed group member was rejected"
}

@Composable
fun SecurityInfoScreen(state: UiState, vm: AppViewModel, onBack: () -> Unit) {
    val v = state.vault
    val (protText, protBad) = when (v?.protection) {
        ProtectionFfi.STRONGBOX -> "Dedicated secure element (StrongBox)" to false
        ProtectionFfi.TEE -> "Hardware-backed (trusted execution environment)" to false
        ProtectionFfi.SOFTWARE_OR_UNKNOWN -> "Software or unknown — NOT hardware protected" to true
        else -> "Unavailable" to true
    }
    Page("Security information", onBack) {
        InfoRow("Key protection", protText, bad = protBad)
        if (protBad &&
            BuildConfig.DEBUG
        ) {
            Banner("Debug build on a device without hardware-backed keys. Release builds refuse to run this way.", error = true)
        }
        InfoRow("Unlock", if (state.pinOnly) "PIN only" else "Biometrics / screen lock${if (v?.hasPin == true) " + PIN" else ""}")
        InfoRow("Auto-lock", "On leaving the app, screen off, or after ${vm.host.lockTimeoutSecs()} s of inactivity")
        InfoRow("Server", (vm.host.relayUrl() ?: "—").removePrefix("https://"))
        InfoRow(
            "Connection",
            if (vm.host.relayPin() ==
                null
            ) {
                "TLS 1.3 only. Certificate checked against trusted authorities."
            } else {
                "TLS 1.3 only. Server authenticated by the certificate key you pinned."
            }
        )
        InfoRow("Message encryption", "MLS (RFC 9420) end-to-end. Keys refresh every 24 h of use or 100 messages.")
        InfoRow("Screenshots", "Blocked inside Cipher")
        Spacer(Modifier.height(12.dp))
        Text("What the server can see", style = MaterialTheme.typography.titleMedium)
        Text(
            "The recipient's device, the time and rough size of each message, and your IP address while you're connected. " +
                "It cannot read messages or attachments, and it never receives your contacts.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        Text("What Cipher can't protect against", style = MaterialTheme.typography.titleMedium)
        Text(
            "Someone photographing your screen with another camera. Malware or a compromised phone while Cipher is unlocked. " +
                "Weak phone screen locks. Metadata such as who talks to whom and when, which the server can observe. " +
                "Cipher has not been independently audited yet.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        Text("Recent security events", style = MaterialTheme.typography.titleMedium)
        if (state.securityEvents.isEmpty()) Text("Nothing to report.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        state.securityEvents.take(20).forEach { Text("• ${eventText(it.kind)}", modifier = Modifier.padding(vertical = 2.dp)) }
        Spacer(Modifier.height(8.dp))
        if (state.contacts.any {
                it.trust == TrustStateFfi.IDENTITY_CHANGED
            }
        ) {
            Banner("Some contacts have an unreviewed identity change.", error = true)
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String, bad: Boolean = false) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, color = if (bad) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
        HorizontalDivider(Modifier.padding(top = 6.dp))
    }
}

@Composable
private fun NetworkSection(state: UiState, vm: AppViewModel) {
    val s = state.settings
    var socks by remember { mutableStateOf(vm.host.socksEndpoint().toString()) }
    var socksOk by remember { mutableStateOf(true) }
    Text("Private network route", style = MaterialTheme.typography.titleMedium)
    val (label, detail) = when (state.route) {
        RouteStatus.PROTECTED -> "Protected" to "Requests are reaching the relay through your privacy route."
        RouteStatus.CONNECTING -> "Connecting privately" to "No request has completed through the route yet."
        RouteStatus.UNAVAILABLE ->
            "Privacy route unavailable" to
                "Nothing is sent another way. Messages wait, encrypted, until the route works."
        RouteStatus.OFFLINE -> "Offline" to "This phone has no network."
    }
    Text(label, fontWeight = FontWeight.SemiBold)
    Text(detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(
        "Cipher sends everything through a local SOCKS5 proxy such as Tor (for example the Orbot app). " +
            "That hides your phone's address from the relay. Your internet provider can still see that you use a privacy " +
            "network. Message content is protected end to end either way.",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp),
    )
    PrivateTextField(
        socks,
        { socks = it },
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        label = { Text("Local proxy (IP:port)") },
        singleLine = true,
    )
    if (!socksOk) {
        Text("Enter the proxy as IPv4 address and port, as shown by your privacy app (Orbot).", color = MaterialTheme.colorScheme.error)
    }
    OutlinedButton(onClick = {
        socksOk = vm.saveSocks(socks)
    }, modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) { Text("Save route") }
    if (s != null) {
        Spacer(Modifier.height(8.dp))
        listOf(
            NetworkProfileFfi.STANDARD to ("Standard" to "Lowest delay and data use."),
            NetworkProfileFfi.ENHANCED to ("Enhanced" to "Steadier traffic pattern; slower sending, more data while Cipher is open."),
        ).forEach { (p, text) ->
            Row(
                Modifier.fillMaxWidth().clickable {
                    vm.saveSettings(s.copy(networkProfile = p))
                }.padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(s.networkProfile == p, { vm.saveSettings(s.copy(networkProfile = p)) })
                Column {
                    Text(text.first)
                    Text(text.second, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}
