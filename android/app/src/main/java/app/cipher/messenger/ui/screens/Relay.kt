package app.cipher.messenger.ui.screens

import androidx.compose.foundation.layout.Column
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
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.net.RelayAddress
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrimaryButton
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.QrCode
import app.cipher.messenger.util.SensitiveClipboard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RelayPage(title: String, onBack: () -> Unit, content: @Composable () -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp)) { content() }
    }
}

/** Shows a signed contact card as a QR code and as text. A card names YOUR server, so it is only created on request and expires. */
@Composable
fun ContactCardScreen(state: UiState, vm: AppViewModel, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var card by remember { mutableStateOf<String?>(null) }
    var failed by remember { mutableStateOf(false) }
    RelayPage("My contact card", onBack) {
        Text(
            "A contact card lets someone on ANY Cipher server start a conversation with you. " +
                "It contains your server address, your public identity key and a one-time introduction code, all signed by your key. It expires after 7 days.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(12.dp))
        Banner(
            "Show it in person for the strongest guarantee. If you send it through another app, the other person should compare safety numbers with you afterwards."
        )
        Spacer(Modifier.height(16.dp))
        val c = card
        if (c == null) {
            PrimaryButton("Create a card (valid 7 days)", enabled = !state.busy, modifier = Modifier.testTag("create_card")) {
                failed = false
                vm.createContactCard(7) { result -> if (result == null) failed = true else card = result }
            }
            if (failed) {
                Text(
                    "Could not create a card. This server cannot be named in a card yet (an onion server needs its pin).",
                    color = MaterialTheme.colorScheme.error
                )
            }
        } else {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                QrCode(c, 280.dp, Modifier.testTag("card_qr"))
                Spacer(Modifier.height(12.dp))
                Text(
                    c,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelSmall,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("card_text")
                )
                Spacer(Modifier.height(12.dp))
                OutlinedButton(onClick = { SensitiveClipboard.copy(ctx, "Cipher contact card", c) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Copy (cleared after 60 s)")
                }
                OutlinedButton(onClick = { card = null }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Hide") }
            }
        }
    }
}

/** The configured server, how it is authenticated, and pin rotation. */
@Composable
fun RelaySettingsScreen(vm: AppViewModel, onBack: () -> Unit) {
    val url = vm.host.relayUrl()
    val pin = vm.host.relayPin()
    var newPin by remember { mutableStateOf("") }
    val parsed = remember(newPin) { RelayAddress.normalisePin(newPin) }
    RelayPage("Server and certificate", onBack) {
        Text("Server", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(url ?: "—", modifier = Modifier.testTag("relay_url"))
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        Text(
            "How the server is authenticated",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (pin == null) {
            Text("By its certificate, checked against your phone's trusted authorities and the server's name.")
        } else {
            Text("ONLY by the certificate key you pinned (no certificate authority is consulted for this server):")
            Text(
                pin,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.testTag("relay_pin")
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Connections always use TLS 1.3. A pinned server whose key does not match is refused; there is no way to continue anyway.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (pin != null) {
            HorizontalDivider(Modifier.padding(vertical = 12.dp))
            Text("The operator rotated the server certificate?", style = MaterialTheme.typography.titleMedium)
            Text(
                "Get the new pin from the operator over a channel you trust (in person is best) and enter it here. Do not accept a new pin just because a connection failed.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            PrivateTextField(newPin, {
                newPin = it
            }, label = { Text("New certificate pin (sha256/…)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.height(8.dp))
            PrimaryButton("Save new pin", enabled = parsed != null && parsed != pin) {
                vm.updateRelayPin(newPin)
                newPin = ""
            }
        }
    }
}
