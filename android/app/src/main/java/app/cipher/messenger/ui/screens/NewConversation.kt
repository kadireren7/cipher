package app.cipher.messenger.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.ui.components.Avatar
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrimaryButton
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.TrustBadge
import uniffi.cipher_ffi.TrustStateFfi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewConversationScreen(
    state: UiState,
    vm: AppViewModel,
    onBack: () -> Unit,
    onOpenConversation: (String) -> Unit,
    onScanQr: () -> Unit,
    onNewGroup: () -> Unit,
    onVerify: (String) -> Unit,
    onMyCard: () -> Unit,
) {
    var cardText by remember { mutableStateOf("") }
    var cipherId by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    Scaffold(topBar = {
        TopAppBar(title = {
            Text("New conversation")
        }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad)) {
            item {
                Column(Modifier.padding(16.dp)) {
                    Text("Add a contact", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.size(8.dp))
                    PrivateTextField(cipherId, {
                        cipherId = it
                    }, label = { Text("Cipher ID") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    Spacer(Modifier.size(8.dp))
                    PrivateTextField(name, {
                        name = it
                    }, label = { Text("Name (only you see it)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    Spacer(Modifier.size(12.dp))
                    PrimaryButton("Add by Cipher ID", enabled = cipherId.length >= 20 && !state.busy) {
                        vm.addContactById(cipherId, name) { c ->
                            if (c != null) {
                                cipherId = ""
                                name = ""
                            }
                        }
                    }
                    Spacer(Modifier.size(8.dp))
                    OutlinedButton(onClick = onScanQr, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.QrCodeScanner, null)
                        Spacer(Modifier.size(8.dp))
                        Text("Scan their code")
                    }
                    Spacer(Modifier.size(8.dp))
                    OutlinedButton(onClick = onMyCard, modifier = Modifier.fillMaxWidth()) { Text("Show my contact card") }
                    Spacer(Modifier.size(12.dp))
                    Text("Add from a contact card", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "For someone on another server. Paste the card here, or scan it with the button above.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    PrivateTextField(cardText, {
                        cardText = it
                    }, label = { Text("Contact card") }, modifier = Modifier.fillMaxWidth().testTag("card_input"))
                    Spacer(Modifier.size(8.dp))
                    PrimaryButton("Add card", enabled = vm.looksLikeCard(cardText) && !state.busy) {
                        // pasted, not scanned in person: starts UNVERIFIED
                        vm.addContactByCard(cardText, name, false) { c -> if (c != null) cardText = "" }
                    }
                    Spacer(Modifier.size(8.dp))
                    OutlinedButton(onClick = onNewGroup, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Group, null)
                        Spacer(Modifier.size(8.dp))
                        Text("New group")
                    }
                    Spacer(Modifier.size(16.dp))
                    Text("Contacts", style = MaterialTheme.typography.titleMedium)
                    if (state.contacts.isEmpty()) {
                        Text("No contacts yet. Cipher never reads your address book.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            items(state.contacts, key = { it.accountId }) { c ->
                Row(
                    Modifier.fillMaxWidth().clickable {
                        vm.startDm(c.accountId, onOpenConversation)
                    }.padding(16.dp, 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Avatar(c.name)
                    Spacer(Modifier.size(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(c.name, fontWeight = FontWeight.SemiBold)
                        TrustBadge(c.trust)
                    }
                    OutlinedButton(onClick = { onVerify(c.accountId) }) { Text("Verify") }
                }
                HorizontalDivider()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewGroupScreen(state: UiState, vm: AppViewModel, onBack: () -> Unit, onCreated: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    val selected = remember { mutableStateListOf<String>() }
    val eligible = state.contacts.filter { !it.blocked && it.trust != TrustStateFfi.IDENTITY_CHANGED }
    Scaffold(topBar = {
        TopAppBar(title = { Text("New group") }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).padding(16.dp)) {
            PrivateTextField(name, { name = it }, label = { Text("Group name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Spacer(Modifier.size(12.dp))
            Text("Members", style = MaterialTheme.typography.titleMedium)
            Text(
                "New members only see messages sent after they join. You'll be the group's owner.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
            LazyColumn(Modifier.weight(1f)) {
                items(eligible, key = { it.accountId }) { c ->
                    Row(
                        Modifier.fillMaxWidth().clickable {
                            if (c.accountId in
                                selected
                            ) {
                                selected.remove(c.accountId)
                            } else {
                                selected.add(c.accountId)
                            }
                        }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(c.accountId in selected, { if (it) selected.add(c.accountId) else selected.remove(c.accountId) })
                        Avatar(c.name, 36.dp)
                        Spacer(Modifier.size(10.dp))
                        Text(c.name)
                    }
                }
            }
            PrimaryButton("Create group", enabled = name.isNotBlank() && selected.isNotEmpty() && !state.busy) {
                vm.createGroup(name.trim(), selected.toList(), onCreated)
            }
        }
    }
}
