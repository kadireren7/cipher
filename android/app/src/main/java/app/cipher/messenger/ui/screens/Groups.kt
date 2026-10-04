package app.cipher.messenger.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.cipher.messenger.data.ChatViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.ui.components.Avatar
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.SecureDialog
import app.cipher.messenger.ui.components.TrustBadge
import uniffi.cipher_ffi.MemberFfi
import uniffi.cipher_ffi.RoleFfi
import uniffi.cipher_ffi.TrustStateFfi

private fun roleLabel(r: RoleFfi) = when (r) {
    RoleFfi.OWNER -> "Owner"
    RoleFfi.ADMIN -> "Admin"
    RoleFfi.MEMBER -> "Member"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupInfoScreen(vm: ChatViewModel, onBack: () -> Unit, onMembers: () -> Unit, onLeft: () -> Unit) {
    LaunchedEffect(Unit) {
        vm.refresh()
        vm.loadMembers()
    }
    val conv = vm.conversation
    var renaming by remember { mutableStateOf(false) }
    var confirmLeave by remember { mutableStateOf(false) }
    var newName by remember(conv?.title) { mutableStateOf(conv?.title ?: "") }
    val canAdmin = vm.myRole != RoleFfi.MEMBER

    Scaffold(topBar = {
        TopAppBar(title = { Text("Group info") }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Avatar(conv?.title ?: "?", 88.dp, group = true)
            Spacer(Modifier.size(12.dp))
            Text(conv?.title ?: "", style = MaterialTheme.typography.titleLarge)
            Text(
                "${vm.members.size} members · you are ${roleLabel(vm.myRole).lowercase()}",
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            vm.error?.let { Banner(it, error = true, actionLabel = "Dismiss") { vm.error = null } }
            Spacer(Modifier.size(16.dp))
            if (canAdmin) OutlinedButton(onClick = { renaming = true }, modifier = Modifier.fillMaxWidth()) { Text("Rename group") }
            OutlinedButton(onClick = onMembers, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Members and roles") }
            OutlinedButton(onClick = {
                vm.refreshKeys()
            }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("Refresh my encryption keys") }
            Spacer(Modifier.size(16.dp))
            Banner(
                "Everyone in this group can read new messages. People added later can't read messages from before they joined. " +
                    "Someone removed from the group can't read anything sent after they were removed, but keeps what they already received.",
            )
            Spacer(Modifier.size(8.dp))
            OutlinedButton(onClick = { confirmLeave = true }, enabled = vm.myRole != RoleFfi.OWNER, modifier = Modifier.fillMaxWidth()) {
                Text(
                    "Leave group",
                    color = if (vm.myRole ==
                        RoleFfi.OWNER
                    ) {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    } else {
                        MaterialTheme.colorScheme.error
                    }
                )
            }
            if (vm.myRole ==
                RoleFfi.OWNER
            ) {
                Text(
                    "Owners must transfer ownership before leaving.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
    if (renaming) {
        SecureDialog(
            onDismiss = { renaming = false },
            title = "Rename group",
            text = { PrivateTextField(newName, { newName = it.take(64) }, singleLine = true) },
            confirmLabel = "Save",
            onConfirm = { if (newName.isNotBlank()) vm.rename(newName.trim()) },
        )
    }
    if (confirmLeave) {
        SecureDialog(
            onDismiss = { confirmLeave = false },
            title = "Leave this group?",
            text = { Text("You'll stop receiving messages. An admin removes you from the group's encryption.") },
            confirmLabel = "Leave",
            destructive = true,
            onConfirm = { vm.leave(onLeft) },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MembersScreen(vm: ChatViewModel, state: UiState, onBack: () -> Unit, onVerify: (String) -> Unit) {
    LaunchedEffect(Unit) { vm.loadMembers() }
    var selected by remember { mutableStateOf<MemberFfi?>(null) }
    var adding by remember { mutableStateOf(false) }
    val canAdmin = vm.myRole != RoleFfi.MEMBER

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("Members") },
            navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) },
            actions = { if (canAdmin) IconAction(Icons.Default.PersonAdd, "Add members") { adding = true } },
        )
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            vm.error?.let { Banner(it, error = true, actionLabel = "Dismiss") { vm.error = null } }
            LazyColumn(Modifier.fillMaxSize()) {
                items(vm.members, key = { it.accountId }) { m ->
                    Row(
                        Modifier.fillMaxWidth().clickable {
                            if (!m.isMe) selected = m
                        }.padding(16.dp, 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Avatar(m.name)
                        Spacer(Modifier.size(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(m.name, fontWeight = FontWeight.SemiBold)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    roleLabel(m.role),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                m.trust?.let { if (!m.isMe) TrustBadge(it) }
                            }
                        }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
    selected?.let { m ->
        val myRole = vm.myRole
        SecureDialog(
            onDismiss = { selected = null },
            title = m.name,
            confirmLabel = "Close",
            dismissLabel = null,
            text = {
                Column {
                    TextButton(onClick = {
                        onVerify(m.accountId)
                        selected = null
                    }) { Text("Verify safety number") }
                    if (myRole == RoleFfi.OWNER &&
                        m.role == RoleFfi.MEMBER
                    ) {
                        TextButton(onClick = {
                            vm.promote(m.accountId)
                            selected = null
                        }) { Text("Make admin") }
                    }
                    if (myRole == RoleFfi.OWNER &&
                        m.role == RoleFfi.ADMIN
                    ) {
                        TextButton(onClick = {
                            vm.demote(m.accountId)
                            selected = null
                        }) { Text("Remove admin role") }
                    }
                    if (myRole ==
                        RoleFfi.OWNER
                    ) {
                        TextButton(onClick = {
                            vm.transferOwnership(m.accountId)
                            selected = null
                        }) { Text("Transfer ownership") }
                    }
                    val canRemove = (myRole == RoleFfi.OWNER) || (myRole == RoleFfi.ADMIN && m.role == RoleFfi.MEMBER)
                    if (canRemove) {
                        TextButton(onClick = {
                            vm.removeMember(m.accountId)
                            selected = null
                        }) { Text("Remove from group", color = MaterialTheme.colorScheme.error) }
                    }
                }
            },
        )
    }
    if (adding) {
        val existing = vm.members.map { it.accountId }.toSet()
        val eligible = state.contacts.filter { it.accountId !in existing && !it.blocked && it.trust != TrustStateFfi.IDENTITY_CHANGED }
        val picks = remember { mutableStateListOf<String>() }
        SecureDialog(
            onDismiss = { adding = false },
            title = "Add members",
            confirmLabel = "Add",
            onConfirm = { picks.forEach { vm.addMember(it) } },
            text = {
                Column {
                    if (eligible.isEmpty()) Text("All your contacts are already in this group.")
                    eligible.forEach { c ->
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                if (c.accountId in
                                    picks
                                ) {
                                    picks.remove(c.accountId)
                                } else {
                                    picks.add(c.accountId)
                                }
                            },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(c.accountId in picks, { if (it) picks.add(c.accountId) else picks.remove(c.accountId) })
                            Text(c.name)
                        }
                    }
                }
            },
        )
    }
}
