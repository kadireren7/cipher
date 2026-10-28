package app.cipher.messenger.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.cipher.messenger.data.InviteViewModel
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrimaryButton
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.QrCode
import app.cipher.messenger.util.InviteFormat
import app.cipher.messenger.util.SensitiveClipboard
import uniffi.cipher_ffi.InviteCreatedFfi
import uniffi.cipher_ffi.InviteInfoFfi
import uniffi.cipher_ffi.InvitePreviewFfi
import uniffi.cipher_ffi.JoinRequestFfi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InvitePage(title: String, onBack: () -> Unit, content: @Composable () -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(title) }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp)) { content() }
    }
}

// ------------------------------------------------------------------------------------------------------------------------------ admin side

data class InvitationsUiState(
    val invites: List<InviteInfoFfi> = emptyList(),
    val requests: List<JoinRequestFfi> = emptyList(),
    /** The link just created. Shown once, never stored in instance state. */
    val created: InviteCreatedFfi? = null,
    val busy: Boolean = false,
    val error: String? = null,
    /** False on the screen that only lists requests across groups. */
    val canCreate: Boolean = true,
    val nowMs: Long = 0L,
)

@Composable
fun InvitationsContent(
    state: InvitationsUiState,
    onCreate: (lifetimeMs: Long, maxUses: Int, automatic: Boolean) -> Unit,
    onRevoke: (String) -> Unit,
    onResolve: (requestId: String, approve: Boolean) -> Unit,
    onDismissCreated: () -> Unit,
    onCopy: (String) -> Unit,
    onDismissError: () -> Unit,
) {
    state.error?.let { Banner(it, error = true, actionLabel = "Dismiss", onAction = onDismissError) }

    if (state.requests.isNotEmpty()) {
        Text("Waiting for your decision", style = MaterialTheme.typography.titleMedium)
        Text(
            "Compare the safety number with the person in person or on a channel you trust before you approve. Anyone who has the link can ask.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        state.requests.forEach { r ->
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("request_${r.requestId}")) {
                Text(r.name, fontWeight = FontWeight.SemiBold)
                Text(r.safetyNumber, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelMedium)
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton("Approve", enabled = !state.busy, modifier = Modifier.testTag("approve_${r.requestId}")) {
                        onResolve(r.requestId, true)
                    }
                    OutlinedButton(onClick = {
                        onResolve(r.requestId, false)
                    }, enabled = !state.busy, modifier = Modifier.testTag("reject_${r.requestId}")) {
                        Text("Reject")
                    }
                }
            }
            HorizontalDivider()
        }
        Spacer(Modifier.height(16.dp))
    }

    if (state.canCreate) {
        CreateInvite(state, onCreate, onDismissCreated, onCopy)
        Spacer(Modifier.height(16.dp))
        Text("Your links", style = MaterialTheme.typography.titleMedium)
        if (state.invites.isEmpty()) {
            Text("None yet.", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.testTag("no_invites"))
        }
        state.invites.forEach { i ->
            val live = InviteFormat.isLive(i.revoked, i.expiresMs.toLong(), state.nowMs, i.admitted.toInt(), i.maxUses.toInt())
            Row(
                Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("invite_${i.inviteId}"),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "${i.admitted} of ${i.maxUses} joined" + if (i.autoAdmission) " · automatic" else "",
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        InviteFormat.status(i.revoked, i.expiresMs.toLong(), state.nowMs, i.admitted.toInt(), i.maxUses.toInt()),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("status_${i.inviteId}"),
                    )
                }
                if (live) {
                    OutlinedButton(onClick = {
                        onRevoke(i.inviteId)
                    }, enabled = !state.busy, modifier = Modifier.testTag("revoke_${i.inviteId}")) {
                        Text("Revoke")
                    }
                }
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun CreateInvite(
    state: InvitationsUiState,
    onCreate: (Long, Int, Boolean) -> Unit,
    onDismissCreated: () -> Unit,
    onCopy: (String) -> Unit,
) {
    var lifetime by remember { mutableLongStateOf(InviteFormat.DAY_MS) }
    var uses by remember { mutableStateOf(1) }
    var automatic by remember { mutableStateOf(false) }
    val lifetimes = InviteFormat.lifetimeChoices(automatic)
    val usesChoices = InviteFormat.usesChoices(automatic)
    if (lifetime !in lifetimes) lifetime = lifetimes.last()
    if (uses !in usesChoices) uses = usesChoices.last()

    val created = state.created
    if (created != null) {
        Text("Your link", style = MaterialTheme.typography.titleMedium)
        Banner("This link is shown once. Treat it like a password: whoever has it can ask to join, and forwarding it forwards that right.")
        Spacer(Modifier.height(12.dp))
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
            QrCode(created.link, 260.dp, Modifier.testTag("invite_qr"))
            Spacer(Modifier.height(8.dp))
            Text(
                created.link,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.labelSmall,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("invite_link_text"),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { onCopy(created.link) }, modifier = Modifier.fillMaxWidth().testTag("invite_copy")) {
                Text("Copy (cleared after 60 s)")
            }
            PrimaryButton("Done", modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag("invite_done"), onClick = onDismissCreated)
        }
        return
    }

    Text("Invite with a link", style = MaterialTheme.typography.titleMedium)
    Text(
        "People you invite can't read messages from before they join. A link only lets someone ask to join: nobody is added without a decision.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(8.dp))
    Text("Valid for")
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        lifetimes.forEach { ms ->
            FilterChip(
                selected = lifetime == ms,
                onClick = { lifetime = ms },
                label = { Text(InviteFormat.lifetimeLabel(ms)) },
                modifier = Modifier.testTag("lifetime_$ms"),
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    Text("Up to")
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        usesChoices.forEach { n ->
            FilterChip(selected = uses == n, onClick = {
                uses = n
            }, label = { Text(InviteFormat.usesLabel(n)) }, modifier = Modifier.testTag("uses_$n"))
        }
    }
    Spacer(Modifier.height(8.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("Admit automatically")
            Text(
                "Off by default. When on, whoever has the link joins at once, up to 10 people within 24 hours, and a forwarded link lets others in.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = automatic, onCheckedChange = { automatic = it }, modifier = Modifier.testTag("invite_auto"))
    }
    Spacer(Modifier.height(8.dp))
    PrimaryButton("Create link", enabled = !state.busy, modifier = Modifier.fillMaxWidth().testTag("invite_create")) {
        onCreate(lifetime, uses, automatic)
    }
}

@Composable
fun InvitationsScreen(vm: InviteViewModel, onBack: () -> Unit) {
    val ctx = LocalContext.current
    LaunchedEffect(Unit) { vm.load() }
    InvitePage("Invite with a link", onBack) {
        InvitationsContent(
            state = InvitationsUiState(
                vm.invites,
                vm.requests,
                vm.created,
                vm.busy,
                vm.error,
                canCreate = true,
                nowMs = System.currentTimeMillis()
            ),
            onCreate = { l, u, a -> vm.create(l, u, a) },
            onRevoke = vm::revoke,
            onResolve = vm::resolve,
            onDismissCreated = vm::dismissCreated,
            onCopy = { SensitiveClipboard.copy(ctx, "Cipher invitation link", it) },
            onDismissError = { vm.error = null },
        )
    }
}

@Composable
fun JoinRequestsScreen(vm: InviteViewModel, onBack: () -> Unit) {
    LaunchedEffect(Unit) { vm.load() }
    InvitePage("Requests to join", onBack) {
        if (vm.requests.isEmpty() && !vm.busy) Text("Nobody is waiting.", modifier = Modifier.testTag("no_requests"))
        InvitationsContent(
            state = InvitationsUiState(
                emptyList(),
                vm.requests,
                null,
                vm.busy,
                vm.error,
                canCreate = false,
                nowMs = System.currentTimeMillis()
            ),
            onCreate = { _, _, _ -> },
            onRevoke = {},
            onResolve = vm::resolve,
            onDismissCreated = {},
            onCopy = {},
            onDismissError = { vm.error = null },
        )
    }
}

// ----------------------------------------------------------------------------------------------------------------------------- joiner side

data class JoinUiState(
    val preview: InvitePreviewFfi? = null,
    val requested: Boolean = false,
    val busy: Boolean = false,
    val error: String? = null,
)

@Composable
fun JoinWithLinkContent(
    state: JoinUiState,
    initialLink: String,
    onLookUp: (String) -> Unit,
    onRequest: (link: String, name: String) -> Unit,
    onScan: () -> Unit,
    onDismissError: () -> Unit,
) {
    // Plain `remember`, never `rememberSaveable`: the link is a bearer secret and must not reach saved instance state.
    var link by remember { mutableStateOf(initialLink) }
    var name by remember { mutableStateOf("") }
    state.error?.let { Banner(it, error = true, actionLabel = "Dismiss", onAction = onDismissError) }

    if (state.requested) {
        Text("Request sent", style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("join_sent"))
        Spacer(Modifier.height(8.dp))
        Text(
            "An admin of the group has to approve it. When they do, the group appears in your chats within a minute. " +
                "You'll see it as a request first, and nothing is shared until you accept.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }

    Text(
        "Paste an invitation link or scan its QR code. A link lets you ask to join; an admin decides.",
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(12.dp))
    PrivateTextField(
        link,
        { link = it },
        label = { Text("Invitation link") },
        modifier = Modifier.fillMaxWidth().testTag("join_link_field"),
    )
    Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        PrimaryButton("Look up", enabled = !state.busy && link.isNotBlank(), modifier = Modifier.testTag("join_lookup")) { onLookUp(link) }
        OutlinedButton(onClick = onScan, modifier = Modifier.testTag("join_scan")) { Text("Scan QR") }
    }

    val p = state.preview ?: return
    Spacer(Modifier.height(16.dp))
    HorizontalDivider()
    Spacer(Modifier.height(12.dp))
    Text(p.groupName, style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("join_group"))
    Text("Invited by ${p.inviterName}", modifier = Modifier.testTag("join_inviter"))
    Banner(
        "These details were written by whoever made the link. They don't prove who that is: compare safety numbers with them after you join.",
    )
    if (!p.acceptsOtherRelays) {
        Column(Modifier.testTag("join_same_server_only")) { Banner("Only people on the same server as the inviter can join this group.") }
    }
    if (p.autoAdmission) {
        Banner("This link admits people automatically: you will be in the group as soon as it is used.")
    }
    Spacer(Modifier.height(8.dp))
    PrivateTextField(
        name,
        { name = it },
        label = { Text("Your name, shown to the admin") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("join_name"),
    )
    Spacer(Modifier.height(8.dp))
    PrimaryButton("Ask to join", enabled = !state.busy && name.isNotBlank(), modifier = Modifier.fillMaxWidth().testTag("join_request")) {
        onRequest(link, name)
    }
}

@Composable
fun JoinWithLinkScreen(vm: InviteViewModel, initialLink: String, onBack: () -> Unit, onScan: () -> Unit) {
    LaunchedEffect(initialLink) { if (initialLink.isNotBlank()) vm.lookUp(initialLink) }
    InvitePage("Join with a link", onBack) {
        JoinWithLinkContent(
            state = JoinUiState(vm.preview, vm.requested, vm.busy, vm.error),
            initialLink = initialLink,
            onLookUp = vm::lookUp,
            onRequest = vm::requestToJoin,
            onScan = onScan,
            onDismissError = { vm.error = null },
        )
    }
}
