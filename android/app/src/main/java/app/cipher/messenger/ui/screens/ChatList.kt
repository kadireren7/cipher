package app.cipher.messenger.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.cipher.messenger.data.UiState
import app.cipher.messenger.net.RouteStatus
import app.cipher.messenger.ui.components.Avatar
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.EmptyState
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.util.formatTime
import uniffi.cipher_ffi.ConvKindFfi
import uniffi.cipher_ffi.ConvStateFfi
import uniffi.cipher_ffi.ConversationFfi
import uniffi.cipher_ffi.SecurityEventKind
import uniffi.cipher_ffi.TrustStateFfi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatListScreen(
    state: UiState,
    onOpen: (ConversationFfi) -> Unit,
    onNew: () -> Unit,
    onIdentity: () -> Unit,
    onSettings: () -> Unit,
    onLock: () -> Unit,
    onAccept: (String) -> Unit,
    onDecline: (String) -> Unit,
    onVerify: (String) -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cipher", fontWeight = FontWeight.Bold) },
                actions = {
                    IconAction(Icons.Default.Lock, "Lock Cipher", onLock)
                    IconAction(Icons.Default.QrCode2, "My identity", onIdentity)
                    IconAction(Icons.Default.Settings, "Settings", onSettings)
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onNew) { Icon(Icons.Default.Add, contentDescription = "New conversation") }
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            RouteBanner(state.route, state.offline)
            // Identity warnings are prominent and never auto-dismissed.
            state.contacts.filter { it.trust == TrustStateFfi.IDENTITY_CHANGED }.forEach { c ->
                Banner("${c.name}'s security identity changed. Verify before sending new messages.", error = true, actionLabel = "Review") {
                    onVerify(c.accountId)
                }
            }
            if (state.securityEvents.any { it.kind == SecurityEventKind.UNAUTHORIZED_GROUP_CHANGE }) {
                Banner("A group change that breaks the group's rules was blocked.")
            }
            val requests = state.conversations.filter { it.state == ConvStateFfi.REQUESTED }
            val active = state.conversations.filter { it.state != ConvStateFfi.REQUESTED }
            if (active.isEmpty() && requests.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    EmptyState(
                        Icons.Default.ChatBubbleOutline,
                        "No conversations yet",
                        "Tap + to add someone with their Cipher ID or by scanning their code."
                    )
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    if (requests.isNotEmpty()) {
                        item {
                            Text(
                                "Message requests",
                                Modifier.padding(16.dp, 12.dp, 16.dp, 4.dp),
                                color = MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                        items(requests, key = { it.id }) { c ->
                            Row(Modifier.fillMaxWidth().padding(16.dp, 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Avatar(c.title.ifBlank { "?" })
                                Spacer(Modifier.size(12.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(c.title.ifBlank { "Unknown sender" }, fontWeight = FontWeight.SemiBold)
                                    Text(
                                        "Wants to message you. Nothing is shown until you accept.",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                TextButton(onClick = { onDecline(c.id) }) { Text("Decline") }
                                TextButton(onClick = { onAccept(c.id) }) { Text("Accept") }
                            }
                        }
                        item { HorizontalDivider() }
                    }
                    items(active, key = { it.id }) { c -> ConversationRow(c) { onOpen(c) } }
                }
            }
        }
    }
}

@Composable
private fun ConversationRow(c: ConversationFfi, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Avatar(c.title.ifBlank { "?" }, group = c.kind == ConvKindFfi.GROUP)
        Spacer(Modifier.size(14.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    c.title.ifBlank { "Conversation" },
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (c.lastActivityMs > 0uL && c.lastPreview.isNotEmpty()) {
                    Text(
                        formatTime(c.lastActivityMs),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(Modifier.size(2.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (c.state == ConvStateFfi.LEFT) "You left this group" else c.lastPreview.ifBlank { "No messages yet" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (c.unread > 0u) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (c.unread > 0u) {
                    Box(
                        Modifier.padding(
                            start = 8.dp
                        ).clip(CircleShape).background(MaterialTheme.colorScheme.primary).padding(horizontal = 8.dp, vertical = 2.dp),
                    ) { Text("${c.unread}", color = MaterialTheme.colorScheme.onPrimary, style = MaterialTheme.typography.labelSmall) }
                }
            }
        }
    }
}

/** The route banner shows the ACTUAL privacy-route state (PRIV-013): "Protected" only after a request really completed through the route. */
@Composable
internal fun RouteBanner(route: RouteStatus, offline: Boolean) {
    when {
        route == RouteStatus.PROTECTED -> Unit // nothing to say; Settings shows the detail
        route == RouteStatus.UNAVAILABLE ->
            Banner("Privacy route unavailable. Messages stay queued, encrypted, and will not be sent another way.", error = true)
        route == RouteStatus.OFFLINE || offline -> Banner("You're offline. Messages will send when you're back.")
        else -> Banner("Connecting privately\u2026")
    }
}
