package app.cipher.messenger.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import app.cipher.messenger.data.ChatViewModel
import app.cipher.messenger.media.ThumbnailMaker
import app.cipher.messenger.media.VoiceRecorder
import app.cipher.messenger.ui.components.Avatar
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrivateTextField
import app.cipher.messenger.ui.components.SecureDialog
import app.cipher.messenger.ui.components.TrustBadge
import app.cipher.messenger.util.SensitiveClipboard
import app.cipher.messenger.util.formatDuration
import app.cipher.messenger.util.formatSize
import app.cipher.messenger.util.formatTime
import kotlinx.coroutines.delay
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.ConvKindFfi
import uniffi.cipher_ffi.ConvStateFfi
import uniffi.cipher_ffi.DeliveryStateFfi
import uniffi.cipher_ffi.MessageFfi

private const val MAX_ATTACHMENT_BYTES = 100L * 1024 * 1024

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationScreen(
    vm: ChatViewModel,
    syncTick: Int,
    onBack: () -> Unit,
    onInfo: () -> Unit,
    onVerify: (String) -> Unit,
    onOpenAttachment: (MessageFfi) -> Unit
) {
    val ctx = LocalContext.current
    LaunchedEffect(Unit) {
        vm.refresh()
        vm.loadMembers()
    }
    LaunchedEffect(syncTick) { if (syncTick > 0) vm.refresh() }

    val conv = vm.conversation
    val isGroup = conv?.kind == ConvKindFfi.GROUP
    val active = conv?.state == ConvStateFfi.ACTIVE
    val peer = vm.members.firstOrNull { !it.isMe }
    var actionsFor by remember { mutableStateOf<MessageFfi?>(null) }

    Scaffold(
        modifier = Modifier.imePadding(),
        topBar = {
            TopAppBar(
                navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) },
                title = {
                    Row(
                        Modifier.clickable {
                            if (isGroup) onInfo() else peer?.let { onVerify(it.accountId) }
                        },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Avatar(conv?.title ?: "?", 36.dp)
                        Spacer(Modifier.size(10.dp))
                        Column {
                            Text(
                                conv?.title ?: "",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                style = MaterialTheme.typography.titleMedium
                            )
                            if (isGroup) {
                                Text(
                                    "${vm.members.size} members",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            } else {
                                peer?.trust?.let { TrustBadge(it) }
                            }
                        }
                    }
                },
                actions = { if (isGroup) IconAction(Icons.Default.MoreVert, "Group info", onInfo) },
            )
        },
        bottomBar = {
            when {
                conv?.accessRevoked == true -> Banner("Group access revoked. Earlier messages can no longer be opened on this device.")
                active -> InputBar(vm)
                else -> Banner("You can't send messages in this conversation.")
            }
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            vm.error?.let { Banner(it, error = true, actionLabel = "Dismiss") { vm.error = null } }
            vm.uploading?.let { LinearProgressIndicator(progress = { it }, modifier = Modifier.fillMaxWidth()) }
            if (vm.messages.isEmpty()) {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Text(
                        "Messages are end-to-end encrypted.\nSay hello 👋",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(32.dp)
                    )
                }
            } else {
                LazyColumn(
                    Modifier.weight(1f).fillMaxWidth(),
                    reverseLayout = true,
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    items(vm.messages, key = { it.id }) { m ->
                        val prevSender = vm.messages.getOrNull(vm.messages.indexOf(m) + 1)?.senderAccount
                        MessageBubble(m, isGroup && !m.outgoing && prevSender != m.senderAccount, vm, onOpenAttachment, onLong = {
                            actionsFor =
                                m
                        })
                    }
                    if (vm.hasMore) {
                        item(key = "older") {
                            LaunchedEffect(vm.messages.size) { vm.loadOlder() }
                            Box(Modifier.fillMaxWidth().padding(8.dp), contentAlignment = Alignment.Center) {
                                Text("Loading earlier messages…", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
            }
        }
    }
    actionsFor?.let { m ->
        SecureDialog(
            onDismiss = { actionsFor = null },
            title = "Message",
            confirmLabel = "Close",
            dismissLabel = null,
            text = {
                Column {
                    TextButton(onClick = {
                        vm.replyTo = m
                        actionsFor = null
                    }) { Text("Reply") }
                    if (m.text.isNotEmpty()) {
                        TextButton(onClick = {
                            SensitiveClipboard.copy(ctx, "Cipher message", m.text)
                            actionsFor =
                                null
                        }) { Text("Copy text (cleared after 60 s)") }
                    }
                    if (m.state ==
                        DeliveryStateFfi.FAILED
                    ) {
                        TextButton(onClick = {
                            vm.retry(m)
                            actionsFor = null
                        }) { Text("Retry sending") }
                    }
                    TextButton(onClick = {
                        vm.delete(m)
                        actionsFor = null
                    }) { Text("Delete on this device", color = MaterialTheme.colorScheme.error) }
                }
            },
        )
    }
}

@Composable
private fun MessageBubble(m: MessageFfi, showSender: Boolean, vm: ChatViewModel, onOpen: (MessageFfi) -> Unit, onLong: () -> Unit) {
    val mine = m.outgoing
    val bg = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start) {
        Surface(
            color = bg,
            shape = RoundedCornerShape(
                topStart = 18.dp,
                topEnd = 18.dp,
                bottomStart = if (mine) 18.dp else 4.dp,
                bottomEnd = if (mine) 4.dp else 18.dp
            ),
            modifier = Modifier.widthIn(max = 300.dp).clip(RoundedCornerShape(18.dp)).combinedClickable(
                onClick = {
                    if (m.attachment != null) {
                        onOpen(m)
                    } else if (m.state == DeliveryStateFfi.FAILED) {
                        vm.retry(m)
                    }
                },
                onLongClick = onLong,
            ),
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                if (m.unavailable) {
                    Text(
                        "Message unavailable \u2014 group access revoked",
                        style = MaterialTheme.typography.bodyMedium,
                        fontStyle = FontStyle.Italic,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    return@Column
                }
                if (showSender) Text(m.senderName, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                m.replyTo?.let { rid ->
                    val quoted = vm.messages.firstOrNull { it.id == rid }
                    Surface(
                        color = MaterialTheme.colorScheme.background.copy(alpha = 0.35f),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.padding(bottom = 4.dp)
                    ) {
                        Text(
                            quoted?.let { it.text.ifBlank { it.attachment?.filename ?: "" } } ?: "Earlier message",
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(8.dp),
                        )
                    }
                }
                m.attachment?.let { AttachmentTile(m, it, vm) }
                if (m.text.isNotEmpty()) Text(m.text, style = MaterialTheme.typography.bodyLarge)
                Row(Modifier.align(Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        formatTime(m.tsMs),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (mine) {
                        Spacer(Modifier.size(4.dp))
                        val (icon, tint) = when (m.state) {
                            DeliveryStateFfi.PENDING -> Icons.Default.Schedule to MaterialTheme.colorScheme.onSurfaceVariant
                            DeliveryStateFfi.SENT -> Icons.Default.Check to MaterialTheme.colorScheme.onSurfaceVariant
                            DeliveryStateFfi.DELIVERED -> Icons.Default.DoneAll to MaterialTheme.colorScheme.tertiary
                            DeliveryStateFfi.FAILED -> Icons.Default.ErrorOutline to MaterialTheme.colorScheme.error
                            DeliveryStateFfi.RECEIVED -> Icons.Default.Check to MaterialTheme.colorScheme.onSurfaceVariant
                        }
                        Icon(icon, contentDescription = m.state.name.lowercase(), tint = tint, modifier = Modifier.size(14.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun AttachmentTile(m: MessageFfi, a: uniffi.cipher_ffi.AttachmentViewFfi, vm: ChatViewModel) {
    when (a.kind) {
        AttachmentKindFfi.IMAGE, AttachmentKindFfi.VIDEO, AttachmentKindFfi.PDF -> {
            val thumb by produceState<androidx.compose.ui.graphics.ImageBitmap?>(null, m.id) {
                if (a.hasThumbnail) {
                    vm.openAttachment(m, true)?.let { b ->
                        app.cipher.messenger.media.SafeDecode.bitmap(b, 640)?.let { value = it.asImageBitmap() }
                    }
                }
            }
            Box(
                Modifier.size(
                    width = 240.dp,
                    height = 170.dp
                ).clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.background.copy(alpha = 0.4f)),
                contentAlignment = Alignment.Center
            ) {
                thumb?.let { Image(it, null, contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize()) }
                    ?: Icon(
                        if (a.kind ==
                            AttachmentKindFfi.PDF
                        ) {
                            Icons.Default.PictureAsPdf
                        } else if (a.kind ==
                            AttachmentKindFfi.VIDEO
                        ) {
                            Icons.Default.Videocam
                        } else {
                            Icons.Default.Image
                        },
                        null,
                        modifier = Modifier.size(40.dp)
                    )
                if (a.kind == AttachmentKindFfi.VIDEO) Icon(Icons.Default.PlayArrow, "Play", modifier = Modifier.size(48.dp))
            }
            if (a.kind ==
                AttachmentKindFfi.PDF
            ) {
                Text("${a.filename} · ${formatSize(a.sizeBytes)}", style = MaterialTheme.typography.bodyMedium)
            }
        }
        AttachmentKindFfi.VOICE, AttachmentKindFfi.AUDIO -> Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(vertical = 4.dp)
        ) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primary, modifier = Modifier.size(36.dp)) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Default.PlayArrow, "Play", tint = MaterialTheme.colorScheme.onPrimary)
                }
            }
            Spacer(Modifier.size(10.dp))
            Text(
                if (a.kind ==
                    AttachmentKindFfi.VOICE
                ) {
                    "Voice message · ${formatDuration(a.durationMs)}"
                } else {
                    "${a.filename} · ${formatSize(a.sizeBytes)}"
                }
            )
        }
        AttachmentKindFfi.FILE -> Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
            Icon(Icons.AutoMirrored.Filled.InsertDriveFile, null, modifier = Modifier.size(32.dp))
            Spacer(Modifier.size(8.dp))
            Column {
                Text(a.filename, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    formatSize(a.sizeBytes),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun InputBar(vm: ChatViewModel) {
    val ctx = LocalContext.current
    var text by remember { mutableStateOf("") }
    var panel by remember { mutableStateOf(false) }
    var recording by remember { mutableStateOf(false) }
    var elapsed by remember { mutableStateOf(0) }
    val recorder = remember { VoiceRecorder(ctx) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let { sendPicked(ctx, vm, it) } }
    val micPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) {
            runCatching {
                recorder.start()
                recording = true
            }.onFailure { vm.error = "Couldn't start recording." }
        } else {
            vm.error = "Microphone permission is needed for voice notes."
        }
    }
    LaunchedEffect(recording) {
        elapsed = 0
        while (recording) {
            delay(1000)
            elapsed++
            if (elapsed >= 300) {
                recorder.stop()?.let { (a, d) -> vm.sendVoice(a, d) }
                recording = false
            }
        }
    }

    Column(Modifier.navigationBarsPadding().background(MaterialTheme.colorScheme.surfaceContainer)) {
        vm.replyTo?.let { r ->
            Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Replying to: ${r.text.ifBlank {
                        r.attachment?.filename ?: "attachment"
                    }}",
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium
                )
                IconButton(onClick = { vm.replyTo = null }) { Icon(Icons.Default.Close, "Cancel reply") }
            }
        }
        if (panel && !recording) {
            Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.SpaceEvenly) {
                AttachOption("Photo", Icons.Default.Image) {
                    picker.launch(arrayOf("image/*"))
                    panel = false
                }
                AttachOption("Video", Icons.Default.Videocam) {
                    picker.launch(arrayOf("video/*"))
                    panel = false
                }
                AttachOption("PDF", Icons.Default.PictureAsPdf) {
                    picker.launch(arrayOf("application/pdf"))
                    panel = false
                }
                AttachOption("File", Icons.AutoMirrored.Filled.InsertDriveFile) {
                    picker.launch(arrayOf("*/*"))
                    panel = false
                }
            }
        }
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            if (recording) {
                IconButton(onClick = {
                    recorder.cancel()
                    recording = false
                }) { Icon(Icons.Default.Close, "Discard recording", tint = MaterialTheme.colorScheme.error) }
                Text(
                    "Recording  ${elapsed / 60}:${"%02d".format(elapsed % 60)}",
                    modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.error
                )
                IconButton(onClick = {
                    recorder.stop()?.let { (a, d) -> vm.sendVoice(a, d) }
                    recording = false
                }) {
                    Icon(Icons.AutoMirrored.Filled.Send, "Send voice note", tint = MaterialTheme.colorScheme.primary)
                }
            } else {
                IconButton(onClick = { panel = !panel }) { Icon(Icons.Default.AttachFile, "Attach") }
                PrivateTextField(
                    value = text,
                    onValueChange = { text = it.take(8000) },
                    placeholder = { Text("Message") },
                    maxLines = 5,
                    shape = RoundedCornerShape(24.dp),
                    modifier = Modifier.weight(1f),
                )
                if (text.isBlank()) {
                    IconButton(onClick = {
                        if (ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                            runCatching {
                                recorder.start()
                                recording = true
                            }.onFailure { vm.error = "Couldn't start recording." }
                        } else {
                            micPermission.launch(Manifest.permission.RECORD_AUDIO)
                        }
                    }) { Icon(Icons.Default.Mic, "Record voice note") }
                } else {
                    IconButton(onClick = {
                        vm.send(text.trim())
                        text = ""
                    }) { Icon(Icons.AutoMirrored.Filled.Send, "Send", tint = MaterialTheme.colorScheme.primary) }
                }
            }
        }
    }
}

@Composable
private fun AttachOption(label: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Column(Modifier.clickable(onClick = onClick).padding(8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(icon, label)
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}

/** The picked file is handed to the Rust core as a file DESCRIPTOR (`/proc/self/fd/N`): no plaintext copy is ever written. */
private fun sendPicked(ctx: android.content.Context, vm: ChatViewModel, uri: Uri) {
    val resolver = ctx.contentResolver
    var name = "file"
    var size = -1L
    resolver.query(uri, null, null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            c.getColumnIndex(OpenableColumns.DISPLAY_NAME).takeIf { it >= 0 }?.let { name = c.getString(it) ?: name }
            c.getColumnIndex(OpenableColumns.SIZE).takeIf { it >= 0 }?.let { size = c.getLong(it) }
        }
    }
    if (size > MAX_ATTACHMENT_BYTES) {
        vm.error = "Files can be at most 100 MB."
        return
    }
    val pfd = resolver.openFileDescriptor(uri, "r") ?: run {
        vm.error = "Couldn't open that file."
        return
    }
    val declared = resolver.getType(uri) ?: "application/octet-stream"
    val (mime, kind) = when {
        declared in setOf("image/jpeg", "image/png", "image/gif", "image/webp") -> declared to AttachmentKindFfi.IMAGE
        declared == "video/mp4" -> declared to AttachmentKindFfi.VIDEO
        declared == "application/pdf" -> declared to AttachmentKindFfi.PDF
        declared == "audio/aac" || declared == "audio/ogg" || declared == "audio/mp4" -> declared to AttachmentKindFfi.AUDIO
        else -> "application/octet-stream" to AttachmentKindFfi.FILE
    }
    val thumb = when (kind) {
        AttachmentKindFfi.IMAGE -> ThumbnailMaker.forImage(ctx, uri)
        AttachmentKindFfi.VIDEO -> ThumbnailMaker.forVideo(ctx, uri)
        AttachmentKindFfi.PDF -> ThumbnailMaker.forPdf(ctx, uri)
        else -> null
    }
    vm.sendAttachment("/proc/self/fd/${pfd.fd}", mime, name, kind, thumb) { pfd.close() }
}
