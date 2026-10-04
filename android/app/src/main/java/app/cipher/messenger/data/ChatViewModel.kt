package app.cipher.messenger.data

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.cipher.messenger.CipherApplication
import app.cipher.messenger.util.humanize
import kotlinx.coroutines.launch
import uniffi.cipher_ffi.ConversationFfi
import uniffi.cipher_ffi.MemberFfi
import uniffi.cipher_ffi.MessageFfi
import uniffi.cipher_ffi.RoleFfi

/** State of one open conversation: newest-first message page(s), members, role. Pages are loaded on demand (never the whole history). */
class ChatViewModel(app: Application, val convId: String) : AndroidViewModel(app) {
    private val host = (app as CipherApplication).host
    val messages = mutableStateListOf<MessageFfi>() // newest first
    var conversation by mutableStateOf<ConversationFfi?>(null)
        private set
    var members by mutableStateOf<List<MemberFfi>>(emptyList())
        private set
    var myRole by mutableStateOf(RoleFfi.MEMBER)
        private set
    var error by mutableStateOf<String?>(null)
    var loadingOlder by mutableStateOf(false)
        private set
    private var cursor: String? = null
    var hasMore by mutableStateOf(false)
        private set
    var replyTo by mutableStateOf<MessageFfi?>(null)
    var uploading by mutableStateOf<Float?>(null)
        private set

    private fun fail(e: Throwable) {
        error = humanize(e)
    }

    fun refresh() {
        viewModelScope.launch {
            try {
                val (conv, page, roster) = host.call {
                    val c = it.getConversation(convId)
                    val p = it.getHistory(convId, null, 40u)
                    if (c.unread > 0u) it.markRead(convId)
                    // Membership can change under us (commits from other members), so the roster is re-read with every refresh.
                    val r = if (c.kind == uniffi.cipher_ffi.ConvKindFfi.GROUP) it.getMembers(convId) to it.myRole(convId) else null
                    Triple(c, p, r)
                }
                conversation = conv
                roster?.let { (m, r) ->
                    members = m
                    myRole = r
                }
                // Replace the first page; keep any older pages that were already loaded.
                val loadedOlder = if (messages.size > page.items.size) messages.drop(page.items.size) else emptyList()
                val ids = page.items.map { it.id }.toSet()
                val keepOlder = loadedOlder.filter { it.id !in ids }
                messages.clear()
                messages.addAll(page.items)
                messages.addAll(keepOlder)
                if (cursor == null || keepOlder.isEmpty()) {
                    cursor = page.nextCursor
                    hasMore = page.nextCursor != null
                }
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun loadMembers() {
        viewModelScope.launch {
            try {
                val (m, r) = host.call { it.getMembers(convId) to it.myRole(convId) }
                members = m
                myRole = r
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun loadOlder() {
        val c = cursor ?: return
        if (loadingOlder) return
        loadingOlder = true
        viewModelScope.launch {
            try {
                val page = host.call { it.getHistory(convId, c, 40u) }
                val ids = messages.map { it.id }.toSet()
                messages.addAll(page.items.filter { it.id !in ids })
                cursor = page.nextCursor
                hasMore = page.nextCursor != null
            } catch (e: Exception) {
                fail(e)
            } finally {
                loadingOlder = false
            }
        }
    }

    fun send(text: String) {
        val reply = replyTo?.id
        replyTo = null
        viewModelScope.launch {
            try {
                host.call { it.sendText(convId, text, reply) }
                refresh()
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun sendVoice(audio: ByteArray, durationMs: Int) {
        viewModelScope.launch {
            try {
                host.call { it.sendVoiceNote(convId, audio, durationMs.toUInt(), replyTo?.id) }
                replyTo = null
                refresh()
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun sendAttachment(
        fdPath: String,
        mime: String,
        name: String,
        kind: uniffi.cipher_ffi.AttachmentKindFfi,
        thumb: ByteArray?,
        onFinished: () -> Unit,
    ) {
        val reply = replyTo?.id
        replyTo = null
        viewModelScope.launch {
            uploading = 0f
            try {
                val progress = object : uniffi.cipher_ffi.ProgressCallback {
                    override fun onProgress(done: ULong, total: ULong): Boolean {
                        uploading = if (total == 0uL) 0f else (done.toDouble() / total.toDouble()).toFloat().coerceIn(0f, 1f)
                        return true
                    }
                }
                host.call { it.sendAttachment(convId, fdPath, mime, name, kind, "", thumb, null, reply, progress) }
                refresh()
            } catch (e: Exception) {
                fail(e)
            } finally {
                uploading = null
                onFinished()
            }
        }
    }

    fun retry(m: MessageFfi) {
        viewModelScope.launch {
            try {
                host.call { it.retryMessage(convId, m.id) }
                refresh()
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun delete(m: MessageFfi) {
        viewModelScope.launch {
            try {
                host.call { it.deleteMessageLocal(convId, m.id) }
                messages.removeAll { it.id == m.id }
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    suspend fun openAttachment(m: MessageFfi, thumbnail: Boolean): ByteArray? = try {
        host.call { it.openAttachment(convId, m.id, thumbnail, null) }
    } catch (e: Exception) {
        if (!thumbnail) fail(e)
        null
    }

    // ---- group administration (each is authorised by the Rust core against the group's role policy) ----

    private fun admin(block: (uniffi.cipher_ffi.CipherEngine) -> Unit) {
        viewModelScope.launch {
            try {
                host.call(block)
                refresh()
                loadMembers()
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun rename(name: String) = admin { it.renameGroup(convId, name) }

    fun addMember(account: String) = admin { it.addGroupMember(convId, account) }

    fun removeMember(account: String) = admin { it.removeGroupMember(convId, account) }

    fun promote(account: String) = admin { it.promoteAdmin(convId, account) }

    fun demote(account: String) = admin { it.demoteAdmin(convId, account) }

    fun transferOwnership(account: String) = admin { it.transferOwnership(convId, account) }

    fun leave(onDone: () -> Unit) {
        viewModelScope.launch {
            try {
                host.call { it.leaveGroup(convId) }
                onDone()
            } catch (e: Exception) {
                fail(e)
            }
        }
    }

    fun refreshKeys() = admin { it.refreshKeys(convId) }
}
