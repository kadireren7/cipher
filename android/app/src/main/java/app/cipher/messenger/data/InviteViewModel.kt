package app.cipher.messenger.data

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.cipher.messenger.CipherApplication
import app.cipher.messenger.util.humanize
import kotlinx.coroutines.launch
import uniffi.cipher_ffi.InviteCreatedFfi
import uniffi.cipher_ffi.InviteInfoFfi
import uniffi.cipher_ffi.InvitePreviewFfi
import uniffi.cipher_ffi.JoinRequestFfi

/**
 * Invitation state for one group (`convId`) or, with `convId == null`, for every request waiting for this admin.
 * The created link is held ONLY here, in memory: it is shown once, is never saved in instance state, and is dropped with this object.
 */
class InviteViewModel(app: Application, private val convId: String?) : AndroidViewModel(app) {
    private val host = (app as CipherApplication).host

    var invites by mutableStateOf<List<InviteInfoFfi>>(emptyList())
        private set
    var requests by mutableStateOf<List<JoinRequestFfi>>(emptyList())
        private set
    var created by mutableStateOf<InviteCreatedFfi?>(null)
        private set
    var preview by mutableStateOf<InvitePreviewFfi?>(null)
        private set
    var requested by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)

    private fun run(block: suspend () -> Unit) {
        viewModelScope.launch {
            busy = true
            try {
                block()
            } catch (e: Exception) {
                error = humanize(e)
            } finally {
                busy = false
            }
        }
    }

    /** Reloads this group's invitations and polls the relay for new requests. */
    fun load() = run {
        convId?.let { id -> invites = host.call { it.listInvites(id) } }
        refreshRequests()
    }

    private suspend fun refreshRequests() {
        val all = if (host.call { it.hasLiveInvites() }) host.call { it.pollJoinRequests() } else emptyList()
        requests = if (convId == null) all else all.filter { it.conversationId == convId }
    }

    fun create(lifetimeMs: Long, maxUses: Int, automatic: Boolean) = run {
        val id = convId ?: return@run
        created = host.call { it.createInvite(id, lifetimeMs.toULong(), maxUses.toUInt(), automatic) }
        invites = host.call { it.listInvites(id) }
    }

    fun dismissCreated() {
        created = null
    }

    fun revoke(inviteId: String) = run {
        host.call { it.revokeInvite(inviteId) }
        convId?.let { id -> invites = host.call { it.listInvites(id) } }
        refreshRequests()
    }

    fun resolve(requestId: String, approve: Boolean) = run {
        host.call { it.resolveJoinRequest(requestId, approve) }
        convId?.let { id -> invites = host.call { it.listInvites(id) } }
        refreshRequests()
    }

    // ---- the joiner's side ----

    fun lookUp(link: String) = run {
        preview = null
        requested = false
        preview = host.call { it.previewInvite(link.trim()) }
    }

    fun requestToJoin(link: String, name: String) = run {
        host.call { it.requestToJoin(link.trim(), name.trim()) }
        requested = true
    }
}
