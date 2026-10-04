package app.cipher.messenger.data

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.cipher.messenger.CipherApplication
import app.cipher.messenger.net.RouteStatus
import app.cipher.messenger.net.SocksEndpoint
import app.cipher.messenger.util.SafeLog
import app.cipher.messenger.util.humanize
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import uniffi.cipher_ffi.CipherException
import uniffi.cipher_ffi.ContactFfi
import uniffi.cipher_ffi.ConversationFfi
import uniffi.cipher_ffi.LockStateFfi
import uniffi.cipher_ffi.PublicIdentityFfi
import uniffi.cipher_ffi.SecurityEventFfi
import uniffi.cipher_ffi.SettingsFfi
import uniffi.cipher_ffi.VaultStatusFfi

data class UiState(
    val loaded: Boolean = false,
    val relayConfigured: Boolean = false,
    val vault: VaultStatusFfi? = null,
    val identity: PublicIdentityFfi? = null,
    val conversations: List<ConversationFfi> = emptyList(),
    val contacts: List<ContactFfi> = emptyList(),
    val settings: SettingsFfi? = null,
    val securityEvents: List<SecurityEventFfi> = emptyList(),
    val toast: String? = null,
    val busy: Boolean = false,
    val syncTick: Int = 0,
    val offline: Boolean = false,
    val onboardingDone: Boolean = false,
    val pinOnly: Boolean = false,
    /** The vault was refused because the files on this phone are older than the state the device last recorded (FR-05). */
    val rolledBack: Boolean = false,
    /** Actual state of the privacy route (never inferred from E2EE being active). */
    val route: RouteStatus = RouteStatus.CONNECTING,
) {
    val unlocked: Boolean get() = vault?.state == LockStateFfi.UNLOCKED
    val needsOnboarding: Boolean get() = !relayConfigured || !onboardingDone
}

/** Application-wide state: vault lifecycle, identity, contacts, conversation list, periodic sync. */
class AppViewModel(app: Application) : AndroidViewModel(app) {
    val host = (app as CipherApplication).host
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        viewModelScope.launch { refreshStatus() }
    }

    private fun toast(msg: String?) = _state.update { it.copy(toast = msg) }

    fun consumeToast() = toast(null)

    /** Runs an engine operation; user-facing errors become a toast and state is refreshed if the vault changed under us. */
    private fun launchOp(busy: Boolean = false, block: suspend () -> Unit) {
        viewModelScope.launch {
            if (busy) _state.update { it.copy(busy = true) }
            try {
                block()
            } catch (e: CipherException) {
                if (e is CipherException.Locked || e is CipherException.Invalidated || e is CipherException.RolledBack) refreshStatus()
                toast(humanize(e))
            } catch (e: Exception) {
                SafeLog.event(SafeLog.Code.UI_ERROR)
                toast(humanize(e))
            } finally {
                if (busy) _state.update { it.copy(busy = false) }
            }
        }
    }

    suspend fun refreshStatus() {
        if (!host.isConfigured) {
            _state.update { it.copy(loaded = true, relayConfigured = false, vault = null) }
            return
        }
        val status = runCatching { host.call { it.status() } }.getOrNull()
        _state.update {
            it.copy(
                loaded = true,
                relayConfigured = true,
                vault = status,
                onboardingDone = host.onboardingComplete(),
                pinOnly = status?.pinOnly == true,
                rolledBack = host.wasRolledBack(),
            )
        }
        if (status?.state == LockStateFfi.UNLOCKED) loadAll()
    }

    /** Called when the app returns to the foreground: the engine already dropped its keys when we left. */
    fun onResume() {
        viewModelScope.launch { refreshStatus() }
    }

    private suspend fun loadAll() {
        val ident = runCatching { host.call { it.getPublicIdentity() } }.getOrNull()
        val convs = runCatching { host.call { it.listConversations() } }.getOrDefault(emptyList())
        val contacts = runCatching { host.call { it.listContacts() } }.getOrDefault(emptyList())
        val settings = runCatching { host.call { it.getSettings() } }.getOrNull()
        _state.update { it.copy(identity = ident, conversations = convs, contacts = contacts, settings = settings) }
        drainEvents()
    }

    private suspend fun drainEvents() {
        val ev = runCatching { host.call { it.takeSecurityEvents() } }.getOrDefault(emptyList())
        if (ev.isNotEmpty()) {
            val log = runCatching { host.call { it.securityEventLog(50u) } }.getOrDefault(ev)
            _state.update { it.copy(securityEvents = log) }
        }
    }

    // ------------------------------------------------------------------------------------------------ onboarding

    fun configureRelay(url: String) = launchOp {
        val u = url.trim().removeSuffix("/")
        if (!u.startsWith("https://")) {
            toast("The server address must start with https://")
            return@launchOp
        }
        // Only scheme://host[:port] is a valid relay address: no user info, path, query or fragment (and no concatenated URLs).
        val parsed = runCatching { java.net.URI(u) }.getOrNull()
        if (parsed == null ||
            parsed.host.isNullOrEmpty() ||
            parsed.userInfo != null ||
            !parsed.rawPath.isNullOrEmpty() ||
            parsed.rawQuery != null ||
            parsed.rawFragment != null ||
            u.indexOf("://") != u.lastIndexOf("://")
        ) {
            toast("Enter the address like https://relay.example.org or https://relay.example.org:8443")
            return@launchOp
        }
        host.configureRelay(u)
        refreshStatus()
    }

    /** Runs [block] like [launchOp] but ALWAYS reports the outcome, so an onboarding screen can never wait forever on a failure. */
    private fun launchReporting(onDone: (Boolean) -> Unit, block: suspend () -> Unit) = launchOp(busy = true) {
        var ok = false
        try {
            block()
            ok = true
        } finally {
            onDone(ok)
        }
    }

    fun provisionWithDeviceAuth(pin: String?, onDone: (Boolean) -> Unit = {}) = launchReporting(onDone) {
        host.setUnlockMode("biometric")
        host.call {
            it.provisionVault()
            if (!pin.isNullOrEmpty()) it.enablePin(pin)
        }
        refreshStatus()
    }

    fun provisionPinOnly(pin: String, onDone: (Boolean) -> Unit = {}) = launchReporting(onDone) {
        host.setUnlockMode("pin")
        host.call { it.provisionVaultPinOnly(pin) }
        refreshStatus()
    }

    fun createIdentity(inviteCode: String, onDone: (Boolean) -> Unit = {}) = launchReporting(onDone) {
        val id = host.call { it.createIdentity(inviteCode.trim()) }
        _state.update { it.copy(identity = id) }
        refreshStatus()
    }

    fun finishOnboarding() {
        host.markOnboardingComplete()
        viewModelScope.launch { refreshStatus() }
    }

    /** User-confirmed reset of this device's Cipher data (never automatic). */
    fun resetLocalData() {
        viewModelScope.launch {
            host.resetLocalData()
            _state.value = UiState(loaded = true)
        }
    }

    // --------------------------------------------------------------------------------------------------- lock

    fun unlockWithDeviceAuth() = launchOp {
        try {
            host.call { it.unlockVaultWithDeviceAuth() }
        } catch (e: CipherException.RolledBack) {
            host.markRolledBack()
            throw e
        }
        SafeLog.event(SafeLog.Code.APP_UNLOCKED)
        refreshStatus()
    }

    fun unlockWithPin(pin: String, onFail: () -> Unit = {}) {
        viewModelScope.launch {
            try {
                host.call { it.unlockVaultWithPin(pin) }
                SafeLog.event(SafeLog.Code.APP_UNLOCKED)
                refreshStatus()
            } catch (e: CipherException) {
                if (e is CipherException.RolledBack) host.markRolledBack()
                SafeLog.event(SafeLog.Code.UNLOCK_FAILED)
                refreshStatus()
                toast(humanize(e))
                onFail()
            }
        }
    }

    fun lockNow() {
        viewModelScope.launch {
            host.signalLockNow()
            runCatching { host.call { it.lockVault() } }
            SafeLog.event(SafeLog.Code.APP_LOCKED)
            _state.update { it.copy(conversations = emptyList(), contacts = emptyList(), identity = null, settings = null) }
            refreshStatus()
        }
    }

    // ---------------------------------------------------------------------------------------------------- sync

    /** One foreground tick for the configured network profile; returns how long to wait before the next one. */
    suspend fun sync(): Long {
        var next = 4_000L
        try {
            val t = host.call { it.networkTick() }
            next = t.nextDelayMs.toLong().coerceIn(1_000L, 60_000L)
            val r = t.report
            val convs = host.call { it.listConversations() }
            _state.update {
                it.copy(
                    conversations = convs,
                    syncTick =
                    it.syncTick + (if (r.newMessages > 0u || r.changedConversations.isNotEmpty()) 1 else 0),
                    offline = false
                )
            }
            drainEvents()
        } catch (e: CipherException.Offline) {
            _state.update { it.copy(offline = true) }
        } catch (e: CipherException.Locked) {
            refreshStatus()
        } catch (e: CipherException.Invalidated) {
            refreshStatus()
        } catch (e: Exception) {
            SafeLog.event(SafeLog.Code.SYNC_ERROR)
        }
        _state.update { it.copy(route = host.routeStatus()) }
        return next
    }

    fun saveSocks(text: String): Boolean {
        val e = SocksEndpoint.parse(text) ?: return false
        host.configureSocks(e)
        _state.update { it.copy(route = host.routeStatus()) }
        return true
    }

    fun reloadConversations() {
        viewModelScope.launch {
            val convs = runCatching { host.call { it.listConversations() } }.getOrNull() ?: return@launch
            _state.update { it.copy(conversations = convs) }
        }
    }

    // ------------------------------------------------------------------------------------------------ contacts

    fun addContactById(cipherId: String, name: String, onDone: (ContactFfi?) -> Unit) = launchOp(busy = true) {
        val c = host.call { it.addContactByCipherId(cipherId.trim(), name.trim()) }
        loadAll()
        onDone(c)
    }

    fun addContactByQr(payload: String, name: String, onDone: (ContactFfi?) -> Unit) = launchOp(busy = true) {
        val c = host.call { it.addContactByQr(payload.trim(), name.trim()) }
        loadAll()
        onDone(c)
    }

    fun verifyContactByQr(account: String, payload: String) = launchOp {
        host.call { it.verifyContactByQr(account, payload) }
        loadAll()
        showToast("Verified")
    }

    fun markVerified(account: String) = launchOp {
        host.call { it.verifyIdentity(account) }
        loadAll()
    }

    fun acknowledgeIdentityChange(account: String) = launchOp {
        host.call { it.acknowledgeIdentityChange(account) }
        loadAll()
    }

    fun setBlocked(account: String, blocked: Boolean) = launchOp {
        host.call { it.setContactBlocked(account, blocked) }
        loadAll()
    }

    fun renameContact(account: String, name: String) = launchOp {
        host.call { it.renameContact(account, name) }
        loadAll()
    }

    // ------------------------------------------------------------------------------------------- conversations

    fun startDm(account: String, onDone: (String) -> Unit) = launchOp(busy = true) {
        val id = host.call { it.createConversation(account) }
        reloadConversations()
        onDone(id)
    }

    fun createGroup(name: String, members: List<String>, onDone: (String) -> Unit) = launchOp(busy = true) {
        val id = host.call { it.createGroup(name, members) }
        reloadConversations()
        onDone(id)
    }

    fun acceptConversation(id: String) = launchOp {
        host.call { it.acceptConversation(id) }
        reloadConversations()
    }

    fun declineConversation(id: String) = launchOp {
        host.call { it.declineConversation(id) }
        reloadConversations()
    }

    fun deleteConversation(id: String) = launchOp {
        host.call { it.deleteConversationLocal(id) }
        reloadConversations()
    }

    // --------------------------------------------------------------------------------------------------- settings

    fun saveSettings(s: SettingsFfi) = launchOp {
        host.call { it.setSettings(s) }
        _state.update { it.copy(settings = s) }
    }

    fun setLockTimeout(secs: Int) {
        host.setLockTimeoutSecs(secs)
        toast("Takes effect the next time Cipher starts.")
    }

    fun showToast(message: String) = toast(message)
}
