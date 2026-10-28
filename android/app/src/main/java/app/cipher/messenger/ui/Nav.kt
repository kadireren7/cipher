package app.cipher.messenger.ui

import android.app.Application
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.ChatViewModel
import app.cipher.messenger.data.InviteViewModel
import app.cipher.messenger.ui.screens.ChatListScreen
import app.cipher.messenger.ui.screens.ContactCardScreen
import app.cipher.messenger.ui.screens.ConversationScreen
import app.cipher.messenger.ui.screens.DevicesScreen
import app.cipher.messenger.ui.screens.GroupInfoScreen
import app.cipher.messenger.ui.screens.IdentityScreen
import app.cipher.messenger.ui.screens.InvitationsScreen
import app.cipher.messenger.ui.screens.JoinRequestsScreen
import app.cipher.messenger.ui.screens.JoinWithLinkScreen
import app.cipher.messenger.ui.screens.LockScreen
import app.cipher.messenger.ui.screens.MembersScreen
import app.cipher.messenger.ui.screens.NewConversationScreen
import app.cipher.messenger.ui.screens.NewGroupScreen
import app.cipher.messenger.ui.screens.OnboardingFlow
import app.cipher.messenger.ui.screens.QrScanScreen
import app.cipher.messenger.ui.screens.RelaySettingsScreen
import app.cipher.messenger.ui.screens.SecurityInfoScreen
import app.cipher.messenger.ui.screens.SettingsScreen
import app.cipher.messenger.ui.screens.VerifyContactScreen
import app.cipher.messenger.ui.screens.ViewerScreen
import app.cipher.messenger.ui.theme.CipherTheme
import kotlinx.coroutines.delay
import uniffi.cipher_ffi.SecurityEventKind

@Composable
fun CipherRoot() {
    CipherTheme {
        val vm: AppViewModel = viewModel()
        val state by vm.state.collectAsState()
        val snackbar = remember { SnackbarHostState() }

        LifecycleResumeEffect(Unit) {
            vm.onResume()
            onPauseOrDispose { }
        }
        LaunchedEffect(state.toast) {
            state.toast?.let {
                snackbar.showSnackbar(it)
                vm.consumeToast()
            }
        }
        // Foreground polling while unlocked. The engine locks itself (and this loop stops) the moment the app is backgrounded.
        LaunchedEffect(state.unlocked) {
            while (state.unlocked) {
                delay(vm.sync()) // the engine's network profile decides the (jittered) cadence
            }
        }

        Scaffold(snackbarHost = { SnackbarHost(snackbar) }) { pad ->
            Box(Modifier.fillMaxSize().then(Modifier), contentAlignment = Alignment.Center) {
                when {
                    !state.loaded -> CircularProgressIndicator()
                    state.needsOnboarding -> OnboardingFlow(state, vm)
                    !state.unlocked -> LockScreen(state, vm)
                    else -> MainNav(vm, rememberNavController())
                }
            }
            pad.hashCode()
        }
    }
}

@Composable
private fun MainNav(vm: AppViewModel, nav: NavHostController) {
    val state by vm.state.collectAsState()
    val app = LocalContext.current.applicationContext as Application

    @Composable
    fun chat(id: String): ChatViewModel = viewModel(key = "chat-$id", factory = viewModelFactory { initializer { ChatViewModel(app, id) } })

    NavHost(nav, startDestination = "list") {
        composable("list") {
            ChatListScreen(
                state,
                onOpen = { nav.navigate("chat/${it.id}") },
                onNew = { nav.navigate("new") },
                onIdentity = { nav.navigate("identity") },
                onSettings = { nav.navigate("settings") },
                onLock = { vm.lockNow() },
                onAccept = { vm.acceptConversation(it) },
                onDecline = { vm.declineConversation(it) },
                onVerify = { nav.navigate("verify/$it") },
                onJoinRequests = { nav.navigate("joinrequests") },
            )
        }
        composable("new") { entry ->
            val scanned by entry.savedStateHandle.getStateFlow<String?>("qr", null).collectAsState()
            LaunchedEffect(scanned) {
                scanned?.let {
                    // a scanned CONTACT CARD (possibly for a person on another server) is read from their screen: it counts as verified
                    if (vm.looksLikeInvite(it)) {
                        vm.pendingInviteLink = it.trim()
                        entry.savedStateHandle["qr"] = null
                        nav.navigate("join")
                        return@let
                    }
                    if (vm.looksLikeCard(it)) vm.addContactByCard(it, "", true) { } else vm.addContactByQr(it, "") { }
                    entry.savedStateHandle["qr"] = null
                }
            }
            NewConversationScreen(
                state,
                vm,
                onBack = { nav.popBackStack() },
                onOpenConversation = { id -> nav.navigate("chat/$id") { popUpTo("list") } },
                onScanQr = { nav.navigate("scan") },
                onNewGroup = { nav.navigate("newgroup") },
                onVerify = { nav.navigate("verify/$it") },
                onMyCard = { nav.navigate("mycard") },
                onJoinLink = { nav.navigate("join") },
            )
        }
        composable("join") { entry ->
            val scanned by entry.savedStateHandle.getStateFlow<String?>("qr", null).collectAsState()
            val ivm: InviteViewModel = viewModel(key = "join", factory = viewModelFactory { initializer { InviteViewModel(app, null) } })
            val link = scanned?.takeIf { vm.looksLikeInvite(it) } ?: vm.pendingInviteLink
            LaunchedEffect(link) {
                // consume the in-memory hand-over: the link lives only in this screen's state from here on
                if (link.isNotBlank()) vm.pendingInviteLink = ""
            }
            JoinWithLinkScreen(ivm, link, onBack = { nav.popBackStack() }, onScan = { nav.navigate("scan") })
        }
        composable("joinrequests") {
            val ivm: InviteViewModel =
                viewModel(key = "joinrequests", factory = viewModelFactory { initializer { InviteViewModel(app, null) } })
            JoinRequestsScreen(ivm, onBack = { nav.popBackStack() })
        }
        composable("invites/{id}") { entry ->
            val id = entry.arguments?.getString("id") ?: return@composable
            val ivm: InviteViewModel =
                viewModel(key = "invites-$id", factory = viewModelFactory { initializer { InviteViewModel(app, id) } })
            InvitationsScreen(ivm, onBack = { nav.popBackStack() })
        }
        composable("mycard") { ContactCardScreen(state, vm, onBack = { nav.popBackStack() }) }
        composable("relay") { RelaySettingsScreen(vm, onBack = { nav.popBackStack() }) }
        composable("newgroup") {
            NewGroupScreen(state, vm, onBack = { nav.popBackStack() }, onCreated = { id -> nav.navigate("chat/$id") { popUpTo("list") } })
        }
        composable("scan") {
            QrScanScreen(
                onResult = { payload ->
                    nav.previousBackStackEntry?.savedStateHandle?.set("qr", payload)
                    nav.popBackStack()
                },
                onBack = { nav.popBackStack() },
            )
        }
        composable("chat/{id}", arguments = listOf(navArgument("id") { type = NavType.StringType })) { entry ->
            val id = entry.arguments?.getString("id") ?: return@composable
            val cvm = chat(id)
            ConversationScreen(
                cvm,
                state.syncTick,
                onBack = { nav.popBackStack() },
                onInfo = { nav.navigate("groupinfo/$id") },
                onVerify = { nav.navigate("verify/$it") },
                onOpenAttachment = { m -> nav.navigate("viewer/$id/${m.id}") },
            )
        }
        composable("groupinfo/{id}") { entry ->
            val id = entry.arguments?.getString("id") ?: return@composable
            GroupInfoScreen(
                chat(id),
                onBack = { nav.popBackStack() },
                onMembers = { nav.navigate("members/$id") },
                onLeft = {
                    vm.reloadConversations()
                    nav.popBackStack("list", false)
                },
                homeUnavailable = state.securityEvents.any { it.kind == SecurityEventKind.HOME_RELAY_UNAVAILABLE && it.subject == id },
                onInvites = { nav.navigate("invites/$id") },
                onReplaced = { newId ->
                    vm.reloadConversations()
                    nav.navigate("chat/$newId") { popUpTo("list") }
                },
            )
        }
        composable("members/{id}") { entry ->
            val id = entry.arguments?.getString("id") ?: return@composable
            MembersScreen(chat(id), state, onBack = { nav.popBackStack() }, onVerify = { nav.navigate("verify/$it") })
        }
        composable("verify/{account}") { entry ->
            val account = entry.arguments?.getString("account") ?: return@composable
            val scanned by entry.savedStateHandle.getStateFlow<String?>("qr", null).collectAsState()
            VerifyContactScreen(
                account,
                state,
                vm,
                state.identity?.qrPayload,
                scanned,
                onScan = { nav.navigate("scan") },
                onBack = { nav.popBackStack() },
            )
            LaunchedEffect(scanned) { if (scanned != null) entry.savedStateHandle["qr"] = null }
        }
        composable("viewer/{conv}/{msg}") { entry ->
            val conv = entry.arguments?.getString("conv") ?: return@composable
            val msg = entry.arguments?.getString("msg") ?: return@composable
            ViewerScreen(conv, msg, vm, onBack = { nav.popBackStack() })
        }
        composable("identity") { IdentityScreen(state, onBack = { nav.popBackStack() }) }
        composable("devices") { DevicesScreen(vm, onBack = { nav.popBackStack() }) }
        composable("settings") {
            SettingsScreen(state, vm, onBack = {
                nav.popBackStack()
            }, onSecurity = { nav.navigate("security") }, onDevices = { nav.navigate("devices") }, onRelay = { nav.navigate("relay") })
        }
        composable("security") { SecurityInfoScreen(state, vm, onBack = { nav.popBackStack() }) }
    }
}
