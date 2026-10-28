package app.cipher.messenger

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.cipher.messenger.ui.screens.InvitationsContent
import app.cipher.messenger.ui.screens.InvitationsUiState
import app.cipher.messenger.ui.screens.JoinUiState
import app.cipher.messenger.ui.screens.JoinWithLinkContent
import app.cipher.messenger.util.InviteFormat
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.cipher_ffi.InviteCreatedFfi
import uniffi.cipher_ffi.InviteInfoFfi
import uniffi.cipher_ffi.InvitePreviewFfi
import uniffi.cipher_ffi.JoinRequestFfi

/** The invitation screens as a person sees them: every state, with the engine replaced by callbacks (the protocol itself is tested end to end in Rust). */
@RunWith(AndroidJUnit4::class)
class InvitationsInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    private val now = 1_800_000_000_000L
    private fun info(id: String, expiresMs: Long, uses: Int, admitted: Int, revoked: Boolean = false, auto: Boolean = false) =
        InviteInfoFfi(id, "conv", expiresMs.toULong(), uses.toUInt(), admitted.toUInt(), auto, revoked)

    private fun request(id: String, name: String) = JoinRequestFfi(id, "inv", "conv", "acct-$id", name, "12345 67890", now.toULong())

    private fun admin(
        state: InvitationsUiState,
        onCreate: (Long, Int, Boolean) -> Unit = { _, _, _ -> },
        onRevoke: (String) -> Unit = {},
        onResolve: (String, Boolean) -> Unit = { _, _ -> },
        onDismissCreated: () -> Unit = {},
        onCopy: (String) -> Unit = {},
        onDismissError: () -> Unit = {},
    ) = compose.setContent {
        MaterialTheme {
            Column(scrollModifier()) {
                InvitationsContent(state, onCreate, onRevoke, onResolve, onDismissCreated, onCopy, onDismissError)
            }
        }
    }

    @Test fun theDefaultIsOneUseTwentyFourHoursAndAnAdminDecides() {
        var got: Triple<Long, Int, Boolean>? = null
        admin(InvitationsUiState(nowMs = now), onCreate = { l, u, a -> got = Triple(l, u, a) })
        compose.onNodeWithTag("invite_create").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(Triple(InviteFormat.DAY_MS, 1, false), got) }
    }

    @Test fun choosingAutomaticAdmissionCapsTheChoicesAndSaysWhyItIsRisky() {
        var got: Triple<Long, Int, Boolean>? = null
        admin(InvitationsUiState(nowMs = now), onCreate = { l, u, a -> got = Triple(l, u, a) })
        compose.onNodeWithTag("lifetime_${7 * InviteFormat.DAY_MS}").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("uses_20").performScrollTo().performClick()
        compose.onNodeWithTag("lifetime_${7 * InviteFormat.DAY_MS}").performScrollTo().performClick()
        compose.onNodeWithTag("invite_auto").performScrollTo().performClick()
        // 7 days and 20 people are no longer offered; the selection snapped to the largest allowed values
        compose.onNodeWithTag("lifetime_${7 * InviteFormat.DAY_MS}").assertDoesNotExist()
        compose.onNodeWithTag("uses_20").assertDoesNotExist()
        compose.onNodeWithText("Off by default.", substring = true).assertIsDisplayed()
        compose.onNodeWithTag("invite_create").performScrollTo().performClick()
        compose.runOnIdle {
            val (lifetime, uses, auto) = got!!
            assertTrue(auto)
            assertTrue(lifetime <= InviteFormat.AUTO_MAX_LIFETIME_MS)
            assertTrue(uses <= InviteFormat.AUTO_MAX_USES)
        }
    }

    @Test fun aCreatedLinkIsShownOnceWithAWarningAndCanBeCopied() {
        val copied = mutableListOf<String>()
        var done = 0
        val state = mutableStateOf(InvitationsUiState(created = InviteCreatedFfi("inv1", "cipher-invite:v1:SECRETLINK", (now + 1000).toULong()), nowMs = now))
        compose.setContent {
            MaterialTheme {
                Column(scrollModifier()) {
                    InvitationsContent(state.value, { _, _, _ -> }, {}, { _, _ -> }, { done++; state.value = state.value.copy(created = null) }, { copied += it }, {})
                }
            }
        }
        compose.onNodeWithTag("invite_qr").assertIsDisplayed()
        compose.onNodeWithTag("invite_link_text").assertIsDisplayed()
        compose.onNodeWithText("This link is shown once.", substring = true).assertIsDisplayed()
        compose.onNodeWithTag("invite_copy").performClick()
        compose.runOnIdle { assertEquals(listOf("cipher-invite:v1:SECRETLINK"), copied) }
        compose.onNodeWithTag("invite_done").performClick()
        compose.onNodeWithTag("invite_link_text").assertDoesNotExist()
        compose.runOnIdle { assertEquals(1, done) }
    }

    @Test fun requestsShowTheSafetyNumberAndApproveOrRejectExactlyThatRequest() {
        val resolved = mutableListOf<Pair<String, Boolean>>()
        admin(
            InvitationsUiState(requests = listOf(request("r1", "Erin"), request("r2", "Bob")), nowMs = now),
            onResolve = { id, ok -> resolved += id to ok },
        )
        compose.onNodeWithText("Erin").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("12345 67890", useUnmergedTree = true).assertExists()
        compose.onNodeWithTag("approve_r1").performScrollTo().performClick()
        compose.onNodeWithTag("reject_r2").performScrollTo().performClick()
        compose.runOnIdle { assertEquals(listOf("r1" to true, "r2" to false), resolved) }
    }

    @Test fun onlyUsableLinksOfferRevocationAndTheOthersExplainWhy() {
        val revoked = mutableListOf<String>()
        admin(
            InvitationsUiState(
                invites = listOf(
                    info("live", now + 5 * InviteFormat.HOUR_MS, 5, 1),
                    info("gone", now + 5 * InviteFormat.HOUR_MS, 5, 0, revoked = true),
                    info("old", now - 1, 5, 2),
                    info("full", now + 5 * InviteFormat.HOUR_MS, 2, 2),
                ),
                nowMs = now,
            ),
            onRevoke = { revoked += it },
        )
        compose.onNodeWithTag("revoke_live").performScrollTo().performClick()
        compose.onNodeWithTag("revoke_gone").assertDoesNotExist()
        compose.onNodeWithTag("revoke_old").assertDoesNotExist()
        compose.onNodeWithTag("revoke_full").assertDoesNotExist()
        compose.onNodeWithTag("status_live").assertIsDisplayed()
        compose.onNodeWithText("revoked").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("expired").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("used up").performScrollTo().assertIsDisplayed()
        compose.runOnIdle { assertEquals(listOf("live"), revoked) }
    }

    @Test fun anErrorIsShownAndCanBeDismissed() {
        var dismissed = 0
        admin(InvitationsUiState(error = "Couldn't reach the server.", nowMs = now), onDismissError = { dismissed++ })
        compose.onNodeWithText("Couldn't reach the server.").assertIsDisplayed()
        compose.onNodeWithText("Dismiss").performClick()
        compose.runOnIdle { assertEquals(1, dismissed) }
    }

    @Test fun theRequestsOnlyScreenOffersNoCreationControls() {
        admin(InvitationsUiState(requests = listOf(request("r1", "Erin")), canCreate = false, nowMs = now))
        compose.onNodeWithTag("approve_r1").performScrollTo().assertIsDisplayed()
        compose.onNodeWithTag("invite_create").assertDoesNotExist()
    }

    // ------------------------------------------------------------------------------------------------------------------------- joiner

    private fun preview(other: Boolean = true, auto: Boolean = false) = InvitePreviewFfi("Team", "Alice", "acct", auto, (now + 1000).toULong(), other)

    private fun join(
        state: JoinUiState,
        initialLink: String = "",
        onLookUp: (String) -> Unit = {},
        onRequest: (String, String) -> Unit = { _, _ -> },
        onScan: () -> Unit = {},
    ) = compose.setContent {
        MaterialTheme {
            Column(scrollModifier()) {
                JoinWithLinkContent(state, initialLink, onLookUp, onRequest, onScan, {})
            }
        }
    }

    @Test fun lookingUpNeedsALinkAndPassesExactlyWhatWasTyped() {
        var looked: String? = null
        join(JoinUiState(), onLookUp = { looked = it })
        compose.onNodeWithTag("join_lookup").assertIsNotEnabled()
        compose.onNodeWithTag("join_link_field").performTextInput("cipher-invite:v1:ABC")
        compose.onNodeWithTag("join_lookup").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals("cipher-invite:v1:ABC", looked) }
    }

    @Test fun thePreviewNamesTheGroupAndInviterWithoutOverclaimingAndAsksForAName() {
        var asked: Pair<String, String>? = null
        join(JoinUiState(preview = preview(other = false, auto = true)), initialLink = "cipher-invite:v1:ABC", onRequest = { l, n -> asked = l to n })
        compose.onNodeWithTag("join_group").assertIsDisplayed()
        compose.onNodeWithText("Team").assertIsDisplayed()
        compose.onNodeWithTag("join_inviter").assertIsDisplayed()
        compose.onNodeWithText("They don't prove who that is", substring = true).assertExists()
        compose.onNodeWithTag("join_same_server_only").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("admits people automatically", substring = true).assertExists()
        compose.onNodeWithTag("join_request").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithTag("join_name").performScrollTo().performTextInput("Erin")
        compose.onNodeWithTag("join_request").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals("cipher-invite:v1:ABC" to "Erin", asked) }
    }

    @Test fun aGroupThatTakesOtherServersDoesNotShowTheSameServerNotice() {
        join(JoinUiState(preview = preview(other = true)), initialLink = "cipher-invite:v1:ABC")
        compose.onNodeWithTag("join_same_server_only").assertDoesNotExist()
    }

    @Test fun afterRequestingTheScreenSaysAnAdminMustApproveAndOffersNoSecondRequest() {
        join(JoinUiState(preview = preview(), requested = true), initialLink = "cipher-invite:v1:ABC")
        compose.onNodeWithTag("join_sent").assertIsDisplayed()
        compose.onNodeWithText("An admin of the group has to approve it", substring = true).assertIsDisplayed()
        compose.onNodeWithTag("join_request").assertDoesNotExist()
    }

    @Test fun scanningIsOffered() {
        var scanned = 0
        join(JoinUiState(), onScan = { scanned++ })
        compose.onNodeWithTag("join_scan").performClick()
        compose.runOnIdle { assertEquals(1, scanned) }
    }
}

@Composable
private fun scrollModifier(): Modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
