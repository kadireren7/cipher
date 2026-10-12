package app.cipher.messenger

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import app.cipher.messenger.ui.screens.ReplacementGroupAction
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** UI confirmation and lifecycle only; engine successor semantics are covered by GR-010. */
@RunWith(AndroidJUnit4::class)
class GroupReplacementInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test fun healthyRelayOffersNoReplacement() {
        compose.setContent { MaterialTheme { ReplacementGroupAction(false, false) { error("unexpected creation") } } }
        compose.onNodeWithText("Create replacement group").assertDoesNotExist()
    }

    @Test fun cancelDoesNotCreateAGroup() {
        var created = 0
        compose.setContent { MaterialTheme { ReplacementGroupAction(true, false) { created++ } } }
        compose.onNodeWithText("Create replacement group").performClick()
        compose.onNodeWithText("A new group is created with the same members. Members must accept it again.").assertIsDisplayed()
        compose.onNodeWithText("Cancel").performClick()
        compose.onNodeWithText("Create a replacement group?").assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, created) }
    }

    @Test fun confirmationCreatesOnceAndPendingCreationDisablesAnotherAttempt() {
        var created = 0
        val creating = mutableStateOf(false)
        compose.setContent {
            MaterialTheme {
                ReplacementGroupAction(true, creating.value) {
                    created++
                    creating.value = true
                }
            }
        }
        compose.onNodeWithText("Create replacement group").performClick()
        compose.runOnIdle { assertEquals(0, created) }
        compose.onNodeWithText("Create").performClick()
        compose.onNodeWithText("Creating replacement group…").assertIsNotEnabled()
        compose.onNodeWithText("Create a replacement group?").assertDoesNotExist()
        compose.runOnIdle { assertEquals(1, created) }
        // Failure clears the pending flag in the ViewModel; a retry must require confirmation again.
        compose.runOnIdle { creating.value = false }
        compose.onNodeWithText("Create replacement group").performClick()
        compose.onNodeWithText("Cancel").performClick()
        compose.runOnIdle { assertEquals(1, created) }
    }

    @Test fun relayRecoveryDismissesStaleConfirmation() {
        val unavailable = mutableStateOf(true)
        compose.setContent {
            MaterialTheme { ReplacementGroupAction(unavailable.value, false) { error("stale confirmation") } }
        }
        compose.onNodeWithText("Create replacement group").performClick()
        compose.runOnIdle { unavailable.value = false }
        compose.onNodeWithText("Create a replacement group?").assertDoesNotExist()
        compose.runOnIdle { unavailable.value = true }
        compose.onNodeWithText("Create replacement group").assertIsDisplayed()
        compose.onNodeWithText("Create a replacement group?").assertDoesNotExist()
    }
}
