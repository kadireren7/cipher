package app.cipher.messenger.gallery

import android.content.ContentValues
import android.graphics.Bitmap
import android.provider.MediaStore
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChatBubbleOutline
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import app.cipher.messenger.ui.components.Avatar
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.EmptyState
import app.cipher.messenger.ui.components.TrustBadge
import app.cipher.messenger.ui.screens.ConversationRow
import app.cipher.messenger.ui.screens.InputBar
import app.cipher.messenger.ui.screens.InvitationsContent
import app.cipher.messenger.ui.screens.InvitationsUiState
import app.cipher.messenger.ui.screens.JoinUiState
import app.cipher.messenger.ui.screens.JoinWithLinkContent
import app.cipher.messenger.ui.screens.MessageBubble
import app.cipher.messenger.ui.theme.CipherTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import uniffi.cipher_ffi.AttachmentKindFfi
import uniffi.cipher_ffi.AttachmentViewFfi
import uniffi.cipher_ffi.ConvKindFfi
import uniffi.cipher_ffi.ConvStateFfi
import uniffi.cipher_ffi.ConversationFfi
import uniffi.cipher_ffi.DeliveryStateFfi
import uniffi.cipher_ffi.InviteCreatedFfi
import uniffi.cipher_ffi.InviteInfoFfi
import uniffi.cipher_ffi.InvitePreviewFfi
import uniffi.cipher_ffi.JoinRequestFfi
import uniffi.cipher_ffi.MessageFfi
import uniffi.cipher_ffi.TrustStateFfi

/**
 * Renders the real components with REPRESENTATIVE test data (never shipped: this is the androidTest source set)
 * in light/dark, at font scales 1.0 and 1.6 and a narrow 320 dp width, and writes PNGs for human inspection
 * (`scripts/ci-emulator-tests.sh` pulls them as the `design-gallery` artifact).
 * It asserts only that composition and capture succeed; layout quality is judged by looking at the images, not by this test.
 */
class DesignGalleryInstrumentedTest {
    private companion object {
        const val TS = 1_760_000_000_000uL
    }

    @get:Rule val rule = createComposeRule()

    /** Saved through MediaStore into Pictures/cipher-gallery: app-private storage is deleted when Gradle uninstalls the app after the run. */
    private fun save(name: String, bmp: Bitmap): Long {
        val resolver = InstrumentationRegistry.getInstrumentation().targetContext.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.Images.Media.DISPLAY_NAME, name)
            put(MediaStore.Images.Media.MIME_TYPE, "image/png")
            put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/cipher-gallery")
        }
        val uri = checkNotNull(resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)) { "MediaStore insert failed" }
        var size = 0L
        resolver.openOutputStream(uri)!!.use { out ->
            bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
            size = bmp.byteCount.toLong()
        }
        return size
    }

    private fun msg(
        id: String,
        mine: Boolean,
        text: String,
        state: DeliveryStateFfi = DeliveryStateFfi.DELIVERED,
        sender: String = "Mira",
        att: AttachmentViewFfi? = null,
        reply: String? = null,
    ): MessageFfi {
        val who = if (mine) "You" else sender
        return MessageFfi(id, "c", mine, if (mine) "me" else sender, who, TS, reply, text, att, state, false)
    }

    private fun conv(
        title: String,
        preview: String,
        unread: UInt = 0u,
        kind: ConvKindFfi = ConvKindFfi.DM,
        state: ConvStateFfi = ConvStateFfi.ACTIVE,
    ) = ConversationFfi("id-$title", kind, state, title, null, unread, TS, preview, false)

    @Composable
    private fun ListScene() {
        Column(Modifier.background(MaterialTheme.colorScheme.background)) {
            Text("Cipher", Modifier.padding(16.dp), style = MaterialTheme.typography.headlineSmall)
            Banner("You're offline. Messages will send when you're back.")
            ConversationRow(conv("Mira Okafor", "Landed. See you at the station.", 2u)) {}
            ConversationRow(conv("Reading group", "Tomás: the PDF is up to date", 0u, ConvKindFfi.GROUP)) {}
            ConversationRow(conv("Ayşe", "Voice message", 0u)) {}
            ConversationRow(
                conv(
                    "A very long conversation title that must truncate instead of wrapping into the time",
                    "And an equally long last message preview that keeps going and going",
                    12u
                )
            ) {
            }
            ConversationRow(conv("Old trip", "", 0u, ConvKindFfi.GROUP, ConvStateFfi.LEFT)) {}
            HorizontalDivider()
            EmptyState(
                Icons.Default.ChatBubbleOutline,
                "No conversations yet",
                "Tap + to add someone with their Cipher ID or by scanning their code."
            )
        }
    }

    @Composable
    private fun ChatScene(group: Boolean) {
        Column(Modifier.background(MaterialTheme.colorScheme.background)) {
            Column(Modifier.padding(16.dp)) {
                Text(if (group) "Reading group" else "Mira Okafor", style = MaterialTheme.typography.titleMedium)
                if (!group) TrustBadge(TrustStateFfi.VERIFIED) else Text("4 members", style = MaterialTheme.typography.labelSmall)
            }
            Column(Modifier.padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                MessageBubble(msg("1", false, "Landed. See you at the station?", sender = "Mira"), group, null, {}, {})
                MessageBubble(msg("2", true, "Yes — platform 4, by the coffee place.", DeliveryStateFfi.DELIVERED), false, null, {}, {})
                MessageBubble(
                    msg(
                        "3",
                        true,
                        "Bringing the PDF.",
                        DeliveryStateFfi.SENT,
                        att = AttachmentViewFfi(AttachmentKindFfi.PDF, "application/pdf", "itinerary-final.pdf", 412_000uL, false, null)
                    ),
                    false,
                    null,
                    {
                    },
                    {}
                )
                MessageBubble(
                    msg(
                        "4",
                        false,
                        "",
                        att = AttachmentViewFfi(AttachmentKindFfi.VOICE, "audio/mp4", "v.m4a", 31_000uL, false, 14_000u),
                        sender = "Tomás"
                    ),
                    group,
                    null,
                    {
                    },
                    {}
                )
                MessageBubble(msg("5", true, "Sending…", DeliveryStateFfi.PENDING), false, null, {}, {})
                MessageBubble(
                    msg(
                        "6",
                        true,
                        "This one did not go out. Tap to retry. A deliberately long line to check wrapping at large font scales.",
                        DeliveryStateFfi.FAILED
                    ),
                    false,
                    null,
                    {
                    },
                    {}
                )
            }
            InputBar(null)
        }
    }

    @Composable
    private fun PartsScene() {
        Column(
            Modifier.background(MaterialTheme.colorScheme.background).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Banner("Privacy route unavailable. Messages stay queued, encrypted, and will not be sent another way.", error = true)
            Banner("Ayşe's security identity changed. Verify before sending new messages.", error = true, actionLabel = "Review") {}
            TrustBadge(TrustStateFfi.VERIFIED)
            TrustBadge(TrustStateFfi.UNVERIFIED)
            TrustBadge(TrustStateFfi.IDENTITY_CHANGED)
            Avatar("Mira Okafor")
            Avatar("Reading group", group = true)
        }
    }

    private val nowMs = 1_760_000_000_000L
    private val hourMs = 3_600_000L

    @Composable
    private fun InvitesAdminScene() {
        Column(Modifier.background(MaterialTheme.colorScheme.background).padding(16.dp)) {
            InvitationsContent(
                state = InvitationsUiState(
                    invites = listOf(
                        InviteInfoFfi("a", "c", (nowMs + 5 * hourMs).toULong(), 5u, 1u, false, false),
                        InviteInfoFfi("b", "c", (nowMs + 20 * hourMs).toULong(), 10u, 3u, true, false),
                        InviteInfoFfi("c", "c", (nowMs - hourMs).toULong(), 5u, 2u, false, false),
                        InviteInfoFfi("d", "c", (nowMs + 40 * hourMs).toULong(), 5u, 0u, false, true),
                    ),
                    requests = listOf(
                        JoinRequestFfi("r1", "a", "c", "acct1", "Erin Kaya", "48291 03357 71204 66810 93752 20483", TS),
                        JoinRequestFfi(
                            "r2",
                            "a",
                            "c",
                            "acct2",
                            "A very long display name that has to wrap and never push the buttons off screen",
                            "12345 67890 11223 34455 66778 89900",
                            TS
                        ),
                    ),
                    nowMs = nowMs,
                ),
                onCreate = { _, _, _ -> },
                onRevoke = {},
                onResolve = { _, _ -> },
                onDismissCreated = {},
                onCopy = {},
                onDismissError = {},
            )
        }
    }

    @Composable
    private fun InviteCreatedScene() {
        Column(Modifier.background(MaterialTheme.colorScheme.background).padding(16.dp)) {
            InvitationsContent(
                state = InvitationsUiState(
                    created = InviteCreatedFfi(
                        "a",
                        "cipher-invite:v1:EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
                        (
                            nowMs +
                                24 * hourMs
                            ).toULong()
                    ),
                    nowMs = nowMs,
                ),
                onCreate = { _, _, _ -> },
                onRevoke = {},
                onResolve = { _, _ -> },
                onDismissCreated = {},
                onCopy = {},
                onDismissError = {},
            )
        }
    }

    @Composable
    private fun JoinScene(other: Boolean, auto: Boolean) {
        Column(Modifier.background(MaterialTheme.colorScheme.background).padding(16.dp)) {
            JoinWithLinkContent(
                state = JoinUiState(
                    preview = InvitePreviewFfi("Reading group", "Mira Okafor", "acct", auto, (nowMs + 24 * hourMs).toULong(), other)
                ),
                initialLink = "cipher-invite:v1:AWRlbW8tZ2FsbGVyeS1saW5r",
                onLookUp = {},
                onRequest = { _, _ -> },
                onScan = {},
                onDismissError = {},
            )
        }
    }

    private fun shoot(name: String, dark: Boolean, fontScale: Float, widthDp: Int, content: @Composable () -> Unit) {
        rule.setContent {
            val d = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(d.density, fontScale)) {
                CipherTheme(dark) {
                    androidx.compose.material3.Surface(color = MaterialTheme.colorScheme.background) {
                        Column(Modifier.width(widthDp.dp).fillMaxWidth()) { content() }
                    }
                }
            }
        }
        rule.waitForIdle()
        val bmp = rule.onRoot().captureToImage().asAndroidBitmap()
        val file = "$name-${if (dark) "dark" else "light"}-fs${(fontScale * 100).toInt()}-w$widthDp.png"
        assertTrue(save(file, bmp) > 0)
    }

    @Test fun listDark() = shoot("list", true, 1.0f, 360) { ListScene() }

    @Test fun chatDark() = shoot("chat-dm", true, 1.0f, 360) { ChatScene(false) }

    @Test fun groupDark() = shoot("chat-group", true, 1.0f, 360) { ChatScene(true) }

    @Test fun partsDark() = shoot("parts", true, 1.0f, 360) { PartsScene() }

    @Test fun listLightLargeFont() = shoot("list", false, 1.6f, 360) { ListScene() }

    @Test fun chatLightNarrow() = shoot("chat-dm", false, 1.0f, 320) { ChatScene(false) }

    @Test fun chatDarkLargeFont() = shoot("chat-dm", true, 1.6f, 360) { ChatScene(false) }

    @Test fun groupLight() = shoot("chat-group", false, 1.0f, 360) { ChatScene(true) }

    @Test fun partsLight() = shoot("parts", false, 1.0f, 360) { PartsScene() }

    @Test fun invitesAdminDark() = shoot("invites-admin", true, 1.0f, 360) { InvitesAdminScene() }

    @Test fun invitesAdminLightLargeFont() = shoot("invites-admin", false, 1.6f, 360) { InvitesAdminScene() }

    @Test fun inviteCreatedDark() = shoot("invite-created", true, 1.0f, 360) { InviteCreatedScene() }

    @Test fun inviteCreatedLightNarrow() = shoot("invite-created", false, 1.0f, 320) { InviteCreatedScene() }

    @Test fun joinPreviewDark() = shoot("join-preview", true, 1.0f, 360) { JoinScene(other = false, auto = true) }

    @Test fun joinPreviewLightLargeFont() = shoot("join-preview", false, 1.6f, 360) { JoinScene(other = true, auto = false) }
}
