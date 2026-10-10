//! The exported object. One `Mutex<Engine>`: calls are serialised; every call is panic-contained.
use crate::callbacks::*;
use crate::error::CipherError;
use crate::types::*;
use crate::validate::{self as v, bounded};
use cipher_core::app::model::*;
use cipher_core::app::notify::PrivacyMode;
use cipher_core::app::{Engine, EngineConfig, Settings};
use cipher_core::attachment::AttachmentDescriptor;
use cipher_core::clock::SystemClock;
use cipher_core::error::SecurityError;
use cipher_core::keystore::ProtectionLevel;
use cipher_core::vault::VaultConfig;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, uniffi::Record)]
pub struct EngineSettings {
    pub data_dir: String,
    /// `https://host[:port]` only.
    pub relay_url: String,
    /// Debug builds on emulators without hardware-backed keys. MUST be false in release builds (CI-enforced).
    pub allow_software_keystore: bool,
    pub inactivity_timeout_secs: u64,
    /// Per-use biometric/device-credential authentication for the vault key. Always `true` in release builds; only debug builds
    /// on emulators without a secure lock screen may turn it off (CI-enforced).
    pub require_user_auth: bool,
    /// Tests only; `None` in production. Allows reading attachment sources from this directory instead of /proc/self/fd.
    pub extra_source_dir: Option<String>,
}

#[derive(uniffi::Object)]
pub struct CipherEngine {
    inner: Mutex<Engine>,
    extra_source_dir: Option<String>,
    /// FR-11: set (without taking the engine mutex) when a lock is imminent. In-flight network calls and progress callbacks then fail
    /// fast, so a long upload/download cannot keep the vault unlocked behind a pending "lock on background".
    abort: Arc<AtomicBool>,
}

impl std::fmt::Debug for CipherEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CipherEngine")
    }
}

type R<T> = Result<T, CipherError>;

fn msg_view(e: &mut Engine, m: &StoredMessage) -> MessageFfi {
    let (text, attachment) = match &m.content {
        Content::Text { body } => (body.clone(), None),
        Content::Attachment { caption, att } => {
            let view = AttachmentDescriptor::from_bytes(att.descriptor.as_bytes()).ok().map(|d| AttachmentViewFfi {
                kind: att.kind.into(),
                mime: d.mime.clone(),
                filename: d.filename.clone(),
                size_bytes: d.plaintext_len,
                has_thumbnail: att.thumb_blob_id.is_some(),
                duration_ms: att.duration_ms,
            });
            (caption.clone(), view)
        }
        Content::Receipt { .. } | Content::LeaveRequest | Content::DeliveryCap { .. } => (String::new(), None),
    };
    MessageFfi {
        id: m.id.to_hex(),
        conversation_id: m.conv.to_hex(),
        outgoing: m.outgoing,
        sender_account: m.sender_account.to_hex(),
        sender_name: if m.outgoing { "You".to_owned() } else { e.display_name(&m.sender_account) },
        ts_ms: m.ts_ms,
        reply_to: m.reply_to.map(|r| r.to_hex()),
        text,
        attachment,
        unavailable: m.unavailable,
        state: match m.state {
            DeliveryState::Pending => DeliveryStateFfi::Pending,
            DeliveryState::Sent => DeliveryStateFfi::Sent,
            DeliveryState::Delivered => DeliveryStateFfi::Delivered,
            DeliveryState::Failed => DeliveryStateFfi::Failed,
            DeliveryState::Received => DeliveryStateFfi::Received,
        },
    }
}

fn progress_fn<'a>(p: &'a Option<Arc<dyn ProgressCallback>>, abort: &'a AtomicBool) -> impl FnMut(u64, u64) -> bool + 'a {
    move |done, total| !abort.load(Ordering::SeqCst) && p.as_ref().is_none_or(|cb| cb.on_progress(done, total))
}

#[uniffi::export]
impl CipherEngine {
    #[uniffi::constructor]
    pub fn new(settings: EngineSettings, keystore: Arc<dyn KeystoreCallbacks>, http: Arc<dyn HttpCallbacks>) -> R<Arc<Self>> {
        bounded(&settings.data_dir, v::MAX_PATH_BYTES, "data dir")?;
        bounded(&settings.relay_url, 512, "relay url")?;
        let cfg = EngineConfig {
            data_dir: settings.data_dir.clone().into(),
            relay_url: settings.relay_url.clone(),
            vault: VaultConfig {
                min_protection: ProtectionLevel::HardwareBacked,
                allow_software_keystore: settings.allow_software_keystore,
                require_user_auth: settings.require_user_auth,
                inactivity_timeout_secs: settings.inactivity_timeout_secs.clamp(15, 24 * 3600),
                ..VaultConfig::default()
            },
        };
        let abort = Arc::new(AtomicBool::new(false));
        let adapter = Arc::new(HttpAdapter { inner: http, abort: abort.clone() });
        let engine = catch_unwind(AssertUnwindSafe(|| {
            Engine::new(cfg, Arc::new(KeystoreAdapter(keystore)), adapter, Arc::new(SystemClock::default()))
        }))
        .map_err(|_| CipherError::Internal)??;
        Ok(Arc::new(Self { inner: Mutex::new(engine), extra_source_dir: settings.extra_source_dir, abort }))
    }

    // ---------------------------------------------------------------------------------------------- vault

    pub fn status(&self) -> R<VaultStatusFfi> {
        self.with(|e| {
            let s = e.status()?;
            Ok(VaultStatusFfi {
                state: s.state.into(),
                provisioned: s.provisioned,
                has_identity: s.has_identity,
                has_pin: s.has_pin,
                pin_only: s.pin_only,
                pin_retry_after_secs: s.pin_retry_after_secs,
                protection: protection(s.protection),
            })
        })
    }

    pub fn provision_vault(&self) -> R<()> {
        self.with(|e| e.provision_vault())
    }

    /// Create the vault in PIN-only mode (no biometric / keystore-only unlock path at all).
    pub fn provision_vault_pin_only(&self, pin: String) -> R<()> {
        bounded(&pin, v::MAX_PIN_BYTES, "pin")?;
        self.with(|e| e.provision_vault_pin_only(&pin))
    }

    pub fn enable_pin(&self, pin: String) -> R<()> {
        bounded(&pin, v::MAX_PIN_BYTES, "pin")?;
        self.with(|e| e.enable_pin(&pin))
    }

    /// Biometric / device-credential unlock (the Android Keystore performs the prompt through the callback).
    pub fn unlock_vault_with_device_auth(&self) -> R<()> {
        self.with(|e| e.unlock_with_device_auth())
    }

    pub fn unlock_vault_with_pin(&self, pin: String) -> R<()> {
        bounded(&pin, v::MAX_PIN_BYTES, "pin")?;
        self.with(|e| e.unlock_with_pin(&pin))
    }

    /// Non-blocking: call this FIRST (from any thread) when the app is about to lock/background. It does not take the engine mutex, so
    /// it cannot be stuck behind a running operation; running network calls and transfers abort at their next step.
    pub fn request_lock(&self) {
        self.abort.store(true, Ordering::SeqCst);
    }

    pub fn lock_vault(&self) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.with(|e| {
            e.lock();
            Ok(())
        });
        self.abort.store(false, Ordering::SeqCst);
    }

    pub fn on_background(&self) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.with(|e| {
            e.on_background();
            Ok(())
        });
        self.abort.store(false, Ordering::SeqCst);
    }

    pub fn on_foreground(&self) {
        let _ = self.with(|e| {
            e.on_foreground();
            Ok(())
        });
    }

    pub fn on_device_event(&self, event: DeviceEventFfi) {
        self.abort.store(true, Ordering::SeqCst);
        let _ = self.with(|e| {
            e.on_device_event(event.into());
            Ok(())
        });
        self.abort.store(false, Ordering::SeqCst);
    }

    pub fn tick(&self) {
        let _ = self.with(|e| {
            e.tick();
            Ok(())
        });
    }

    // ------------------------------------------------------------------------------------------- identity

    pub fn create_identity(&self, registration_token: String) -> R<PublicIdentityFfi> {
        bounded(&registration_token, v::MAX_TOKEN_BYTES, "registration token")?;
        self.with(|e| e.create_identity(&registration_token).map(identity))
    }

    pub fn get_public_identity(&self) -> R<PublicIdentityFfi> {
        self.with(|e| e.public_identity().map(identity))
    }

    pub fn own_devices(&self) -> R<Vec<DeviceFfi>> {
        self.with(|e| {
            Ok(e.own_devices()?
                .into_iter()
                .map(|(d, me, endorsed)| DeviceFfi { device_id: d.to_hex(), is_this_device: me, endorsed_by_another_device: endorsed })
                .collect())
        })
    }

    // ------------------------------------------------------------------------------------------- contacts

    pub fn list_contacts(&self) -> R<Vec<ContactFfi>> {
        self.with(|e| Ok(e.list_contacts()?.iter().map(ContactFfi::from).collect()))
    }

    pub fn get_contact(&self, account_id: String) -> R<Option<ContactFfi>> {
        let a = v::id(&account_id, "account id")?;
        self.with(|e| Ok(e.contact(&a)?.as_ref().map(ContactFfi::from)))
    }

    pub fn add_contact_by_cipher_id(&self, cipher_id: String, name: String) -> R<ContactFfi> {
        bounded(&cipher_id, 64, "cipher id")?;
        bounded(&name, v::MAX_NAME_BYTES, "name")?;
        self.with(|e| e.add_contact_by_id(&cipher_id, &name).map(|c| ContactFfi::from(&c)))
    }

    pub fn add_contact_by_qr(&self, qr_payload: String, name: String) -> R<ContactFfi> {
        bounded(&qr_payload, v::MAX_PAYLOAD_BYTES, "qr payload")?;
        bounded(&name, v::MAX_NAME_BYTES, "name")?;
        self.with(|e| e.add_contact_by_qr(&qr_payload, &name).map(|c| ContactFfi::from(&c)))
    }

    /// How other relays' users must name THIS relay in cards and capability frames. `spki_pin_b64` (SHA-256 of the relay certificate's public key,
    /// unpadded base64url) is REQUIRED for `.onion` relays and optional otherwise. Fails for an invalid URL or an onion relay without a pin.
    pub fn set_own_relay(&self, relay_url: String, spki_pin_b64: Option<String>) -> R<()> {
        bounded(&relay_url, 255, "relay url")?;
        let pin = match spki_pin_b64 {
            Some(p) => {
                bounded(&p, 64, "pin")?;
                let raw = cipher_wire::b64::decode(&p).ok_or(CipherError::InvalidInput { what: "pin".into() })?;
                Some(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CipherError::InvalidInput { what: "pin".into() })?)
            }
            None => None,
        };
        let d = cipher_wire::RelayDescriptor::new(&relay_url, pin).map_err(|_| CipherError::InvalidInput { what: "relay url".into() })?;
        self.with(|e| e.set_own_relay(d))
    }

    /// A signed contact card (show as QR / send as a link) that lets someone on ANY relay start a conversation with this account. Expires after
    /// `lifetime_days` (1..=30).
    pub fn create_contact_card(&self, lifetime_days: u32) -> R<String> {
        self.with(|e| e.create_contact_card(lifetime_days))
    }

    /// Add a contact from their card, possibly on another relay. `scanned_in_person`: the card was read from their screen (it then counts as verified).
    pub fn add_contact_by_card(&self, card: String, name: String, scanned_in_person: bool) -> R<ContactFfi> {
        bounded(&card, v::MAX_PAYLOAD_BYTES, "card")?;
        bounded(&name, v::MAX_NAME_BYTES, "name")?;
        self.with(|e| e.add_contact_by_card(&card, &name, scanned_in_person).map(|c| ContactFfi::from(&c)))
    }

    /// Verify an existing contact with their QR code (must be that contact's own code).
    pub fn verify_contact_by_qr(&self, account_id: String, qr_payload: String) -> R<ContactFfi> {
        let a = v::id(&account_id, "account id")?;
        bounded(&qr_payload, v::MAX_PAYLOAD_BYTES, "qr payload")?;
        self.with(|e| e.verify_contact_with_qr(&a, &qr_payload).map(|c| ContactFfi::from(&c)))
    }

    pub fn get_message(&self, conversation_id: String, message_id: String) -> R<Option<MessageFfi>> {
        let (c, m) = (v::id(&conversation_id, "conversation id")?, v::id(&message_id, "message id")?);
        self.with(|e| {
            let msg = e.message(&c, &m)?;
            Ok(msg.map(|m| msg_view(e, &m)))
        })
    }

    pub fn get_safety_number(&self, account_id: String) -> R<String> {
        let a = v::id(&account_id, "account id")?;
        self.with(|e| e.safety_number(&a))
    }

    /// The user compared the safety number with the contact.
    pub fn verify_identity(&self, account_id: String) -> R<()> {
        let a = v::id(&account_id, "account id")?;
        self.with(|e| e.mark_verified(&a))
    }

    pub fn acknowledge_identity_change(&self, account_id: String) -> R<()> {
        let a = v::id(&account_id, "account id")?;
        self.with(|e| e.acknowledge_identity_change(&a))
    }

    pub fn rename_contact(&self, account_id: String, name: String) -> R<()> {
        let a = v::id(&account_id, "account id")?;
        bounded(&name, v::MAX_NAME_BYTES, "name")?;
        self.with(|e| e.rename_contact(&a, &name))
    }

    pub fn set_contact_blocked(&self, account_id: String, blocked: bool) -> R<()> {
        let a = v::id(&account_id, "account id")?;
        self.with(|e| e.set_blocked(&a, blocked))
    }

    // ------------------------------------------------------------------------------------- conversations

    pub fn list_conversations(&self) -> R<Vec<ConversationFfi>> {
        self.with(|e| Ok(e.list_conversations()?.iter().map(ConversationFfi::from).collect()))
    }

    pub fn get_conversation(&self, conversation_id: String) -> R<ConversationFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.conversation(&c).map(|c| ConversationFfi::from(&c)))
    }

    /// Start (or reopen) a 1:1 conversation with a contact.
    pub fn create_conversation(&self, peer_account_id: String) -> R<String> {
        let p = v::id(&peer_account_id, "account id")?;
        self.with(|e| e.start_dm(&p).map(|c| c.to_hex()))
    }

    pub fn accept_conversation(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.accept_conversation(&c))
    }

    pub fn decline_conversation(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.decline_conversation(&c))
    }

    pub fn delete_conversation_local(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.delete_conversation_local(&c))
    }

    // -------------------------------------------------------------------------------------------- groups

    pub fn create_group(&self, name: String, member_account_ids: Vec<String>) -> R<String> {
        bounded(&name, v::MAX_NAME_BYTES, "group name")?;
        let m = v::ids(&member_account_ids, "member id")?;
        self.with(|e| e.create_group(&name, &m).map(|c| c.to_hex()))
    }

    pub fn add_group_member(&self, conversation_id: String, account_id: String) -> R<()> {
        let (c, a) = (v::id(&conversation_id, "conversation id")?, v::id(&account_id, "account id")?);
        self.with(|e| e.add_group_members(&c, &[a]))
    }

    pub fn remove_group_member(&self, conversation_id: String, account_id: String) -> R<()> {
        let (c, a) = (v::id(&conversation_id, "conversation id")?, v::id(&account_id, "account id")?);
        self.with(|e| e.remove_group_member(&c, &a))
    }

    pub fn rename_group(&self, conversation_id: String, name: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        bounded(&name, v::MAX_NAME_BYTES, "group name")?;
        self.with(|e| e.rename_group(&c, &name))
    }

    pub fn promote_admin(&self, conversation_id: String, account_id: String) -> R<()> {
        let (c, a) = (v::id(&conversation_id, "conversation id")?, v::id(&account_id, "account id")?);
        self.with(|e| e.promote_admin(&c, &a))
    }

    pub fn demote_admin(&self, conversation_id: String, account_id: String) -> R<()> {
        let (c, a) = (v::id(&conversation_id, "conversation id")?, v::id(&account_id, "account id")?);
        self.with(|e| e.demote_admin(&c, &a))
    }

    pub fn transfer_ownership(&self, conversation_id: String, account_id: String) -> R<()> {
        let (c, a) = (v::id(&conversation_id, "conversation id")?, v::id(&account_id, "account id")?);
        self.with(|e| e.transfer_ownership(&c, &a))
    }

    pub fn leave_group(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.leave_group(&c))
    }

    pub fn refresh_keys(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.refresh_keys(&c))
    }

    pub fn get_members(&self, conversation_id: String) -> R<Vec<MemberFfi>> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| {
            Ok(e.members(&c)?
                .into_iter()
                .map(|m| MemberFfi {
                    account_id: m.account.to_hex(),
                    name: m.name,
                    role: m.role.into(),
                    devices: m.devices,
                    is_me: m.is_me,
                    trust: m.trust.map(Into::into),
                })
                .collect())
        })
    }

    pub fn my_role(&self, conversation_id: String) -> R<RoleFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.my_role(&c).map(Into::into))
    }

    // ------------------------------------------------------------------------------------------ messages

    pub fn send_text(&self, conversation_id: String, text: String, reply_to: Option<String>) -> R<MessageFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        bounded(&text, v::MAX_TEXT_BYTES, "text")?;
        let r = v::opt_id(&reply_to, "reply id")?;
        self.with(|e| {
            let m = e.send_text(&c, &text, r)?;
            Ok(msg_view(e, &m))
        })
    }

    pub fn get_history(&self, conversation_id: String, before_cursor: Option<String>, limit: u32) -> R<HistoryPageFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        if let Some(b) = &before_cursor {
            bounded(b, 128, "cursor")?;
        }
        self.with(|e| {
            let page = e.history(&c, before_cursor, (limit as usize).clamp(1, v::MAX_LIST))?;
            let items = page.items.iter().map(|m| msg_view(e, m)).collect();
            Ok(HistoryPageFfi { items, next_cursor: page.next })
        })
    }

    pub fn mark_read(&self, conversation_id: String) -> R<()> {
        let c = v::id(&conversation_id, "conversation id")?;
        self.with(|e| e.mark_read(&c))
    }

    pub fn delete_message_local(&self, conversation_id: String, message_id: String) -> R<()> {
        let (c, m) = (v::id(&conversation_id, "conversation id")?, v::id(&message_id, "message id")?);
        self.with(|e| e.delete_message_local(&c, &m))
    }

    pub fn retry_message(&self, conversation_id: String, message_id: String) -> R<()> {
        let (c, m) = (v::id(&conversation_id, "conversation id")?, v::id(&message_id, "message id")?);
        self.with(|e| e.retry_message(&c, &m))
    }

    /// Foreground tick for the configured network profile (see `netprofile`): sync, optional bounded cover request, and the jittered delay to the next tick.
    pub fn network_tick(&self) -> R<TickFfi> {
        self.with(|e| {
            let t = e.network_tick()?;
            let r = t.report;
            let notification = if r.new_messages > 0 { Some(e.notification_for(&r.notices).into()) } else { None };
            Ok(TickFfi {
                report: SyncReportFfi {
                    new_messages: r.new_messages,
                    changed_conversations: r.conversations_changed.iter().map(|c| c.to_hex()).collect(),
                    notification,
                },
                next_delay_ms: t.next_delay_ms,
            })
        })
    }

    pub fn delivery_path_counts(&self) -> R<DeliveryPathFfi> {
        self.with(|e| {
            let (a, u) = e.delivery_path_counts();
            Ok(DeliveryPathFfi { anonymous: a, authenticated: u })
        })
    }

    /// Fetch, decrypt and process incoming envelopes; deliver the outbox; run key-refresh maintenance.
    pub fn sync(&self) -> R<SyncReportFfi> {
        self.with(|e| {
            let r = e.sync()?;
            let notification = if r.new_messages > 0 { Some(e.notification_for(&r.notices).into()) } else { None };
            Ok(SyncReportFfi {
                new_messages: r.new_messages,
                changed_conversations: r.conversations_changed.iter().map(|c| c.to_hex()).collect(),
                notification,
            })
        })
    }

    pub fn flush_outbox(&self) -> R<u32> {
        self.with(|e| e.flush_outbox())
    }

    // ------------------------------------------------------------------------------------------ attachments

    /// `source_path` must be `/proc/self/fd/<n>` for a descriptor the app opened (no plaintext copy is made). The file is encrypted
    /// chunk by chunk into a ciphertext-only temp file, uploaded, and the temp file deleted.
    #[allow(clippy::too_many_arguments)]
    pub fn send_attachment(
        &self,
        conversation_id: String,
        source_path: String,
        mime: String,
        filename: String,
        kind: AttachmentKindFfi,
        caption: String,
        thumbnail_jpeg: Option<Vec<u8>>,
        duration_ms: Option<u32>,
        reply_to: Option<String>,
        progress: Option<Arc<dyn ProgressCallback>>,
    ) -> R<MessageFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        v::source_path(&source_path, self.extra_source_dir.as_deref())?;
        bounded(&mime, 100, "mime")?;
        bounded(&filename, v::MAX_NAME_BYTES, "filename")?;
        bounded(&caption, v::MAX_TEXT_BYTES, "caption")?;
        if thumbnail_jpeg.as_ref().is_some_and(|t| t.len() > v::MAX_THUMB_BYTES) {
            return Err(CipherError::InvalidInput { what: "thumbnail".into() });
        }
        let r = v::opt_id(&reply_to, "reply id")?;
        self.with(|e| {
            let m = e.send_attachment(
                &c,
                &source_path,
                &mime,
                &filename,
                kind.into(),
                &caption,
                thumbnail_jpeg.as_deref(),
                duration_ms,
                r,
                &mut progress_fn(&progress, &self.abort),
            )?;
            Ok(msg_view(e, &m))
        })
    }

    /// Download, verify and decrypt an attachment (or its thumbnail) into memory. Nothing is cached on disk.
    pub fn open_attachment(
        &self,
        conversation_id: String,
        message_id: String,
        thumbnail: bool,
        progress: Option<Arc<dyn ProgressCallback>>,
    ) -> R<Vec<u8>> {
        let (c, m) = (v::id(&conversation_id, "conversation id")?, v::id(&message_id, "message id")?);
        self.with(|e| {
            let bytes = e.open_attachment(&c, &m, thumbnail, &mut progress_fn(&progress, &self.abort))?;
            Ok(bytes.to_vec())
        })
    }

    /// Voice note recorded in memory (AAC/ADTS). No plaintext file is ever created.
    pub fn send_voice_note(
        &self,
        conversation_id: String,
        audio_aac: Vec<u8>,
        duration_ms: u32,
        reply_to: Option<String>,
    ) -> R<MessageFfi> {
        let c = v::id(&conversation_id, "conversation id")?;
        if audio_aac.is_empty() || audio_aac.len() > 16 * 1024 * 1024 || duration_ms > 15 * 60 * 1000 {
            return Err(CipherError::InvalidInput { what: "voice note".into() });
        }
        let r = v::opt_id(&reply_to, "reply id")?;
        self.with(|e| {
            let m = e.send_attachment_bytes(
                &c,
                &audio_aac,
                "audio/aac",
                "voice-note.aac",
                AttachmentKind::Voice,
                Some(duration_ms),
                r,
                &mut |_, _| true,
            )?;
            Ok(msg_view(e, &m))
        })
    }

    // -------------------------------------------------------------------------- settings, events, misc

    pub fn get_settings(&self) -> R<SettingsFfi> {
        self.with(|e| {
            let s = e.settings()?;
            Ok(SettingsFfi {
                privacy_mode: s.privacy_mode.into(),
                send_receipts: s.send_receipts,
                network_profile: s.network_profile.into(),
            })
        })
    }

    pub fn set_settings(&self, settings: SettingsFfi) -> R<()> {
        self.with(|e| {
            e.set_settings(&Settings {
                privacy_mode: PrivacyMode::from(settings.privacy_mode),
                send_receipts: settings.send_receipts,
                network_profile: settings.network_profile.into(),
            })
        })
    }

    pub fn take_security_events(&self) -> Vec<SecurityEventFfi> {
        self.with(|e| Ok(e.take_events().iter().map(SecurityEventFfi::from).collect())).unwrap_or_default()
    }

    pub fn security_event_log(&self, limit: u32) -> R<Vec<SecurityEventFfi>> {
        self.with(|e| Ok(e.security_event_log((limit as usize).clamp(1, 200))?.iter().map(SecurityEventFfi::from).collect()))
    }
}

fn identity(p: cipher_core::app::PublicIdentity) -> PublicIdentityFfi {
    PublicIdentityFfi {
        cipher_id: p.cipher_id,
        account_id: p.account_id.to_hex(),
        device_id: p.device_id.to_hex(),
        qr_payload: p.qr_payload,
        fingerprint: p.fingerprint,
    }
}

impl CipherEngine {
    /// Runs `f` with the engine under a panic guard. A panic (or a poisoned lock) LOCKS THE VAULT and surfaces as `Internal`:
    /// the engine never continues from a possibly half-updated state with keys in memory.
    fn with<T>(&self, f: impl FnOnce(&mut Engine) -> Result<T, SecurityError>) -> R<T> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                let mut g = poisoned.into_inner();
                g.lock();
                return Err(CipherError::Internal);
            }
        };
        match catch_unwind(AssertUnwindSafe(|| f(&mut guard))) {
            Ok(r) => r.map_err(CipherError::from),
            Err(_) => {
                guard.lock();
                Err(CipherError::Internal)
            }
        }
    }
}

#[cfg(feature = "test-hooks")]
impl CipherEngine {
    /// Forces a panic inside a guarded call (proves containment). Not exported over FFI.
    #[allow(clippy::panic)] // the whole point: proves a panic inside a guarded call is contained (feature `test-hooks`, never shipped)
    pub fn panic_inside_call_for_tests(&self) -> R<()> {
        self.with::<()>(|_| panic!("injected panic"))
    }
}
