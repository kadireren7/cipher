//! OpenMLS-backed implementation of `GroupProtocol`.
//!
//! No cryptographic primitive is implemented here. Ciphersuite:
//! MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 mandatory-to-implement).
//! Handshake messages use the pure-ciphertext wire format so the relay cannot even
//! distinguish membership operations from application messages by framing.
use crate::app::groupmeta::{authorize_commit, CommitInfo, GroupMeta, Members, META_EXTENSION_TYPE};
use crate::error::{Result, SecurityError};
use crate::protocol::{CommitOutput, CommitValidator, ExpectedPeer, GroupOp, GroupProtocol, GroupRef, Header, Processed, ProcessedEx};
use cipher_wire::messages::{binding_message, endorsement_message, DeviceRecord, Endorsement};
use cipher_wire::Id16;
use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use zeroize::Zeroizing;

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const SEEN_CAP: usize = 8192;
const SNAPSHOT_MAGIC: &[u8; 4] = b"CMS1";
const MAX_SNAPSHOT_ENTRIES: u32 = 1_000_000;
const MAX_SNAPSHOT_FIELD: u32 = 64 * 1024 * 1024;

fn perr<E>(_: E) -> SecurityError {
    // Deliberately drops the underlying error text: it could embed protocol detail.
    SecurityError::Protocol("mls operation failed")
}

pub fn identity_bytes(account: &Id16, device: &Id16) -> Vec<u8> {
    let mut v = Vec::with_capacity(32);
    v.extend_from_slice(&account.0);
    v.extend_from_slice(&device.0);
    v
}

pub fn parse_identity(b: &[u8]) -> Option<(Id16, Id16)> {
    let a: [u8; 16] = b.get(..16)?.try_into().ok()?;
    let d: [u8; 16] = b.get(16..32)?.try_into().ok()?;
    if b.len() != 32 {
        return None;
    }
    Some((Id16(a), Id16(d)))
}

pub struct MlsClient {
    provider: OpenMlsRustCrypto,
    sig: SignatureKeyPair,
    credential: CredentialWithKey,
    account_id: Id16,
    device_id: Id16,
    auth_key: SigningKey,
    seen: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
}

impl std::fmt::Debug for MlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsClient").field("device_id", &self.device_id).finish_non_exhaustive()
    }
}

fn group_id(g: &GroupRef) -> GroupId {
    GroupId::from_slice(&g.0)
}

impl MlsClient {
    pub fn generate(account_id: Id16, device_id: Id16) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let sig = SignatureKeyPair::new(SignatureScheme::ED25519).map_err(perr)?;
        sig.store(provider.storage()).map_err(perr)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity_bytes(&account_id, &device_id)).into(),
            signature_key: sig.to_public_vec().into(),
        };
        let auth_key = SigningKey::from_bytes(&*crate::rng::secret32()?);
        Ok(Self { provider, sig, credential, account_id, device_id, auth_key, seen: HashSet::new(), seen_order: VecDeque::new() })
    }

    pub fn account_id(&self) -> Id16 {
        self.account_id
    }
    pub fn device_id(&self) -> Id16 {
        self.device_id
    }
    pub fn identity_public(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let pk = self.sig.to_public_vec();
        if pk.len() == 32 {
            out.copy_from_slice(&pk);
        }
        out
    }
    pub fn auth_public(&self) -> [u8; 32] {
        self.auth_key.verifying_key().to_bytes()
    }

    /// Sign an HTTP request canonical string with the transport-auth key
    /// (distinct from the identity key; never leaves this struct).
    pub fn sign_transport(&self, msg: &[u8]) -> [u8; 64] {
        self.auth_key.sign(msg).to_bytes()
    }

    /// Public device record: identity key, auth key and the identity key's signature
    /// binding the two. `endorser` signs for additional devices.
    pub fn device_record(&self, endorsement: Option<Endorsement>) -> Result<DeviceRecord> {
        let auth_pub = self.auth_public().to_vec();
        let binding = self.sig.sign(&binding_message(&self.account_id, &self.device_id, &auth_pub)).map_err(perr)?;
        Ok(DeviceRecord {
            device_id: self.device_id,
            identity_key: self.identity_public().to_vec(),
            auth_key: auth_pub,
            binding_sig: binding,
            endorsement,
        })
    }

    /// Endorse a new device of the same account with this device's identity key.
    pub fn endorse_device(&self, new_device: &Id16, identity_key: &[u8], auth_key: &[u8]) -> Result<Endorsement> {
        let sig = self.sig.sign(&endorsement_message(&self.account_id, new_device, identity_key, auth_key)).map_err(perr)?;
        Ok(Endorsement { endorser_device: self.device_id, signature: sig })
    }

    /// Leaf capabilities: every device must advertise support for our group-metadata extension.
    fn capabilities() -> Capabilities {
        Capabilities::new(None, None, Some(&[ExtensionType::Unknown(META_EXTENSION_TYPE)]), None, None)
    }

    /// GroupContext extension set carrying our metadata. `RequiredCapabilities` declares the custom extension so that
    /// OpenMLS enforces that EVERY member device supports it.
    fn context_extensions(meta_bytes: Vec<u8>) -> Result<Extensions<GroupContext>> {
        let req = RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(META_EXTENSION_TYPE)], &[], &[]);
        Extensions::from_vec(vec![
            Extension::RequiredCapabilities(req),
            Extension::Unknown(META_EXTENSION_TYPE, UnknownExtension(meta_bytes)),
        ])
        .map_err(perr)
    }

    fn group_config(meta: Option<&GroupMeta>) -> Result<MlsGroupCreateConfig> {
        let mut b = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .padding_size(128)
            .use_ratchet_tree_extension(true)
            // Keep the previous two epochs' secrets so a message sent just before a commit still decrypts if it arrives
            // after it (async delivery). Cost: un-consumed message keys of those epochs are retained until used.
            .max_past_epochs(2)
            .capabilities(Self::capabilities())
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(5, 1000));
        if let Some(m) = meta {
            let bytes = m.encode().map_err(|_| SecurityError::Malformed("group metadata"))?;
            b = b.with_group_context_extensions(Self::context_extensions(bytes)?);
        }
        Ok(b.build())
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .padding_size(128)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(2)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(5, 1000))
            .build()
    }

    fn load(&self, g: &GroupRef) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &group_id(g)).map_err(perr)?.ok_or(SecurityError::Protocol("unknown group"))
    }

    fn member_identity(group: &MlsGroup, idx: LeafNodeIndex) -> Option<(Id16, Id16)> {
        parse_identity(group.member(idx)?.serialized_content())
    }

    /// Test-only: byte strings that must NEVER appear on the wire, in relay storage,
    /// or in logs (transport-auth secret, identity private key).
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn secret_material_for_tests(&self) -> Vec<Vec<u8>> {
        vec![self.auth_key.to_bytes().to_vec(), self.sig.private().to_vec()]
    }

    /// Test-only: drop the client-side replay cache so tests can prove that the
    /// cryptographic layer *itself* refuses old messages (forward secrecy).
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn clear_replay_cache_for_tests(&mut self) {
        self.seen.clear();
        self.seen_order.clear();
    }

    fn mark_seen(&mut self, h: [u8; 32]) {
        if self.seen.insert(h) {
            self.seen_order.push_back(h);
            while self.seen_order.len() > SEEN_CAP {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    // ---- persistence: whole-state snapshot, to be sealed by the vault ----

    /// Serialise ALL secret protocol state. The result contains private keys: it
    /// must only ever be written through `EncryptedStore` and is zeroized on drop.
    pub fn snapshot(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&self.account_id.0);
        out.extend_from_slice(&self.device_id.0);
        out.extend_from_slice(&self.auth_key.to_bytes());
        out.extend_from_slice(&self.identity_public());
        let seen: Vec<[u8; 32]> = self.seen_order.iter().copied().collect();
        out.extend_from_slice(&(seen.len() as u32).to_be_bytes());
        for h in &seen {
            out.extend_from_slice(h);
        }
        let values = self.provider.storage().values.read().map_err(|_| SecurityError::Protocol("storage lock"))?;
        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for (k, v) in values.iter() {
            out.extend_from_slice(&(k.len() as u32).to_be_bytes());
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        Ok(out)
    }

    /// Parse a snapshot. Strictly bounds-checked; any malformation is an error.
    pub fn restore(snapshot: &[u8]) -> Result<Self> {
        let mut r = Reader { b: snapshot, pos: 0 };
        if r.take(4)? != SNAPSHOT_MAGIC {
            return Err(SecurityError::Malformed("snapshot magic"));
        }
        let account_id = Id16(r.array::<16>()?);
        let device_id = Id16(r.array::<16>()?);
        let auth_secret = Zeroizing::new(r.array::<32>()?);
        let identity_pub = r.array::<32>()?;
        let n_seen = r.u32(MAX_SNAPSHOT_ENTRIES)?;
        let mut seen = HashSet::new();
        let mut seen_order = VecDeque::new();
        for _ in 0..n_seen {
            let h = r.array::<32>()?;
            if seen.insert(h) {
                seen_order.push_back(h);
            }
        }
        let n = r.u32(MAX_SNAPSHOT_ENTRIES)?;
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider.storage().values.write().map_err(|_| SecurityError::Protocol("storage lock"))?;
            for _ in 0..n {
                let kl = r.u32(MAX_SNAPSHOT_FIELD)? as usize;
                let vl = r.u32(MAX_SNAPSHOT_FIELD)? as usize;
                let k = r.take(kl)?.to_vec();
                let v = r.take(vl)?.to_vec();
                values.insert(k, v);
            }
        }
        if r.pos != snapshot.len() {
            return Err(SecurityError::Malformed("trailing snapshot bytes"));
        }
        let sig = SignatureKeyPair::read(provider.storage(), &identity_pub, SignatureScheme::ED25519)
            .ok_or(SecurityError::Malformed("identity key missing from snapshot"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity_bytes(&account_id, &device_id)).into(),
            signature_key: sig.to_public_vec().into(),
        };
        Ok(Self { provider, sig, credential, account_id, device_id, auth_key: SigningKey::from_bytes(&auth_secret), seen, seen_order })
    }

    fn validate_key_package(&self, bytes: &[u8], expected: &ExpectedPeer) -> Result<KeyPackage> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(perr)?;
        let MlsMessageBodyIn::KeyPackage(kp_in) = msg.extract() else {
            return Err(SecurityError::Protocol("not a key package"));
        };
        let kp = kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10).map_err(perr)?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(SecurityError::Protocol("unexpected ciphersuite"));
        }
        let leaf = kp.leaf_node();
        let id = parse_identity(leaf.credential().serialized_content())
            .ok_or(SecurityError::IdentityUntrusted("credential identity malformed"))?;
        if id != (expected.account_id, expected.device_id) {
            return Err(SecurityError::IdentityUntrusted("key package is for a different device"));
        }
        // Constant-time comparison of the signature key against the pinned identity key.
        use subtle::ConstantTimeEq;
        let pk = leaf.signature_key().as_slice();
        if pk.len() != 32 || !bool::from(pk.ct_eq(&expected.identity_key)) {
            return Err(SecurityError::IdentityUntrusted("identity key does not match pinned key"));
        }
        Ok(kp)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(SecurityError::Malformed("snapshot length"))?;
        let s = self.b.get(self.pos..end).ok_or(SecurityError::Malformed("snapshot truncated"))?;
        self.pos = end;
        Ok(s)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| SecurityError::Malformed("snapshot field"))
    }
    fn u32(&mut self, max: u32) -> Result<u32> {
        let v = u32::from_be_bytes(self.array::<4>()?);
        if v > max {
            return Err(SecurityError::Malformed("snapshot field too large"));
        }
        Ok(v)
    }
}

impl GroupProtocol for MlsClient {
    fn generate_key_packages(&mut self, n: usize) -> Result<Vec<Vec<u8>>> {
        if n == 0 || n > cipher_wire::limits::MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(SecurityError::Malformed("key package count"));
        }
        (0..n)
            .map(|_| {
                let bundle = KeyPackage::builder()
                    .leaf_node_capabilities(Self::capabilities())
                    .build(CIPHERSUITE, &self.provider, &self.sig, self.credential.clone())
                    .map_err(perr)?;
                MlsMessageOut::from(bundle.key_package().clone()).tls_serialize_detached().map_err(perr)
            })
            .collect()
    }

    fn create_group(&mut self) -> Result<GroupRef> {
        let gid = GroupId::from_slice(&crate::rng::array::<16>()?);
        let g = MlsGroup::new_with_group_id(&self.provider, &self.sig, &Self::group_config(None)?, gid, self.credential.clone())
            .map_err(perr)?;
        Ok(GroupRef(g.group_id().as_slice().to_vec()))
    }

    fn add_member(&mut self, group: &GroupRef, key_package: &[u8], expected: &ExpectedPeer) -> Result<CommitOutput> {
        let kp = self.validate_key_package(key_package, expected)?;
        let mut g = self.load(group)?;
        let (commit, welcome, _gi) = g.add_members(&self.provider, &self.sig, core::slice::from_ref(&kp)).map_err(perr)?;
        Ok(CommitOutput {
            commit: commit.tls_serialize_detached().map_err(perr)?,
            welcome: Some(welcome.tls_serialize_detached().map_err(perr)?),
        })
    }

    fn remove_member(&mut self, group: &GroupRef, device: &Id16) -> Result<CommitOutput> {
        let mut g = self.load(group)?;
        let idx = g
            .members()
            .find(|m| parse_identity(m.credential.serialized_content()).map(|(_, d)| d) == Some(*device))
            .map(|m| m.index)
            .ok_or(SecurityError::Protocol("member not found"))?;
        let (commit, welcome, _gi) = g.remove_members(&self.provider, &self.sig, &[idx]).map_err(perr)?;
        Ok(CommitOutput {
            commit: commit.tls_serialize_detached().map_err(perr)?,
            welcome: match welcome {
                Some(w) => Some(w.tls_serialize_detached().map_err(perr)?),
                None => None,
            },
        })
    }

    fn self_update(&mut self, group: &GroupRef) -> Result<CommitOutput> {
        let mut g = self.load(group)?;
        let (commit, welcome, _gi) =
            g.self_update(&self.provider, &self.sig, openmls::treesync::LeafNodeParameters::default()).map_err(perr)?.into_contents();
        Ok(CommitOutput {
            commit: commit.tls_serialize_detached().map_err(perr)?,
            welcome: match welcome {
                Some(w) => Some(w.tls_serialize_detached().map_err(perr)?),
                None => None,
            },
        })
    }

    fn merge_pending_commit(&mut self, group: &GroupRef) -> Result<()> {
        let mut g = self.load(group)?;
        g.merge_pending_commit(&self.provider).map_err(perr)
    }

    fn clear_pending_commit(&mut self, group: &GroupRef) -> Result<()> {
        let mut g = self.load(group)?;
        g.clear_pending_commit(self.provider.storage()).map_err(perr)
    }

    fn join_from_welcome(&mut self, welcome: &[u8]) -> Result<GroupRef> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(perr)?;
        let MlsMessageBodyIn::Welcome(w) = msg.extract() else {
            return Err(SecurityError::Protocol("not a welcome"));
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), w, None).map_err(perr)?;
        let g = staged.into_group(&self.provider).map_err(perr)?;
        Ok(GroupRef(g.group_id().as_slice().to_vec()))
    }

    fn encrypt(&mut self, group: &GroupRef, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut g = self.load(group)?;
        if !g.is_active() {
            return Err(SecurityError::Protocol("group inactive"));
        }
        let m = g.create_message(&self.provider, &self.sig, plaintext).map_err(perr)?;
        m.tls_serialize_detached().map_err(perr)
    }

    fn process(&mut self, group: &GroupRef, ciphertext: &[u8], validator: &dyn CommitValidator) -> Result<Processed> {
        Ok(match self.process_ex(group, ciphertext, validator)? {
            ProcessedEx::Application { plaintext, .. } => Processed::Application(plaintext),
            ProcessedEx::Commit { epoch, added, removed, self_removed, .. } => Processed::Commit { epoch, added, removed, self_removed },
            ProcessedEx::Ignored => Processed::Ignored,
        })
    }

    fn epoch(&self, group: &GroupRef) -> Result<u64> {
        Ok(self.load(group)?.epoch().as_u64())
    }

    fn members(&self, group: &GroupRef) -> Result<Vec<(Id16, Id16)>> {
        let g = self.load(group)?;
        Ok(g.members().filter_map(|m| parse_identity(m.credential.serialized_content())).collect())
    }

    fn is_active(&self, group: &GroupRef) -> Result<bool> {
        Ok(self.load(group)?.is_active())
    }
}

/// A group member as seen in the (authenticated) ratchet tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInfo {
    pub account: Id16,
    pub device: Id16,
    pub identity_key: Vec<u8>,
}

/// Result of joining through a Welcome.
#[derive(Debug)]
pub struct Joined {
    pub group: GroupRef,
    /// The epoch this device joined at (history keys exist only from here on: no pre-join history).
    pub epoch: u64,
    pub inviter: (Id16, Id16),
    pub meta: Option<GroupMeta>,
    pub members: Vec<MemberInfo>,
}

fn meta_from_extensions(ext: &Extensions<GroupContext>) -> std::result::Result<Option<GroupMeta>, ()> {
    match ext.unknown(META_EXTENSION_TYPE) {
        None => Ok(None),
        Some(u) => GroupMeta::decode(&u.0).map(Some).map_err(|_| ()),
    }
}

impl MlsClient {
    fn meta_of(g: &MlsGroup) -> Option<GroupMeta> {
        meta_from_extensions(g.extensions()).ok().flatten()
    }

    fn identity_of(g: &MlsGroup, idx: LeafNodeIndex) -> Option<(Id16, Id16)> {
        Self::member_identity(g, idx)
    }

    fn devices_of(g: &MlsGroup) -> Members {
        let mut m: Members = BTreeMap::new();
        for mem in g.members() {
            if let Some((a, d)) = parse_identity(mem.credential.serialized_content()) {
                m.entry(a).or_default().insert(d);
            }
        }
        m
    }

    pub fn create_group_with_meta(&mut self, meta: &GroupMeta) -> Result<GroupRef> {
        meta.validate_shape().map_err(|_| SecurityError::Malformed("group metadata"))?;
        let gid = GroupId::from_slice(&crate::rng::array::<16>()?);
        let g = MlsGroup::new_with_group_id(&self.provider, &self.sig, &Self::group_config(Some(meta))?, gid, self.credential.clone())
            .map_err(perr)?;
        Ok(GroupRef(g.group_id().as_slice().to_vec()))
    }

    /// TEST ONLY: models an attacker who creates a group with a CHOSEN group id (e.g. one they learned as a member or ex-member).
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn create_group_with_id_for_tests(&mut self, meta: &GroupMeta, id: &[u8]) -> Result<GroupRef> {
        let g = MlsGroup::new_with_group_id(
            &self.provider,
            &self.sig,
            &Self::group_config(Some(meta))?,
            GroupId::from_slice(id),
            self.credential.clone(),
        )
        .map_err(perr)?;
        Ok(GroupRef(g.group_id().as_slice().to_vec()))
    }

    pub fn group_meta(&self, group: &GroupRef) -> Result<Option<GroupMeta>> {
        let g = self.load(group)?;
        meta_from_extensions(g.extensions()).map_err(|()| SecurityError::Malformed("group metadata"))
    }

    pub fn members_detailed(&self, group: &GroupRef) -> Result<Vec<MemberInfo>> {
        let g = self.load(group)?;
        Ok(g.members()
            .filter_map(|m| {
                parse_identity(m.credential.serialized_content()).map(|(account, device)| MemberInfo {
                    account,
                    device,
                    identity_key: m.signature_key.clone(),
                })
            })
            .collect())
    }

    /// Cleartext framing header of an MLS message (no keys needed).
    pub fn peek_header(bytes: &[u8]) -> Result<Header> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(perr)?;
        if matches!(msg.extract(), MlsMessageBodyIn::Welcome(_)) {
            return Ok(Header::Welcome);
        }
        let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(perr)?;
        Ok(match msg.try_into_protocol_message() {
            Ok(p) => Header::Group { group_id: p.group_id().as_slice().to_vec(), epoch: p.epoch().as_u64() },
            Err(_) => Header::Other,
        })
    }

    fn commit_info(g: &MlsGroup, staged: &StagedCommit, sender: (Id16, Id16)) -> CommitInfo {
        let mut info = CommitInfo { sender_account: Some(sender.0), ..CommitInfo::default() };
        for qp in staged.queued_proposals() {
            match qp.proposal() {
                Proposal::Add(a) => match parse_identity(a.key_package().leaf_node().credential().serialized_content()) {
                    Some(id) => info.adds.push(id),
                    None => info.unsupported_proposals += 1,
                },
                Proposal::Remove(r) => match Self::member_identity(g, r.removed()) {
                    Some(id) => info.removes.push(id),
                    None => info.unsupported_proposals += 1,
                },
                Proposal::GroupContextExtensions(p) => match meta_from_extensions(p.extensions()) {
                    Ok(Some(m)) => info.new_meta = Some(m),
                    _ => info.unsupported_proposals += 1, // stripping or corrupting the metadata is never allowed
                },
                _ => info.unsupported_proposals += 1,
            }
        }
        info
    }

    pub fn process_ex(&mut self, group: &GroupRef, ciphertext: &[u8], validator: &dyn CommitValidator) -> Result<ProcessedEx> {
        let h: [u8; 32] = Sha256::digest(ciphertext).into();
        if self.seen.contains(&h) {
            return Err(SecurityError::Replay);
        }
        let mut g = self.load(group)?;
        let msg = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(perr)?;
        let proto: ProtocolMessage = msg.try_into_protocol_message().map_err(|_| SecurityError::Protocol("not a protocol message"))?;
        let (msg_epoch, cur) = (proto.epoch().as_u64(), g.epoch().as_u64());
        if msg_epoch > cur {
            return Err(SecurityError::FutureEpoch);
        }
        if msg_epoch + 2 < cur {
            return Err(SecurityError::StaleEpoch);
        }
        let old_meta = Self::meta_of(&g);
        let devices_before = Self::devices_of(&g);
        let processed = g.process_message(&self.provider, proto).map_err(perr)?;
        let sender = match processed.sender() {
            // a leaf that no longer exists in the current tree: the sender was removed (REV-001)
            Sender::Member(idx) => Self::identity_of(&g, *idx).ok_or(SecurityError::Unauthorized("sender is no longer a member"))?,
            _ => return Err(SecurityError::Protocol("unsupported sender")),
        };
        let out = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => {
                // REV-001/REV-008: a message from a RETAINED PAST epoch (max_past_epochs) is only accepted from someone who is STILL a
                // member now. Otherwise a removed member who was offline could keep sending into the epoch before their removal.
                if msg_epoch < cur && !devices_before.get(&sender.0).is_some_and(|d| d.contains(&sender.1)) {
                    return Err(SecurityError::Unauthorized("sender is no longer a member"));
                }
                ProcessedEx::Application { plaintext: a.into_bytes(), sender, epoch: msg_epoch }
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let info = Self::commit_info(&g, &staged, sender);
                for (acc, dev) in &info.adds {
                    let key = staged
                        .add_proposals()
                        .find(|ap| {
                            parse_identity(ap.add_proposal().key_package().leaf_node().credential().serialized_content())
                                == Some((*acc, *dev))
                        })
                        .map(|ap| ap.add_proposal().key_package().leaf_node().signature_key().as_slice().to_vec())
                        .unwrap_or_default();
                    if !validator.approve_add(acc, dev, &key) {
                        return Err(SecurityError::IdentityUntrusted("commit adds an unapproved device"));
                    }
                }
                // Authorization is enforced HERE, by every client, before the commit is merged. Fail closed.
                if let Some(meta) = &old_meta {
                    authorize_commit(meta, &devices_before, &info)
                        .map_err(|_| SecurityError::Unauthorized("commit violates group policy"))?;
                } else if info.unsupported_proposals > 0 {
                    return Err(SecurityError::Unauthorized("unsupported proposal"));
                }
                let self_removed = staged.self_removed();
                g.merge_staged_commit(&self.provider, *staged).map_err(perr)?;
                ProcessedEx::Commit { epoch: g.epoch().as_u64(), added: info.adds, removed: info.removes, self_removed, sender }
            }
            _ => ProcessedEx::Ignored,
        };
        self.mark_seen(h);
        Ok(out)
    }

    /// Stage ONE commit combining any number of operations. The caller must `merge_pending_commit` once the
    /// sequencer accepted it, or `clear_pending_commit` if it lost the race. A client never builds a commit that
    /// the group's own policy would reject.
    pub fn commit(&mut self, group: &GroupRef, ops: &[GroupOp]) -> Result<CommitOutput> {
        self.commit_inner(group, ops, true)
    }

    /// TEST ONLY: models a malicious or modified client that skips its own policy pre-check, so tests can prove the
    /// RECEIVERS reject the commit.
    #[cfg(any(test, feature = "insecure-test-support"))]
    pub fn commit_unchecked_for_tests(&mut self, group: &GroupRef, ops: &[GroupOp]) -> Result<CommitOutput> {
        self.commit_inner(group, ops, false)
    }

    fn commit_inner(&mut self, group: &GroupRef, ops: &[GroupOp], precheck: bool) -> Result<CommitOutput> {
        let mut g = self.load(group)?;
        #[allow(unused_mut)]
        let mut raw_meta: Option<Vec<u8>> = None;
        let mut kps = Vec::new();
        let mut info = CommitInfo { sender_account: Some(self.account_id), ..CommitInfo::default() };
        let mut remove_idx = Vec::new();
        let mut meta_ops = None;
        let mut force_update = false;
        for op in ops {
            match op {
                GroupOp::Add { key_package, expected } => {
                    let kp = self.validate_key_package(key_package, expected)?;
                    info.adds.push((expected.account_id, expected.device_id));
                    kps.push(kp);
                }
                GroupOp::Remove { devices } => {
                    for d in devices {
                        let m = g
                            .members()
                            .find(|m| parse_identity(m.credential.serialized_content()).map(|(_, dd)| dd) == Some(*d))
                            .ok_or(SecurityError::Protocol("member not found"))?;
                        let id = parse_identity(m.credential.serialized_content()).ok_or(SecurityError::Protocol("member identity"))?;
                        if m.index == g.own_leaf_index() {
                            return Err(SecurityError::Protocol("cannot remove self in a commit"));
                        }
                        remove_idx.push(m.index);
                        info.removes.push(id);
                    }
                }
                GroupOp::SetMeta(m) => meta_ops = Some(m.clone()),
                GroupOp::SelfUpdate => force_update = true,
                #[cfg(any(test, feature = "insecure-test-support"))]
                GroupOp::SetMetaRawForTests(b) => raw_meta = Some(b.clone()),
            }
        }
        info.new_meta = meta_ops.clone();
        if let (true, Some(old)) = (precheck, Self::meta_of(&g)) {
            authorize_commit(&old, &Self::devices_of(&g), &info)
                .map_err(|_| SecurityError::Unauthorized("not permitted by group policy"))?;
        }
        let mut b = g.commit_builder();
        if !kps.is_empty() {
            b = b.propose_adds(kps);
        }
        if !remove_idx.is_empty() {
            b = b.propose_removals(remove_idx);
        }
        if let Some(m) = &meta_ops {
            let bytes = m.encode().map_err(|_| SecurityError::Malformed("group metadata"))?;
            b = b.propose_group_context_extensions(Self::context_extensions(bytes)?).map_err(perr)?;
        }
        if let Some(bytes) = raw_meta {
            b = b.propose_group_context_extensions(Self::context_extensions(bytes)?).map_err(perr)?;
        }
        if force_update {
            b = b.force_self_update(true);
        }
        let staged = b
            .load_psks(self.provider.storage())
            .map_err(perr)?
            .build(self.provider.rand(), self.provider.crypto(), &self.sig, |_| true)
            .map_err(perr)?
            .stage_commit(&self.provider)
            .map_err(perr)?;
        let (commit, welcome, _gi) = staged.into_messages();
        Ok(CommitOutput {
            commit: commit.tls_serialize_detached().map_err(perr)?,
            welcome: match welcome {
                Some(w) => Some(w.tls_serialize_detached().map_err(perr)?),
                None => None,
            },
        })
    }

    /// Join through a Welcome, validating the group metadata and member roles BEFORE persisting any state.
    pub fn join_welcome_ex(&mut self, welcome: &[u8]) -> Result<Joined> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(perr)?;
        let MlsMessageBodyIn::Welcome(w) = msg.extract() else {
            return Err(SecurityError::Protocol("not a welcome"));
        };
        let staged = StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), w, None).map_err(perr)?;
        let inviter = staged
            .welcome_sender()
            .ok()
            .and_then(|leaf| parse_identity(leaf.credential().serialized_content()))
            .ok_or(SecurityError::Protocol("welcome sender"))?;
        let meta = meta_from_extensions(staged.group_context().extensions())
            .map_err(|()| SecurityError::Unauthorized("invalid group metadata"))?;
        let accounts: BTreeSet<Id16> =
            staged.members().filter_map(|m| parse_identity(m.credential.serialized_content()).map(|(a, _)| a)).collect();
        if let Some(m) = &meta {
            let ok = if m.kind == crate::app::groupmeta::MetaKind::Group {
                m.owner().is_some_and(|o| accounts.contains(&o)) && m.roles.iter().all(|r| accounts.contains(&r.account))
            } else {
                accounts.len() <= 2
            };
            if !ok {
                return Err(SecurityError::Unauthorized("group roles inconsistent with members"));
            }
        }
        // Defence in depth: never let a Welcome replace the state of a group we already hold. (OpenMLS also refuses; this makes the
        // refusal explicit and independent of that behaviour — see tests/group_attacks.rs.)
        if self.load(&GroupRef(staged.group_context().group_id().as_slice().to_vec())).is_ok() {
            return Err(SecurityError::Replay);
        }
        let g = staged.into_group(&self.provider).map_err(perr)?;
        let members = g
            .members()
            .filter_map(|m| {
                parse_identity(m.credential.serialized_content()).map(|(account, device)| MemberInfo {
                    account,
                    device,
                    identity_key: m.signature_key.clone(),
                })
            })
            .collect();
        Ok(Joined { group: GroupRef(g.group_id().as_slice().to_vec()), epoch: g.epoch().as_u64(), inviter, meta, members })
    }

    /// History key for the CURRENT epoch of `group` (see docs/HISTORY_REVOCATION.md): the RFC 9420 exporter secret for a Cipher-specific label,
    /// bound to the group id and epoch. Only devices that are members of this epoch can compute it; a removed member cannot compute any later one.
    /// The exporter is a standard MLS mechanism (RFC 9420 §8.5); no new primitive is introduced.
    pub fn export_epoch_key(&self, group: &GroupRef) -> Result<Zeroizing<[u8; 32]>> {
        let g = self.load(group)?;
        let mut ctx = Vec::with_capacity(group.0.len() + 8);
        ctx.extend_from_slice(&group.0);
        ctx.extend_from_slice(&g.epoch().as_u64().to_be_bytes());
        let raw = g.export_secret(self.provider.crypto(), crate::history::EXPORTER_LABEL, &ctx, 32).map_err(perr)?;
        let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| SecurityError::Protocol("exporter length"))?;
        Ok(Zeroizing::new(key))
    }

    pub fn leave_group_state(&mut self, group: &GroupRef) -> Result<()> {
        let mut g = self.load(group)?;
        g.delete(self.provider.storage()).map_err(perr)
    }

    pub fn drop_replay_marker(&mut self, ciphertext: &[u8]) {
        let h: [u8; 32] = Sha256::digest(ciphertext).into();
        self.seen.remove(&h);
        self.seen_order.retain(|x| x != &h);
    }
}
