//! Relay persistence on PostgreSQL. Contents: public keys, opaque ciphertext, expiry times, counters.
//! There is deliberately no column that could hold plaintext, private keys, or the sender of a message.
//! Everything transient is bounded and expires. All multi-row invariants run in transactions.
use crate::db::internal;
use crate::error::ApiError;
use cipher_wire::limits::*;
use cipher_wire::messages::{Delivery, DeviceRecord, Endorsement, Envelope};
use cipher_wire::Id16;
use deadpool_postgres::{Pool, Transaction};
use tokio_postgres::error::SqlState;

/// Expiry timestamps are rounded up to this granularity to blur enqueue-time metadata.
pub const EXPIRY_GRANULARITY_SECS: u64 = 600;
/// Groups idle this many days are garbage-collected.
pub const GROUP_IDLE_DAYS: i32 = 180;

#[derive(Debug, PartialEq, Eq)]
pub enum Enqueue {
    Queued,
    Duplicate,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GroupOutcome {
    Accepted(u64),
    Stale(u64),
    /// The routing tag was retired by a removal commit.
    Gone,
}

/// Who is enqueueing (for the per-sender share of a recipient's queue). Never stored in the clear: only a keyed pair hash.
#[derive(Debug)]
pub struct Sender<'a> {
    pub device: Id16,
    pub keys: &'a crate::ratelimit::KeyHasher,
}

/// A single sending device may occupy at most a quarter of a recipient's queue (ST-031).
pub const MAX_QUEUED_ENVELOPES_PER_SENDER: usize = MAX_QUEUED_ENVELOPES_PER_DEVICE / 4;
pub const MAX_QUEUED_BYTES_PER_SENDER: usize = MAX_QUEUED_BYTES_PER_DEVICE / 4;

/// Which queue lane an envelope enters. Lanes are what keeps an unauthenticated or stranger flood from starving contacts (ST-031).
#[derive(Debug, Clone, Copy)]
pub enum Lane<'a> {
    /// Authenticated send without a capability (first contact, legacy): small fixed allowance, per-sender share.
    Open(Option<&'a Sender<'a>>),
    /// Group commits/Welcomes through the sequencer: per-sender share only.
    Commit(Option<&'a Sender<'a>>),
    /// Holder of a capability: per-capability allowance.
    Cap([u8; 32]),
}

impl Lane<'_> {
    fn code(&self) -> i16 {
        match self {
            Lane::Open(_) => 0,
            Lane::Cap(_) => 1,
            Lane::Commit(_) => 2,
        }
    }
}

pub fn cap_hash(cap: &Id16) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"cipher/delivery-cap/v1");
    h.update(cap.0);
    h.finalize().into()
}

pub struct PgStore {
    pool: Pool,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PgStore")
    }
}

fn is_unique(e: &tokio_postgres::Error) -> bool {
    e.code() == Some(&SqlState::UNIQUE_VIOLATION)
}

fn round_up(t: u64) -> i64 {
    (t.div_ceil(EXPIRY_GRANULARITY_SECS) * EXPIRY_GRANULARITY_SECS) as i64
}

fn id(v: Vec<u8>) -> Result<Id16, ApiError> {
    v.try_into().map(Id16).map_err(|_| ApiError::Internal)
}

impl PgStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    async fn conn(&self) -> Result<deadpool_postgres::Object, ApiError> {
        self.pool.get().await.map_err(internal)
    }

    /// Readiness probe: the database answers a trivial query.
    pub async fn ping(&self) -> bool {
        match self.conn().await {
            Ok(c) => c.query_one("SELECT 1", &[]).await.is_ok(),
            Err(_) => false,
        }
    }

    // ---- accounts / devices ----

    async fn insert_device(tx: &Transaction<'_>, account: &Id16, rec: &DeviceRecord) -> Result<(), ApiError> {
        let (endorser, esig): (Option<Vec<u8>>, Option<Vec<u8>>) = match &rec.endorsement {
            Some(e) => (Some(e.endorser_device.0.to_vec()), Some(e.signature.clone())),
            None => (None, None),
        };
        match tx
            .execute(
                "INSERT INTO devices (device_id, account_id, identity_key, auth_key, binding_sig, endorser, endorsement_sig) VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[&rec.device_id.0.as_slice(), &account.0.as_slice(), &rec.identity_key, &rec.auth_key, &rec.binding_sig, &endorser, &esig],
            )
            .await
        {
            Err(e) if is_unique(&e) => Err(ApiError::Conflict),
            r => r.map(|_| ()).map_err(internal),
        }
    }

    pub async fn create_account(&self, account: &Id16, rec: &DeviceRecord) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        match tx.execute("INSERT INTO accounts (account_id) VALUES ($1)", &[&account.0.as_slice()]).await {
            Err(e) if is_unique(&e) => return Err(ApiError::Conflict),
            r => r.map_err(internal)?,
        };
        Self::insert_device(&tx, account, rec).await?;
        tx.commit().await.map_err(internal)
    }

    pub async fn add_device(&self, account: &Id16, rec: &DeviceRecord) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        // Serialise concurrent device additions for one account.
        tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'), 0))", &[&account.0.as_slice()])
            .await
            .map_err(internal)?;
        let n: i64 =
            tx.query_one("SELECT count(*) FROM devices WHERE account_id=$1", &[&account.0.as_slice()]).await.map_err(internal)?.get(0);
        if n == 0 {
            return Err(ApiError::NotFound);
        }
        if n as usize >= MAX_DEVICES_PER_ACCOUNT {
            return Err(ApiError::Forbidden);
        }
        Self::insert_device(&tx, account, rec).await?;
        tx.commit().await.map_err(internal)
    }

    fn row_to_record(r: &tokio_postgres::Row) -> Result<DeviceRecord, ApiError> {
        let endorser: Option<Vec<u8>> = r.get(4);
        let esig: Option<Vec<u8>> = r.get(5);
        Ok(DeviceRecord {
            device_id: id(r.get(0))?,
            identity_key: r.get(1),
            auth_key: r.get(2),
            binding_sig: r.get(3),
            endorsement: match (endorser, esig) {
                (Some(e), Some(s)) => Some(Endorsement { endorser_device: id(e)?, signature: s }),
                _ => None,
            },
        })
    }

    pub async fn device(&self, device: &Id16) -> Result<Option<(Id16, DeviceRecord)>, ApiError> {
        let c = self.conn().await?;
        let row = c
            .query_opt(
                "SELECT device_id, identity_key, auth_key, binding_sig, endorser, endorsement_sig, account_id FROM devices WHERE device_id=$1",
                &[&device.0.as_slice()],
            )
            .await
            .map_err(internal)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some((id(r.get(6))?, Self::row_to_record(&r)?))),
        }
    }

    pub async fn devices_of(&self, account: &Id16) -> Result<Vec<DeviceRecord>, ApiError> {
        let c = self.conn().await?;
        let rows = c
            .query(
                "SELECT device_id, identity_key, auth_key, binding_sig, endorser, endorsement_sig FROM devices WHERE account_id=$1 ORDER BY ord",
                &[&account.0.as_slice()],
            )
            .await
            .map_err(internal)?;
        rows.iter().map(Self::row_to_record).collect()
    }

    pub async fn set_push_token(&self, device: &Id16, token: &str) -> Result<(), ApiError> {
        let c = self.conn().await?;
        c.execute("UPDATE devices SET push_token=$2 WHERE device_id=$1", &[&device.0.as_slice(), &token]).await.map_err(internal)?;
        Ok(())
    }

    pub async fn push_token(&self, device: &Id16) -> Result<Option<String>, ApiError> {
        let c = self.conn().await?;
        let r = c.query_opt("SELECT push_token FROM devices WHERE device_id=$1", &[&device.0.as_slice()]).await.map_err(internal)?;
        Ok(r.and_then(|r| r.get::<_, Option<String>>(0)))
    }

    // ---- key packages ----

    pub async fn put_key_packages(&self, device: &Id16, kps: &[Vec<u8>]) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        tx.query_one("SELECT 1 FROM devices WHERE device_id=$1 FOR UPDATE", &[&device.0.as_slice()]).await.map_err(internal)?;
        let n: i64 =
            tx.query_one("SELECT count(*) FROM key_packages WHERE device_id=$1", &[&device.0.as_slice()]).await.map_err(internal)?.get(0);
        if n as usize + kps.len() > MAX_KEY_PACKAGES_PER_DEVICE {
            return Err(ApiError::QueueFull);
        }
        for kp in kps {
            tx.execute("INSERT INTO key_packages (device_id, kp) VALUES ($1,$2)", &[&device.0.as_slice(), kp]).await.map_err(internal)?;
        }
        tx.commit().await.map_err(internal)
    }

    /// Single-use: deleted as it is handed out (atomic, safe under concurrent consumers).
    pub async fn pop_key_package(&self, device: &Id16) -> Result<Option<Vec<u8>>, ApiError> {
        let c = self.conn().await?;
        let r = c
            .query_opt(
                "DELETE FROM key_packages WHERE id = (SELECT id FROM key_packages WHERE device_id=$1 ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING kp",
                &[&device.0.as_slice()],
            )
            .await
            .map_err(internal)?;
        Ok(r.map(|r| r.get(0)))
    }

    // ---- ciphertext queue ----

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_tx(
        tx: &Transaction<'_>,
        recipient: &Id16,
        message_id: &Id16,
        ct: &[u8],
        ttl_secs: u64,
        now: u64,
        group_seq: Option<i64>,
        lane: Lane<'_>,
    ) -> Result<Enqueue, ApiError> {
        let expires = round_up(now.saturating_add(ttl_secs));
        let now_i = now as i64;
        let rec = recipient.0.as_slice();
        // Row lock on the recipient serialises concurrent enqueues, making the bound checks exact.
        let row = tx
            .query_opt("SELECT queued_count, queued_bytes FROM devices WHERE device_id=$1 FOR UPDATE", &[&rec])
            .await
            .map_err(internal)?;
        let Some(row) = row else { return Err(ApiError::NotFound) };
        let (mut count, mut bytes): (i32, i64) = (row.get(0), row.get(1));
        let purged = tx
            .query_one(
                "WITH d AS (DELETE FROM queue WHERE recipient=$1 AND expires_at<=$2 RETURNING octet_length(ct)::bigint AS l) SELECT count(*)::int, COALESCE(sum(l),0)::bigint FROM d",
                &[&rec, &now_i],
            )
            .await
            .map_err(internal)?;
        count -= purged.get::<_, i32>(0);
        bytes -= purged.get::<_, i64>(1);
        tx.execute("DELETE FROM seen WHERE recipient=$1 AND expires_at<=$2", &[&rec, &now_i]).await.map_err(internal)?;
        let ins = tx
            .execute(
                "INSERT INTO seen (recipient, message_id, expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&rec, &message_id.0.as_slice(), &expires],
            )
            .await
            .map_err(internal)?;
        if ins == 0 {
            // Persist the purge accounting even though this is a duplicate.
            tx.execute("UPDATE devices SET queued_count=$2, queued_bytes=$3 WHERE device_id=$1", &[&rec, &count, &bytes])
                .await
                .map_err(internal)?;
            return Ok(Enqueue::Duplicate);
        }
        if count as usize >= MAX_QUEUED_ENVELOPES_PER_DEVICE || bytes as usize + ct.len() > MAX_QUEUED_BYTES_PER_DEVICE {
            return Err(ApiError::QueueFull); // caller rolls back: no tombstone for a rejected message
        }
        // ST-031: lanes. No stranger can take more than the OPEN lane; a capability holder only its capability's allowance; and no single
        // sending device more than a fixed share of the queue.
        let sender = match lane {
            Lane::Open(s) | Lane::Commit(s) => s,
            Lane::Cap(_) => None,
        };
        let pair: Option<Vec<u8>> = sender.map(|s| s.keys.key("pair", &[s.device.0.as_slice(), rec].concat()).to_vec());
        if let Some(p) = &pair {
            let share = tx
                .query_one(
                    "SELECT count(*)::int, COALESCE(sum(octet_length(ct)),0)::bigint FROM queue WHERE recipient=$1 AND sender_h=$2",
                    &[&rec, p],
                )
                .await
                .map_err(internal)?;
            if share.get::<_, i32>(0) as usize >= MAX_QUEUED_ENVELOPES_PER_SENDER
                || share.get::<_, i64>(1) as usize + ct.len() > MAX_QUEUED_BYTES_PER_SENDER
            {
                return Err(ApiError::QueueFull);
            }
        }
        let cap_h: Option<Vec<u8>> = if let Lane::Cap(h) = lane { Some(h.to_vec()) } else { None };
        match lane {
            Lane::Open(_) => {
                let l = tx
                    .query_one(
                        "SELECT count(*)::int, COALESCE(sum(octet_length(ct)),0)::bigint FROM queue WHERE recipient=$1 AND lane=0",
                        &[&rec],
                    )
                    .await
                    .map_err(internal)?;
                if l.get::<_, i32>(0) as usize >= OPEN_LANE_ENVELOPES || l.get::<_, i64>(1) as usize + ct.len() > OPEN_LANE_BYTES {
                    return Err(ApiError::QueueFull);
                }
            }
            Lane::Cap(h) => {
                let l = tx
                    .query_one(
                        "SELECT count(*)::int, COALESCE(sum(octet_length(ct)),0)::bigint FROM queue WHERE cap_hash=$1",
                        &[&h.as_slice()],
                    )
                    .await
                    .map_err(internal)?;
                if l.get::<_, i32>(0) as usize >= CAP_QUOTA_ENVELOPES || l.get::<_, i64>(1) as usize + ct.len() > CAP_QUOTA_BYTES {
                    return Err(ApiError::QueueFull);
                }
            }
            Lane::Commit(_) => {
                let l = tx
                    .query_one(
                        "SELECT count(*)::int, COALESCE(sum(octet_length(ct)),0)::bigint FROM queue WHERE recipient=$1 AND lane=2",
                        &[&rec],
                    )
                    .await
                    .map_err(internal)?;
                if l.get::<_, i32>(0) as usize >= COMMIT_LANE_ENVELOPES || l.get::<_, i64>(1) as usize + ct.len() > COMMIT_LANE_BYTES {
                    return Err(ApiError::QueueFull);
                }
            }
        }
        tx.execute(
            "INSERT INTO queue (recipient, message_id, ct, expires_at, group_seq, sender_h, lane, cap_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&rec, &message_id.0.as_slice(), &ct, &expires, &group_seq, &pair, &lane.code(), &cap_h],
        )
        .await
        .map_err(internal)?;
        tx.execute(
            "UPDATE devices SET queued_count=$2, queued_bytes=$3 WHERE device_id=$1",
            &[&rec, &(count + 1), &(bytes + ct.len() as i64)],
        )
        .await
        .map_err(internal)?;
        Ok(Enqueue::Queued)
    }

    pub async fn enqueue(
        &self,
        recipient: &Id16,
        message_id: &Id16,
        ct: &[u8],
        ttl_secs: u64,
        now: u64,
        sender: Option<&Sender<'_>>,
    ) -> Result<Enqueue, ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let r = Self::enqueue_tx(&tx, recipient, message_id, ct, ttl_secs, now, None, Lane::Open(sender)).await?;
        tx.commit().await.map_err(internal)?;
        Ok(r)
    }

    /// Batch fan-out: each delivery is independent (one full queue must not block the others).
    pub async fn enqueue_batch(
        &self,
        deliveries: &[Delivery],
        ttl_secs: u64,
        now: u64,
        sender: Option<&Sender<'_>>,
    ) -> Result<Vec<String>, ApiError> {
        let mut out = Vec::with_capacity(deliveries.len());
        for d in deliveries {
            out.push(match self.enqueue(&d.recipient_device, &d.message_id, &d.ciphertext, ttl_secs, now, sender).await {
                Ok(Enqueue::Queued) => "queued".to_owned(),
                Ok(Enqueue::Duplicate) => "duplicate".to_owned(),
                Err(ApiError::NotFound) => "not_found".to_owned(),
                Err(ApiError::QueueFull) => "queue_full".to_owned(),
                Err(e) => return Err(e),
            });
        }
        Ok(out)
    }

    pub async fn fetch(&self, recipient: &Id16, now: u64) -> Result<(Vec<Envelope>, bool), ApiError> {
        let c = self.conn().await?;
        let rows = c
            .query(
                "SELECT message_id, ct, group_seq FROM queue WHERE recipient=$1 AND expires_at>$2 ORDER BY seq LIMIT $3",
                &[&recipient.0.as_slice(), &(now as i64), &((MAX_FETCH_BATCH + 1) as i64)],
            )
            .await
            .map_err(internal)?;
        let mut out = Vec::new();
        for r in &rows {
            out.push(Envelope { message_id: id(r.get(0))?, ciphertext: r.get(1), group_seq: r.get::<_, Option<i64>>(2).map(|v| v as u64) });
        }
        let more = out.len() > MAX_FETCH_BATCH;
        out.truncate(MAX_FETCH_BATCH);
        Ok((out, more))
    }

    pub async fn ack(&self, recipient: &Id16, ids: &[Id16]) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let rec = recipient.0.as_slice();
        tx.query_opt("SELECT 1 FROM devices WHERE device_id=$1 FOR UPDATE", &[&rec]).await.map_err(internal)?;
        let id_vec: Vec<Vec<u8>> = ids.iter().map(|i| i.0.to_vec()).collect();
        tx.execute(
            "WITH d AS (DELETE FROM queue WHERE recipient=$1 AND message_id = ANY($2) RETURNING octet_length(ct)::bigint AS l)
             UPDATE devices SET queued_count = queued_count - (SELECT count(*) FROM d)::int,
                                queued_bytes = queued_bytes - (SELECT COALESCE(sum(l),0) FROM d)::bigint
             WHERE device_id=$1",
            &[&rec, &id_vec],
        )
        .await
        .map_err(internal)?;
        tx.commit().await.map_err(internal)
    }

    // ---- group epoch sequencer ----

    pub async fn group_epoch(&self, tag: &Id16) -> Result<Option<(u64, bool)>, ApiError> {
        let c = self.conn().await?;
        let r = c.query_opt("SELECT epoch, retired FROM groups WHERE tag=$1", &[&tag.0.as_slice()]).await.map_err(internal)?;
        Ok(r.map(|r| (r.get::<_, i64>(0) as u64, r.get(1))))
    }

    /// Atomic compare-and-swap commit: accepts only if `expected_epoch` is current; on success the
    /// commit (and any welcomes) are queued to every recipient in the same transaction.
    pub async fn group_commit(
        &self,
        tag: &Id16,
        expected_epoch: u64,
        new_tag: Option<&Id16>,
        deliveries: &[Delivery],
        now: u64,
        sender: Option<&Sender<'_>>,
    ) -> Result<GroupOutcome, ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let day = (now / 86_400) as i32;
        let t = tag.0.as_slice();
        // Serialise creation races on a not-yet-existing row.
        tx.execute("SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'), 1))", &[&t]).await.map_err(internal)?;
        let row = tx
            .query_opt("SELECT epoch, retired, last_mid, last_from FROM groups WHERE tag=$1 FOR UPDATE", &[&t])
            .await
            .map_err(internal)?;
        // Idempotent retry: the SAME commit (same first delivery id, same consumed epoch) was already accepted; the committer lost the response.
        if let (Some(r), Some(first)) = (&row, deliveries.first()) {
            let (mid, from): (Option<Vec<u8>>, Option<i64>) = (r.get(2), r.get(3));
            if mid.as_deref() == Some(first.message_id.0.as_slice()) && from == Some(expected_epoch as i64) {
                return Ok(GroupOutcome::Accepted(expected_epoch + 1));
            }
        }
        let current: u64 = match row {
            None if expected_epoch == 0 => {
                tx.execute("INSERT INTO groups (tag, epoch, touched_day) VALUES ($1, 0, $2)", &[&t, &day]).await.map_err(internal)?;
                0
            }
            None => return Ok(GroupOutcome::Stale(0)),
            Some(r) => {
                if r.get::<_, bool>(1) {
                    return Ok(GroupOutcome::Gone);
                }
                r.get::<_, i64>(0) as u64
            }
        };
        if current != expected_epoch {
            return Ok(GroupOutcome::Stale(current));
        }
        let next = (current + 1) as i64;
        let first_mid: Option<Vec<u8>> = deliveries.first().map(|d| d.message_id.0.to_vec());
        if let Some(nt) = new_tag {
            match tx.execute("INSERT INTO groups (tag, epoch, touched_day) VALUES ($1,$2,$3)", &[&nt.0.as_slice(), &next, &day]).await {
                Err(e) if is_unique(&e) => return Err(ApiError::Conflict),
                r => r.map_err(internal)?,
            };
            tx.execute(
                "UPDATE groups SET retired=true, touched_day=$2, last_mid=$3, last_from=$4 WHERE tag=$1",
                &[&t, &day, &first_mid, &(expected_epoch as i64)],
            )
            .await
            .map_err(internal)?;
        } else {
            tx.execute(
                "UPDATE groups SET epoch=$2, touched_day=$3, last_mid=$4, last_from=$5 WHERE tag=$1",
                &[&t, &next, &day, &first_mid, &(expected_epoch as i64)],
            )
            .await
            .map_err(internal)?;
        }
        for d in deliveries {
            Self::enqueue_tx(
                &tx,
                &d.recipient_device,
                &d.message_id,
                &d.ciphertext,
                DEFAULT_TTL_SECS,
                now,
                Some(next),
                Lane::Commit(sender),
            )
            .await?;
        }
        tx.commit().await.map_err(internal)?;
        Ok(GroupOutcome::Accepted(next as u64))
    }

    // ---- delivery capabilities (docs/DELIVERY_CAPABILITIES.md) ----

    /// Mints `caps` (the caller generated the random ids; the relay stores only their hashes). Bounded per device.
    pub async fn mint_caps(&self, device: &Id16, caps: &[Id16], intro: bool, now: u64) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let d = device.0.as_slice();
        tx.execute("SELECT 1 FROM devices WHERE device_id=$1 FOR UPDATE", &[&d]).await.map_err(internal)?;
        tx.execute("DELETE FROM delivery_caps WHERE device_id=$1 AND expires_at<=$2", &[&d, &(now as i64)]).await.map_err(internal)?;
        let live: i64 = tx.query_one("SELECT count(*) FROM delivery_caps WHERE device_id=$1", &[&d]).await.map_err(internal)?.get(0);
        if live as usize + caps.len() > MAX_CAPS_PER_DEVICE {
            return Err(ApiError::QueueFull);
        }
        if intro {
            // Few cards at a time: every live intro capability is a way for a stranger who holds it to claim KeyPackages.
            let live_intro: i64 =
                tx.query_one("SELECT count(*) FROM delivery_caps WHERE device_id=$1 AND intro", &[&d]).await.map_err(internal)?.get(0);
            if live_intro as usize + caps.len() > MAX_INTRO_CAPS_PER_DEVICE {
                return Err(ApiError::QueueFull);
            }
        }
        let exp = (now + CAP_TTL_SECS) as i64;
        for cap in caps {
            let h = cap_hash(cap);
            match tx
                .execute("INSERT INTO delivery_caps (cap_hash, device_id, expires_at, intro) VALUES ($1,$2,$3,$4)", &[&h.as_slice(), &d, &exp, &intro])
                .await
            {
                Err(e) if is_unique(&e) => return Err(ApiError::Conflict),
                r => r.map_err(internal)?,
            };
        }
        tx.commit().await.map_err(internal)
    }

    /// Revokes capabilities owned by `device`: they stop working after `grace_secs` (0 = immediately). Unknown/foreign ones are ignored silently.
    pub async fn revoke_caps(&self, device: &Id16, caps: &[Id16], grace_secs: u64, now: u64) -> Result<(), ApiError> {
        let c = self.conn().await?;
        for cap in caps {
            let h = cap_hash(cap);
            if grace_secs == 0 {
                c.execute("DELETE FROM delivery_caps WHERE cap_hash=$1 AND device_id=$2", &[&h.as_slice(), &device.0.as_slice()])
                    .await
                    .map_err(internal)?;
            } else {
                c.execute(
                    "UPDATE delivery_caps SET expires_at = LEAST(expires_at, $3) WHERE cap_hash=$1 AND device_id=$2",
                    &[&h.as_slice(), &device.0.as_slice(), &((now + grace_secs) as i64)],
                )
                .await
                .map_err(internal)?;
            }
        }
        Ok(())
    }

    /// Unauthenticated delivery. `Err(NotFound)` for an unknown, revoked or expired capability (one indistinguishable outcome).
    pub async fn enqueue_anon(
        &self,
        cap: &Id16,
        message_id: &Id16,
        ct: &[u8],
        ttl_secs: u64,
        now: u64,
    ) -> Result<(Id16, Enqueue), ApiError> {
        let h = cap_hash(cap);
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let row = tx
            .query_opt("SELECT device_id FROM delivery_caps WHERE cap_hash=$1 AND expires_at>$2", &[&h.as_slice(), &(now as i64)])
            .await
            .map_err(internal)?;
        let Some(row) = row else { return Err(ApiError::NotFound) };
        let dev = id(row.get(0))?;
        let r = Self::enqueue_tx(&tx, &dev, message_id, ct, ttl_secs, now, None, Lane::Cap(h)).await?;
        tx.commit().await.map_err(internal)?;
        Ok((dev, r))
    }

    /// The device an INTRO capability belongs to (valid, unexpired, kind intro). Unknown / expired / revoked / ordinary capabilities are one outcome.
    pub async fn intro_device(&self, cap: &Id16, now: u64) -> Result<Id16, ApiError> {
        let c = self.conn().await?;
        let row = c
            .query_opt(
                "SELECT device_id FROM delivery_caps WHERE cap_hash=$1 AND intro AND expires_at>$2",
                &[&cap_hash(cap).as_slice(), &(now as i64)],
            )
            .await
            .map_err(internal)?;
        match row {
            Some(r) => id(r.get(0)),
            None => Err(ApiError::NotFound),
        }
    }

    // ---- blobs ----

    pub async fn put_blob(&self, blob: &Id16, data: &[u8], now: u64, max_total: u64) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        tx.execute("SELECT pg_advisory_xact_lock(7263002)", &[]).await.map_err(internal)?;
        tx.execute("DELETE FROM blobs WHERE expires_at<=$1", &[&(now as i64)]).await.map_err(internal)?;
        let total: i64 = tx.query_one("SELECT COALESCE(sum(size_bytes),0)::bigint FROM blobs", &[]).await.map_err(internal)?.get(0);
        if total as u64 + data.len() as u64 > max_total {
            return Err(ApiError::QueueFull);
        }
        let expires = round_up(now.saturating_add(BLOB_TTL_SECS));
        match tx
            .execute(
                "INSERT INTO blobs (blob_id, size_bytes, data, expires_at) VALUES ($1,$2,$3,$4)",
                &[&blob.0.as_slice(), &(data.len() as i64), &data, &expires],
            )
            .await
        {
            Err(e) if is_unique(&e) => return Err(ApiError::Conflict),
            r => r.map_err(internal)?,
        };
        tx.commit().await.map_err(internal)
    }

    pub async fn get_blob(&self, blob: &Id16, now: u64) -> Result<Option<Vec<u8>>, ApiError> {
        let c = self.conn().await?;
        let r = c
            .query_opt("SELECT data FROM blobs WHERE blob_id=$1 AND expires_at>$2", &[&blob.0.as_slice(), &(now as i64)])
            .await
            .map_err(internal)?;
        Ok(r.map(|r| r.get(0)))
    }

    // ---- replay protection and rate limiting (shared by all relay instances) ----

    /// Records a request nonce. `Err(Unauthorized)` if it was already used (replay).
    pub async fn use_nonce(&self, device: &Id16, nonce: &[u8; 16], expires: u64) -> Result<(), ApiError> {
        let c = self.conn().await?;
        let n = c
            .execute(
                "INSERT INTO request_nonces (device_id, nonce, expires_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&device.0.as_slice(), &nonce.as_slice(), &(expires as i64)],
            )
            .await
            .map_err(internal)?;
        if n == 0 {
            Err(ApiError::Unauthorized)
        } else {
            Ok(())
        }
    }

    pub async fn take_tokens(&self, key: &[u8; 16], cost: f64, cap: f64, rate: f64, now: u64) -> Result<bool, ApiError> {
        let c = self.conn().await?;
        let r = c
            .query_one("SELECT take_tokens($1,$2,$3,$4,$5)", &[&key.as_slice(), &cost, &cap, &rate, &(now as i64)])
            .await
            .map_err(internal)?;
        Ok(r.get(0))
    }

    pub async fn bucket_available(&self, key: &[u8; 16], cap: f64, rate: f64, now: u64) -> Result<bool, ApiError> {
        let c = self.conn().await?;
        let r =
            c.query_one("SELECT bucket_available($1,$2,$3,$4)", &[&key.as_slice(), &cap, &rate, &(now as i64)]).await.map_err(internal)?;
        Ok(r.get(0))
    }

    // ---- maintenance ----

    pub async fn purge(&self, now: u64) -> Result<(), ApiError> {
        let mut c = self.conn().await?;
        let tx = c.transaction().await.map_err(internal)?;
        let n = now as i64;
        tx.execute(
            "WITH d AS (DELETE FROM queue WHERE expires_at<=$1 RETURNING recipient, octet_length(ct)::bigint AS l),
                  a AS (SELECT recipient, count(*)::int AS c, sum(l)::bigint AS b FROM d GROUP BY recipient)
             UPDATE devices SET queued_count = devices.queued_count - a.c, queued_bytes = devices.queued_bytes - a.b
             FROM a WHERE devices.device_id = a.recipient",
            &[&n],
        )
        .await
        .map_err(internal)?;
        for sql in [
            "DELETE FROM seen WHERE expires_at<=$1",
            "DELETE FROM blobs WHERE expires_at<=$1",
            "DELETE FROM request_nonces WHERE expires_at<=$1",
            "DELETE FROM delivery_caps WHERE expires_at<=$1",
            "DELETE FROM rate_buckets WHERE updated<=$1::bigint - 86400",
        ] {
            tx.execute(sql, &[&n]).await.map_err(internal)?;
        }
        let day = (now / 86_400) as i32 - GROUP_IDLE_DAYS;
        tx.execute("DELETE FROM groups WHERE touched_day<=$1", &[&day]).await.map_err(internal)?;
        tx.commit().await.map_err(internal)
    }
}
