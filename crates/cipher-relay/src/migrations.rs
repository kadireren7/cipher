//! Forward-only SQL migrations with checksum verification.
//!
//! * Applied under a global advisory lock, so concurrent relay instances cannot race.
//! * Each migration runs in one transaction.
//! * Fail closed: an already-applied migration whose checksum no longer matches, or a database that
//!   is *ahead* of this binary, stops startup (no silent schema drift, no downgrade).
use crate::db::internal;
use crate::error::ApiError;
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};

pub const MIGRATIONS: &[(i32, &str, &str)] = &[
    (1, "init", include_str!("../migrations/0001_init.sql")),
    (2, "groups", include_str!("../migrations/0002_groups.sql")),
    (3, "group_seq", include_str!("../migrations/0003_group_seq.sql")),
    (4, "commit_idempotency", include_str!("../migrations/0004_commit_idempotency.sql")),
    (5, "sender_share", include_str!("../migrations/0005_sender_share.sql")),
    (6, "delivery_caps", include_str!("../migrations/0006_delivery_caps.sql")),
    (7, "intro_caps", include_str!("../migrations/0007_intro_caps.sql")),
    (8, "blob_caps", include_str!("../migrations/0008_blob_caps.sql")),
];

const LOCK_KEY: i64 = 0x6369_7068; // "ciph"

pub async fn run(pool: &Pool) -> Result<(), ApiError> {
    let mut c = pool.get().await.map_err(internal)?;
    c.execute("SELECT pg_advisory_lock($1)", &[&LOCK_KEY]).await.map_err(internal)?;
    let res = apply(&mut c).await;
    let _ = c.execute("SELECT pg_advisory_unlock($1)", &[&LOCK_KEY]).await;
    res
}

async fn apply(c: &mut deadpool_postgres::Object) -> Result<(), ApiError> {
    c.batch_execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, name text NOT NULL, checksum bytea NOT NULL)",
    )
    .await
    .map_err(internal)?;
    let rows = c.query("SELECT version, checksum FROM schema_migrations ORDER BY version", &[]).await.map_err(internal)?;
    let max_known = MIGRATIONS.iter().map(|m| m.0).max().unwrap_or(0);
    for r in &rows {
        let v: i32 = r.get(0);
        let sum: Vec<u8> = r.get(1);
        match MIGRATIONS.iter().find(|m| m.0 == v) {
            None if v > max_known => return Err(ApiError::Internal), // database is newer than this binary
            None => return Err(ApiError::Internal),
            Some((_, _, sql)) if Sha256::digest(sql.as_bytes()).as_slice() != sum.as_slice() => return Err(ApiError::Internal),
            Some(_) => {}
        }
    }
    let applied: Vec<i32> = rows.iter().map(|r| r.get::<_, i32>(0)).collect();
    for (v, name, sql) in MIGRATIONS {
        if applied.contains(v) {
            continue;
        }
        let tx = c.transaction().await.map_err(internal)?;
        tx.batch_execute(sql).await.map_err(internal)?;
        let sum = Sha256::digest(sql.as_bytes()).to_vec();
        tx.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)", &[v, name, &sum])
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        tracing::info!(version = *v, "migration applied");
    }
    Ok(())
}
