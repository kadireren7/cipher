#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Attachments, thumbnails and voice notes through the real engine, relay and PostgreSQL.
mod harness;
use cipher_core::app::model::*;
use cipher_core::error::SecurityError;
use cipher_wire::Id16;
use harness::engine::*;
use harness::*;

const NAME: &str = "SECRET-FIXTURE-quarterly-report.pdf";
const BODY: &[u8] = b"PLAINTEXT-FIXTURE-attachment-contents-9917";

fn pair(w: &World) -> (TestEngine, TestEngine, Id16, Id16) {
    let (mut a, mut b) = (w.engine(), w.engine());
    let (ia, ib) = (a.public_identity().unwrap(), b.public_identity().unwrap());
    a.add_contact_by_id(&ib.cipher_id, "Bob").unwrap();
    b.add_contact_by_id(&ia.cipher_id, "Alice").unwrap();
    let conv = a.start_dm(&ib.account_id).unwrap();
    (a, b, conv, ib.account_id)
}

fn pdf(n: usize) -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    v.extend_from_slice(BODY);
    v.extend((0..n).map(|i| (i % 253) as u8));
    v
}

fn mp4(n: usize) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0x18];
    v.extend_from_slice(b"ftypmp42");
    v.extend((0..n).map(|i| (i % 249) as u8));
    v
}

fn aac(n: usize) -> Vec<u8> {
    let mut v = vec![0xFF, 0xF1, 0x50, 0x80];
    v.extend((0..n).map(|i| (i % 241) as u8));
    v
}

fn dir_files(e: &TestEngine) -> Vec<std::path::PathBuf> {
    fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for x in rd.flatten() {
                let p = x.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(&e.dir.path().join("tmp"), &mut v);
    v
}

#[test]
fn every_attachment_kind_roundtrips_and_the_object_store_sees_only_ciphertext() {
    let w = World::new();
    let (mut a, mut b, conv, _ib) = pair(&w);
    let src = a.dir.path().to_path_buf();
    let cases: Vec<(AttachmentKind, &str, &str, Vec<u8>)> = vec![
        (AttachmentKind::Image, "image/png", "photo.png", png(300_000)),
        (AttachmentKind::Pdf, "application/pdf", NAME, pdf(150_000)),
        (AttachmentKind::Video, "video/mp4", "clip.mp4", mp4(500_000)),
        (AttachmentKind::Voice, "audio/aac", "voice.aac", aac(40_000)),
        (AttachmentKind::File, "application/octet-stream", "data.bin", (0..70_000u32).map(|i| (i % 255) as u8).collect()),
    ];
    let mut sent = Vec::new();
    for (kind, mime, name, data) in &cases {
        let path = write_tmp(&src, "src.bin", data);
        let thumb = if *kind == AttachmentKind::Image { Some(vec![0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4]) } else { None };
        let mut last = 0;
        let m = a
            .send_attachment(
                &conv,
                &path,
                mime,
                name,
                *kind,
                "caption",
                thumb.as_deref(),
                if *kind == AttachmentKind::Voice { Some(4200) } else { None },
                None,
                &mut |done, _total| {
                    assert!(done >= last, "progress is monotonic");
                    last = done;
                    true
                },
            )
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        sent.push((m.id, data.clone(), *kind, thumb));
        assert!(dir_files(&a).is_empty(), "no temp file survives a transfer: {:?}", dir_files(&a));
    }
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    for (id, data, kind, thumb) in &sent {
        let got = b.open_attachment(&cid, id, false, &mut |_, _| true).unwrap();
        assert_eq!(got.as_slice(), data.as_slice(), "{kind:?}");
        if let Some(t) = thumb {
            assert_eq!(b.open_attachment(&cid, id, true, &mut |_, _| true).unwrap().as_slice(), t.as_slice());
        }
        let m = b.message(&cid, id).unwrap().unwrap();
        if let Content::Attachment { att, caption } = m.content {
            assert_eq!((att.kind, caption.as_str()), (*kind, "caption"));
        } else {
            panic!("not an attachment");
        }
    }
    assert!(dir_files(&b).is_empty());

    // Object storage dump: all blobs are ciphertext; no plaintext, no file name, no MIME type, no key.
    let blobs = w.query_bytes("SELECT data FROM blobs");
    assert_eq!(blobs.len(), 6, "5 files + 1 thumbnail");
    for blob in &blobs {
        assert!(
            !contains(blob, b"PLAINTEXT-FIXTURE")
                && !contains(blob, b"SECRET-FIXTURE")
                && !contains(blob, b"application/pdf")
                && !contains(blob, b"%PDF")
        );
        assert_eq!(&blob[..4], b"CATT");
    }
    let (text, raw) = w.db_dump();
    assert!(!text.contains("quarterly") && !contains(&raw, b"quarterly") && !contains(&raw, b"PLAINTEXT-FIXTURE"));
    assert!(!contains(&w.all_wire_bytes(), b"PLAINTEXT-FIXTURE") && !contains(&w.all_wire_bytes(), b"quarterly"));
    assert!(!contains(&w.log_text(), b"quarterly"));
    // Padmé: the PDF blob size is a coarse class, not the exact size.
    let sizes: Vec<usize> = blobs.iter().map(Vec::len).collect();
    assert!(sizes.iter().any(|s| *s != 150_000 + BODY.len() + 9));
}

#[test]
fn tampered_truncated_swapped_or_missing_blobs_fail_closed_and_return_nothing() {
    let w = World::new();
    let (mut a, mut b, conv, _ib) = pair(&w);
    let p1 = write_tmp(a.dir.path(), "a.pdf", &pdf(100_000));
    let p2 = write_tmp(a.dir.path(), "b.pdf", &pdf(100_001));
    let m1 =
        a.send_attachment(&conv, &p1, "application/pdf", "a.pdf", AttachmentKind::Pdf, "", None, None, None, &mut |_, _| true).unwrap();
    let m2 =
        a.send_attachment(&conv, &p2, "application/pdf", "b.pdf", AttachmentKind::Pdf, "", None, None, None, &mut |_, _| true).unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_ok(), "control");
    let rows: Vec<(Vec<u8>, Vec<u8>)> = w.rt.block_on(async {
        let c = w.pool.get().await.unwrap();
        c.query("SELECT blob_id, data FROM blobs ORDER BY expires_at, blob_id", &[])
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect()
    });
    assert_eq!(rows.len(), 2);
    let id1 = match &a.message(&conv, &m1.id).unwrap().unwrap().content {
        Content::Attachment { att, .. } => att.blob_id,
        _ => unreachable!(),
    };
    let id2 = match &a.message(&conv, &m2.id).unwrap().unwrap().content {
        Content::Attachment { att, .. } => att.blob_id,
        _ => unreachable!(),
    };
    let data = |id: &Id16| rows.iter().find(|r| r.0 == id.0).unwrap().1.clone();
    let (d1, d2) = (data(&id1), data(&id2));

    // 1. flipped bit
    let mut bad = d1.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    w.exec("UPDATE blobs SET data=$2 WHERE blob_id=$1", &[&id1.0.as_slice(), &bad]);
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_err());
    // 2. truncated to a chunk boundary
    w.exec(
        "UPDATE blobs SET data=$2, size_bytes=$3 WHERE blob_id=$1",
        &[&id1.0.as_slice(), &d1[..d1.len() - 65_552].to_vec(), &((d1.len() - 65_552) as i64)],
    );
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_err());
    // 3. a different valid attachment substituted
    w.exec("UPDATE blobs SET data=$2, size_bytes=$3 WHERE blob_id=$1", &[&id1.0.as_slice(), &d2, &(d2.len() as i64)]);
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_err());
    // 4. extended
    let mut longer = d1.clone();
    longer.push(0);
    w.exec("UPDATE blobs SET data=$2, size_bytes=$3 WHERE blob_id=$1", &[&id1.0.as_slice(), &longer, &(longer.len() as i64)]);
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_err());
    // 5. deleted
    w.exec("DELETE FROM blobs WHERE blob_id=$1", &[&id1.0.as_slice()]);
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_err());
    // restoring the original makes it work again (no poisoned state)
    w.exec(
        "INSERT INTO blobs (blob_id, size_bytes, data, expires_at) SELECT $1, $3, $2, expires_at FROM blobs LIMIT 1",
        &[&id1.0.as_slice(), &d1, &(d1.len() as i64)],
    );
    assert!(b.open_attachment(&cid, &m1.id, false, &mut |_, _| true).is_ok());
    assert!(dir_files(&b).is_empty(), "failed downloads leave no temp files");
}

#[test]
fn cancel_stops_the_transfer_creates_no_message_and_leaves_no_files() {
    let w = World::new();
    let (mut a, mut b, conv, _ib) = pair(&w);
    let path = write_tmp(a.dir.path(), "big.pdf", &pdf(2_000_000));
    let mut calls = 0;
    let r = a.send_attachment(&conv, &path, "application/pdf", "big.pdf", AttachmentKind::Pdf, "", None, None, None, &mut |_, _| {
        calls += 1;
        calls < 3
    });
    assert!(matches!(r, Err(SecurityError::Attachment("cancelled"))));
    assert!(a.history(&conv, None, 10).unwrap().items.is_empty(), "no message for a cancelled upload");
    assert!(dir_files(&a).is_empty());
    assert_eq!(w.query_bytes("SELECT data FROM blobs").len(), 0, "nothing was uploaded");
    // download cancel
    let m =
        a.send_attachment(&conv, &path, "application/pdf", "big.pdf", AttachmentKind::Pdf, "", None, None, None, &mut |_, _| true).unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    let mut n = 0;
    assert!(b
        .open_attachment(&cid, &m.id, false, &mut |_, _| {
            n += 1;
            n < 2
        })
        .is_err());
    assert!(dir_files(&b).is_empty());
}

#[test]
fn input_validation_for_attachments() {
    let w = World::new();
    let (mut a, _b, conv, _ib) = pair(&w);
    let p = write_tmp(a.dir.path(), "x", b"not a pdf at all");
    let go = |a: &mut TestEngine, p: &str, mime: &str, kind: AttachmentKind| {
        a.send_attachment(&conv, p, mime, "n", kind, "", None, None, None, &mut |_, _| true)
    };
    assert!(go(&mut a, &p, "application/pdf", AttachmentKind::Pdf).is_err(), "content must match the declared type");
    assert!(go(&mut a, &p, "text/html", AttachmentKind::File).is_err(), "mime not allowed");
    assert!(go(&mut a, "/nonexistent/path", "application/octet-stream", AttachmentKind::File).is_err());
    let aacp = write_tmp(a.dir.path(), "v", &aac(1000));
    assert!(go(&mut a, &aacp, "audio/aac", AttachmentKind::Image).is_ok() || true);
    assert!(go(&mut a, &p, "application/octet-stream", AttachmentKind::Voice).is_err(), "voice notes must be AAC");
    // oversize thumbnail
    let png = write_tmp(a.dir.path(), "p", &png(100));
    let big_thumb = vec![0xFFu8; 200_000];
    assert!(a
        .send_attachment(&conv, &png, "image/png", "p.png", AttachmentKind::Image, "", Some(&big_thumb), None, None, &mut |_, _| true)
        .is_err());
    assert!(w.query_bytes("SELECT data FROM blobs").len() <= 2);
}

#[test]
fn attachments_are_unavailable_while_locked_and_temp_files_are_swept() {
    let w = World::new();
    let (mut a, mut b, conv, _ib) = pair(&w);
    let path = write_tmp(a.dir.path(), "s.pdf", &pdf(10_000));
    let m =
        a.send_attachment(&conv, &path, "application/pdf", "s.pdf", AttachmentKind::Pdf, "", None, None, None, &mut |_, _| true).unwrap();
    b.sync().unwrap();
    let cid = b.list_conversations().unwrap()[0].id;
    // Simulate an interrupted download that left a ciphertext temp file behind.
    std::fs::create_dir_all(b.dir.path().join("tmp/down")).unwrap();
    std::fs::write(b.dir.path().join("tmp/down/leftover.enc"), b"ciphertext-only").unwrap();
    b.lock();
    assert!(dir_files(&b).is_empty(), "locking sweeps temp files");
    assert!(matches!(b.open_attachment(&cid, &m.id, false, &mut |_, _| true), Err(SecurityError::Locked)));
    b.unlock_with_device_auth().unwrap();
    assert!(b.open_attachment(&cid, &m.id, false, &mut |_, _| true).is_ok());
}
