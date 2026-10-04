-- Per-sender share of a recipient's queue (ST-031): a keyed pair hash HMAC-like SHA-256(pepper || "pair" || sender || recipient)[..16].
-- Without the relay's pepper it cannot be linked to a device id; it lives exactly as long as the queued envelope (deleted with it).
ALTER TABLE queue ADD COLUMN sender_h bytea;
CREATE INDEX queue_recipient_sender_h ON queue (recipient, sender_h);
