-- Idempotent uploads (ST-046): a client that retries an upload whose response was lost sends the SAME ciphertext again. The row remembers, for the uploader
-- (the hash of the device id or of the delivery capability) and the SHA-256 of the stored bytes, so that the retry gets the same blob id back instead of
-- creating a second, unreferenced copy. Nothing here is new information: the relay already stores the bytes and the capability hash.
ALTER TABLE blobs ADD COLUMN owner_hash bytea;
ALTER TABLE blobs ADD COLUMN body_hash bytea;
CREATE INDEX blobs_dedupe ON blobs (owner_hash, body_hash) WHERE owner_hash IS NOT NULL;
