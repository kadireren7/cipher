-- Capability-gated blob upload (docs/MULTI_RELAY_PROTOCOL.md §10): a contact on another relay stores an (already encrypted) attachment in the recipient's
-- mailbox relay under the recipient's delivery capability. The row remembers only the capability HASH, to enforce a per-capability storage quota.
ALTER TABLE blobs ADD COLUMN cap_hash bytea;
CREATE INDEX blobs_by_cap ON blobs (cap_hash) WHERE cap_hash IS NOT NULL;
