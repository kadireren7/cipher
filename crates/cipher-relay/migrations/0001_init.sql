-- Relay schema v1. Public keys, opaque ciphertext, expiry. No sender, no plaintext, no IPs.
CREATE TABLE accounts (
    account_id bytea PRIMARY KEY CHECK (octet_length(account_id) = 16)
);

CREATE TABLE devices (
    device_id       bytea PRIMARY KEY CHECK (octet_length(device_id) = 16),
    account_id      bytea NOT NULL REFERENCES accounts (account_id),
    identity_key    bytea NOT NULL CHECK (octet_length(identity_key) = 32),
    auth_key        bytea NOT NULL CHECK (octet_length(auth_key) = 32),
    binding_sig     bytea NOT NULL CHECK (octet_length(binding_sig) = 64),
    endorser        bytea CHECK (endorser IS NULL OR octet_length(endorser) = 16),
    endorsement_sig bytea CHECK (endorsement_sig IS NULL OR octet_length(endorsement_sig) = 64),
    push_token      text CHECK (push_token IS NULL OR length(push_token) <= 512),
    -- O(1) queue bound checks; maintained transactionally.
    queued_count    integer NOT NULL DEFAULT 0 CHECK (queued_count >= 0),
    queued_bytes    bigint  NOT NULL DEFAULT 0 CHECK (queued_bytes >= 0),
    ord             bigserial
);
CREATE INDEX devices_by_account ON devices (account_id, ord);

CREATE TABLE key_packages (
    id        bigserial PRIMARY KEY,
    device_id bytea NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    kp        bytea NOT NULL CHECK (octet_length(kp) BETWEEN 1 AND 8192)
);
CREATE INDEX key_packages_by_device ON key_packages (device_id, id);

CREATE TABLE queue (
    seq        bigserial PRIMARY KEY,
    recipient  bytea  NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    message_id bytea  NOT NULL CHECK (octet_length(message_id) = 16),
    ct         bytea  NOT NULL CHECK (octet_length(ct) BETWEEN 1 AND 262144),
    expires_at bigint NOT NULL,
    UNIQUE (recipient, message_id)
);
CREATE INDEX queue_by_recipient ON queue (recipient, seq);
CREATE INDEX queue_by_expiry ON queue (expires_at);

-- Idempotency tombstones: survive acknowledgement until the TTL window closes.
CREATE TABLE seen (
    recipient  bytea  NOT NULL,
    message_id bytea  NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (recipient, message_id)
);
CREATE INDEX seen_by_expiry ON seen (expires_at);

CREATE TABLE blobs (
    blob_id    bytea  PRIMARY KEY CHECK (octet_length(blob_id) = 16),
    size_bytes bigint NOT NULL,
    data       bytea  NOT NULL,
    expires_at bigint NOT NULL
);
CREATE INDEX blobs_by_expiry ON blobs (expires_at);

-- Distributed replay protection for signed requests (shared by all relay instances).
CREATE TABLE request_nonces (
    device_id  bytea  NOT NULL,
    nonce      bytea  NOT NULL,
    expires_at bigint NOT NULL,
    PRIMARY KEY (device_id, nonce)
);
CREATE INDEX request_nonces_by_expiry ON request_nonces (expires_at);

-- Distributed token buckets. `key` is a peppered hash: IPs/device ids are not stored.
CREATE TABLE rate_buckets (
    key     bytea PRIMARY KEY CHECK (octet_length(key) = 16),
    tokens  double precision NOT NULL,
    updated bigint NOT NULL
);
CREATE INDEX rate_buckets_by_updated ON rate_buckets (updated);

-- Atomic token-bucket take. Does not consume when denied. Safe under concurrency (row lock).
CREATE FUNCTION take_tokens(k bytea, cost double precision, cap double precision, rate double precision, now_s bigint)
RETURNS boolean AS $$
DECLARE cur double precision; upd bigint;
BEGIN
    INSERT INTO rate_buckets (key, tokens, updated) VALUES (k, cap, now_s) ON CONFLICT (key) DO NOTHING;
    SELECT tokens, updated INTO cur, upd FROM rate_buckets WHERE key = k FOR UPDATE;
    cur := LEAST(cap, cur + GREATEST(now_s - upd, 0) * rate);
    IF cur >= cost THEN
        UPDATE rate_buckets SET tokens = cur - cost, updated = now_s WHERE key = k;
        RETURN true;
    END IF;
    UPDATE rate_buckets SET tokens = cur, updated = now_s WHERE key = k;
    RETURN false;
END
$$ LANGUAGE plpgsql;

CREATE FUNCTION bucket_available(k bytea, cap double precision, rate double precision, now_s bigint)
RETURNS boolean AS $$
    SELECT COALESCE((SELECT LEAST(cap, tokens + GREATEST(now_s - updated, 0) * rate) >= 1 FROM rate_buckets WHERE key = k), true)
$$ LANGUAGE sql STABLE;
