-- Private invitations (docs/INVITATIONS.md §5). The relay is an opaque mailbox for them:
--  * it never stores the invitation identifier itself, only SHA-256 of it (a database leak yields no usable identifier);
--  * the preview and every join request are ciphertext it cannot read (the preview key is derived from the link secret, which the relay never sees;
--    requests are encrypted to the issuing admin device);
--  * it enforces only what it can enforce without reading anything: expiry, a use counter, revocation, and who may poll/resolve/revoke.
CREATE TABLE invites (
    id_hash       bytea PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    issuer_device bytea NOT NULL REFERENCES devices (device_id) ON DELETE CASCADE,
    preview       bytea NOT NULL CHECK (octet_length(preview) BETWEEN 1 AND 4096),
    expires_at    bigint NOT NULL,
    max_uses      integer NOT NULL CHECK (max_uses BETWEEN 1 AND 100),
    used          integer NOT NULL DEFAULT 0 CHECK (used >= 0),
    revoked       boolean NOT NULL DEFAULT false,
    created_at    bigint NOT NULL
);
CREATE INDEX invites_issuer ON invites (issuer_device);
CREATE INDEX invites_expiry ON invites (expires_at);

CREATE TABLE invite_requests (
    request_id bytea PRIMARY KEY CHECK (octet_length(request_id) = 16),
    id_hash    bytea NOT NULL REFERENCES invites (id_hash) ON DELETE CASCADE,
    body       bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 32768),
    state      smallint NOT NULL DEFAULT 0 CHECK (state IN (0, 1, 2)), -- 0 pending, 1 approved, 2 rejected
    created_at bigint NOT NULL
);
CREATE INDEX invite_requests_invite ON invite_requests (id_hash, state);
