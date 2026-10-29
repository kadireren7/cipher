-- Relay administration (docs/RELAY_ADMIN.md). Two small tables and nothing about users:
--  * relay_settings: operator switches (currently only `registration_open`);
--  * admin_audit: an append-only, hash-chained record of administrative CHANGES. Reads are not logged and no row can name a user, a device or a message.
CREATE TABLE relay_settings (
    key   text PRIMARY KEY CHECK (length(key) <= 64),
    value text NOT NULL CHECK (length(value) <= 256)
);

CREATE TABLE admin_audit (
    seq       bigserial PRIMARY KEY,
    at        bigint NOT NULL,
    action    text   NOT NULL CHECK (length(action) <= 64),
    detail    text   NOT NULL CHECK (length(detail) <= 256),
    prev_hash bytea  NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash      bytea  NOT NULL CHECK (octet_length(hash) = 32)
);

-- Append-only: the relay's own database role cannot rewrite history. (A database superuser still can; the hash chain makes that visible.)
CREATE FUNCTION admin_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'admin_audit is append-only';
END;
$$;
CREATE TRIGGER admin_audit_no_rewrite BEFORE UPDATE OR DELETE ON admin_audit FOR EACH ROW EXECUTE FUNCTION admin_audit_immutable();
