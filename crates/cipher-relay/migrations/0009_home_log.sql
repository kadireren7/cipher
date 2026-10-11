-- Home-relay commit log for groups whose members live on different relays (docs/CROSS_RELAY_GROUPS.md §7). The relay stores an opaque tag, the
-- commits (MLS ciphertext it cannot read) and, per epoch, two PUBLIC keys that authenticate requests; it never learns members or accounts.
CREATE TABLE home_groups (
    tag         bytea   PRIMARY KEY,
    head_seq    bigint  NOT NULL,
    bytes       bigint  NOT NULL DEFAULT 0,
    touched_day integer NOT NULL
);
CREATE TABLE home_log (
    tag        bytea  NOT NULL REFERENCES home_groups (tag) ON DELETE CASCADE,
    seq        bigint NOT NULL,
    commit_id  bytea  NOT NULL,
    commit     bytea  NOT NULL,
    chain      bytea  NOT NULL,
    commit_pub bytea  NOT NULL,
    read_pub   bytea  NOT NULL,
    PRIMARY KEY (tag, seq)
);
CREATE INDEX home_groups_touched ON home_groups (touched_day);
