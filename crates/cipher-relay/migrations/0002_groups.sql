-- Group epoch sequencer. The relay orders commits for LIVENESS only; it learns a random routing tag and an
-- epoch counter, never membership. `touched_day` is coarse (days since epoch) and used only for garbage collection.
CREATE TABLE groups (
    tag         bytea   PRIMARY KEY CHECK (octet_length(tag) = 16),
    epoch       bigint  NOT NULL CHECK (epoch >= 0),
    retired     boolean NOT NULL DEFAULT false,
    touched_day integer NOT NULL
);
CREATE INDEX groups_by_touched ON groups (touched_day);
