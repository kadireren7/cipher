-- Commit/welcome deliveries carry the sequencer position so clients know exactly which commits they processed.
ALTER TABLE queue ADD COLUMN group_seq bigint;
