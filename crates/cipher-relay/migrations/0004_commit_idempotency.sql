-- Idempotent group commits: a committer whose response was lost re-sends the SAME request and must learn that it was accepted
-- (otherwise its MLS state diverges from the group's). Only the first delivery's random message id and the epoch it consumed are kept.
ALTER TABLE groups ADD COLUMN last_mid bytea;
ALTER TABLE groups ADD COLUMN last_from bigint;
