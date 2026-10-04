-- Delivery capabilities (docs/DELIVERY_CAPABILITIES.md). Only SHA-256(cap) is stored: a database leak does not yield usable capabilities.
CREATE TABLE delivery_caps (
    cap_hash   bytea PRIMARY KEY,
    device_id  bytea NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    expires_at bigint NOT NULL
);
CREATE INDEX delivery_caps_device ON delivery_caps (device_id);
-- lane 0 = OPEN (authenticated send without a capability), 1 = CAPABILITY, 2 = COMMIT/WELCOME (group sequencer)
ALTER TABLE queue ADD COLUMN lane smallint NOT NULL DEFAULT 0;
ALTER TABLE queue ADD COLUMN cap_hash bytea;
CREATE INDEX queue_lane ON queue (recipient, lane);
CREATE INDEX queue_cap_hash ON queue (cap_hash) WHERE cap_hash IS NOT NULL;
