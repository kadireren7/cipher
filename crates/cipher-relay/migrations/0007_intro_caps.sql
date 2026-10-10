-- Intro capabilities (docs/MULTI_RELAY_PROTOCOL.md §4): a delivery capability that ALSO allows an unauthenticated visitor to read the issuer's
-- (self-authenticating) device records and to claim KeyPackages, so a contact from another relay can start a conversation without an account here.
ALTER TABLE delivery_caps ADD COLUMN intro boolean NOT NULL DEFAULT false;
