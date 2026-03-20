-- ============================================================
--  Migration 039: user contact fields
--
--  Adds optional user profile fields:
--   - users.neighborhood
--   - users.phone_primary
--   - users.phone_secondary
-- ============================================================

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN neighborhood VARCHAR(120) NULL;

ALTER TABLE users
    ADD COLUMN phone_primary VARCHAR(30) NULL;

ALTER TABLE users
    ADD COLUMN phone_secondary VARCHAR(30) NULL;
