-- Add super-admin support

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" / "Duplicate index" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER verification_sent_at;

ALTER TABLE users
    ADD INDEX idx_is_admin (is_admin);
