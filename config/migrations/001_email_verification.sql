-- Add email verification fields to existing installs

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" / "Duplicate index" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN email_verified_at DATETIME NULL AFTER vault_verifier_salt;

ALTER TABLE users
    ADD COLUMN email_verification_hash CHAR(64) NULL AFTER email_verified_at;

ALTER TABLE users
    ADD COLUMN email_verification_expires_at DATETIME NULL AFTER email_verification_hash;

ALTER TABLE users
    ADD COLUMN verification_sent_at DATETIME NULL AFTER email_verification_expires_at;

ALTER TABLE users
    ADD INDEX idx_email_verification_hash (email_verification_hash);
