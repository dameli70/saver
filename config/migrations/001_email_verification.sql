-- Add email verification fields to existing installs

ALTER TABLE users
    ADD COLUMN email_verified_at DATETIME NULL AFTER vault_verifier_salt,
    ADD COLUMN email_verification_hash CHAR(64) NULL AFTER email_verified_at,
    ADD COLUMN email_verification_expires_at DATETIME NULL AFTER email_verification_hash,
    ADD COLUMN verification_sent_at DATETIME NULL AFTER email_verification_expires_at,
    ADD INDEX idx_email_verification_hash (email_verification_hash);
