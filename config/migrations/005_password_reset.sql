-- Add password reset fields (email-based login password recovery)

ALTER TABLE users ADD COLUMN password_reset_hash CHAR(64) NULL;
ALTER TABLE users ADD COLUMN password_reset_expires_at DATETIME NULL;
ALTER TABLE users ADD COLUMN password_reset_sent_at DATETIME NULL;
ALTER TABLE users ADD INDEX idx_password_reset_hash (password_reset_hash);
