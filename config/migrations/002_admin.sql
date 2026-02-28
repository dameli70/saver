-- Add super-admin support

ALTER TABLE users
    ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0 AFTER verification_sent_at,
    ADD INDEX idx_is_admin (is_admin);
