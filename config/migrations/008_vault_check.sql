-- Vault passphrase check blob (zero-knowledge)
--
-- Stores an encrypted constant so the browser can verify the user entered the
-- correct vault passphrase even before any codes exist.
-- The passphrase itself is NEVER stored.

ALTER TABLE users ADD COLUMN vault_check_cipher TEXT NULL;
ALTER TABLE users ADD COLUMN vault_check_iv VARCHAR(64) NULL;
ALTER TABLE users ADD COLUMN vault_check_auth_tag VARCHAR(64) NULL;
ALTER TABLE users ADD COLUMN vault_check_salt VARCHAR(64) NULL;
ALTER TABLE users ADD COLUMN vault_check_iterations INT UNSIGNED NOT NULL DEFAULT 310000;
ALTER TABLE users ADD COLUMN vault_check_set_at DATETIME NULL;
