-- Support vault passphrase rotation without breaking locked codes
--
-- Strategy:
--  - users keeps a primary verifier (vault_verifier*) and an optional alt verifier (vault_verifier_alt*)
--  - each lock records which verifier slot its ciphertext expects (vault_verifier_slot)

ALTER TABLE users ADD COLUMN vault_verifier_alt VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN vault_verifier_alt_salt CHAR(64) NULL;
ALTER TABLE users ADD COLUMN vault_verifier_alt_set_at DATETIME NULL;

ALTER TABLE locks ADD COLUMN vault_verifier_slot TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE locks ADD INDEX idx_vault_verifier_slot (vault_verifier_slot);
