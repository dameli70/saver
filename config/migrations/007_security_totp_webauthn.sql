-- Personal-use security hardening
--
-- Adds:
--  - TOTP 2FA (users.totp_secret_enc, users.totp_enabled_at)
--  - WebAuthn / passkeys (webauthn_credentials)
--  - vault_active_slot (tracks which vault slot to use for new codes; not secret)

ALTER TABLE users ADD COLUMN totp_secret_enc TEXT NULL;
ALTER TABLE users ADD COLUMN totp_enabled_at DATETIME NULL;

ALTER TABLE users ADD COLUMN vault_active_slot TINYINT(1) NOT NULL DEFAULT 1;

ALTER TABLE users ADD COLUMN require_webauthn TINYINT(1) NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED NOT NULL,
    credential_id   VARBINARY(255) NOT NULL,
    public_key_pem  TEXT NOT NULL,
    sign_count      INT UNSIGNED NOT NULL DEFAULT 0,
    label           VARCHAR(255) NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME NULL,

    UNIQUE KEY uniq_cred (credential_id),
    INDEX idx_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
