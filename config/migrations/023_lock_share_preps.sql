-- ============================================================
--  Migration 023: lock_share_preps
--
--  Stores per-lock, precomputed share ciphertext + a vault-wrapped
--  share secret, allowing users to create share links even while
--  the lock is still sealed (without needing plaintext).
-- ============================================================

CREATE TABLE IF NOT EXISTS lock_share_preps (
    lock_id                 CHAR(36) PRIMARY KEY,
    user_id                 INT UNSIGNED NOT NULL,

    -- Share secret wrapped with a key derived from the user's vault passphrase
    -- (so the server never knows the share secret).
    share_secret_cipher_blob TEXT NOT NULL,
    share_secret_iv          VARCHAR(64) NOT NULL,
    share_secret_auth_tag    VARCHAR(64) NOT NULL,
    share_secret_kdf_salt    VARCHAR(64) NOT NULL,
    share_secret_kdf_iterations INT UNSIGNED NOT NULL DEFAULT 310000,

    -- Ciphertext encrypted with a key derived from the share secret.
    share_cipher_blob        MEDIUMTEXT NOT NULL,
    share_iv                 VARCHAR(64) NOT NULL,
    share_auth_tag           VARCHAR(64) NOT NULL,
    share_kdf_salt           VARCHAR(64) NOT NULL,
    share_kdf_iterations     INT UNSIGNED NOT NULL DEFAULT 310000,

    created_at               DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (lock_id) REFERENCES locks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user (user_id)
) ENGINE=InnoDB;
