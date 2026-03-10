-- Lock shares (link + shared secret)
-- v1: share is usable without accounts; server still enforces lock reveal_date.

CREATE TABLE IF NOT EXISTS lock_shares (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    lock_id              CHAR(36) NOT NULL,
    created_by_user_id   INT UNSIGNED NOT NULL,

    token_hash           CHAR(64) NOT NULL,

    -- Ciphertext encrypted in-browser using a key derived from the share secret.
    share_cipher_blob    MEDIUMTEXT NOT NULL,
    share_iv             VARCHAR(64) NOT NULL,
    share_auth_tag       VARCHAR(64) NOT NULL,
    share_kdf_salt       VARCHAR(64) NOT NULL,
    share_kdf_iterations INT UNSIGNED NOT NULL DEFAULT 310000,

    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at           DATETIME NULL,
    last_accessed_at     DATETIME NULL,

    UNIQUE KEY uniq_token (token_hash),
    INDEX idx_lock (lock_id),
    INDEX idx_creator (created_by_user_id),

    FOREIGN KEY (lock_id) REFERENCES locks(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
