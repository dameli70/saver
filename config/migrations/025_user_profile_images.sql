-- ============================================================
--  Migration 025: encrypted profile images
--
--  Stores user avatar images encrypted server-side (AES-256-GCM)
--  so images never sit in plaintext at rest.
-- ============================================================

CREATE TABLE IF NOT EXISTS user_profile_images (
    user_id      INT UNSIGNED PRIMARY KEY,
    content_type VARCHAR(50) NOT NULL,
    enc_cipher   LONGBLOB NOT NULL,
    iv           VARBINARY(16) NOT NULL,
    tag          VARBINARY(16) NOT NULL,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
