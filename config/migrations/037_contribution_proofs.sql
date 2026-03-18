-- ============================================================
--  Migration 037: Saving room contribution proofs (encrypted)
--
--  Adds saving_room_contribution_proofs to store encrypted
--  image screenshots as proof of contribution.
--  AES-256-GCM at rest (server-side key, like KYC docs).
-- ============================================================

CREATE TABLE IF NOT EXISTS saving_room_contribution_proofs (
    id                 BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id            CHAR(36) NOT NULL,
    contribution_id    INT UNSIGNED NOT NULL,
    user_id            INT UNSIGNED NOT NULL,

    reference_snapshot VARCHAR(120) NULL,

    original_filename  VARCHAR(255) NULL,
    content_type       VARCHAR(100) NOT NULL,
    size_bytes         INT UNSIGNED NOT NULL,
    sha256             VARBINARY(32) NOT NULL,

    enc_cipher         LONGBLOB NOT NULL,
    iv                 VARBINARY(16) NOT NULL,
    tag                VARBINARY(16) NOT NULL,

    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_room (room_id),
    INDEX idx_contribution (contribution_id),
    INDEX idx_user (user_id),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (contribution_id) REFERENCES saving_room_contributions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
