-- ============================================================
--  Migration 028: KYC + user addresses
--
--  Adds users.address_* fields and introduces:
--   - kyc_submissions (one per user)
--   - kyc_documents (encrypted at rest; AES-256-GCM)
-- ============================================================

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN address_line1 VARCHAR(255) NULL;

ALTER TABLE users
    ADD COLUMN address_line2 VARCHAR(255) NULL;

ALTER TABLE users
    ADD COLUMN address_city VARCHAR(120) NULL;

ALTER TABLE users
    ADD COLUMN address_region VARCHAR(120) NULL;

ALTER TABLE users
    ADD COLUMN address_postal_code VARCHAR(32) NULL;

ALTER TABLE users
    ADD COLUMN address_country VARCHAR(64) NULL;

CREATE TABLE IF NOT EXISTS kyc_submissions (
    id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id            INT UNSIGNED NOT NULL UNIQUE,
    status             ENUM('draft','submitted','approved','rejected') NOT NULL DEFAULT 'draft',

    admin_note         VARCHAR(500) NULL,

    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at       DATETIME NULL,
    decided_at         DATETIME NULL,
    decided_by_user_id INT UNSIGNED NULL,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_status (status),
    INDEX idx_submitted (submitted_at),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (decided_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS kyc_documents (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    submission_id     INT UNSIGNED NOT NULL,
    user_id           INT UNSIGNED NOT NULL,

    doc_kind          VARCHAR(50) NULL,
    original_filename VARCHAR(255) NULL,
    content_type      VARCHAR(100) NOT NULL,
    size_bytes        INT UNSIGNED NOT NULL,
    sha256            VARBINARY(32) NOT NULL,

    enc_cipher        LONGBLOB NOT NULL,
    iv                VARBINARY(16) NOT NULL,
    tag               VARBINARY(16) NOT NULL,

    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_submission (submission_id),
    INDEX idx_user (user_id),

    FOREIGN KEY (submission_id) REFERENCES kyc_submissions(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
