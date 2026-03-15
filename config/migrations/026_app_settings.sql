-- ============================================================
--  Migration 026: app settings (singleton)
--
--  Stores application-wide settings in a singleton row (id=1).
--  Currently used for the app logo, stored encrypted server-side (AES-256-GCM).
-- ============================================================

CREATE TABLE IF NOT EXISTS app_settings (
    id               TINYINT UNSIGNED PRIMARY KEY,

    logo_content_type VARCHAR(50) NULL,
    logo_enc_cipher   LONGBLOB NULL,
    logo_iv           VARBINARY(16) NULL,
    logo_tag          VARBINARY(16) NULL,
    logo_updated_at   DATETIME NULL
) ENGINE=InnoDB;

INSERT IGNORE INTO app_settings (id) VALUES (1);
