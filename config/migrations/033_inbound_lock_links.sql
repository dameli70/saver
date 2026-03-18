-- Inbound lock links (recipient-wrapped inbound secret)
--
-- Adds:
--  - inbound_lock_links table
--  - locks.inbound_link_id (nullable FK)

CREATE TABLE IF NOT EXISTS inbound_lock_links (
  id                  CHAR(36) PRIMARY KEY,
  user_id             INT UNSIGNED NOT NULL,
  token_hash          CHAR(64) NOT NULL,

  mode                ENUM('recipient_sets_date','sender_sets_date') NOT NULL,
  reveal_date_fixed   DATETIME NULL,

  max_uses            INT UNSIGNED NOT NULL DEFAULT 1,
  uses_count          INT UNSIGNED NOT NULL DEFAULT 0,

  expires_at          DATETIME NULL,
  revoked_at          DATETIME NULL,
  created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,

  -- Secret wrapped/encrypted under the recipient vault
  secret_cipher_blob  TEXT NOT NULL,
  secret_iv           VARCHAR(64) NOT NULL,
  secret_auth_tag     VARCHAR(64) NOT NULL,
  secret_kdf_salt     VARCHAR(64) NOT NULL,
  secret_kdf_iterations INT UNSIGNED NOT NULL DEFAULT 310000,

  UNIQUE KEY uniq_token (token_hash),
  INDEX idx_user (user_id),

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Add locks.inbound_link_id (nullable)
SET @has_inbound_link_id := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'locks'
    AND column_name = 'inbound_link_id'
);
SET @sql := IF(
  @has_inbound_link_id = 0,
  'ALTER TABLE locks ADD COLUMN inbound_link_id CHAR(36) NULL AFTER user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Optional index for inbound link lookups
SET @has_idx_inbound_link := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'locks'
    AND index_name = 'idx_inbound_link'
);
SET @sql := IF(
  @has_idx_inbound_link = 0,
  'ALTER TABLE locks ADD INDEX idx_inbound_link (inbound_link_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Optional FK constraint (locks.inbound_link_id → inbound_lock_links.id)
SET @has_fk_inbound_link := (
  SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE
  WHERE table_schema = DATABASE()
    AND table_name = 'locks'
    AND column_name = 'inbound_link_id'
    AND referenced_table_name = 'inbound_lock_links'
    AND referenced_column_name = 'id'
);
SET @sql := IF(
  @has_fk_inbound_link = 0,
  'ALTER TABLE locks ADD CONSTRAINT fk_locks_inbound_link FOREIGN KEY (inbound_link_id) REFERENCES inbound_lock_links(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
