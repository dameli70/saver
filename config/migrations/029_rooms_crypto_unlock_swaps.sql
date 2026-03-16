-- Rooms: crypto destination accounts + per-room unlock code rotation + swap window/slot swaps
--
-- Requirements implemented:
-- 1) Extend platform_destination_accounts.account_type with 'crypto_wallet' and add crypto fields.
-- 2) Move unlock code + rotation metadata from platform_destination_accounts to saving_room_accounts (per-room).
--    Includes backfill from existing platform_destination_accounts fields.
-- 3) Add room_state='swap_window', swap_window_ends_at, slot swap table, and slot lock metadata.

-- ───────────────────────────────────────────────────────────
-- 1) platform_destination_accounts: crypto wallet support
-- ───────────────────────────────────────────────────────────
SET @has_crypto_type := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'account_type'
      AND COLUMN_TYPE LIKE '%\'crypto_wallet\'%'
);
SET @sql := IF(
    @has_crypto_type = 0,
    'ALTER TABLE platform_destination_accounts MODIFY account_type ENUM(''mobile_money'',''bank'',''crypto_wallet'') NOT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_display_label := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'display_label'
);
SET @sql := IF(
    @has_display_label = 0,
    'ALTER TABLE platform_destination_accounts ADD COLUMN display_label VARCHAR(120) NULL AFTER account_type',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_crypto_network := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'crypto_network'
);
SET @sql := IF(
    @has_crypto_network = 0,
    'ALTER TABLE platform_destination_accounts ADD COLUMN crypto_network VARCHAR(64) NULL AFTER bank_iban',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_crypto_address := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'crypto_address'
);
SET @sql := IF(
    @has_crypto_address = 0,
    'ALTER TABLE platform_destination_accounts ADD COLUMN crypto_address VARCHAR(180) NULL AFTER crypto_network',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ───────────────────────────────────────────────────────────
-- 2) Per-room unlock code rotation: move code fields to saving_room_accounts
-- ───────────────────────────────────────────────────────────
SET @sra_has_unlock_code := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_accounts'
      AND COLUMN_NAME = 'unlock_code_enc'
);
SET @sql := IF(
    @sra_has_unlock_code = 0,
    'ALTER TABLE saving_room_accounts ADD COLUMN unlock_code_enc TEXT NULL AFTER account_id',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sra_has_code_rotated_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_accounts'
      AND COLUMN_NAME = 'code_rotated_at'
);
SET @sql := IF(
    @sra_has_code_rotated_at = 0,
    'ALTER TABLE saving_room_accounts ADD COLUMN code_rotated_at DATETIME NULL AFTER unlock_code_enc',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sra_has_code_rotation_version := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_accounts'
      AND COLUMN_NAME = 'code_rotation_version'
);
SET @sql := IF(
    @sra_has_code_rotation_version = 0,
    'ALTER TABLE saving_room_accounts ADD COLUMN code_rotation_version INT UNSIGNED NOT NULL DEFAULT 1 AFTER code_rotated_at',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @sra_has_updated_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_accounts'
      AND COLUMN_NAME = 'updated_at'
);
SET @sql := IF(
    @sra_has_updated_at = 0,
    'ALTER TABLE saving_room_accounts ADD COLUMN updated_at DATETIME NULL AFTER created_at',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Backfill: copy existing code fields from platform_destination_accounts into saving_room_accounts
-- Only runs if the legacy columns exist.
SET @pda_has_unlock_code := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'unlock_code_enc'
);
SET @sql := IF(
    @pda_has_unlock_code > 0,
    'UPDATE saving_room_accounts sra\n     JOIN platform_destination_accounts pda ON pda.id = sra.account_id\n     SET sra.unlock_code_enc = COALESCE(sra.unlock_code_enc, pda.unlock_code_enc),\n         sra.code_rotated_at = COALESCE(sra.code_rotated_at, pda.code_rotated_at),\n         sra.code_rotation_version = COALESCE(sra.code_rotation_version, pda.code_rotation_version),\n         sra.updated_at = COALESCE(sra.updated_at, NOW())\n     WHERE sra.unlock_code_enc IS NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Drop legacy unlock code fields from platform_destination_accounts (after backfill)
SET @has_pda_unlock_code := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'unlock_code_enc'
);
SET @sql := IF(
    @has_pda_unlock_code > 0,
    'ALTER TABLE platform_destination_accounts DROP COLUMN unlock_code_enc',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_pda_code_rotated_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'code_rotated_at'
);
SET @sql := IF(
    @has_pda_code_rotated_at > 0,
    'ALTER TABLE platform_destination_accounts DROP COLUMN code_rotated_at',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_pda_code_rotation_version := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'platform_destination_accounts'
      AND COLUMN_NAME = 'code_rotation_version'
);
SET @sql := IF(
    @has_pda_code_rotation_version > 0,
    'ALTER TABLE platform_destination_accounts DROP COLUMN code_rotation_version',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- ───────────────────────────────────────────────────────────
-- 3) Swap window state + slots
-- ───────────────────────────────────────────────────────────
SET @has_swap_window_state := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_rooms'
      AND COLUMN_NAME = 'room_state'
      AND COLUMN_TYPE LIKE '%\'swap_window\'%'
);
SET @sql := IF(
    @has_swap_window_state = 0,
    'ALTER TABLE saving_rooms MODIFY room_state ENUM(''lobby'',''swap_window'',''active'',''closed'',''cancelled'') NOT NULL DEFAULT ''lobby''',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_swap_window_ends_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_rooms'
      AND COLUMN_NAME = 'swap_window_ends_at'
);
SET @sql := IF(
    @has_swap_window_ends_at = 0,
    'ALTER TABLE saving_rooms ADD COLUMN swap_window_ends_at DATETIME NULL AFTER room_state',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS saving_room_slot_swaps (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id      CHAR(36) NOT NULL,
    from_user_id INT UNSIGNED NOT NULL,
    to_user_id   INT UNSIGNED NOT NULL,

    status       ENUM('pending','accepted','declined','expired','cancelled') NOT NULL DEFAULT 'pending',
    expires_at   DATETIME NOT NULL,

    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME NULL,
    updated_at   DATETIME NULL,

    INDEX idx_room_status (room_id, status),
    INDEX idx_from_status (from_user_id, status),
    INDEX idx_to_status (to_user_id, status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Ensure responded_at exists if the table pre-existed (CREATE TABLE IF NOT EXISTS does not add new columns).
SET @has_slot_swaps_responded_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_slot_swaps'
      AND COLUMN_NAME = 'responded_at'
);
SET @sql := IF(
    @has_slot_swaps_responded_at = 0,
    'ALTER TABLE saving_room_slot_swaps ADD COLUMN responded_at DATETIME NULL AFTER created_at',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @has_slot_locked_at := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_rotation_queue'
      AND COLUMN_NAME = 'slot_locked_at'
);
SET @sql := IF(
    @has_slot_locked_at = 0,
    'ALTER TABLE saving_room_rotation_queue ADD COLUMN slot_locked_at DATETIME NULL AFTER status',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
