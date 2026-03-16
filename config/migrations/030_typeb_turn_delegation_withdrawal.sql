-- Type B: delegation + withdrawal confirmation + code view audit

-- Add delegation + withdrawal confirmation fields to rotation windows
SET @has_delegate_user_id := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'delegate_user_id'
);
SET @sql := IF(
  @has_delegate_user_id = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN delegate_user_id INT UNSIGNED NULL AFTER user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_delegate_set_at := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'delegate_set_at'
);
SET @sql := IF(
  @has_delegate_set_at = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN delegate_set_at DATETIME NULL AFTER delegate_user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_withdrawal_confirmed_at := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'withdrawal_confirmed_at'
);
SET @sql := IF(
  @has_withdrawal_confirmed_at = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN withdrawal_confirmed_at DATETIME NULL AFTER expires_at',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_withdrawal_confirmed_by_user_id := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'withdrawal_confirmed_by_user_id'
);
SET @sql := IF(
  @has_withdrawal_confirmed_by_user_id = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN withdrawal_confirmed_by_user_id INT UNSIGNED NULL AFTER withdrawal_confirmed_at',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_withdrawal_reference := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'withdrawal_reference'
);
SET @sql := IF(
  @has_withdrawal_reference = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN withdrawal_reference VARCHAR(120) NULL AFTER withdrawal_confirmed_by_user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_withdrawal_confirmed_role := (
  SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'withdrawal_confirmed_role'
);
SET @sql := IF(
  @has_withdrawal_confirmed_role = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN withdrawal_confirmed_role VARCHAR(20) NULL AFTER withdrawal_reference',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Optional indexes for new columns
SET @has_idx_delegate := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND index_name = 'idx_delegate'
);
SET @sql := IF(
  @has_idx_delegate = 0,
  'ALTER TABLE saving_room_rotation_windows ADD INDEX idx_delegate (delegate_user_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx_withdraw_confirm := (
  SELECT COUNT(*) FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND index_name = 'idx_withdraw_confirm'
);
SET @sql := IF(
  @has_idx_withdraw_confirm = 0,
  'ALTER TABLE saving_room_rotation_windows ADD INDEX idx_withdraw_confirm (withdrawal_confirmed_at)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Code view audit (who accessed the code, when, and in which role)
CREATE TABLE IF NOT EXISTS saving_room_turn_code_views (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  room_id         CHAR(36) NOT NULL,
  rotation_index  INT UNSIGNED NOT NULL,
  viewer_user_id  INT UNSIGNED NOT NULL,
  viewer_role     VARCHAR(20) NOT NULL,
  viewed_at       DATETIME DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uniq_view (room_id, rotation_index, viewer_user_id),
  INDEX idx_room_rotation (room_id, rotation_index),
  INDEX idx_viewer_time (viewer_user_id, viewed_at),

  FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (viewer_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
