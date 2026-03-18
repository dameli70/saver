-- ============================================================
--  Migration 035: Type B approbation windows (timing)
--
--  Adds approve_opens_at / approve_due_at to saving_room_rotation_windows
--  to control when Type B turn votes can be cast.
-- ============================================================

SET @has_approve_opens_at := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'approve_opens_at'
);

SET @sql := IF(
  @has_approve_opens_at = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN approve_opens_at DATETIME NULL AFTER rotation_index',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_approve_due_at := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND column_name = 'approve_due_at'
);

SET @sql := IF(
  @has_approve_due_at = 0,
  'ALTER TABLE saving_room_rotation_windows ADD COLUMN approve_due_at DATETIME NULL AFTER approve_opens_at',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_rotation_windows'
    AND index_name = 'idx_approve_due'
);

SET @sql := IF(
  @has_idx = 0,
  'ALTER TABLE saving_room_rotation_windows ADD INDEX idx_approve_due (approve_due_at)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
