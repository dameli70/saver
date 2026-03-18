-- ============================================================
--  Migration 036: Exit request reason + maker replacement
--
--  - saving_rooms.platform_controlled
--  - saving_room_exit_requests.reason
--  - saving_room_exit_requests.replacement_maker_user_id
-- ============================================================

-- saving_rooms.platform_controlled
SET @has_platform_controlled := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_rooms'
    AND column_name = 'platform_controlled'
);

SET @sql := IF(
  @has_platform_controlled = 0,
  'ALTER TABLE saving_rooms ADD COLUMN platform_controlled TINYINT(1) NOT NULL DEFAULT 0 AFTER maker_user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- saving_room_exit_requests.reason
SET @has_reason := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_exit_requests'
    AND column_name = 'reason'
);

SET @sql := IF(
  @has_reason = 0,
  'ALTER TABLE saving_room_exit_requests ADD COLUMN reason VARCHAR(500) NOT NULL DEFAULT '''''' AFTER requested_by_user_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_rep_idx := (
  SELECT COUNT(*)
  FROM information_schema.statistics
  WHERE table_schema = DATABASE()
    AND table_name = 'saving_room_exit_requests'
    AND index_name = 'idx_replacement_maker'
);

SET @sql := IF(
  @has_rep_idx = 0,
  'ALTER TABLE saving_room_exit_requests ADD INDEX idx_replacement_maker (replacement_maker_user_id)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_fk := (
  SELECT COUNT(*)
  FROM information_schema.table_constraints
  WHERE constraint_schema = DATABASE()
    AND table_name = 'saving_room_exit_requests'
    AND constraint_type = 'FOREIGN KEY'
    AND constraint_name = 'fk_exit_replacement_maker'
);

SET @sql := IF(
  @has_fk = 0,
  'ALTER TABLE saving_room_exit_requests ADD CONSTRAINT fk_exit_replacement_maker FOREIGN KEY (replacement_maker_user_id) REFERENCES users(id) ON DELETE SET NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
