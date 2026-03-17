-- Votes: ensure one vote per user (Type A votes use target_rotation_index=0)
--
-- MySQL UNIQUE indexes treat NULL as distinct, so the previous schema
-- (target_rotation_index NULL) allowed infinite Type A votes.
-- This migration normalizes NULL -> 0, deduplicates, and enforces NOT NULL DEFAULT 0.

SET @has_table := (
    SELECT COUNT(*)
    FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_unlock_votes'
);

SET @has_col := (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_unlock_votes'
      AND COLUMN_NAME = 'target_rotation_index'
);

-- Normalize NULL -> 0
SET @sql := IF(
    @has_table > 0 AND @has_col > 0,
    'UPDATE saving_room_unlock_votes SET target_rotation_index = 0 WHERE target_rotation_index IS NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Deduplicate any accidental duplicates (keep the newest row by id)
SET @sql := IF(
    @has_table > 0 AND @has_col > 0,
    'DELETE v1 FROM saving_room_unlock_votes v1\n     JOIN saving_room_unlock_votes v2\n       ON v2.room_id = v1.room_id\n      AND v2.user_id = v1.user_id\n      AND v2.scope = v1.scope\n      AND v2.target_rotation_index = v1.target_rotation_index\n      AND v2.id > v1.id',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Enforce NOT NULL DEFAULT 0
SET @is_nullable := (
    SELECT IS_NULLABLE
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_unlock_votes'
      AND COLUMN_NAME = 'target_rotation_index'
    LIMIT 1
);

SET @col_default := (
    SELECT COLUMN_DEFAULT
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'saving_room_unlock_votes'
      AND COLUMN_NAME = 'target_rotation_index'
    LIMIT 1
);

SET @sql := IF(
    @has_table > 0 AND @has_col > 0 AND (@is_nullable = 'YES' OR @col_default IS NULL),
    'ALTER TABLE saving_room_unlock_votes MODIFY target_rotation_index INT UNSIGNED NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
