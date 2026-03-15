-- ============================================================
--  Migration 024: user profile fields
--
--  Adds optional profile fields for room display privacy:
--   - users.room_display_name
--   - users.profile_image_url
-- ============================================================

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN room_display_name VARCHAR(60) NULL AFTER email;

ALTER TABLE users
    ADD COLUMN profile_image_url VARCHAR(500) NULL AFTER room_display_name;
