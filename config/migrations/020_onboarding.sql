-- Add onboarding completion marker (first-login setup page)

-- Split into a separate ALTER statement so the installer can safely ignore
-- "Duplicate column" errors and still apply missing pieces.
ALTER TABLE users
    ADD COLUMN onboarding_completed_at DATETIME NULL AFTER created_at;
