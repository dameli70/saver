-- Last used 2FA / authenticator hint
--
-- Adds:
--  - users.last_2fa_method
--  - users.last_2fa_provider

ALTER TABLE users ADD COLUMN last_2fa_method VARCHAR(32) NULL;
ALTER TABLE users ADD COLUMN last_2fa_provider VARCHAR(255) NULL;
