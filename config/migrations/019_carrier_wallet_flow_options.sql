-- ============================================================
--  Carrier wallet setup flow options
--
--  Adds per-carrier flags controlling which wallet setup actions
--  are allowed in the client (open dialer vs copy USSD).
-- ============================================================

-- Split into separate ALTER statements so the installer can safely
-- ignore "Duplicate column" errors and still apply any missing columns.
ALTER TABLE carriers
    ADD COLUMN wallet_allow_open_dialer TINYINT(1) NOT NULL DEFAULT 1 AFTER ussd_balance_template;

ALTER TABLE carriers
    ADD COLUMN wallet_allow_copy_ussd  TINYINT(1) NOT NULL DEFAULT 1 AFTER wallet_allow_open_dialer;

ALTER TABLE carriers
    ADD COLUMN wallet_default_action   ENUM('open_dialer','copy_ussd') NOT NULL DEFAULT 'open_dialer' AFTER wallet_allow_copy_ussd;
