-- ============================================================
--  Default Mobile Money carrier templates (inactive)
--
--  These are starter rows to help admins quickly configure
--  wallet templates in the Admin UI.
--
--  IMPORTANT:
--  - They are inserted as inactive (is_active=0)
--  - USSD templates are left blank and MUST be configured
--    by an admin before users can select them.
-- ============================================================

-- Mixx by YAS (Togo)
INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at)
SELECT 'Mixx by YAS', 'TG', 'numeric', 4, '', '', 0, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM carriers WHERE name = 'Mixx by YAS' LIMIT 1);

-- Moov Money (Togo)
INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at)
SELECT 'Moov Money', 'TG', 'numeric', 4, '', '', 0, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM carriers WHERE name = 'Moov Money' LIMIT 1);

-- Coris Money (Togo)
INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at)
SELECT 'Coris Money', 'TG', 'numeric', 4, '', '', 0, NOW(), NOW()
WHERE NOT EXISTS (SELECT 1 FROM carriers WHERE name = 'Coris Money' LIMIT 1);
