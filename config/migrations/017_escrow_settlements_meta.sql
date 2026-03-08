-- Add metadata to escrow settlement records so operations can process/interpret them.

-- Split into separate ALTER statements so the installer can safely ignore
-- "Duplicate column" errors and still apply any missing columns.
ALTER TABLE saving_room_escrow_settlements
    ADD COLUMN reason VARCHAR(64) NULL AFTER policy;

ALTER TABLE saving_room_escrow_settlements
    ADD COLUMN fee_rate DECIMAL(5,4) NOT NULL DEFAULT 0.1000 AFTER reason;
