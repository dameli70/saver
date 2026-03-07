-- Add metadata to escrow settlement records so operations can process/interpret them.

ALTER TABLE saving_room_escrow_settlements
    ADD COLUMN reason VARCHAR(64) NULL AFTER policy,
    ADD COLUMN fee_rate DECIMAL(5,4) NOT NULL DEFAULT 0.1000 AFTER reason;
