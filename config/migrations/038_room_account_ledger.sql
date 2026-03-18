-- ============================================================
--  Migration 038: Room account ledger (derived balance)
--
--  Tracks the room's running balance based on confirmed
--  contributions (credits) and confirmed withdrawals (debits).
-- ============================================================

CREATE TABLE IF NOT EXISTS saving_room_account_ledger (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id         CHAR(36) NOT NULL,

    entry_seq       BIGINT UNSIGNED NOT NULL,

    entry_type      ENUM('credit','debit') NOT NULL,
    entry_kind      ENUM('contribution','withdrawal') NOT NULL,

    amount          DECIMAL(14,2) NOT NULL,
    balance_after   DECIMAL(14,2) NOT NULL,

    source_type     VARCHAR(32) NOT NULL,
    source_id       VARCHAR(64) NOT NULL,

    created_by_user_id INT UNSIGNED NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_room_seq (room_id, entry_seq),
    UNIQUE KEY uniq_source (room_id, source_type, source_id),
    INDEX idx_room_time (room_id, created_at),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
