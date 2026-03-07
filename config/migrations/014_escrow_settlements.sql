-- Escrow settlement records for participants removed due to strikes

CREATE TABLE IF NOT EXISTS saving_room_escrow_settlements (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id              CHAR(36) NOT NULL,
    removed_user_id      INT UNSIGNED NOT NULL,

    policy               ENUM('redistribute','refund_minus_fee') NOT NULL,

    total_contributed    DECIMAL(14,2) NOT NULL,
    platform_fee_amount  DECIMAL(14,2) NOT NULL DEFAULT 0.00,
    refund_amount        DECIMAL(14,2) NOT NULL DEFAULT 0.00,

    redistribution_json  JSON NULL,

    status               ENUM('recorded','processed') NOT NULL DEFAULT 'recorded',
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at         DATETIME NULL,

    UNIQUE KEY uniq_room_user (room_id, removed_user_id),
    INDEX idx_room (room_id),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (removed_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
