-- Underfilled room alert / decision window

CREATE TABLE IF NOT EXISTS saving_room_underfill_alerts (
    room_id            CHAR(36) PRIMARY KEY,
    alerted_at         DATETIME NOT NULL,
    decision_deadline_at DATETIME NOT NULL,
    status             ENUM('open','resolved','expired') NOT NULL DEFAULT 'open',
    resolved_at        DATETIME NULL,
    resolution_action  ENUM('extend_start','lower_min','cancel') NULL,
    resolution_payload JSON NULL,

    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    INDEX idx_status_deadline (status, decision_deadline_at)
) ENGINE=InnoDB;
