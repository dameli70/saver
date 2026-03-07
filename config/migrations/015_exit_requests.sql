-- Type B exit requests

CREATE TABLE IF NOT EXISTS saving_room_exit_requests (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id              CHAR(36) NOT NULL,
    requested_by_user_id INT UNSIGNED NOT NULL,

    status               ENUM('open','approved','declined','cancelled') NOT NULL DEFAULT 'open',

    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at          DATETIME NULL,
    resolved_by_user_id  INT UNSIGNED NULL,

    INDEX idx_room_status (room_id, status),
    INDEX idx_room_time (room_id, created_at),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
