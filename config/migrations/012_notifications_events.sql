-- Notification deduplication events
-- Prevent duplicate notifications from cron-based logic.

CREATE TABLE IF NOT EXISTS notification_events (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    event_key   VARCHAR(80) NOT NULL,
    ref_type    VARCHAR(40) NULL,
    ref_id      VARCHAR(80) NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_event (user_id, event_key, ref_type, ref_id),
    INDEX idx_user_time (user_id, created_at),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
