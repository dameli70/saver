-- ============================================================
--  Migration 027: Packages / Plans
--
--  Adds subscription-like packages to enforce limits:
--   - max_active_locks
--   - max_active_rooms
--   - max_active_wallet_locks
--   - fast_support
-- ============================================================

CREATE TABLE IF NOT EXISTS packages (
    id                     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    slug                   VARCHAR(60) NOT NULL UNIQUE,
    name                   VARCHAR(120) NOT NULL,
    sort_order             INT UNSIGNED NOT NULL DEFAULT 0,

    max_active_locks        INT UNSIGNED NOT NULL DEFAULT 1,
    max_active_rooms        INT UNSIGNED NOT NULL DEFAULT 1,
    max_active_wallet_locks INT UNSIGNED NOT NULL DEFAULT 1,
    fast_support            TINYINT(1) NOT NULL DEFAULT 0,

    is_active              TINYINT(1) NOT NULL DEFAULT 1,
    created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NULL,

    INDEX idx_active (is_active),
    INDEX idx_sort (sort_order)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_packages (
    user_id             INT UNSIGNED PRIMARY KEY,
    package_id          INT UNSIGNED NOT NULL,
    purchase_id         INT UNSIGNED NULL,
    assigned_by_user_id INT UNSIGNED NULL,
    is_active           TINYINT(1) NOT NULL DEFAULT 1,
    assigned_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE RESTRICT,
    INDEX idx_package (package_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS package_purchases (
    id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id            INT UNSIGNED NOT NULL,
    package_id         INT UNSIGNED NOT NULL,
    status             ENUM('pending','approved','rejected','cancelled') NOT NULL DEFAULT 'pending',
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    decided_at         DATETIME NULL,
    decided_by_user_id INT UNSIGNED NULL,
    note               VARCHAR(255) NULL,

    INDEX idx_user (user_id),
    INDEX idx_package (package_id),
    INDEX idx_status (status),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (package_id) REFERENCES packages(id) ON DELETE RESTRICT,
    FOREIGN KEY (decided_by_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Seed the two default plans.
INSERT IGNORE INTO packages (slug, name, max_active_locks, max_active_rooms, max_active_wallet_locks, fast_support, is_active, sort_order)
VALUES
  ('controle_plus', 'Controle+', 10, 3, 3, 1, 1, 10),
  ('control_max',  'Control Max', 100, 20, 20, 1, 1, 20);
