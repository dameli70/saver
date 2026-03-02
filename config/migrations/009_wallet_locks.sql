-- Mobile Money carriers + time-locked wallet PINs
--
-- Carriers define USSD templates and PIN requirements.
-- Wallet locks store only ciphertext of the generated PIN (zero-knowledge).

CREATE TABLE IF NOT EXISTS carriers (
    id                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(255) NOT NULL,
    country                 VARCHAR(10) NULL,

    -- PIN policy for the carrier
    pin_type                ENUM('numeric','alphanumeric') NOT NULL DEFAULT 'numeric',
    pin_length              TINYINT UNSIGNED NOT NULL DEFAULT 4,

    -- USSD templates (placeholders: {old_pin}, {new_pin})
    ussd_change_pin_template VARCHAR(500) NOT NULL,

    -- Balance check template (should not include a PIN)
    ussd_balance_template   VARCHAR(500) NOT NULL,

    is_active               TINYINT(1) NOT NULL DEFAULT 1,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NULL,

    INDEX idx_active (is_active),
    INDEX idx_name (name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wallet_locks (
    id               CHAR(36) PRIMARY KEY,
    user_id          INT UNSIGNED NOT NULL,
    carrier_id       INT UNSIGNED NOT NULL,

    label            VARCHAR(255) NULL,
    unlock_at        DATETIME NOT NULL,

    -- Ensure the PIN is stored server-side before the user completes USSD.
    setup_status     ENUM('pending','active','failed') NOT NULL DEFAULT 'pending',
    setup_confirmed_at DATETIME NULL,
    setup_failed_at  DATETIME NULL,

    -- Zero-knowledge crypto fields for the generated wallet PIN
    cipher_blob      TEXT NOT NULL,
    iv               VARCHAR(64) NOT NULL,
    auth_tag         VARCHAR(64) NOT NULL,
    kdf_salt         VARCHAR(64) NOT NULL,
    kdf_iterations   INT UNSIGNED NOT NULL DEFAULT 310000,

    revealed_at      DATETIME NULL,
    is_active        TINYINT(1) NOT NULL DEFAULT 1,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (carrier_id) REFERENCES carriers(id) ON DELETE RESTRICT,
    INDEX idx_user_active (user_id, is_active),
    INDEX idx_unlock_at (unlock_at),
    INDEX idx_carrier (carrier_id),
    INDEX idx_setup_status (setup_status)
) ENGINE=InnoDB;
