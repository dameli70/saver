-- ============================================================
--  LOCKSMITH — Zero-Knowledge Schema v3
--
--  SECURITY GUARANTEE:
--  The server stores ONLY ciphertext. The decryption key is
--  derived entirely in the user's browser from their vault
--  passphrase — which is NEVER stored.
--  A full server dump + source code = mathematically useless
--  without the user's vault passphrase.
-- ============================================================

CREATE DATABASE IF NOT EXISTS locksmith
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE locksmith;

CREATE TABLE IF NOT EXISTS users (
    id                           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email                        VARCHAR(255) NOT NULL UNIQUE,
    login_hash                   VARCHAR(255) NOT NULL,       -- Argon2id of LOGIN password (for auth only)
    vault_verifier               VARCHAR(255) NOT NULL,       -- Argon2id of VAULT passphrase (only to verify, never to derive keys)
    vault_verifier_salt          CHAR(64) NOT NULL,           -- hex: random salt for vault_verifier
    vault_verifier_alt           VARCHAR(255) NULL,           -- optional 2nd verifier (for passphrase rotation)
    vault_verifier_alt_salt      CHAR(64) NULL,
    vault_verifier_alt_set_at    DATETIME NULL,

    -- Email verification (required before using the dashboard)
    email_verified_at            DATETIME NULL,
    email_verification_hash      CHAR(64) NULL,               -- hex sha256(token)
    email_verification_expires_at DATETIME NULL,
    verification_sent_at         DATETIME NULL,

    -- Admin
    is_admin                     TINYINT(1) NOT NULL DEFAULT 0,

    -- Password reset (login password only; vault passphrase is never recoverable)
    password_reset_hash          CHAR(64) NULL,
    password_reset_expires_at    DATETIME NULL,
    password_reset_sent_at       DATETIME NULL,

    created_at                   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login                   DATETIME NULL,
    INDEX idx_email (email),
    INDEX idx_email_verification_hash (email_verification_hash),
    INDEX idx_password_reset_hash (password_reset_hash),
    INDEX idx_is_admin (is_admin)
) ENGINE=InnoDB;

-- Zero-Knowledge lock table
-- EVERYTHING needed to decrypt lives in the browser.
-- Server stores only opaque bytes + metadata.
CREATE TABLE IF NOT EXISTS locks (
    id                   CHAR(36) PRIMARY KEY,
    user_id              INT UNSIGNED NOT NULL,
    label                VARCHAR(255) NOT NULL,

    -- === ZERO-KNOWLEDGE CRYPTO FIELDS ===
    -- All crypto done in browser with Web Crypto API.
    -- Server has NO decryption capability.
    cipher_blob          TEXT NOT NULL,        -- base64(AES-256-GCM ciphertext)
    iv                   VARCHAR(64) NOT NULL, -- base64(96-bit GCM IV)
    auth_tag             VARCHAR(64) NOT NULL, -- base64(128-bit GCM auth tag)
    kdf_salt             VARCHAR(64) NOT NULL, -- base64(256-bit PBKDF2 salt, per-lock, server-generated)
    kdf_iterations       INT UNSIGNED NOT NULL DEFAULT 310000, -- PBKDF2 iterations used
    vault_verifier_slot  TINYINT(1) NOT NULL DEFAULT 1, -- 1=primary vault passphrase, 2=alt (rotation)

    -- === METADATA (no secrets) ===
    password_type        ENUM('numeric','alphanumeric','alpha','custom') NOT NULL DEFAULT 'alphanumeric',
    password_length      TINYINT UNSIGNED NOT NULL DEFAULT 16,
    hint                 VARCHAR(500) NULL,     -- Memory hint, never the password
    reveal_date          DATETIME NOT NULL,

    -- === CONFIRMATION FLOW ===
    confirmation_status  ENUM('pending','confirmed','rejected','auto_saved') NOT NULL DEFAULT 'pending',
    copied_at            DATETIME NULL,
    confirmed_at         DATETIME NULL,
    rejected_at          DATETIME NULL,
    auto_saved_at        DATETIME NULL,
    revealed_at          DATETIME NULL,
    is_active            TINYINT(1) NOT NULL DEFAULT 1,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_active (user_id, is_active),
    INDEX idx_status (confirmation_status),
    INDEX idx_reveal (reveal_date),
    INDEX idx_vault_verifier_slot (vault_verifier_slot)
) ENGINE=InnoDB;

-- Cloud backups (still zero-knowledge: stores ciphertext only)
CREATE TABLE IF NOT EXISTS backups (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    label       VARCHAR(255) NULL,
    backup_blob MEDIUMTEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_time (user_id, created_at)
) ENGINE=InnoDB;

-- Server-side session tracking (logout all sessions, session listing)
CREATE TABLE IF NOT EXISTS user_sessions (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED NOT NULL,
    session_id_hash CHAR(64) NOT NULL,
    ip_address      VARCHAR(45) NULL,
    user_agent      VARCHAR(500) NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_session (session_id_hash),
    INDEX idx_user_time (user_id, last_seen_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Audit log — no secrets ever logged
CREATE TABLE IF NOT EXISTS audit_log (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NULL,
    lock_id     CHAR(36) NULL,
    action      VARCHAR(64) NOT NULL,
    ip_address  VARCHAR(45) NULL,
    user_agent  VARCHAR(500) NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user  (user_id),
    INDEX idx_lock  (lock_id),
    INDEX idx_time  (created_at)
) ENGINE=InnoDB;
