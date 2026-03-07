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
    vault_verifier               VARCHAR(255) NOT NULL,       -- legacy verifier (no longer required for reveals)
    vault_verifier_salt          CHAR(64) NOT NULL,
    vault_verifier_alt           VARCHAR(255) NULL,
    vault_verifier_alt_salt      CHAR(64) NULL,
    vault_verifier_alt_set_at    DATETIME NULL,

    -- Personal-use security
    totp_secret_enc              TEXT NULL,
    totp_enabled_at              DATETIME NULL,
    require_webauthn             TINYINT(1) NOT NULL DEFAULT 0,

    -- Not secret: which vault slot is used for NEW codes (1=primary, 2=rotated)
    vault_active_slot            TINYINT(1) NOT NULL DEFAULT 1,

    -- Vault passphrase check (zero-knowledge): encrypted constant to validate passphrase client-side
    vault_check_cipher           TEXT NULL,
    vault_check_iv               VARCHAR(64) NULL,
    vault_check_auth_tag         VARCHAR(64) NULL,
    vault_check_salt             VARCHAR(64) NULL,
    vault_check_iterations       INT UNSIGNED NOT NULL DEFAULT 310000,
    vault_check_set_at           DATETIME NULL,

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

-- Mobile Money carriers
CREATE TABLE IF NOT EXISTS carriers (
    id                      INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name                    VARCHAR(255) NOT NULL,
    country                 VARCHAR(10) NULL,

    pin_type                ENUM('numeric','alphanumeric') NOT NULL DEFAULT 'numeric',
    pin_length              TINYINT UNSIGNED NOT NULL DEFAULT 4,

    ussd_change_pin_template VARCHAR(500) NOT NULL,
    ussd_balance_template   VARCHAR(500) NOT NULL,

    is_active               TINYINT(1) NOT NULL DEFAULT 1,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at              DATETIME NULL,

    INDEX idx_active (is_active),
    INDEX idx_name (name)
) ENGINE=InnoDB;

-- Time-locked wallet PINs (zero-knowledge ciphertext only)
CREATE TABLE IF NOT EXISTS wallet_locks (
    id               CHAR(36) PRIMARY KEY,
    user_id          INT UNSIGNED NOT NULL,
    carrier_id       INT UNSIGNED NOT NULL,

    label            VARCHAR(255) NULL,
    unlock_at        DATETIME NOT NULL,

    setup_status     ENUM('pending','active','failed') NOT NULL DEFAULT 'pending',
    setup_confirmed_at DATETIME NULL,
    setup_failed_at  DATETIME NULL,

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

-- WebAuthn / Passkeys (public keys only)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED NOT NULL,
    credential_id   VARBINARY(255) NOT NULL,
    public_key_pem  TEXT NOT NULL,
    sign_count      INT UNSIGNED NOT NULL DEFAULT 0,
    label           VARCHAR(255) NULL,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME NULL,

    UNIQUE KEY uniq_cred (credential_id),
    INDEX idx_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================================
--  Joint Saving Rooms + Trust Passport + Notifications
--  (migrations 010-014 inlined for fresh installs)
-- ============================================================

-- Joint Saving Rooms + Trust Passport + Consensus Unlock (schema)
-- Adds saving rooms, contributions, unlock voting, disputes, activity feed,
-- trust level tracking, and notification scaffolding.

-- ───────────────────────────────────────────────────────────
-- Trust passport
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS user_trust (
    user_id                 INT UNSIGNED PRIMARY KEY,
    trust_level             TINYINT UNSIGNED NOT NULL DEFAULT 1,
    completed_reveals_count  INT UNSIGNED NOT NULL DEFAULT 0,
    last_level_change_at     DATETIME NULL,
    created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_level (trust_level)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_completed_reveals (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id             INT UNSIGNED NOT NULL,
    room_id             CHAR(36) NOT NULL,
    started_at          DATETIME NOT NULL,
    unlocked_at         DATETIME NOT NULL,
    duration_days       INT UNSIGNED NOT NULL,
    qualified_for_level TINYINT(1) NOT NULL DEFAULT 1,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user_time (user_id, unlocked_at),
    INDEX idx_room (room_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_strikes (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NOT NULL,
    room_id      CHAR(36) NULL,
    cycle_id     INT UNSIGNED NULL,
    strike_type  ENUM('missed_contribution','false_dispute','abandonment') NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_user_time (user_id, created_at),
    INDEX idx_room (room_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_restrictions (
    user_id          INT UNSIGNED PRIMARY KEY,
    restricted_until DATETIME NOT NULL,
    reason           VARCHAR(80) NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_until (restricted_until)
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Saving rooms
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saving_rooms (
    id                    CHAR(36) PRIMARY KEY,
    maker_user_id         INT UNSIGNED NOT NULL,

    purpose_category      ENUM('education','travel','business','emergency','community','other') NOT NULL DEFAULT 'other',
    goal_text             VARCHAR(500) NOT NULL,

    saving_type           ENUM('A','B') NOT NULL,
    visibility            ENUM('public','unlisted','private') NOT NULL DEFAULT 'public',

    required_trust_level  TINYINT UNSIGNED NOT NULL DEFAULT 1,

    min_participants      INT UNSIGNED NOT NULL DEFAULT 2,
    max_participants      INT UNSIGNED NOT NULL,

    participation_amount  DECIMAL(14,2) NOT NULL,
    periodicity           ENUM('weekly','biweekly','monthly') NOT NULL,

    start_at              DATETIME NOT NULL,
    reveal_at             DATETIME NOT NULL,

    lobby_state           ENUM('open','locked') NOT NULL DEFAULT 'open',
    room_state            ENUM('lobby','active','closed','cancelled') NOT NULL DEFAULT 'lobby',

    privacy_mode          TINYINT(1) NOT NULL DEFAULT 1,
    escrow_policy         ENUM('redistribute','refund_minus_fee') NOT NULL DEFAULT 'redistribute',

    extensions_used       TINYINT UNSIGNED NOT NULL DEFAULT 0,

    created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NULL,

    FOREIGN KEY (maker_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    INDEX idx_state (room_state, lobby_state),
    INDEX idx_visibility (visibility),
    INDEX idx_required_level (required_trust_level),
    INDEX idx_start (start_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_participants (
    room_id                    CHAR(36) NOT NULL,
    user_id                    INT UNSIGNED NOT NULL,

    status                     ENUM('pending','approved','declined','active','removed','completed','exited_prestart','exited_poststart') NOT NULL DEFAULT 'pending',

    joined_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved_at                DATETIME NULL,
    removed_at                 DATETIME NULL,
    completed_at               DATETIME NULL,

    removal_reason             VARCHAR(120) NULL,

    missed_contributions_count INT UNSIGNED NOT NULL DEFAULT 0,
    silent_abandonment_flag    TINYINT(1) NOT NULL DEFAULT 0,

    PRIMARY KEY (room_id, user_id),
    INDEX idx_room_status (room_id, status),
    INDEX idx_user_status (user_id, status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_join_requests (
    id                 INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id            CHAR(36) NOT NULL,
    user_id            INT UNSIGNED NOT NULL,

    status             ENUM('pending','approved','declined','cancelled') NOT NULL DEFAULT 'pending',
    maker_decided_at   DATETIME NULL,

    snapshot_level     TINYINT UNSIGNED NOT NULL DEFAULT 1,
    snapshot_strikes_6m INT UNSIGNED NOT NULL DEFAULT 0,
    snapshot_restricted_until DATETIME NULL,

    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_room_user_pending (room_id, user_id),
    INDEX idx_room_status (room_id, status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_invites (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id             CHAR(36) NOT NULL,

    invite_mode         ENUM('unlisted_link','private_user') NOT NULL,

    invite_token_hash   CHAR(64) NULL,
    invited_user_id     INT UNSIGNED NULL,
    invited_email       VARCHAR(255) NULL,

    status              ENUM('active','accepted','declined','revoked','expired') NOT NULL DEFAULT 'active',
    expires_at          DATETIME NULL,

    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    responded_at        DATETIME NULL,

    INDEX idx_room (room_id),
    INDEX idx_token (invite_token_hash),
    INDEX idx_invited_user (invited_user_id),
    INDEX idx_invited_email (invited_email),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Contribution cycles + contributions
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saving_room_contribution_cycles (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id       CHAR(36) NOT NULL,
    cycle_index   INT UNSIGNED NOT NULL,

    due_at        DATETIME NOT NULL,
    grace_ends_at DATETIME NOT NULL,

    status        ENUM('open','grace','closed') NOT NULL DEFAULT 'open',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_room_cycle (room_id, cycle_index),
    INDEX idx_room_due (room_id, due_at),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_contributions (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id       CHAR(36) NOT NULL,
    user_id       INT UNSIGNED NOT NULL,
    cycle_id      INT UNSIGNED NOT NULL,

    amount        DECIMAL(14,2) NOT NULL,
    status        ENUM('paid','unpaid','paid_in_grace','missed') NOT NULL DEFAULT 'unpaid',
    reference     VARCHAR(120) NULL,

    confirmed_at  DATETIME NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_cycle_user (cycle_id, user_id),
    INDEX idx_room_user (room_id, user_id),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (cycle_id) REFERENCES saving_room_contribution_cycles(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Platform destination accounts (admin-controlled)
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_destination_accounts (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    account_type          ENUM('mobile_money','bank') NOT NULL,

    carrier_id            INT UNSIGNED NULL,
    mobile_money_number   VARCHAR(64) NULL,

    bank_name             VARCHAR(120) NULL,
    bank_account_name     VARCHAR(120) NULL,
    bank_account_number   VARCHAR(64) NULL,
    bank_routing_number   VARCHAR(64) NULL,
    bank_swift            VARCHAR(64) NULL,
    bank_iban             VARCHAR(64) NULL,

    unlock_code_enc       TEXT NOT NULL,
    code_rotated_at       DATETIME NULL,
    code_rotation_version INT UNSIGNED NOT NULL DEFAULT 1,

    is_active             TINYINT(1) NOT NULL DEFAULT 1,

    created_at            DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NULL,

    INDEX idx_active (is_active),
    FOREIGN KEY (carrier_id) REFERENCES carriers(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_accounts (
    room_id     CHAR(36) PRIMARY KEY,
    account_id  INT UNSIGNED NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES platform_destination_accounts(id) ON DELETE RESTRICT,
    INDEX idx_account (account_id)
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Unlock cycles + votes (code itself is never logged)
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saving_room_unlock_events (
    room_id      CHAR(36) PRIMARY KEY,
    status       ENUM('pending','revealed','expired') NOT NULL DEFAULT 'pending',
    revealed_at  DATETIME NULL,
    expires_at   DATETIME NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_rotation_queue (
    room_id     CHAR(36) NOT NULL,
    user_id     INT UNSIGNED NOT NULL,
    position    INT UNSIGNED NOT NULL,
    status      ENUM('queued','active_window','completed','skipped_removed') NOT NULL DEFAULT 'queued',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (room_id, user_id),
    UNIQUE KEY uniq_room_pos (room_id, position),
    INDEX idx_room_status (room_id, status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_rotation_windows (
    id                     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id                CHAR(36) NOT NULL,
    user_id                INT UNSIGNED NOT NULL,
    rotation_index         INT UNSIGNED NOT NULL,

    status                 ENUM('pending_votes','revealed','expired','blocked_dispute','blocked_debt') NOT NULL DEFAULT 'pending_votes',
    revealed_at            DATETIME NULL,
    expires_at             DATETIME NULL,
    dispute_window_ends_at DATETIME NULL,

    created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_room_rotation (room_id, rotation_index),
    INDEX idx_room_status (room_id, status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_unlock_votes (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id              CHAR(36) NOT NULL,
    user_id              INT UNSIGNED NOT NULL,

    scope                ENUM('typeA_room_unlock','typeB_turn_unlock','typeB_exit_request') NOT NULL,
    target_rotation_index INT UNSIGNED NULL,

    vote                 ENUM('approve','reject') NOT NULL,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NULL,

    UNIQUE KEY uniq_vote (room_id, user_id, scope, target_rotation_index),
    INDEX idx_room_scope (room_id, scope),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Exit requests (Type B)
-- ───────────────────────────────────────────────────────────
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

-- ───────────────────────────────────────────────────────────
-- Disputes (Type B)
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saving_room_disputes (
    id                     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id                CHAR(36) NOT NULL,
    rotation_index         INT UNSIGNED NOT NULL,
    raised_by_user_id      INT UNSIGNED NOT NULL,

    reason                 VARCHAR(500) NULL,

    status                 ENUM('open','threshold_met','escalated_admin','validated','dismissed') NOT NULL DEFAULT 'open',
    threshold_count_required INT UNSIGNED NOT NULL,

    admin_decision_at      DATETIME NULL,
    admin_decision_by      INT UNSIGNED NULL,

    created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NULL,

    INDEX idx_room_rotation (room_id, rotation_index),
    INDEX idx_status (status),

    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (raised_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (admin_decision_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS saving_room_dispute_ack (
    dispute_id  INT UNSIGNED NOT NULL,
    user_id     INT UNSIGNED NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (dispute_id, user_id),
    FOREIGN KEY (dispute_id) REFERENCES saving_room_disputes(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Transparency feed (privacy-filtered payload; never includes unlock code)
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS saving_room_activity (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id       CHAR(36) NOT NULL,
    event_type    VARCHAR(64) NOT NULL,
    public_payload_json JSON NOT NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_room_time (room_id, created_at),
    FOREIGN KEY (room_id) REFERENCES saving_rooms(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ───────────────────────────────────────────────────────────
-- Notifications
-- ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NOT NULL,
    tier         ENUM('critical','important','informational') NOT NULL,
    channel_mask VARCHAR(20) NOT NULL,
    title        VARCHAR(160) NOT NULL,
    body         VARCHAR(800) NOT NULL,
    data_json    JSON NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at      DATETIME NULL,
    sent_email_at DATETIME NULL,
    sent_push_at DATETIME NULL,

    INDEX idx_user_time (user_id, created_at),
    INDEX idx_user_read (user_id, read_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id       INT UNSIGNED PRIMARY KEY,
    important_json JSON NULL,
    informational_json JSON NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

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

-- Notification deduplication events
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

-- Ensure completed reveal records are not duplicated
ALTER TABLE user_completed_reveals
    ADD UNIQUE KEY uniq_user_room (user_id, room_id);

-- Escrow settlement records for participants removed due to strikes
CREATE TABLE IF NOT EXISTS saving_room_escrow_settlements (
    id                   INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    room_id              CHAR(36) NOT NULL,
    removed_user_id      INT UNSIGNED NOT NULL,

    policy               ENUM('redistribute','refund_minus_fee') NOT NULL,
    reason               VARCHAR(64) NULL,
    fee_rate             DECIMAL(5,4) NOT NULL DEFAULT 0.1000,

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