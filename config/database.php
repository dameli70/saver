<?php
// ============================================================
//  LOCKSMITH — Database Configuration
//  Edit DB_*, APP_HMAC_SECRET, and mail settings.
//
//  NOTE ON "ZERO-KNOWLEDGE":
//  Vault code encryption keys are derived only in the browser from the user's
//  vault passphrase (which is never stored on the server).
//
//  Some optional features require server-managed secrets (e.g. TOTP verification,
//  Saving Rooms destination unlock codes) which are encrypted at rest but are
//  decryptable by the server.
// ============================================================

define('DB_HOST',    'localhost');
define('DB_NAME',    'locksmith');
define('DB_USER',    'root');
define('DB_PASS',    '');
define('DB_CHARSET', 'utf8mb4');

// Application secret used for server-side integrity/authentication features.
// Today it is used for:
// - Session-bound identifiers (session_id_hash in user_sessions)
// - Encrypting server-stored secrets like TOTP seeds (AES-256-GCM)
// - Encrypting admin-managed destination account unlock codes for Saving Rooms
//
// It is NOT used to encrypt vault codes or wallet locks. Those are encrypted/decrypted
// only in the browser from the user's vault passphrase.
define('APP_HMAC_SECRET', 'REPLACE_WITH_64+_RANDOM_BYTES_hex_php_r_echo_bin2hex_random_bytes_32');

define('APP_ENV', 'development'); // 'production' in prod

define('APP_NAME', 'LOCKSMITH');
define('MAIL_FROM', 'no-reply@localhost');
define('EMAIL_VERIFY_TTL_HOURS', 24);

// SMTP (optional; if SMTP_HOST is empty, PHP mail() is used)
define('SMTP_HOST', '');
define('SMTP_PORT', 587);
define('SMTP_USER', '');
define('SMTP_PASS', '');
define('SMTP_SECURE', 'tls'); // '', 'tls', or 'ssl'
define('SMTP_VERIFY_PEER', 1);

// PBKDF2 iterations — match what client uses
define('PBKDF2_ITERATIONS', 310000);

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=".DB_CHARSET;
        $opts = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '+00:00'",
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $opts);
        } catch (PDOException $e) {
            if (APP_ENV === 'development') {
                die(json_encode(['error' => 'DB: ' . $e->getMessage()]));
            }
            die(json_encode(['error' => 'Database unavailable']));
        }
    }
    return $pdo;
}
