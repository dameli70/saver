<?php
// ============================================================
//  LOCKSMITH — Database Configuration
//  Edit DB_*, APP_HMAC_SECRET, and mail settings.
//  The encryption key NEVER appears here — it lives only
//  in the user's browser, derived from their vault passphrase.
//  (The vault passphrase is never stored on the server.)
// ============================================================

define('DB_HOST',    'localhost');
define('DB_NAME',    'locksmith');
define('DB_USER',    'root');
define('DB_PASS',    '');
define('DB_CHARSET', 'utf8mb4');

// Used ONLY for server-side integrity and secret wrapping:
// - HMAC hashing session IDs (logout-all)
// - Deriving a server-side key to encrypt TOTP secrets
// - Audit log integrity
// NOT used for code/lock encryption. Compromise of this key cannot decrypt stored vault contents.
define('APP_HMAC_SECRET', 'REPLACE_WITH_64+_RANDOM_BYTES_hex_php_r_echo_bin2hex_random_bytes_32');

define('APP_ENV', 'development'); // 'production' in prod

define('APP_NAME', 'LOCKSMITH');

// Optional: override the app base URL used in verification/reset links.
// Example: https://example.com or https://example.com/locksmith
// Leave blank to auto-detect from the current request.
define('APP_BASE_URL', '');

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

// Use a single time reference across the app.
// We store and compare lock times in UTC.
date_default_timezone_set('UTC');

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=".DB_HOST.";dbname=".DB_NAME.";charset=".DB_CHARSET;
        $opts = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            // Ensure MySQL time functions (NOW(), etc.) are evaluated in UTC.
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
