<?php
// ============================================================
//  LOCKSMITH — Database Configuration
//  Edit DB_* and APP_HMAC_SECRET only.
//  The encryption key NEVER appears here — it lives only
//  in the user's browser, derived from their vault passphrase.
// ============================================================

define('DB_HOST',    'localhost');
define('DB_NAME',    'locksmith');
define('DB_USER',    'root');
define('DB_PASS',    '');
define('DB_CHARSET', 'utf8mb4');

// Used ONLY for HMAC-signing audit log entries and CSRF tokens.
// NOT used for encryption. Compromise of this key cannot decrypt any password.
define('APP_HMAC_SECRET', 'REPLACE_WITH_64+_RANDOM_BYTES_hex_php_r_echo_bin2hex_random_bytes_32');

define('APP_ENV', 'development'); // 'production' in prod

define('APP_NAME', 'LOCKSMITH');
define('MAIL_FROM', 'no-reply@localhost');
define('EMAIL_VERIFY_TTL_HOURS', 24);

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
