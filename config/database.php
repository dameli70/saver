<?php
// ============================================================
//  Controle — Database Configuration
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

// Application secret used for server-side integrity/authentication features.
// Today it is used for:
// - Session-bound identifiers (session_id_hash in user_sessions)
// - Encrypting server-stored secrets like TOTP seeds (AES-256-GCM)
//
// It is NOT used to encrypt user "locks" (codes). Those are encrypted/decrypted
// only in the browser from the user's vault passphrase (zero-knowledge).
define('APP_HMAC_SECRET', 'REPLACE_WITH_64+_RANDOM_BYTES_hex_php_r_echo_bin2hex_random_bytes_32');

define('APP_ENV', 'development'); // 'production' in prod

define('APP_NAME', 'Controle');

// Optional: display logo image URL/path (e.g. /assets/logo.png). Leave empty to use text-only branding.
define('APP_LOGO_URL', '');

// Canonical base URL used for emailed links (verification + password reset).
// Recommended in production to prevent Host header injection.
// Example: https://controle.example.com
// Leave empty to auto-detect (development only).
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

date_default_timezone_set('UTC');



function isApiRequest(): bool {
    try {
        $script = (string)($_SERVER['SCRIPT_NAME'] ?? '');
        $uri    = (string)($_SERVER['REQUEST_URI'] ?? '');

        // Primary signal: anything under /api/ is an API request.
        if (preg_match('#/api/#', $script) || preg_match('#/api/#', $uri)) return true;

        // Secondary signals: clients that explicitly want JSON.
        $accept = strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? ''));
        if (str_contains($accept, 'application/json') || str_contains($accept, '+json')) return true;

        $ctype = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? ''));
        if (str_contains($ctype, 'application/json')) return true;

        $xrw = strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));
        if ($xrw === 'xmlhttprequest') return true;

    } catch (Throwable) {
        // Fall through
    }

    return false;
}

function dbUnavailableResponse(?string $devDetail = null): void {
    $isDev = defined('APP_ENV') && APP_ENV === 'development';
    $msg = ($isDev && $devDetail) ? ('DB: ' . $devDetail) : 'Database unavailable';

    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, $msg . "\n");
        exit(1);
    }

    http_response_code(503);

    if (!headers_sent()) {
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
    }

    if (isApiRequest()) {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
        }
        echo json_encode(['error' => $msg], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
    }

    $app = defined('APP_NAME') ? (string)APP_NAME : 'Application';
    $safeApp = htmlspecialchars($app, ENT_QUOTES, 'UTF-8');
    $safeMsg = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');

    echo "<!doctype html>\n";
    echo "<html lang=\"en\">\n";
    echo "<head>\n";
    echo "  <meta charset=\"utf-8\">\n";
    echo "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    echo "  <title>{$safeApp} — Service unavailable</title>\n";
    echo "  <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:40px;color:#111}h1{margin:0 0 10px}p{margin:0 0 10px;color:#333}code{background:#f3f3f3;padding:2px 4px;border-radius:4px}</style>\n";
    echo "</head>\n";
    echo "<body>\n";
    echo "  <h1>Service unavailable</h1>\n";
    echo "  <p>{$safeMsg}</p>\n";
    echo "  <p>Please try again in a moment.</p>\n";
    echo "</body>\n";
    echo "</html>";
    exit;
}

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

            // Use UTC consistently for DB time functions like NOW().
            try {
                $pdo->exec("SET time_zone = '+00:00'");
            } catch (Throwable) {
                // Ignore if the DB user lacks permission to set session timezone.
            }
        } catch (PDOException $e) {
            dbUnavailableResponse($e->getMessage());
        }
    }
    return $pdo;
}
