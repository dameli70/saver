<?php
// ============================================================
//  LOCKSMITH — Server-Side Helpers (Zero-Knowledge Edition)
//
//  WHAT THIS FILE DOES NOT DO (by design):
//  - Does NOT derive any encryption key
//  - Does NOT store, transmit, or compute over plaintext passwords
//  - Does NOT have any function that can decrypt a lock
//
//  The only crypto here is:
//  - Argon2id for login password hashing (authentication)
//  - Argon2id for vault passphrase verification (identity check only)
//  - CSRF token generation (HMAC-SHA256)
//  - UUID generation
// ============================================================

require_once __DIR__ . '/../config/database.php';

// ── Session ──────────────────────────────────────────────────
function startSecureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 1 : 0);
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', 1);
        ini_set('session.gc_maxlifetime', 3600);
        session_start();
    }
}

function isLoggedIn(): bool {
    startSecureSession();
    return !empty($_SESSION['user_id']);
}

function requireLogin(): void {
    if (!isLoggedIn()) { jsonResponse(['error' => 'Unauthorized'], 401); }
}

function getCurrentUserId(): ?int { return $_SESSION['user_id'] ?? null; }
function getCurrentUserEmail(): ?string { return $_SESSION['email'] ?? null; }

// ── Email verification ──────────────────────────────────────
function isEmailVerified(?int $userId = null): bool {
    startSecureSession();
    if (!empty($_SESSION['email_verified'])) return true;

    $uid = $userId ?? getCurrentUserId();
    if (!$uid) return false;

    $db   = getDB();
    $stmt = $db->prepare("SELECT email_verified_at FROM users WHERE id = ?");
    $stmt->execute([$uid]);
    $row = $stmt->fetch();

    $ok = !empty($row['email_verified_at']);
    $_SESSION['email_verified'] = $ok ? 1 : 0;
    return $ok;
}

function requireVerifiedEmail(): void {
    if (!isEmailVerified()) {
        jsonResponse(['error' => 'Email address not verified'], 403);
    }
}

function issueEmailVerification(int $userId, string $email): ?string {
    $token   = bin2hex(random_bytes(32));
    $hash    = hash('sha256', $token);
    $expires = (new DateTime())->modify('+' . (int)EMAIL_VERIFY_TTL_HOURS . ' hours')->format('Y-m-d H:i:s');

    $db = getDB();
    $db->prepare("UPDATE users SET email_verification_hash = ?, email_verification_expires_at = ?, verification_sent_at = NOW() WHERE id = ?")
       ->execute([$hash, $expires, $userId]);

    $base = getAppBaseUrl();
    $url  = $base . '/verify.php?email=' . rawurlencode($email) . '&token=' . rawurlencode($token);

    sendEmail($email, APP_NAME . ' — Verify your email',
        "Welcome to " . APP_NAME . "\n\nVerify your email to unlock your dashboard:\n\n" . $url . "\n\nThis link expires in " . EMAIL_VERIFY_TTL_HOURS . " hours.\n"
    );

    return (APP_ENV === 'development') ? $url : null;
}

function getAppBaseUrl(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir    = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    // If invoked from /api/*, step back to app root.
    $dir    = preg_replace('#/api$#', '', $dir);
    return $scheme . '://' . $host . ($dir ? $dir : '');
}

function sendEmail(string $to, string $subject, string $body): void {
    $from = defined('MAIL_FROM') ? MAIL_FROM : 'no-reply@localhost';
    $headers = [
        'From: ' . $from,
        'Reply-To: ' . $from,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'X-Mailer: PHP/' . phpversion(),
    ];
    // If mail() fails (common in dev), we still proceed — the UI can show a dev link.
    @mail($to, $subject, $body, implode("\r\n", $headers));
}

// ── Vault passphrase verification (server-side only) ─────────
// The server verifies the user KNOWS the passphrase (like a login check)
// but does NOT use it to derive any key. Key derivation happens in browser.
function verifyVaultPassphrase(string $passphrase, string $storedHash): bool {
    return password_verify($passphrase, $storedHash);
}

function hashVaultVerifier(string $passphrase): string {
    return password_hash($passphrase, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,  // 64 MB
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

// ── Login password (separate from vault passphrase) ──────────
function hashLoginPassword(string $password): string {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

// ── Cryptographically secure random salt (for client KDF) ────
// Server generates the salt, returns it to client.
// Salt alone is useless without vault passphrase.
function generateKdfSalt(): string {
    return base64_encode(random_bytes(32)); // 256-bit salt
}

// ── UUID v4 ───────────────────────────────────────────────────
function generateUUID(): string {
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

// ── Input ────────────────────────────────────────────────────
function sanitize(string $s): string {
    return htmlspecialchars(trim($s), ENT_QUOTES, 'UTF-8');
}

function jsonResponse(array $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    // Prevent caching of any API responses
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// ── CSRF ─────────────────────────────────────────────────────
function getCsrfToken(): string {
    startSecureSession();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrfToken(string $token): bool {
    startSecureSession();
    return isset($_SESSION['csrf_token']) &&
           hash_equals($_SESSION['csrf_token'], $token);
}

function requireCsrf(): void {
    $t = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!verifyCsrfToken($t)) {
        jsonResponse(['error' => 'Invalid CSRF token'], 403);
    }
}

// ── Audit log ────────────────────────────────────────────────
// Never log any key material, plaintext, or passphrases
function auditLog(string $action, ?string $lockId = null, ?int $userId = null): void {
    try {
        $db = getDB();
        $db->prepare("
            INSERT INTO audit_log (user_id, lock_id, action, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ")->execute([
            $userId ?? getCurrentUserId(),
            $lockId,
            $action,
            $_SERVER['REMOTE_ADDR'] ?? null,
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
        ]);
    } catch (Exception) { /* never break main flow */ }
}

// ── Timing-safe passphrase check gate ────────────────────────
// Used before any reveal endpoint — ensures user still knows their passphrase
// even if session is valid. Double-checks identity.
function requireVaultPassphrase(string $submitted): void {
    $userId = getCurrentUserId();
    if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

    $db   = getDB();
    $stmt = $db->prepare("SELECT vault_verifier, vault_verifier_salt FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $row  = $stmt->fetch();

    $salted = $submitted . ($row ? ($row['vault_verifier_salt'] ?? '') : '');
    if (!$row || !verifyVaultPassphrase($salted, $row['vault_verifier'])) {
        auditLog('vault_auth_fail');
        jsonResponse(['error' => 'Incorrect vault passphrase'], 403);
    }
}
