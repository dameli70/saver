<?php
// ============================================================
//  Controle — Server-Side Helpers (Zero-Knowledge Edition)
//
//  WHAT THIS FILE DOES NOT DO (by design):
//  - Does NOT derive any encryption key
//  - Does NOT store, transmit, or compute over plaintext passwords
//  - Does NOT have any function that can decrypt a lock
//
//  The only crypto here is:
//  - Argon2id for login password hashing (authentication)
//  - Argon2id for vault passphrase verification (legacy identity check only)
//  - Session token generation (random)
//  - Encrypting server-stored secrets (e.g., TOTP seed) with AES-256-GCM
//  - UUID generation
// ============================================================

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/smtp.php';
require_once __DIR__ . '/i18n.php';

// ── Session ──────────────────────────────────────────────────
function isHttpsRequest(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;

    $scheme = strtolower((string)($_SERVER['REQUEST_SCHEME'] ?? ''));
    if ($scheme === 'https') return true;

    $xfp = (string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '');
    if ($xfp !== '') {
        $xfp = strtolower(trim(explode(',', $xfp)[0]));
        if ($xfp === 'https') return true;
    }

    $xfs = strtolower((string)($_SERVER['HTTP_X_FORWARDED_SSL'] ?? ''));
    if ($xfs === 'on') return true;

    return false;
}

function appSessionCookiePath(): string {
    if (function_exists('getAppBasePath')) {
        $base = (string)getAppBasePath();
        return ($base !== '') ? $base : '/';
    }

    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    $dir = preg_replace('#/(api|install)$#', '', $dir);
    if ($dir === '' || $dir === '/' || $dir === '.') return '/';
    return $dir;
}

function appSessionName(): string {
    // Avoid collisions with other PHP apps on the same domain (default PHPSESSID).
    // Include the base path so multiple installs on one domain don't conflict.
    $path = appSessionCookiePath();
    return 'controle_sess_' . substr(hash('sha256', $path), 0, 12);
}

function startSecureSession(): void {
    if (session_status() !== PHP_SESSION_NONE) {
        if (function_exists('i18nBootstrap')) {
            i18nBootstrap();
        }
        return;
    }

    // Use a stable, app-specific session cookie name (prevents collisions across multiple apps).
    session_name(appSessionName());

    $sent = false;
    try { $sent = headers_sent(); } catch (Throwable) { $sent = false; }

    // Session settings must be applied before session_start().
    if (!$sent) {
        $cookiePath = appSessionCookiePath();

        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isHttpsRequest() ? 1 : 0);

        // Lax prevents losing the session after cross-site top-level navigations
        // (e.g., email verification link -> verify.php -> dashboard.php).
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.cookie_path', $cookiePath);

        ini_set('session.use_strict_mode', 1);
        ini_set('session.gc_maxlifetime', 3600);
    }

    // Avoid sending cache limiter headers from session_start().
    // This reduces the chance of "headers already sent" issues in edge environments.
    if (function_exists('session_cache_limiter')) {
        session_cache_limiter('');
    }

    // If headers are already sent and there's no existing session cookie, we can't start a new session.
    if ($sent && !isset($_COOKIE[session_name()])) {
        return;
    }

    session_start();

    // Initialize i18n after session_start() so it can read/write language preference.
    // Default language is French.
    if (function_exists('i18nBootstrap')) {
        i18nBootstrap();
    }
}

function hasUserSessionsTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'user_sessions' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasPasswordResetColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'password_reset_hash' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasVaultAltVerifierColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'vault_verifier_alt' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasLockVaultVerifierSlotColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'locks' AND column_name = 'vault_verifier_slot' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasLockInboundLinkIdColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'locks' AND column_name = 'inbound_link_id' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasInboundLockLinksTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    $cached = dbHasTable('inbound_lock_links');
    return (bool)$cached;
}

function hasInboundLockLinksWrapColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    if (!hasInboundLockLinksTable()) {
        $cached = false;
        return false;
    }

    $required = [
        'secret_cipher_blob',
        'secret_iv',
        'secret_auth_tag',
        'secret_kdf_salt',
        'secret_kdf_iterations',
    ];

    foreach ($required as $col) {
        if (!dbHasColumn('inbound_lock_links', $col)) {
            $cached = false;
            return false;
        }
    }

    if (!dbHasColumn('inbound_lock_links', 'link_id') && !dbHasColumn('inbound_lock_links', 'id')) {
        $cached = false;
        return false;
    }

    $cached = true;
    return true;
}

function hasVaultActiveSlotColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'vault_active_slot' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasVaultCheckColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'vault_check_cipher' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function userHasVaultPassphraseCheck(int $userId): bool {
    if (!hasVaultCheckColumns()) return false;
    $db = getDB();
    $stmt = $db->prepare('SELECT vault_check_cipher FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();
    return $u && !empty($u['vault_check_cipher']);
}

function hasOnboardingColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'onboarding_completed_at' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasRoomDisplayNameColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'room_display_name' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasProfileImageUrlColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'profile_image_url' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function dbHasTable(string $table): bool {
    static $cache = [];
    if (array_key_exists($table, $cache)) return (bool)$cache[$table];

    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1");
        $stmt->execute([$table]);
        $cache[$table] = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $cache[$table] = false;
    }

    return (bool)$cache[$table];
}

function dbHasColumn(string $table, string $column): bool {
    static $cache = [];
    $key = $table . '.' . $column;
    if (array_key_exists($key, $cache)) return (bool)$cache[$key];

    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
        $stmt->execute([$table, $column]);
        $cache[$key] = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $cache[$key] = false;
    }

    return (bool)$cache[$key];
}

function generateRandomUnlockCode(int $length = 12): string {
    $len = max(6, min(64, (int)$length));

    // Human-friendly alphabet (no 0/1/I/O).
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $out = '';

    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }

    return $out;
}

function sqlRoomUserDisplayNameExpr(string $alias = 'u', string $idCol = 'id'): string {
    if (!hasRoomDisplayNameColumn()) {
        return "CONCAT('User #', {$alias}.{$idCol})";
    }

    return "CASE WHEN {$alias}.room_display_name IS NOT NULL AND TRIM({$alias}.room_display_name) <> '' THEN {$alias}.room_display_name ELSE CONCAT('User #', {$alias}.{$idCol}) END";
}

function isOnboardingComplete(?int $userId = null): bool {
    startSecureSession();

    // If the column doesn't exist, don't block users from the app.
    if (!hasOnboardingColumns()) return true;

    if (!empty($_SESSION['onboarding_complete'])) return true;

    $uid = $userId ?? getCurrentUserId();
    if (!$uid) return false;

    $db = getDB();
    $stmt = $db->prepare('SELECT onboarding_completed_at FROM users WHERE id = ?');
    $stmt->execute([(int)$uid]);
    $row = $stmt->fetch();

    $ok = !empty($row['onboarding_completed_at']);
    if ($ok && $uid === getCurrentUserId()) {
        $_SESSION['onboarding_complete'] = 1;
    }
    return $ok;
}

function markOnboardingComplete(int $userId): void {
    startSecureSession();

    if (!hasOnboardingColumns()) return;

    $db = getDB();
    $db->prepare('UPDATE users SET onboarding_completed_at = NOW() WHERE id = ?')->execute([(int)$userId]);

    // Clear any "skip setup" preference once onboarding is complete.
    if (function_exists('setUserSkipSetupRedirect')) {
        setUserSkipSetupRedirect((int)$userId, false);
    }

    if ($userId === getCurrentUserId()) {
        $_SESSION['onboarding_complete'] = 1;
    }
}

function userSkipSetupRedirect(int $userId): bool {
    if (!hasNotificationPreferencesTable()) return false;
    $prefs = getUserNotificationPrefs((int)$userId, 'informational');
    return !empty($prefs['skip_setup']);
}

function setUserSkipSetupRedirect(int $userId, bool $skip): void {
    if (!hasNotificationPreferencesTable()) return;
    setUserNotificationPref((int)$userId, 'informational', 'skip_setup', $skip ? 1 : 0);
}

function currentSessionIdHash(): string {
    startSecureSession();
    return hash_hmac('sha256', session_id(), APP_HMAC_SECRET);
}

function registerCurrentSession(int $userId): void {
    if (!hasUserSessionsTable()) return;

    $db = getDB();
    $db->prepare("INSERT INTO user_sessions (user_id, session_id_hash, ip_address, user_agent) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE last_seen_at = NOW(), ip_address = VALUES(ip_address), user_agent = VALUES(user_agent)")
       ->execute([
           $userId,
           currentSessionIdHash(),
           $_SERVER['REMOTE_ADDR'] ?? null,
           substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
       ]);
}

function deleteCurrentSessionRecord(?int $userId = null): void {
    if (!hasUserSessionsTable()) return;

    $uid = $userId ?? getCurrentUserId();
    if (!$uid) return;

    $db = getDB();
    $db->prepare('DELETE FROM user_sessions WHERE user_id = ? AND session_id_hash = ?')
       ->execute([(int)$uid, currentSessionIdHash()]);
}

function deleteAllSessionRecords(int $userId): void {
    if (!hasUserSessionsTable()) return;
    $db = getDB();
    $db->prepare('DELETE FROM user_sessions WHERE user_id = ?')->execute([(int)$userId]);
}

function validateCurrentSession(int $userId): bool {
    if (!hasUserSessionsTable()) return true;

    $db = getDB();
    $stmt = $db->prepare('SELECT id FROM user_sessions WHERE user_id = ? AND session_id_hash = ? LIMIT 1');
    $stmt->execute([(int)$userId, currentSessionIdHash()]);
    $row = $stmt->fetch();

    if (!$row) return false;

    $db->prepare('UPDATE user_sessions SET last_seen_at = NOW() WHERE id = ?')->execute([(int)$row['id']]);
    return true;
}

function isLoggedIn(): bool {
    startSecureSession();

    $uid = $_SESSION['user_id'] ?? null;
    if (!$uid) return false;

    if (!validateCurrentSession((int)$uid)) {
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
        return false;
    }

    return true;
}

function requireLogin(): void {
    if (!isLoggedIn()) { jsonResponse(['error' => 'Unauthorized'], 401); }
}

function getCurrentUserId(): ?int { return $_SESSION['user_id'] ?? null; }
function getCurrentUserEmail(): ?string { return $_SESSION['email'] ?? null; }

// ── Admin ───────────────────────────────────────────────────
function isAdmin(?int $userId = null): bool {
    startSecureSession();

    if ($userId === null) {
        if (!empty($_SESSION['is_admin'])) return true;
        $userId = getCurrentUserId();
        if (!$userId) return false;
    }

    try {
        $db   = getDB();
        $stmt = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([(int)$userId]);
        $row = $stmt->fetch();
        $ok = !empty($row['is_admin']);
        if ($userId === getCurrentUserId()) {
            $_SESSION['is_admin'] = $ok ? 1 : 0;
        }
        return $ok;
    } catch (Throwable) {
        return false;
    }
}

function requireAdmin(): void {
    if (!isAdmin()) jsonResponse(['error' => 'Admin access required'], 403);
}

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

function issuePasswordReset(int $userId, string $email): ?string {
    $token   = bin2hex(random_bytes(32));
    $hash    = hash('sha256', $token);
    $minutes = defined('PASSWORD_RESET_TTL_MINUTES') ? (int)PASSWORD_RESET_TTL_MINUTES : 60;
    if ($minutes < 10) $minutes = 10;
    if ($minutes > 720) $minutes = 720;

    $expires = (new DateTime())->modify('+' . $minutes . ' minutes')->format('Y-m-d H:i:s');

    $db = getDB();
    $db->prepare("UPDATE users SET password_reset_hash = ?, password_reset_expires_at = ?, password_reset_sent_at = NOW() WHERE id = ?")
       ->execute([$hash, $expires, $userId]);

    $base = getAppBaseUrl();
    $url  = $base . '/reset.php?email=' . rawurlencode($email) . '&token=' . rawurlencode($token);

    sendEmail($email, APP_NAME . ' — Reset your login password',
        "A password reset was requested for " . APP_NAME . ".\n\nReset your login password here:\n\n" . $url . "\n\nIf you did not request this, you can ignore this email.\n"
    );

    return (APP_ENV === 'development') ? $url : null;
}

function getAppBaseUrl(): string {
    // Prefer a configured canonical base URL to avoid Host header injection in emailed links.
    if (defined('APP_BASE_URL')) {
        $b = trim((string)APP_BASE_URL);
        if ($b !== '') return rtrim($b, '/');
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';

    // In production, prefer SERVER_NAME (server config) over HTTP_HOST (request header).
    $host = 'localhost';
    if (defined('APP_ENV') && APP_ENV === 'production' && !empty($_SERVER['SERVER_NAME'])) {
        $host = (string)$_SERVER['SERVER_NAME'];
    } elseif (!empty($_SERVER['HTTP_HOST'])) {
        $host = (string)$_SERVER['HTTP_HOST'];
    } elseif (!empty($_SERVER['SERVER_NAME'])) {
        $host = (string)$_SERVER['SERVER_NAME'];
    }

    // Minimal sanitation: strip characters that should never appear in a host.
    $host = preg_replace('/[^A-Za-z0-9.\-:]/', '', (string)$host);
    if ($host === '') $host = 'localhost';

    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
    // If invoked from /api/*, step back to app root.
    $dir = preg_replace('#/api$#', '', $dir);

    return $scheme . '://' . $host . ($dir ? $dir : '');
}

function sendEmail(string $to, string $subject, string $body): void {
    $from = defined('MAIL_FROM') ? MAIL_FROM : 'no-reply@localhost';

    if (defined('SMTP_HOST') && SMTP_HOST !== '') {
        // If SMTP fails for any reason, we still proceed — the UI can show a dev link.
        if (@smtpSendMessage($to, $subject, $body, $from)) {
            return;
        }
    }

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

// Historically some fields were escaped before storage (escape-on-write).
// Normalize those legacy values so they render correctly.
function normalizeDisplayText(?string $s): ?string {
    if ($s === null) return null;
    $s = (string)$s;
    if ($s === '') return '';

    if (!preg_match('/&(?:[a-zA-Z]+|#\d+|#x[0-9A-Fa-f]+);/', $s)) {
        return $s;
    }

    $decoded = html_entity_decode($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return $decoded;
}

function jsonResponse(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    // Prevent caching of any API responses
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// ── CSRF ─────────────────────────────────────────────────────
// Random per-session token (not an HMAC).
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
function requireVaultPassphrase(string $submitted, int $slot = 1): void {
    $userId = getCurrentUserId();
    if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

    if (!in_array($slot, [1, 2], true)) $slot = 1;

    $db = getDB();

    $select = hasVaultAltVerifierColumns()
        ? "vault_verifier, vault_verifier_salt, vault_verifier_alt, vault_verifier_alt_salt"
        : "vault_verifier, vault_verifier_salt, NULL AS vault_verifier_alt, NULL AS vault_verifier_alt_salt";

    $stmt = $db->prepare("SELECT {$select} FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    if (!$row) jsonResponse(['error' => 'Unauthorized'], 401);

    if ($slot === 2) {
        if (empty($row['vault_verifier_alt']) || empty($row['vault_verifier_alt_salt'])) {
            jsonResponse(['error' => 'Vault rotation not initialized'], 403);
        }
        $hash = $row['vault_verifier_alt'];
        $salt = $row['vault_verifier_alt_salt'];
    } else {
        $hash = $row['vault_verifier'];
        $salt = $row['vault_verifier_salt'] ?? '';
    }

    $salted = $submitted . $salt;
    if (!verifyVaultPassphrase($salted, $hash)) {
        auditLog('vault_auth_fail');
        jsonResponse(['error' => 'Incorrect vault passphrase'], 403);
    }
}

// ── Strong auth (step-up) ───────────────────────────────────
// For sensitive actions (reveal, vault rotation commit, backups):
// require a recent passkey assertion or TOTP check.
function setStrongAuth(int $ttlSeconds = 600): void {
    startSecureSession();
    $_SESSION['strong_auth_until'] = time() + max(30, $ttlSeconds);
}

function hasStrongAuth(): bool {
    startSecureSession();
    return !empty($_SESSION['strong_auth_until']) && (int)$_SESSION['strong_auth_until'] >= time();
}

function hasTotpColumns(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'totp_secret_enc' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasWebauthnCredentialsTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'webauthn_credentials' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function userHasTotp(int $userId): bool {
    if (!hasTotpColumns()) return false;
    $db = getDB();
    $stmt = $db->prepare('SELECT totp_enabled_at FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();
    return $u && !empty($u['totp_enabled_at']);
}

function userHasPasskeys(int $userId): bool {
    if (!hasWebauthnCredentialsTable()) return false;
    $db = getDB();
    $stmt = $db->prepare('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?');
    $stmt->execute([(int)$userId]);
    return (int)$stmt->fetchColumn() > 0;
}

function hasNotificationPreferencesTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'notification_preferences' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function getUserNotificationPrefs(int $userId, string $tier = 'important'): array {
    if (!hasNotificationPreferencesTable()) return [];

    $col = ($tier === 'informational') ? 'informational_json' : 'important_json';

    $db = getDB();
    $stmt = $db->prepare("SELECT {$col} AS prefs_json FROM notification_preferences WHERE user_id = ?");
    $stmt->execute([(int)$userId]);
    $row = $stmt->fetch();

    if (!$row || empty($row['prefs_json'])) return [];

    $decoded = json_decode((string)$row['prefs_json'], true);
    return is_array($decoded) ? $decoded : [];
}

function setUserNotificationPref(int $userId, string $tier, string $key, $value): void {
    if (!hasNotificationPreferencesTable()) return;

    $col = ($tier === 'informational') ? 'informational_json' : 'important_json';

    $prefs = getUserNotificationPrefs($userId, $tier);
    $prefs[$key] = $value;

    $db = getDB();
    $json = json_encode($prefs, JSON_UNESCAPED_UNICODE);

    $db->prepare("INSERT INTO notification_preferences (user_id, {$col}, updated_at)
                  VALUES (?, ?, NOW())
                  ON DUPLICATE KEY UPDATE {$col} = VALUES({$col}), updated_at = NOW()")
       ->execute([(int)$userId, $json]);
}

function userWantsEmailTimeLockReminders(int $userId): bool {
    $prefs = getUserNotificationPrefs($userId, 'important');
    return !empty($prefs['email_time_lock_reminders']);
}

function hasLockSharesTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'lock_shares' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasLockSharePrepsTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'lock_share_preps' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function hasLockSharesAllowRevealAfterDateColumn(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'lock_shares' AND column_name = 'allow_reveal_after_date' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function requireStrongAuth(): void {
    if (hasStrongAuth()) return;

    $uid = getCurrentUserId();
    if (!$uid) jsonResponse(['error' => 'Unauthorized'], 401);

    $methods = [
        'totp' => userHasTotp((int)$uid),
        'passkey' => userHasPasskeys((int)$uid),
    ];

    if (!$methods['totp'] && !$methods['passkey']) {
        jsonResponse([
            'error' => 'Security setup required. Enable TOTP or add a passkey from your account page.',
            'error_code' => 'security_setup_required',
            'methods' => $methods,
        ], 403);
    }

    jsonResponse([
        'error' => 'Re-authentication required for this action.',
        'error_code' => 'reauth_required',
        'methods' => $methods,
    ], 403);
}

// ── Base64url helpers ───────────────────────────────────────
function b64urlEncode(string $raw): string {
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function b64urlDecode(string $b64url): string {
    $b64 = strtr($b64url, '-_', '+/');
    $pad = strlen($b64) % 4;
    if ($pad) $b64 .= str_repeat('=', 4 - $pad);
    $raw = base64_decode($b64, true);
    return ($raw === false) ? '' : $raw;
}

// ── TOTP (RFC 6238) ─────────────────────────────────────────
function base32Encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $out = '';
    $buffer = 0;
    $bits = 0;

    for ($i = 0; $i < strlen($data); $i++) {
        $buffer = ($buffer << 8) | ord($data[$i]);
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $out .= $alphabet[($buffer >> $bits) & 31];
        }
    }

    if ($bits > 0) {
        $out .= $alphabet[($buffer << (5 - $bits)) & 31];
    }

    return $out;
}

function base32Decode(string $str): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $map = array_flip(str_split($alphabet));

    $s = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $str));
    $buffer = 0;
    $bits = 0;
    $out = '';

    for ($i = 0; $i < strlen($s); $i++) {
        $ch = $s[$i];
        if (!isset($map[$ch])) continue;
        $buffer = ($buffer << 5) | $map[$ch];
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $out .= chr(($buffer >> $bits) & 255);
        }
    }

    return $out;
}

function generateTotpSecret(): string {
    return base32Encode(random_bytes(20)); // 160-bit secret
}

function totpNow(string $base32Secret, int $period = 30, int $digits = 6, ?int $atTime = null): string {
    $secret = base32Decode($base32Secret);
    $t = $atTime ?? time();
    $counter = intdiv($t, $period);

    $binCounter = pack('N*', 0) . pack('N*', $counter);
    $hash = hash_hmac('sha1', $binCounter, $secret, true);

    $offset = ord($hash[19]) & 0x0f;
    $part = substr($hash, $offset, 4);
    $value = unpack('N', $part)[1] & 0x7fffffff;

    $mod = 10 ** $digits;
    return str_pad((string)($value % $mod), $digits, '0', STR_PAD_LEFT);
}

function verifyTotpCode(string $base32Secret, string $code, int $window = 1): bool {
    $c = preg_replace('/\s+/', '', $code);
    if (!preg_match('/^\d{6}$/', $c)) return false;

    $now = time();
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(totpNow($base32Secret, 30, 6, $now + ($i * 30)), $c)) {
            return true;
        }
    }
    return false;
}

function appEncKey(): string {
    return hash('sha256', APP_HMAC_SECRET, true);
}

function encryptForDb(string $plaintext): string {
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', appEncKey(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }
    return base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($cipher);
}

function decryptFromDb(string $enc): string {
    $parts = explode('.', $enc);
    if (count($parts) !== 3) throw new RuntimeException('Invalid encrypted value');

    $iv = base64_decode($parts[0], true);
    $tag = base64_decode($parts[1], true);
    $cipher = base64_decode($parts[2], true);

    if ($iv === false || $tag === false || $cipher === false) {
        throw new RuntimeException('Invalid encrypted value');
    }

    $plain = openssl_decrypt($cipher, 'aes-256-gcm', appEncKey(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($plain === false) {
        throw new RuntimeException('Decryption failed');
    }

    return $plain;
}
 