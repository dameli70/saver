<?php
// ============================================================
//  API: POST /api/generate.php — Zero-Knowledge Edition
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
registerApiErrorHandling();
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);

// ── Validate metadata ─────────────────────────────────────────
$label      = trim((string)($body['label'] ?? ''));
$type       = (string)($body['type'] ?? 'alphanumeric');
$length     = (int)($body['length'] ?? 16);
$revealDate = (string)($body['reveal_date'] ?? '');
$hint       = trim((string)($body['hint'] ?? ''));
$slot = isset($body['vault_verifier_slot']) ? (int)$body['vault_verifier_slot'] : 0;
if (!in_array($slot, [1, 2], true)) $slot = 0;

// ── Validate zero-knowledge crypto fields (opaque blobs from browser) ──
$cipherBlob = trim((string)($body['cipher_blob'] ?? ''));
$iv         = trim((string)($body['iv'] ?? ''));
$authTag    = trim((string)($body['auth_tag'] ?? ''));
$kdfSalt    = trim((string)($body['kdf_salt'] ?? ''));

if ($label === '')      jsonResponse(['error' => 'Label is required'], 400);
if ($cipherBlob === '') jsonResponse(['error' => 'cipher_blob missing'], 400);
if ($iv === '')         jsonResponse(['error' => 'iv missing'], 400);
if ($authTag === '')    jsonResponse(['error' => 'auth_tag missing'], 400);
if ($kdfSalt === '')    jsonResponse(['error' => 'kdf_salt missing'], 400);

// Verify salt was legitimately issued by this server for this user/session.
// Support multiple pending salts (e.g., multiple tabs generating in parallel).
$userIdForSalt = (int)getCurrentUserId();
$listKey = 'pending_salts_' . $userIdForSalt;
$singleKey = 'pending_salt_' . $userIdForSalt;

$pending = [];
if (!empty($_SESSION[$listKey]) && is_array($_SESSION[$listKey])) {
    $pending = array_values(array_filter($_SESSION[$listKey], 'is_string'));
} elseif (!empty($_SESSION[$singleKey]) && is_string($_SESSION[$singleKey])) {
    // Backward-compatible: older installs stored a single pending salt.
    $pending = [$_SESSION[$singleKey]];
}

$idx = array_search($kdfSalt, $pending, true);
if ($idx === false) {
    jsonResponse(['error' => 'Invalid or expired KDF salt — request a new one'], 400);
}

// One-time use: remove the used salt.
unset($pending[$idx]);
$pending = array_values($pending);
$_SESSION[$listKey] = $pending;
unset($_SESSION[$singleKey]);

$validTypes = ['numeric','alpha','alphanumeric','custom'];
if (!in_array($type, $validTypes, true)) jsonResponse(['error' => 'Invalid type'], 400);
if ($length < 4 || $length > 128)        jsonResponse(['error' => 'Length must be 4–128'], 400);
if (strlen($hint) > 500)                 jsonResponse(['error' => 'Hint too long'], 400);
if ($revealDate === '')                  jsonResponse(['error' => 'Reveal date required'], 400);

try {
    // Normalize reveal_date to UTC to avoid timezone ambiguity across client/PHP/MySQL.
    // Accepts ISO-8601 (recommended) or legacy "Y-m-d H:i:s" strings.
    $revealDt = new DateTimeImmutable($revealDate, new DateTimeZone('UTC'));
    $nowUtc   = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if ($revealDt <= $nowUtc) jsonResponse(['error' => 'Reveal date must be future'], 400);
} catch (Exception) {
    jsonResponse(['error' => 'Invalid reveal date'], 400);
}

// Basic sanity checks on cipher material (base64 format, expected sizes)
if (base64_decode($iv, true) === false || strlen(base64_decode($iv)) !== 12)
    jsonResponse(['error' => 'IV must be 12 bytes (base64)'], 400);
if (base64_decode($authTag, true) === false || strlen(base64_decode($authTag)) !== 16)
    jsonResponse(['error' => 'auth_tag must be 16 bytes (base64)'], 400);
if (base64_decode($kdfSalt, true) === false || strlen(base64_decode($kdfSalt)) !== 32)
    jsonResponse(['error' => 'kdf_salt must be 32 bytes (base64)'], 400);

// ── Store — server never touches key material ─────────────────
try {
    $userId = getCurrentUserId();
    $lockId = generateUUID();
    $db     = getDB();

    if ($slot === 0 && hasVaultActiveSlotColumn()) {
        $stmt = $db->prepare('SELECT vault_active_slot FROM users WHERE id = ?');
        $stmt->execute([(int)$userId]);
        $u = $stmt->fetch();
        $slot = (int)($u['vault_active_slot'] ?? 1);
        if (!in_array($slot, [1,2], true)) $slot = 1;
    }
    if ($slot === 0) $slot = 1;

    if ($slot === 2 && !hasLockVaultVerifierSlotColumn()) {
        jsonResponse(['error' => 'Vault rotation is not available (missing vault rotation columns). Apply migrations in config/migrations/.'], 500);
    }

    $hasSlot = hasLockVaultVerifierSlotColumn();

    if ($hasSlot) {
        $sql = "
            INSERT INTO locks
                (id, user_id, label, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations, vault_verifier_slot,
                 password_type, password_length, hint, reveal_date, confirmation_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ";
        $params = [
            $lockId, $userId, $label,
            $cipherBlob, $iv, $authTag, $kdfSalt, PBKDF2_ITERATIONS, $slot,
            $type, $length,
            $hint !== '' ? $hint : null,
            $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
        ];
    } else {
        $sql = "
            INSERT INTO locks
                (id, user_id, label, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations,
                 password_type, password_length, hint, reveal_date, confirmation_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ";
        $params = [
            $lockId, $userId, $label,
            $cipherBlob, $iv, $authTag, $kdfSalt, PBKDF2_ITERATIONS,
            $type, $length,
            $hint !== '' ? $hint : null,
            $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
        ];
    }

    $db->prepare($sql)->execute($params);

    auditLog('generate', $lockId);

    jsonResponse([
        'success'     => true,
        'lock_id'     => $lockId,
        'label'       => $label,
        'reveal_date' => $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
    ]);

} catch (Exception $e) {
    auditLog('generate_error');
    jsonResponse(['error' => 'Storage failed'], 500);
}
