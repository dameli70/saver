<?php
// ============================================================
//  API: POST /api/wallet_create.php — create a time-locked wallet PIN
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();
requireCsrf();
requireVerifiedEmail();
requireStrongAuth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);

$carrierId = (int)($body['carrier_id'] ?? 0);
$label     = trim((string)($body['label'] ?? ''));
$unlockAt  = (string)($body['unlock_at'] ?? '');

$cipherBlob = trim((string)($body['cipher_blob'] ?? ''));
$iv         = trim((string)($body['iv'] ?? ''));
$authTag    = trim((string)($body['auth_tag'] ?? ''));
$kdfSalt    = trim((string)($body['kdf_salt'] ?? ''));
// kdf_iterations is controlled server-side to prevent security downgrade.
$kdfIters   = PBKDF2_ITERATIONS;

if ($carrierId < 1) jsonResponse(['error' => 'carrier_id required'], 400);
if ($unlockAt === '') jsonResponse(['error' => 'unlock_at required'], 400);

if ($cipherBlob === '') jsonResponse(['error' => 'cipher_blob missing'], 400);
if ($iv === '') jsonResponse(['error' => 'iv missing'], 400);
if ($authTag === '') jsonResponse(['error' => 'auth_tag missing'], 400);
if ($kdfSalt === '') jsonResponse(['error' => 'kdf_salt missing'], 400);

try {
    // Normalize unlock time to UTC to avoid timezone ambiguity across client/PHP/MySQL.
    // Accepts ISO-8601 (recommended) or legacy "Y-m-d H:i:s" strings.
    $unlockDt = (new DateTimeImmutable($unlockAt, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'));
    $nowUtc   = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if ($unlockDt <= $nowUtc) jsonResponse(['error' => 'Unlock time must be future'], 400);
} catch (Exception) {
    jsonResponse(['error' => 'Invalid unlock time'], 400);
}

if (base64_decode($iv, true) === false || strlen(base64_decode($iv)) !== 12)
    jsonResponse(['error' => 'IV must be 12 bytes (base64)'], 400);
if (base64_decode($authTag, true) === false || strlen(base64_decode($authTag)) !== 16)
    jsonResponse(['error' => 'auth_tag must be 16 bytes (base64)'], 400);
if (base64_decode($kdfSalt, true) === false || strlen(base64_decode($kdfSalt)) !== 32)
    jsonResponse(['error' => 'kdf_salt must be 32 bytes (base64)'], 400);

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

$db = getDB();

$hasWallet = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' LIMIT 1")->fetchColumn();
if (!$hasWallet) {
    jsonResponse(['error' => 'Wallet locks are not available. Apply migrations in config/migrations/.'], 500);
}

// Verify salt was legitimately issued by this server for this user/session.
// Support multiple pending salts (e.g., multiple tabs generating in parallel).
$listKey   = 'pending_salts_' . (int)$userId;
$singleKey = 'pending_salt_' . (int)$userId;

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

$stmt = $db->prepare('SELECT id FROM carriers WHERE id = ? AND is_active = 1');
$stmt->execute([$carrierId]);
if (!$stmt->fetch()) jsonResponse(['error' => 'Carrier not found'], 404);

$walletId = generateUUID();

$db->prepare("
    INSERT INTO wallet_locks
        (id, user_id, carrier_id, label, unlock_at, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations)
    VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
")->execute([
    $walletId,
    (int)$userId,
    $carrierId,
    $label !== '' ? $label : null,
    $unlockDt->format('Y-m-d H:i:s'),
    $cipherBlob,
    $iv,
    $authTag,
    $kdfSalt,
    $kdfIters > 0 ? $kdfIters : PBKDF2_ITERATIONS,
]);

auditLog('wallet_lock_create', $walletId);

jsonResponse([
    'success' => true,
    'wallet_lock_id' => $walletId,
    'unlock_at' => $unlockDt->format('Y-m-d H:i:s'),
]);
