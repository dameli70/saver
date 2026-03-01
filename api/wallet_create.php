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
$kdfIters   = (int)($body['kdf_iterations'] ?? PBKDF2_ITERATIONS);

if ($carrierId < 1) jsonResponse(['error' => 'carrier_id required'], 400);
if ($unlockAt === '') jsonResponse(['error' => 'unlock_at required'], 400);

if ($cipherBlob === '') jsonResponse(['error' => 'cipher_blob missing'], 400);
if ($iv === '') jsonResponse(['error' => 'iv missing'], 400);
if ($authTag === '') jsonResponse(['error' => 'auth_tag missing'], 400);
if ($kdfSalt === '') jsonResponse(['error' => 'kdf_salt missing'], 400);

try {
    $unlockDt = new DateTime($unlockAt);
    if ($unlockDt <= new DateTime()) jsonResponse(['error' => 'Unlock time must be future'], 400);
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

// Verify salt was legitimately issued by this server for this user/session
$sessionKey = 'pending_salt_' . $userId;
$issuedSalt = $_SESSION[$sessionKey] ?? null;
if (!$issuedSalt || !hash_equals($issuedSalt, $kdfSalt)) {
    jsonResponse(['error' => 'Invalid or expired KDF salt — request a new one'], 400);
}
unset($_SESSION[$sessionKey]);

$stmt = $db->prepare('SELECT id FROM carriers WHERE id = ? AND is_active = 1');
$stmt->execute([$carrierId]);
if (!$stmt->fetch()) jsonResponse(['error' => 'Carrier not found'], 404);

$walletId = generateUUID();

$db->prepare("\
    INSERT INTO wallet_locks
        (id, user_id, carrier_id, label, unlock_at, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations)
    VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\
")->execute([
    $walletId,
    (int)$userId,
    $carrierId,
    $label !== '' ? sanitize($label) : null,
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
