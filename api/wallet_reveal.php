<?php
// ============================================================
//  API: POST /api/wallet_reveal.php — returns ciphertext only
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
$walletId = trim((string)($body['wallet_lock_id'] ?? ''));
if ($walletId === '') jsonResponse(['error' => 'wallet_lock_id required'], 400);

$userId = getCurrentUserId();
$db = getDB();

$hasWallet = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' LIMIT 1")->fetchColumn();
if (!$hasWallet) {
    jsonResponse(['error' => 'Wallet locks are not available. Apply migrations in config/migrations/.'], 500);
}

$hasSetup = (bool)$db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' AND column_name = 'setup_status' LIMIT 1")->fetchColumn();
if (!$hasSetup) {
    jsonResponse(['error' => 'Wallet locks are not available (missing setup columns). Apply migrations in config/migrations/.'], 500);
}

$stmt = $db->prepare("\
    SELECT id, user_id, unlock_at, setup_status, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations, revealed_at
    FROM wallet_locks
    WHERE id = ? AND user_id = ? AND is_active = 1
    LIMIT 1\
");
$stmt->execute([$walletId, (int)$userId]);
$row = $stmt->fetch();
if (!$row) jsonResponse(['error' => 'Wallet lock not found'], 404);

if (($row['setup_status'] ?? '') !== 'active') {
    jsonResponse(['error' => 'Wallet lock setup is not complete'], 409);
}

$unlockDt = new DateTime($row['unlock_at']);
if ($unlockDt > new DateTime()) {
    jsonResponse(['error' => 'Not yet unlocked'], 403);
}

if (empty($row['revealed_at'])) {
    $db->prepare('UPDATE wallet_locks SET revealed_at = NOW() WHERE id = ?')->execute([$walletId]);
}

auditLog('wallet_lock_reveal', $walletId);

jsonResponse([
    'success' => true,
    'wallet_lock' => [
        'id' => $row['id'],
        'unlock_at' => $row['unlock_at'],
        'cipher_blob' => $row['cipher_blob'],
        'iv' => $row['iv'],
        'auth_tag' => $row['auth_tag'],
        'kdf_salt' => $row['kdf_salt'],
        'kdf_iterations' => (int)$row['kdf_iterations'],
    ],
]);
