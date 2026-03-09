<?php
// ============================================================
//  API: POST /api/wallet_delete.php
//  Deactivates a wallet lock (ciphertext only).
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

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

$stmt = $db->prepare('UPDATE wallet_locks SET is_active = 0 WHERE id = ? AND user_id = ?');
$stmt->execute([$walletId, (int)$userId]);

if ($stmt->rowCount() < 1) {
    jsonResponse(['error' => 'Not found'], 404);
}

auditLog('wallet_lock_delete', $walletId);
jsonResponse(['success' => true]);
