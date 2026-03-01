<?php
// ============================================================
//  API: POST /api/wallet_confirm.php
//  Marks a wallet lock as active after the PIN-change USSD completes.
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

$stmt = $db->prepare("UPDATE wallet_locks SET setup_status = 'active', setup_confirmed_at = NOW() WHERE id = ? AND user_id = ? AND is_active = 1 AND setup_status = 'pending'");
$stmt->execute([$walletId, (int)$userId]);

if ($stmt->rowCount() < 1) {
    jsonResponse(['error' => 'Wallet lock not found or already confirmed'], 409);
}

auditLog('wallet_lock_confirm', $walletId);
jsonResponse(['success' => true]);
