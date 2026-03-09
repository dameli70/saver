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

$hasSetup = (bool)$db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' AND column_name = 'setup_status' LIMIT 1")->fetchColumn();
if (!$hasSetup) {
    jsonResponse(['error' => 'Wallet locks are not available (missing setup columns). Apply migrations in config/migrations/.'], 500);
}

$stmt = $db->prepare('SELECT setup_status, revealed_at FROM wallet_locks WHERE id = ? AND user_id = ? AND is_active = 1 LIMIT 1');
$stmt->execute([$walletId, (int)$userId]);
$row = $stmt->fetch();

if (!$row) {
    jsonResponse(['error' => 'Not found'], 404);
}

// Only active (setup-complete) wallet locks are protected from early deletion.
if (($row['setup_status'] ?? '') === 'active') {
    if (empty($row['revealed_at'])) {
        jsonResponse([
            'error' => 'This code cannot be deleted until it has been revealed at least once.',
            'error_code' => 'delete_not_allowed',
        ], 403);
    }

    $revealedAt = new DateTimeImmutable((string)$row['revealed_at']);
    $earliest   = $revealedAt->modify('+1 month');
    $now        = new DateTimeImmutable('now', $revealedAt->getTimezone());

    if ($now < $earliest) {
        $diff = $now->diff($earliest);
        jsonResponse([
            'error' => 'This code can be deleted 1 month after it is revealed.',
            'error_code' => 'delete_too_soon',
            'earliest_delete_at' => $earliest->format('Y-m-d H:i:s'),
            'time_remaining' => sprintf('%dd %dh %dm', $diff->days, $diff->h, $diff->i),
        ], 403);
    }
}

$stmt = $db->prepare('UPDATE wallet_locks SET is_active = 0 WHERE id = ? AND user_id = ? AND is_active = 1');
$stmt->execute([$walletId, (int)$userId]);

if ($stmt->rowCount() < 1) {
    jsonResponse(['error' => 'Not found'], 404);
}

auditLog('wallet_lock_delete', $walletId);
jsonResponse(['success' => true]);
