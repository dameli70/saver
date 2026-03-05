<?php
// ============================================================
//  API: GET /api/wallet_locks.php — metadata only
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

$userId = getCurrentUserId();
$db     = getDB();

$has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' LIMIT 1")->fetchColumn();
if (!$has) {
    jsonResponse(['error' => 'Wallet locks are not available. Apply migrations in config/migrations/.'], 500);
}

$hasSetup = (bool)$db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' AND column_name = 'setup_status' LIMIT 1")->fetchColumn();
if (!$hasSetup) {
    jsonResponse(['error' => 'Wallet locks are not available (missing setup columns). Apply migrations in config/migrations/.'], 500);
}

$stmt = $db->prepare("\
    SELECT
        w.id,
        w.label,
        w.unlock_at,
        w.setup_status,
        w.setup_confirmed_at,
        w.setup_failed_at,
        w.revealed_at,
        w.created_at,
        w.is_active,
        c.id AS carrier_id,
        c.name AS carrier_name,
        CASE
            WHEN w.is_active = 1 AND w.setup_status = 'pending' THEN 'setup_pending'
            WHEN w.is_active = 1 AND w.setup_status = 'failed'  THEN 'setup_failed'
            WHEN w.is_active = 1 AND w.setup_status = 'active' AND w.unlock_at <= NOW() THEN 'unlocked'
            WHEN w.is_active = 1 AND w.setup_status = 'active'                          THEN 'locked'
            ELSE 'inactive'
        END AS display_status
    FROM wallet_locks w
    JOIN carriers c ON c.id = w.carrier_id
    WHERE w.user_id = ? AND w.is_active = 1
    ORDER BY w.created_at DESC\
");
$stmt->execute([(int)$userId]);
$rows = $stmt->fetchAll();

$now = new DateTime();
foreach ($rows as &$row) {
    if ($row['display_status'] === 'locked') {
        $r    = new DateTime($row['unlock_at']);
        $diff = $now->diff($r);
        $row['time_remaining'] = [
            'days' => (int)$diff->days,
            'hours' => (int)$diff->h,
            'minutes' => (int)$diff->i,
            'total_seconds' => max(0, $r->getTimestamp() - $now->getTimestamp()),
        ];
    } else {
        $row['time_remaining'] = null;
    }
}
unset($row);

jsonResponse(['success' => true, 'wallet_locks' => $rows]);
