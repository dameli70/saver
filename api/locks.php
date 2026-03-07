<?php
// ============================================================
//  API: GET /api/locks.php — returns metadata only, no crypto material
// ============================================================
require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireVerifiedEmail();
if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

$userId = getCurrentUserId();
$db     = getDB();

// Server-side safety net: convert stale pending drafts to auto-saved so they
// don't remain "pending" forever if the browser tab is closed before the
// client timer fires.
$db->prepare("UPDATE locks
              SET confirmation_status='auto_saved', auto_saved_at=NOW()
              WHERE user_id = ?
                AND is_active = 1
                AND confirmation_status = 'pending'
                AND created_at <= (NOW() - INTERVAL 2 MINUTE)")
   ->execute([(int)$userId]);

$stmt = $db->prepare("
    SELECT id, label, password_type, password_length, hint,
           reveal_date, confirmation_status,
           copied_at, confirmed_at, rejected_at, auto_saved_at, revealed_at, created_at,
           CASE
               WHEN confirmation_status='confirmed' AND reveal_date <= UTC_TIMESTAMP() THEN 'unlocked'
               WHEN confirmation_status='confirmed'                                    THEN 'locked'
               WHEN confirmation_status='pending'                                      THEN 'pending'
               WHEN confirmation_status='rejected'                                     THEN 'rejected'
               WHEN confirmation_status='auto_saved'                                   THEN 'auto_saved'
               ELSE 'unknown'
           END AS display_status
    FROM locks
    WHERE user_id = ? AND is_active = 1
    ORDER BY created_at DESC
");
$stmt->execute([$userId]);
$locks = $stmt->fetchAll();

$now = new DateTime('now', new DateTimeZone('UTC'));
foreach ($locks as &$lock) {
    $lock['label'] = normalizeDisplayText($lock['label'] ?? null);
    $lock['hint'] = normalizeDisplayText($lock['hint'] ?? null);

    if ($lock['display_status'] === 'locked') {
        $r    = new DateTime($lock['reveal_date'], new DateTimeZone('UTC'));
        $diff = $now->diff($r);
        $lock['time_remaining'] = [
            'days' => (int)$diff->days, 'hours' => (int)$diff->h,
            'minutes' => (int)$diff->i, 'total_seconds' => max(0, $r->getTimestamp() - $now->getTimestamp()),
        ];
    } else {
        $lock['time_remaining'] = null;
    }
}
unset($lock);
jsonResponse(['success' => true, 'locks' => $locks]);
