<?php
// ============================================================
//  API: POST /api/confirm.php — Zero-Knowledge Edition
//  confirm / reject / auto_save flow (unchanged from v2 logic)
//  No crypto involvement — just status management.
//  On reject: returns cipher blobs for browser to decrypt so user sees void password.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$lockId = trim($body['lock_id'] ?? '');
$action = trim($body['action'] ?? '');

if (empty($lockId)) jsonResponse(['error' => 'lock_id required'], 400);
if (!in_array($action, ['confirm','reject','auto_save'], true)) jsonResponse(['error' => 'Invalid action'], 400);

$userId = getCurrentUserId();
$db     = getDB();

$stmt = $db->prepare("SELECT id, confirmation_status, reveal_date, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations FROM locks WHERE id = ? AND user_id = ? AND is_active = 1");
$stmt->execute([$lockId, $userId]);
$lock = $stmt->fetch();

if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);

$status = (string)$lock['confirmation_status'];

$getCurrentStatus = function() use ($db, $lockId, $userId, $status): string {
    $s = $db->prepare("SELECT confirmation_status FROM locks WHERE id = ? AND user_id = ? AND is_active = 1");
    $s->execute([$lockId, $userId]);
    $row = $s->fetch();
    return $row ? (string)$row['confirmation_status'] : $status;
};

// Status gates:
// - confirm/reject can operate on pending OR auto_saved (auto_saved is treated like pending).
// - auto_save can only transition pending -> auto_saved (idempotent if already auto_saved).
if ($action === 'auto_save') {
    if ($status === 'auto_saved') {
        jsonResponse(['success' => true, 'already_set' => $status]);
    }
    if ($status !== 'pending') {
        jsonResponse(['success' => true, 'already_set' => $status]);
    }
} else {
    if (!in_array($status, ['pending', 'auto_saved'], true)) {
        jsonResponse(['success' => true, 'already_set' => $status]);
    }
}

switch ($action) {
    case 'confirm':
        $u = $db->prepare("UPDATE locks SET confirmation_status='confirmed', confirmed_at=NOW() WHERE id=? AND user_id=? AND confirmation_status IN ('pending','auto_saved')");
        $u->execute([$lockId, $userId]);
        if ($u->rowCount() > 0) {
            auditLog('confirm', $lockId);
            jsonResponse(['success' => true, 'status' => 'confirmed', 'reveal_date' => $lock['reveal_date']]);
        }
        jsonResponse(['success' => true, 'already_set' => $getCurrentStatus()]);

    case 'reject':
        $u = $db->prepare("UPDATE locks SET confirmation_status='rejected', rejected_at=NOW() WHERE id=? AND user_id=? AND confirmation_status IN ('pending','auto_saved')");
        $u->execute([$lockId, $userId]);
        if ($u->rowCount() > 0) {
            auditLog('reject', $lockId);
            // Return cipher blobs — browser decrypts with vault passphrase to show void password
            jsonResponse([
                'success'        => true,
                'status'         => 'rejected',
                'cipher_blob'    => $lock['cipher_blob'],
                'iv'             => $lock['iv'],
                'auth_tag'       => $lock['auth_tag'],
                'kdf_salt'       => $lock['kdf_salt'],
                'kdf_iterations' => (int)$lock['kdf_iterations'],
            ]);
        }
        jsonResponse(['success' => true, 'already_set' => $getCurrentStatus()]);

    case 'auto_save':
        $u = $db->prepare("UPDATE locks SET confirmation_status='auto_saved', auto_saved_at=NOW() WHERE id=? AND user_id=? AND confirmation_status='pending'");
        $u->execute([$lockId, $userId]);
        if ($u->rowCount() > 0) {
            auditLog('auto_save', $lockId);
            jsonResponse(['success' => true, 'status' => 'auto_saved']);
        }
        jsonResponse(['success' => true, 'already_set' => $getCurrentStatus()]);
}
