<?php
// ============================================================
//  API: POST /api/confirm.php — Zero-Knowledge Edition
//  confirm / reject / auto_save flow (unchanged from v2 logic)
//  No crypto involvement — just status management.
//  On reject: returns cipher blobs for browser to decrypt so user sees void password.
// ============================================================

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
if (!in_array($action, ['confirm','reject','auto_save'])) jsonResponse(['error' => 'Invalid action'], 400);

$userId = getCurrentUserId();
$db     = getDB();

$stmt = $db->prepare("SELECT id, confirmation_status, reveal_date, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations FROM locks WHERE id = ? AND user_id = ? AND is_active = 1");
$stmt->execute([$lockId, $userId]);
$lock = $stmt->fetch();

if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);
if ($lock['confirmation_status'] !== 'pending') {
    jsonResponse(['success' => true, 'already_set' => $lock['confirmation_status']]);
}

switch ($action) {
    case 'confirm':
        $db->prepare("UPDATE locks SET confirmation_status='confirmed', confirmed_at=NOW() WHERE id=? AND user_id=?")
           ->execute([$lockId, $userId]);
        auditLog('confirm', $lockId);
        jsonResponse(['success' => true, 'status' => 'confirmed', 'reveal_date' => $lock['reveal_date']]);

    case 'reject':
        $db->prepare("UPDATE locks SET confirmation_status='rejected', rejected_at=NOW() WHERE id=? AND user_id=?")
           ->execute([$lockId, $userId]);
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

    case 'auto_save':
        $db->prepare("UPDATE locks SET confirmation_status='auto_saved', auto_saved_at=NOW() WHERE id=? AND user_id=?")
           ->execute([$lockId, $userId]);
        auditLog('auto_save', $lockId);
        jsonResponse(['success' => true, 'status' => 'auto_saved']);
}
