<?php
// ============================================================
//  API: POST /api/password_reset.php
//
//  Password reset affects ONLY the login password.
//  Vault passphrase is never recoverable.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

if ($action === 'request') {
    $email = strtolower(trim((string)($body['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Always return success to avoid enumeration
        jsonResponse(['success' => true]);
    }

    if (!hasPasswordResetColumns()) {
        jsonResponse(['error' => 'Password reset is not available (missing users.password_reset_* columns). Apply migrations in config/migrations/.'], 500);
    }

    $db = getDB();
    $stmt = $db->prepare('SELECT id, email FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $u = $stmt->fetch();

    $devUrl = null;
    if ($u) {
        $devUrl = issuePasswordReset((int)$u['id'], $u['email']);
        auditLog('password_reset_request', null, (int)$u['id']);
    }

    jsonResponse(['success' => true, 'dev_reset_url' => $devUrl]);
}

if ($action === 'reset') {
    $email = strtolower(trim((string)($body['email'] ?? '')));
    $token = trim((string)($body['token'] ?? ''));
    $newPwd = (string)($body['new_password'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['error' => 'Invalid email'], 400);
    if ($token === '' || strlen($token) < 20) jsonResponse(['error' => 'Invalid token'], 400);
    if (strlen($newPwd) < 8) jsonResponse(['error' => 'New password must be at least 8 characters'], 400);

    $hash = hash('sha256', $token);

    if (!hasPasswordResetColumns()) {
        jsonResponse(['error' => 'Password reset is not available (missing users.password_reset_* columns). Apply migrations in config/migrations/.'], 500);
    }

    $db = getDB();

    $hasAdminCol = false;
    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'is_admin' LIMIT 1");
        $hasAdminCol = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $hasAdminCol = false;
    }

    $sql = $hasAdminCol
        ? 'SELECT id, email, email_verified_at, is_admin, password_reset_hash, password_reset_expires_at FROM users WHERE email = ?'
        : 'SELECT id, email, email_verified_at, 0 AS is_admin, password_reset_hash, password_reset_expires_at FROM users WHERE email = ?';

    $stmt = $db->prepare($sql);
    $stmt->execute([$email]);
    $u = $stmt->fetch();

    if (!$u || empty($u['password_reset_hash']) || !hash_equals((string)$u['password_reset_hash'], $hash)) {
        jsonResponse(['error' => 'Invalid or expired reset link'], 400);
    }

    if (empty($u['password_reset_expires_at']) || strtotime($u['password_reset_expires_at']) < time()) {
        jsonResponse(['error' => 'Invalid or expired reset link'], 400);
    }

    $loginHash = hashLoginPassword($newPwd);

    $db->beginTransaction();
    try {
        $db->prepare('UPDATE users SET login_hash = ?, password_reset_hash = NULL, password_reset_expires_at = NULL, password_reset_sent_at = NULL WHERE id = ?')
           ->execute([$loginHash, (int)$u['id']]);

        // Invalidate all sessions (if session tracking is enabled)
        deleteAllSessionRecords((int)$u['id']);

        $db->commit();
    } catch (Throwable $e) {
        $db->rollBack();
        throw $e;
    }

    // Log user in with a fresh session
    session_regenerate_id(true);
    $_SESSION['user_id']        = (int)$u['id'];
    $_SESSION['email']          = $u['email'];
    $_SESSION['email_verified'] = !empty($u['email_verified_at']) ? 1 : 0;
    $_SESSION['is_admin']       = !empty($u['is_admin']) ? 1 : 0;

    registerCurrentSession((int)$u['id']);

    auditLog('password_reset_complete', null, (int)$u['id']);

    jsonResponse([
        'success'  => true,
        'verified' => !empty($u['email_verified_at']) ? true : false,
    ]);
}

jsonResponse(['error' => 'Unknown action'], 400);
