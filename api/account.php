<?php
// ============================================================
//  API: /api/account.php
//  Account-level actions (personal-use baseline):
//   - change_login_password
//   - sessions (list)
//   - logout_all_sessions
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'change_login_password') {
    $current = (string)($body['current_password'] ?? '');
    $next    = (string)($body['new_password'] ?? '');

    if ($current === '' || $next === '') jsonResponse(['error' => 'Missing fields'], 400);
    if (strlen($next) < 8) jsonResponse(['error' => 'New password must be at least 8 characters'], 400);

    $db = getDB();
    $stmt = $db->prepare('SELECT login_hash FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();

    $dummyHash = '$argon2id$v=19$m=65536,t=4,p=2$dummysaltdummy$dummyhash000000000000000000000000';
    $hash = $u ? (string)$u['login_hash'] : $dummyHash;

    if (!$u || !password_verify($current, $hash)) {
        auditLog('change_login_password_fail', null, (int)$userId);
        jsonResponse(['error' => 'Current password is incorrect'], 403);
    }

    $newHash = hashLoginPassword($next);

    $db->beginTransaction();
    try {
        $db->prepare('UPDATE users SET login_hash = ? WHERE id = ?')->execute([$newHash, (int)$userId]);

        // Invalidate all sessions (including this one)
        deleteAllSessionRecords((int)$userId);

        $db->commit();
    } catch (Throwable $e) {
        $db->rollBack();
        throw $e;
    }

    session_regenerate_id(true);
    registerCurrentSession((int)$userId);

    auditLog('change_login_password', null, (int)$userId);
    jsonResponse(['success' => true]);
}

if ($action === 'sessions') {
    if (!hasUserSessionsTable()) {
        jsonResponse(['success' => true, 'sessions' => []]);
    }

    $db = getDB();
    $stmt = $db->prepare('SELECT created_at, last_seen_at, ip_address, user_agent, session_id_hash FROM user_sessions WHERE user_id = ? ORDER BY last_seen_at DESC');
    $stmt->execute([(int)$userId]);
    $rows = $stmt->fetchAll();

    $me = currentSessionIdHash();
    foreach ($rows as &$r) {
        $r['is_current'] = hash_equals($me, (string)($r['session_id_hash'] ?? '')) ? 1 : 0;
        unset($r['session_id_hash']);
    }
    unset($r);

    jsonResponse(['success' => true, 'sessions' => $rows]);
}

if ($action === 'logout_all_sessions') {
    deleteAllSessionRecords((int)$userId);
    auditLog('logout_all_sessions', null, (int)$userId);

    $_SESSION = [];
    session_destroy();

    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
