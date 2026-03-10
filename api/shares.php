<?php
// ============================================================
//  API: /api/shares.php
//  Authenticated share management for time locks.
//
//  POST actions:
//   - create: create a public share link for an unlocked lock
//   - revoke: revoke a share link
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

if (!hasLockSharesTable()) {
    jsonResponse(['error' => 'Sharing is unavailable on this server. Apply database migrations.'], 409);
}

$body = json_decode(file_get_contents('php://input'), true);
$action = (string)($body['action'] ?? '');

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

$db = getDB();

if ($action === 'create') {
    $lockId = trim((string)($body['lock_id'] ?? ''));

    $shareCipher = (string)($body['share_cipher_blob'] ?? '');
    $shareIv = (string)($body['share_iv'] ?? '');
    $shareTag = (string)($body['share_auth_tag'] ?? '');
    $shareSalt = (string)($body['share_kdf_salt'] ?? '');
    $shareIters = (int)($body['share_kdf_iterations'] ?? 310000);

    if ($lockId === '' || strlen($lockId) !== 36) jsonResponse(['error' => 'lock_id required'], 400);
    if ($shareCipher === '' || $shareIv === '' || $shareTag === '' || $shareSalt === '') {
        jsonResponse(['error' => 'Missing share encryption fields'], 400);
    }
    if ($shareIters < 50000) $shareIters = 50000;
    if ($shareIters > 2000000) $shareIters = 2000000;

    // Ensure lock belongs to user and is currently eligible to reveal.
    $stmt = $db->prepare("SELECT id, label, reveal_date, confirmation_status
                          FROM locks
                          WHERE id = ? AND user_id = ? AND is_active = 1
                          LIMIT 1");
    $stmt->execute([$lockId, $userId]);
    $lock = $stmt->fetch();

    if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);
    if ((string)$lock['confirmation_status'] !== 'confirmed') {
        jsonResponse(['error' => 'This lock is not confirmed'], 403);
    }

    $now = new DateTime('now', new DateTimeZone('UTC'));
    $reveal = new DateTime((string)$lock['reveal_date'], new DateTimeZone('UTC'));
    if ($now < $reveal) {
        jsonResponse(['error' => 'This lock is still sealed. Sharing becomes available once it is eligible to reveal.'], 403);
    }

    // Sharing is sensitive: enforce strong re-auth.
    requireStrongAuth();

    $token = null;
    $tokenHash = null;

    $tries = 0;
    while ($tries < 5) {
        $tries++;
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);

        try {
            $db->prepare("INSERT INTO lock_shares
                          (lock_id, created_by_user_id, token_hash,
                           share_cipher_blob, share_iv, share_auth_tag, share_kdf_salt, share_kdf_iterations)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
               ->execute([$lockId, $userId, $tokenHash, $shareCipher, $shareIv, $shareTag, $shareSalt, $shareIters]);
            break;
        } catch (Throwable $e) {
            // Token collision (extremely unlikely) — retry.
            if (str_contains(strtolower($e->getMessage()), 'duplicate')) continue;
            throw $e;
        }
    }

    if (!$token || !$tokenHash) jsonResponse(['error' => 'Failed to create share link'], 500);

    $shareId = (int)$db->lastInsertId();
    auditLog('share_create', $lockId);

    $url = getAppBaseUrl() . '/share.php?t=' . rawurlencode($token);

    jsonResponse([
        'success' => true,
        'share_id' => $shareId,
        'share_url' => $url,
    ]);
}

if ($action === 'revoke') {
    $shareId = (int)($body['share_id'] ?? 0);
    if ($shareId < 1) jsonResponse(['error' => 'share_id required'], 400);

    $stmt = $db->prepare("UPDATE lock_shares
                          SET revoked_at = NOW()
                          WHERE id = ? AND created_by_user_id = ? AND revoked_at IS NULL");
    $stmt->execute([$shareId, $userId]);

    if ($stmt->rowCount() < 1) {
        jsonResponse(['error' => 'Share not found or already revoked'], 404);
    }

    auditLog('share_revoke', null);
    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
