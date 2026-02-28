<?php
// ============================================================
//  API: /api/totp.php
//  TOTP 2FA management + re-auth (step-up)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();
requireVerifiedEmail();

if (!hasTotpColumns()) {
    jsonResponse(['error' => 'TOTP is not available. Apply migrations in config/migrations/.'], 500);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

$db = getDB();

if ($action === 'status') {
    $stmt = $db->prepare('SELECT totp_enabled_at FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();
    jsonResponse(['success' => true, 'enabled' => $u && !empty($u['totp_enabled_at'])]);
}

if ($action === 'begin') {
    $stmt = $db->prepare('SELECT email, totp_enabled_at FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();
    if (!$u) jsonResponse(['error' => 'Unauthorized'], 401);
    if (!empty($u['totp_enabled_at'])) jsonResponse(['error' => 'TOTP is already enabled'], 400);

    $secret = generateTotpSecret();
    $_SESSION['totp_pending_secret'] = $secret;
    $_SESSION['totp_pending_ts'] = time();

    $issuer = defined('APP_NAME') ? APP_NAME : 'LOCKSMITH';
    $label = $issuer . ':' . $u['email'];
    $otpauth = 'otpauth://totp/' . rawurlencode($label) . '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';

    jsonResponse([
        'success' => true,
        'secret' => $secret,
        'otpauth' => $otpauth,
    ]);
}

if ($action === 'enable') {
    $code = trim((string)($body['code'] ?? ''));
    $secret = (string)($_SESSION['totp_pending_secret'] ?? '');
    $ts = (int)($_SESSION['totp_pending_ts'] ?? 0);

    if ($secret === '' || !$ts || (time() - $ts) > 900) {
        jsonResponse(['error' => 'TOTP setup expired. Start again.'], 400);
    }

    if (!verifyTotpCode($secret, $code, 1)) {
        jsonResponse(['error' => 'Invalid code'], 400);
    }

    $enc = encryptForDb($secret);
    $db->prepare('UPDATE users SET totp_secret_enc = ?, totp_enabled_at = NOW() WHERE id = ?')
       ->execute([$enc, (int)$userId]);

    unset($_SESSION['totp_pending_secret'], $_SESSION['totp_pending_ts']);

    setStrongAuth(900);
    auditLog('totp_enable', null, (int)$userId);

    jsonResponse(['success' => true]);
}

if ($action === 'disable') {
    $code = trim((string)($body['code'] ?? ''));

    $stmt = $db->prepare('SELECT totp_secret_enc, totp_enabled_at FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();

    if (!$u || empty($u['totp_enabled_at']) || empty($u['totp_secret_enc'])) {
        jsonResponse(['error' => 'TOTP is not enabled'], 400);
    }

    $secret = decryptFromDb((string)$u['totp_secret_enc']);
    if (!verifyTotpCode($secret, $code, 1)) {
        jsonResponse(['error' => 'Invalid code'], 400);
    }

    $db->prepare('UPDATE users SET totp_secret_enc = NULL, totp_enabled_at = NULL WHERE id = ?')
       ->execute([(int)$userId]);

    auditLog('totp_disable', null, (int)$userId);
    jsonResponse(['success' => true]);
}

if ($action === 'reauth') {
    $code = trim((string)($body['code'] ?? ''));

    $stmt = $db->prepare('SELECT totp_secret_enc, totp_enabled_at FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();

    if (!$u || empty($u['totp_enabled_at']) || empty($u['totp_secret_enc'])) {
        jsonResponse(['error' => 'TOTP not enabled'], 400);
    }

    $secret = decryptFromDb((string)$u['totp_secret_enc']);
    if (!verifyTotpCode($secret, $code, 1)) {
        auditLog('totp_reauth_fail', null, (int)$userId);
        jsonResponse(['error' => 'Invalid code'], 403);
    }

    setStrongAuth(600);
    auditLog('totp_reauth', null, (int)$userId);
    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
