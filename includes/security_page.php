<?php
// Shared bootstrap for Security pages (requires logged in + verified).

require_once __DIR__ . '/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

$userId = (int)(getCurrentUserId() ?? 0);
$db     = getDB();

$hasTotp = hasTotpColumns();
$hasPasskeys = hasWebauthnCredentialsTable();

$hasReqWebauthn = false;
try {
    $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'require_webauthn' LIMIT 1");
    $hasReqWebauthn = (bool)$stmt->fetchColumn();
} catch (Throwable) {
    $hasReqWebauthn = false;
}

$sel = 'email, email_verified_at'
     . ($hasTotp ? ', totp_enabled_at' : ', NULL AS totp_enabled_at')
     . ($hasReqWebauthn ? ', require_webauthn' : ', 0 AS require_webauthn');

$stmt = $db->prepare("SELECT {$sel} FROM users WHERE id = ?");
$stmt->execute([(int)$userId]);
$securityUser = $stmt->fetch();

if (!$securityUser) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

$verified = true;
$_SESSION['email_verified'] = 1;

$userEmail = getCurrentUserEmail() ?? (string)($securityUser['email'] ?? '');
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
