<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

$email = strtolower(trim($_GET['email'] ?? ''));
$token = trim($_GET['token'] ?? '');

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");

function page(string $title, string $msg, bool $ok = false): void {
    $accent = $ok ? '#47ffb0' : '#ffaa00';
    $border = $ok ? 'rgba(71,255,176,.2)' : 'rgba(255,170,0,.25)';
    $bg     = $ok ? 'rgba(71,255,176,.06)' : 'rgba(255,170,0,.06)';
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">";
    echo "<title>" . htmlspecialchars($title) . " — LOCKSMITH</title>";
    echo "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link href=\"https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap\" rel=\"stylesheet\">";
    echo "<style>:root{--bg:#06070a;--s1:#0d0f14;--b1:rgba(255,255,255,.07);--text:#dde1ec;--muted:#525970;--mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;}*{box-sizing:border-box;margin:0;padding:0;}body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px 18px;}a{color:inherit;} .box{width:100%;max-width:520px;background:var(--s1);border:1px solid var(--b1);padding:22px;} .logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:10px;} .logo span{color:#e8ff47;} .msg{border:1px solid {$border};background:{$bg};padding:14px 16px;color:var(--muted);font-size:12px;line-height:1.7;} .msg strong{color:{$accent};} .btn{display:inline-flex;align-items:center;justify-content:center;padding:12px 18px;font-size:11px;letter-spacing:2px;text-transform:uppercase;border:1px solid rgba(255,255,255,.13);text-decoration:none;margin-top:14px;}</style></head><body>";
    echo "<div class=\"box\"><div class=\"logo\">LOCK<span>SMITH</span></div><div class=\"msg\">" . $msg . "</div><a class=\"btn\" href=\"login.php\">Continue</a></div></body></html>";
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($token) < 10) {
    page('Verification failed', '<strong>Invalid verification link.</strong> Please request a new one from your account page.');
    exit;
}

$db = getDB();
$stmt = $db->prepare("SELECT id, email, email_verified_at, email_verification_hash, email_verification_expires_at FROM users WHERE email = ?");
$stmt->execute([$email]);
$u = $stmt->fetch();

if (!$u) {
    page('Verification failed', '<strong>Account not found.</strong>');
    exit;
}

if (!empty($u['email_verified_at'])) {
    page('Email verified', '<strong>Email already verified.</strong> You can log in and use the dashboard.', true);
    exit;
}

$expected = $u['email_verification_hash'] ?? '';
$expires  = $u['email_verification_expires_at'] ?? null;
$given    = hash('sha256', $token);

if (!$expected || !hash_equals($expected, $given)) {
    page('Verification failed', '<strong>Verification link is invalid.</strong> Please request a new one from your account page.');
    exit;
}

if (!$expires || new DateTime($expires) < new DateTime()) {
    page('Verification failed', '<strong>Verification link expired.</strong> Please request a new one from your account page.');
    exit;
}

$db->prepare("UPDATE users SET email_verified_at = NOW(), email_verification_hash = NULL, email_verification_expires_at = NULL WHERE id = ?")
   ->execute([(int)$u['id']]);

session_regenerate_id(true);
$_SESSION['user_id'] = (int)$u['id'];
$_SESSION['email'] = $u['email'];
$_SESSION['email_verified'] = 1;

auditLog('email_verified', null, (int)$u['id']);

header('Location: dashboard.php');
exit;
