<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

$email = strtolower(trim((string)($_GET['email'] ?? '')));
$token = trim((string)($_GET['token'] ?? ''));

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");

function renderVerifyPage(string $titleKey, string $msgKey, bool $ok = false): void {
    $msgClass = $ok ? 'msg msg-ok show' : 'msg msg-warn show';
    $appNameEsc = htmlspecialchars(APP_NAME, ENT_QUOTES, 'UTF-8');
    $langAttr = htmlLangAttr();

    $title = t($titleKey, ['app' => APP_NAME]);
    $msgHtml = t($msgKey, ['app' => APP_NAME]);

    ob_start();
    emitI18nJsGlobals();
    $i18nScript = ob_get_clean();

    $curLang = currentLang();
    $frUrl = htmlspecialchars(langSwitchUrl('fr'), ENT_QUOTES, 'UTF-8');
    $enUrl = htmlspecialchars(langSwitchUrl('en'), ENT_QUOTES, 'UTF-8');

    echo "<!doctype html><html {$langAttr}><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">";
    echo "<title>" . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . " — {$appNameEsc}</title>";
    echo "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link href=\"https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap\" rel=\"stylesheet\">";
    echo $i18nScript;
    echo "<script src=\"assets/theme.js\"></script>";
    echo "<link rel=\"stylesheet\" href=\"assets/base.css\">";
    echo "<link rel=\"stylesheet\" href=\"assets/app.css\">";
    echo "<link rel=\"stylesheet\" href=\"assets/auth.css\">";
    echo "</head><body>";

    ob_start();
    include __DIR__ . '/includes/topbar_public.php';
    $topbar = ob_get_clean();

    echo '<div class="orb orb1"></div><div class="orb orb2"></div>';
    echo '<div id="app">';
    echo $topbar;
    echo '<div class="auth-wrap">';

    echo '<div class="box">'
        . '<div class="logo">' . $appNameEsc . '</div>'
        . '<div class="' . $msgClass . '">' . $msgHtml . '</div>'
        . '<a class="btn btn-primary" href="login.php">' . htmlspecialchars(t('verify.continue'), ENT_QUOTES, 'UTF-8') . '</a>'
        . '</div>';

    echo '</div>';
    echo '</div>';
    echo '</body></html>';
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($token) < 10) {
    renderVerifyPage('verify.failed', 'verify.invalid_link_html');
    exit;
}

$db = getDB();
$stmt = $db->prepare("SELECT id, email, email_verified_at, email_verification_hash, email_verification_expires_at FROM users WHERE email = ?");
$stmt->execute([$email]);
$u = $stmt->fetch();

if (!$u) {
    renderVerifyPage('verify.failed', 'verify.account_not_found_html');
    exit;
}

if (!empty($u['email_verified_at'])) {
    renderVerifyPage('verify.verified', 'verify.already_verified_html', true);
    exit;
}

$expected = $u['email_verification_hash'] ?? '';
$expires  = $u['email_verification_expires_at'] ?? null;
$given    = hash('sha256', $token);

if (!$expected || !hash_equals($expected, $given)) {
    renderVerifyPage('verify.failed', 'verify.invalid_token_html');
    exit;
}

if (!$expires || new DateTime($expires) < new DateTime()) {
    renderVerifyPage('verify.failed', 'verify.expired_html');
    exit;
}

$db->prepare("UPDATE users SET email_verified_at = NOW(), email_verification_hash = NULL, email_verification_expires_at = NULL WHERE id = ?")
   ->execute([(int)$u['id']]);

session_regenerate_id(true);
$_SESSION['user_id'] = (int)$u['id'];
$_SESSION['email'] = $u['email'];
$_SESSION['email_verified'] = 1;

registerCurrentSession((int)$u['id']);

auditLog('email_verified', null, (int)$u['id']);

header('Location: dashboard.php');
exit; 
