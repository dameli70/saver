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

$titleKey = 'verify.failed';
$msgKey   = 'verify.invalid_link_html';
$isOk     = false;

if (filter_var($email, FILTER_VALIDATE_EMAIL) && strlen($token) >= 10) {
    $db = getDB();
    $stmt = $db->prepare("SELECT id, email, email_verified_at, email_verification_hash, email_verification_expires_at FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $u = $stmt->fetch();

    if (!$u) {
        $titleKey = 'verify.failed';
        $msgKey = 'verify.account_not_found_html';
    } elseif (!empty($u['email_verified_at'])) {
        $titleKey = 'verify.verified';
        $msgKey = 'verify.already_verified_html';
        $isOk = true;
    } else {
        $expected = $u['email_verification_hash'] ?? '';
        $expires  = $u['email_verification_expires_at'] ?? null;
        $given    = hash('sha256', $token);

        if (!$expected || !hash_equals($expected, $given)) {
            $titleKey = 'verify.failed';
            $msgKey = 'verify.invalid_token_html';
        } elseif (!$expires || new DateTime($expires) < new DateTime()) {
            $titleKey = 'verify.failed';
            $msgKey = 'verify.expired_html';
        } else {
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
        }
    }
}

$pageTitle = t($titleKey, ['app' => APP_NAME]);
$msgHtml = t($msgKey, ['app' => APP_NAME]);
$msgClass = $isOk ? 'msg msg-ok show' : 'msg msg-warn show';
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars($pageTitle) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <div class="auth-wrap">
    <div class="box">
      <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
      <div class="sub"><?= htmlspecialchars($pageTitle) ?></div>

      <div class="<?= $msgClass ?>"><?= $msgHtml ?></div>

      <a class="btn btn-primary" href="login.php"><?= htmlspecialchars(t('verify.continue'), ENT_QUOTES, 'UTF-8') ?></a>
    </div>
  </div>
</div>
</body>
</html> 
