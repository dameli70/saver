<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

if (!isAdmin()) {
    header('Location: dashboard.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = true;
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('admin.add_user_title')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
</head>
<body>
<div id="app">
  <?php $topbarBadgeText = 'SUPER ADMIN'; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('admin.add_user_title'); ?></div>
        <div class="page-sub"><?php e('admin.add_user_note'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="admin.php?p=users"><?php e('common.back'); ?></a>
        <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      </div>
    </div>

    <div class="card" style="max-width:680px;">
      <div class="card-title"><?php e('admin.add_user_title'); ?></div>

      <div class="field"><label><?php e('common.email'); ?></label><input id="nu-email" type="email" placeholder="user@example.com" autocomplete="off"></div>
      <div class="field"><label><?php e('admin.login_password_label'); ?></label><input id="nu-login" type="password" placeholder="min 8 chars" autocomplete="new-password"></div>

      <div class="field">
        <label><?php e('account.trust_title'); ?></label>
        <select id="nu-trust">
          <option value="1" selected><?php e('rooms.trust_level.1'); ?></option>
          <option value="2"><?php e('rooms.trust_level.2'); ?></option>
          <option value="3"><?php e('rooms.trust_level.3'); ?></option>
        </select>
      </div>

      <label class="chk"><input type="checkbox" id="nu-verified"> <span><?php e('admin.add_user_mark_verified'); ?></span></label>
      <label class="chk"><input type="checkbox" id="nu-admin"> <span><?php e('admin.add_user_make_admin'); ?></span></label>

      <button class="btn btn-primary" onclick="createUser()"><?php e('admin.add_user_btn'); ?></button>

      <div id="nu-msg" class="msg"></div>
      <div id="nu-dev" class="msg" style="display:none;background:rgba(255,170,0,.06);border:1px solid rgba(255,170,0,.25);color:var(--muted);"></div>

      <hr>
      <div class="p" style="margin:0;">
        <?php e('admin.add_user_note'); ?>
      </div>
    </div>

  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
</script>
<script src="assets/admin_shared.js"></script>
<script src="assets/admin_users.js"></script>
</body>
</html>
