<?php
require_once __DIR__ . '/includes/security_page.php';

$totpEnabled = !empty($securityUser['totp_enabled_at']);
$passkeysEnabled = $hasPasskeys ? userHasPasskeys((int)$userId) : false;
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.security')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script>window.LS_SECURITY={csrf:<?= json_encode($csrf) ?>};</script>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<script src="assets/security.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/security_page.css">
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.security'); ?></div>
        <div class="page-sub"><?php e('security.hub_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      </div>
    </div>

    <div class="card">
      <div class="small"><?php e('account.security_note_html'); ?></div>

      <div class="hr"></div>

      <div class="list">
        <div class="item">
          <div>
            <div class="k"><?php e('account.change_login_password_title'); ?></div>
            <div class="small"><?php e('account.security_sub'); ?></div>
          </div>
          <div class="item-actions">
            <a class="btn btn-primary btn-sm" href="security_password.php"><?php e('common.open'); ?></a>
          </div>
        </div>

        <div class="item">
          <div>
            <div class="k"><?php e('account.totp_title'); ?></div>
            <div class="small"><?php e('account.totp_sub'); ?></div>
          </div>
          <div class="item-actions">
            <?php if (!$hasTotp): ?>
              <span class="badge wait"><?= htmlspecialchars(t('common.unavailable'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php elseif ($totpEnabled): ?>
              <span class="badge ok"><?= htmlspecialchars(t('account.totp_enabled'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php else: ?>
              <span class="badge wait"><?= htmlspecialchars(t('account.totp_not_enabled'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php endif; ?>
            <a class="btn btn-ghost btn-sm" href="security_totp.php"><?php e('common.open'); ?></a>
          </div>
        </div>

        <div class="item">
          <div>
            <div class="k"><?php e('account.passkeys_title'); ?></div>
            <div class="small"><?php e('account.passkeys_sub'); ?></div>
          </div>
          <div class="item-actions">
            <?php if (!$hasPasskeys): ?>
              <span class="badge wait"><?= htmlspecialchars(t('common.unavailable'), ENT_QUOTES, 'UTF-8') ?></span>
            <?php elseif ($passkeysEnabled): ?>
              <span class="badge ok">✓</span>
            <?php else: ?>
              <span class="badge wait">⏳</span>
            <?php endif; ?>
            <a class="btn btn-ghost btn-sm" href="security_passkeys.php"><?php e('common.open'); ?></a>
          </div>
        </div>

        <div class="item">
          <div>
            <div class="k"><?php e('account.active_sessions_title'); ?></div>
            <div class="small"><?php e('account.active_sessions_sub'); ?></div>
          </div>
          <div class="item-actions">
            <a class="btn btn-ghost btn-sm" href="security_sessions.php"><?php e('common.open'); ?></a>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>
</body>
</html>
