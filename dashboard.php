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

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

$userId = (int)(getCurrentUserId() ?? 0);
$skipSetup = !empty($_GET['skip_setup']);
if ($skipSetup) {
    $_SESSION['onboarding_skip_once'] = 1;
}

if ($userId && empty($_SESSION['onboarding_skip_once']) && !isOnboardingComplete($userId)) {
    header('Location: setup.php');
    exit;
}

if (!empty($_SESSION['onboarding_skip_once'])) {
    unset($_SESSION['onboarding_skip_once']);
}

$hasTotp    = userHasTotp($userId);
$hasPasskey = userHasPasskeys($userId);
$hasVault   = userHasVaultPassphraseCheck($userId);
$showSecurityBanner = !$hasTotp && !$hasPasskey;

$backupCount = 0;
$lastBackupAt = null;
try {
    $db = getDB();
    $stmt = $db->prepare('SELECT COUNT(*) AS c, MAX(created_at) AS last_at FROM backups WHERE user_id = ?');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();
    if ($row) {
        $backupCount = (int)($row['c'] ?? 0);
        $lastBackupAt = $row['last_at'] ?? null;
    }
} catch (Throwable) {
    $backupCount = 0;
    $lastBackupAt = null;
}

$lockCount = 0;
try {
    $db = $db ?? getDB();
    $stmt = $db->prepare('SELECT COUNT(*) AS c FROM locks WHERE user_id = ?');
    $stmt->execute([$userId]);
    $lockCount = (int)($stmt->fetchColumn() ?? 0);
} catch (Throwable) {
    $lockCount = 0;
}

$setupStepsTotal = 4;
$setupDone = 0;
if ($hasVault) $setupDone++;
if ($hasTotp || $hasPasskey) $setupDone++;
if ($backupCount > 0) $setupDone++;
if ($lockCount > 0) $setupDone++;
$setupPercent = (int)floor(($setupDone / $setupStepsTotal) * 100);

$nextSetupTextKey = 'onboarding.next.review';
$nextSetupLabelKey = 'onboarding.action.open_setup';
$nextSetupHref = 'setup.php';

if (!$hasVault) {
    $nextSetupTextKey = 'onboarding.next.vault_passphrase';
    $nextSetupLabelKey = 'onboarding.action.open_vault';
    $nextSetupHref = 'vault_settings.php';
} elseif (!$hasTotp && !$hasPasskey) {
    $nextSetupTextKey = 'onboarding.next.confirmation';
    $nextSetupLabelKey = 'onboarding.action.add_confirmation';
    $nextSetupHref = 'account.php#passkeys-card';
} elseif ($backupCount <= 0) {
    $nextSetupTextKey = 'onboarding.next.backup';
    $nextSetupLabelKey = 'onboarding.action.open_backup';
    $nextSetupHref = 'backup.php';
} elseif ($lockCount <= 0) {
    $nextSetupTextKey = 'onboarding.next.first_time_lock';
    $nextSetupLabelKey = 'onboarding.action.create_time_lock';
    $nextSetupHref = 'create_code.php';
} else {
    $nextSetupTextKey = 'onboarding.next.ready';
    $nextSetupLabelKey = 'onboarding.action.create_time_lock';
    $nextSetupHref = 'create_code.php';
}

$nextSetupText = t($nextSetupTextKey);
$nextSetupLabel = t($nextSetupLabelKey);

// Strict security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.dashboard')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/dashboard_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="card dash-onboard-card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.onboarding'); ?></div>
      <div class="dash-progress-row">
        <div class="dash-progress-main">
          <div class="dash-progress-meta">
            <strong style="color:var(--text);font-weight:800;"><?= (int)$setupPercent ?>%</strong> <?php e('dashboard.progress_suffix', ['next' => $nextSetupText]); ?>
          </div>
          <div class="dash-progress-track">
            <div class="dash-progress-fill" style="width:<?= (int)$setupPercent ?>%;"></div>
          </div>
        </div>
        <a class="btn btn-primary btn-inline" href="<?= htmlspecialchars($nextSetupHref) ?>"><?= htmlspecialchars($nextSetupLabel) ?></a>
      </div>
    </div>

    <?php if ($showSecurityBanner): ?>
    <div class="sec-banner">
      <div>
        <div class="sec-banner-title"><?php e('dashboard.security_banner_title'); ?></div>
        <div class="sec-banner-sub"><?php e('dashboard.security_banner_sub'); ?></div>
      </div>
      <a class="btn btn-ghost btn-sm" href="account.php#totp-card"><?php e('dashboard.open_account'); ?></a>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.quick_actions'); ?></div>
      <div class="dash-actions">
        <a class="btn btn-primary btn-inline" href="create_code.php"><?php e('dashboard.create_time_lock'); ?></a>
        <a class="btn btn-ghost btn-inline" href="my_codes.php"><?php e('dashboard.my_time_locks'); ?></a>
        <a class="btn btn-ghost btn-inline" href="rooms.php"><?php e('nav.rooms'); ?></a>
        <a class="btn btn-ghost btn-inline" href="notifications.php"><?php e('nav.notifications'); ?></a>
        <a class="btn btn-ghost btn-inline" href="backup.php"><?php e('nav.backups'); ?></a>
        <a class="btn btn-ghost btn-inline" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      </div>
      <div class="dash-actions-sub">
        <?php e('dashboard.quick_actions_sub'); ?>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.setup_checklist'); ?></div>
      <div class="dash-checklist">

        <div class="dash-check-item">
          <div class="dash-check-left">
            <div class="dash-check-ico <?= $hasVault ? 'ok' : 'todo' ?>"><?= $hasVault ? '✓' : '•' ?></div>
            <div class="dash-check-text">
              <div class="dash-check-title"><?php e('dashboard.check.vault_title'); ?></div>
              <div class="dash-check-sub"><?php e('dashboard.check.vault_sub'); ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm btn-inline" href="vault_settings.php"><?php e('common.open'); ?></a>
        </div>

        <div class="dash-check-item">
          <div class="dash-check-left">
            <div class="dash-check-ico <?= ($hasTotp || $hasPasskey) ? 'ok' : 'todo' ?>"><?= ($hasTotp || $hasPasskey) ? '✓' : '•' ?></div>
            <div class="dash-check-text">
              <div class="dash-check-title"><?php e('dashboard.check.confirm_title'); ?></div>
              <div class="dash-check-sub"><?php e('dashboard.check.confirm_sub'); ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm btn-inline" href="account.php#totp-card"><?php e('common.open'); ?></a>
        </div>

        <div class="dash-check-item">
          <div class="dash-check-left">
            <div class="dash-check-ico <?= $backupCount > 0 ? 'ok' : 'todo' ?>"><?= $backupCount > 0 ? '✓' : '•' ?></div>
            <div class="dash-check-text">
              <div class="dash-check-title"><?php e('dashboard.check.backup_title'); ?></div>
              <div class="dash-check-sub">
                <?php if ($backupCount > 0): ?>
                  <?php e('dashboard.backups_count_label'); ?> <span><?= (int)$backupCount ?></span>
                <?php else: ?>
                  <?php e('dashboard.check.backup_sub'); ?>
                <?php endif; ?>
                <?php if ($lastBackupAt): ?>
                  <span class="utc-pill" title="<?= htmlspecialchars(t('dashboard.stored_in_utc'), ENT_QUOTES, 'UTF-8') ?>"><?php e('dashboard.last_backup', ['ts' => $lastBackupAt]); ?></span>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm btn-inline" href="backup.php"><?php e('common.open'); ?></a>
        </div>

        <div class="dash-check-item">
          <div class="dash-check-left">
            <div class="dash-check-ico <?= $lockCount > 0 ? 'ok' : 'todo' ?>"><?= $lockCount > 0 ? '✓' : '•' ?></div>
            <div class="dash-check-text">
              <div class="dash-check-title"><?php e('dashboard.check.first_lock_title'); ?></div>
              <div class="dash-check-sub">
                <?php if ($lockCount > 0): ?>
                  <?php e('dashboard.time_locks_created_label'); ?> <span><?= (int)$lockCount ?></span>
                <?php else: ?>
                  <?php e('dashboard.check.first_lock_sub'); ?>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm btn-inline" href="create_code.php"><?php e('common.create'); ?></a>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.security'); ?></div>
      <div class="dash-actions-sub">
        <?= t('dashboard.security_sub_html', ['account_link' => '<a href="account.php" style="color:var(--text);">' . htmlspecialchars(t('nav.account'), ENT_QUOTES, 'UTF-8') . '</a>']) ?>
      </div>
    </div>

  </div>
</div>

</body>
</html> 
