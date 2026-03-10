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
<style>
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;opacity:.5;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.035'/%3E%3C/svg%3E");}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
      <?php $curLang = currentLang(); ?>
      <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
      <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>
      <a class="btn btn-ghost btn-sm" href="index.php#faq"><?php e('common.faq'); ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php"><?php e('nav.my_codes'); ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?php e('nav.backups'); ?></a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      <a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
    </div>
  </div>

  <div class="app-body">

    <div class="card" style="margin-top:0;">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.onboarding'); ?></div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="min-width:220px;flex:1;">
          <div style="font-size:12px;color:var(--muted);line-height:1.7;">
            <strong style="color:var(--text);font-weight:800;"><?= (int)$setupPercent ?>%</strong> <?php e('dashboard.progress_suffix', ['next' => $nextSetupText]); ?>
          </div>
          <div style="height:10px;border:1px solid var(--b1);background:rgba(255,255,255,.02);margin-top:10px;">
            <div style="height:100%;width:<?= (int)$setupPercent ?>%;background:linear-gradient(90deg, var(--accent), rgba(255,255,255,.12));"></div>
          </div>
        </div>
        <a class="btn btn-primary" href="<?= htmlspecialchars($nextSetupHref) ?>" style="width:auto;"><?= htmlspecialchars($nextSetupLabel) ?></a>
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
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;"><?php e('dashboard.create_time_lock'); ?></a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;"><?php e('dashboard.my_time_locks'); ?></a>
        <a class="btn btn-ghost" href="rooms.php" style="width:auto;"><?php e('nav.rooms'); ?></a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;"><?php e('nav.notifications'); ?></a>
        <a class="btn btn-ghost" href="backup.php" style="width:auto;"><?php e('nav.backups'); ?></a>
        <a class="btn btn-ghost" href="vault_settings.php" style="width:auto;"><?php e('nav.vault'); ?></a>
      </div>
      <div style="margin-top:12px;font-size:12px;color:var(--muted);line-height:1.7;">
        <?php e('dashboard.quick_actions_sub'); ?>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.setup_checklist'); ?></div>
      <div style="display:flex;flex-direction:column;gap:10px;font-size:12px;">

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $hasVault ? 'var(--green)' : 'var(--orange)' ?>;"> <?= $hasVault ? '✓' : '•' ?> </div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?php e('dashboard.check.vault_title'); ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;"><?php e('dashboard.check.vault_sub'); ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="vault_settings.php" style="width:auto;"><?php e('common.open'); ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= ($hasTotp || $hasPasskey) ? 'var(--green)' : 'var(--orange)' ?>;"> <?= ($hasTotp || $hasPasskey) ? '✓' : '•' ?> </div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?php e('dashboard.check.confirm_title'); ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;"><?php e('dashboard.check.confirm_sub'); ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="account.php#totp-card" style="width:auto;"><?php e('common.open'); ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $backupCount > 0 ? 'var(--green)' : 'var(--orange)' ?>;"> <?= $backupCount > 0 ? '✓' : '•' ?> </div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?php e('dashboard.check.backup_title'); ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">
                <?php if ($backupCount > 0): ?>
                  <?php e('dashboard.backups_count_label'); ?> <span style="color:var(--text);"><?= (int)$backupCount ?></span>
                <?php else: ?>
                  <?php e('dashboard.check.backup_sub'); ?>
                <?php endif; ?>
                <?php if ($lastBackupAt): ?>
                  <span class="utc-pill" title="<?= htmlspecialchars(t('dashboard.stored_in_utc'), ENT_QUOTES, 'UTF-8') ?>" style="margin-left:8px;"><?php e('dashboard.last_backup', ['ts' => $lastBackupAt]); ?></span>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="backup.php" style="width:auto;"><?php e('common.open'); ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $lockCount > 0 ? 'var(--green)' : 'var(--orange)' ?>;"> <?= $lockCount > 0 ? '✓' : '•' ?> </div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?php e('dashboard.check.first_lock_title'); ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">
                <?php if ($lockCount > 0): ?>
                  <?php e('dashboard.time_locks_created_label'); ?> <span style="color:var(--text);"><?= (int)$lockCount ?></span>
                <?php else: ?>
                  <?php e('dashboard.check.first_lock_sub'); ?>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="create_code.php" style="width:auto;"><?php e('common.create'); ?></a>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('dashboard.security'); ?></div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;">
        <?= t('dashboard.security_sub_html', ['account_link' => '<a href="account.php" style="color:var(--text);">' . htmlspecialchars(t('nav.account'), ENT_QUOTES, 'UTF-8') . '</a>']) ?>
      </div>
    </div>

  </div>
</div>

</body>
</html> 
