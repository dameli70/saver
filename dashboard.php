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

$lang = getCurrentLang();

$nextSetupText = t('setup.next.review');
$nextSetupLabel = t('action.open_setup');
$nextSetupHref = 'setup.php';

if (!$hasVault) {
    $nextSetupText = t('setup.next.vault');
    $nextSetupLabel = t('action.open_vault');
    $nextSetupHref = 'vault_settings.php';
} elseif (!$hasTotp && !$hasPasskey) {
    $nextSetupText = t('setup.next.confirmation');
    $nextSetupLabel = t('action.add_confirmation');
    $nextSetupHref = 'account.php#passkeys-card';
} elseif ($backupCount <= 0) {
    $nextSetupText = t('setup.next.backup');
    $nextSetupLabel = t('action.open_backup');
    $nextSetupHref = 'backup.php';
} elseif ($lockCount <= 0) {
    $nextSetupText = t('setup.next.first_lock');
    $nextSetupLabel = t('action.create_time_lock');
    $nextSetupHref = 'create_code.php';
} else {
    $nextSetupText = t('setup.next.ready');
    $nextSetupLabel = t('action.create_time_lock');
    $nextSetupHref = 'create_code.php';
}

// Strict security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(getCurrentLang()) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('dashboard.title')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
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
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?= htmlspecialchars(t('nav.theme')) ?></button>
      <a class="btn btn-ghost btn-sm <?= ($lang === 'fr') ? 'btn-lang-active' : '' ?>" href="<?= htmlspecialchars(langUrl('fr')) ?>">FR</a>
      <a class="btn btn-ghost btn-sm <?= ($lang === 'en') ? 'btn-lang-active' : '' ?>" href="<?= htmlspecialchars(langUrl('en')) ?>">EN</a>
      <a class="btn btn-ghost btn-sm" href="index.php#faq"><?= htmlspecialchars(t('nav.faq')) ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?= htmlspecialchars(t('nav.create_code')) ?></a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php"><?= htmlspecialchars(t('nav.my_codes')) ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?= htmlspecialchars(t('nav.rooms')) ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?= htmlspecialchars(t('nav.notifications')) ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?= htmlspecialchars(t('nav.backup')) ?></a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?= htmlspecialchars(t('nav.vault')) ?></a>
      <a class="btn btn-ghost btn-sm" href="setup.php"><?= htmlspecialchars(t('nav.setup')) ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?= htmlspecialchars(t('nav.account')) ?></a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?= htmlspecialchars(t('nav.admin')) ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?= htmlspecialchars(t('nav.logout')) ?></a>
    </div>
  </div>

  <div class="app-body">

    <div class="card" style="margin-top:0;">
      <div class="card-title"><div class="dot"></div><?= htmlspecialchars(t('dashboard.onboarding')) ?></div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="min-width:220px;flex:1;">
          <div style="font-size:12px;color:var(--muted);line-height:1.7;">
            <strong style="color:var(--text);font-weight:800;"><?= (int)$setupPercent ?>%</strong> <?= htmlspecialchars(t('dashboard.percent_complete')) ?> — <?= htmlspecialchars($nextSetupText) ?>
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
        <div class="sec-banner-title"><?= htmlspecialchars(t('dashboard.security_banner_title')) ?></div>
        <div class="sec-banner-sub"><?= htmlspecialchars(t('dashboard.security_banner_sub')) ?></div>
      </div>
      <a class="btn btn-ghost btn-sm" href="account.php#totp-card"><?= htmlspecialchars(t('dashboard.security_banner_btn')) ?></a>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?= htmlspecialchars(t('dashboard.quick_actions')) ?></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;"><?= htmlspecialchars(t('action.create_time_lock')) ?></a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;"><?= htmlspecialchars(t('nav.my_codes')) ?></a>
        <a class="btn btn-ghost" href="rooms.php" style="width:auto;"><?= htmlspecialchars(t('nav.rooms')) ?></a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;"><?= htmlspecialchars(t('nav.notifications')) ?></a>
        <a class="btn btn-ghost" href="backup.php" style="width:auto;"><?= htmlspecialchars(t('nav.backup')) ?></a>
        <a class="btn btn-ghost" href="vault_settings.php" style="width:auto;"><?= htmlspecialchars(t('nav.vault')) ?></a>
      </div>
      <div style="margin-top:12px;font-size:12px;color:var(--muted);line-height:1.7;"><?= htmlspecialchars(t('dashboard.quick_actions_desc')) ?></div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?= htmlspecialchars(t('dashboard.setup_checklist')) ?></div>
      <div style="display:flex;flex-direction:column;gap:10px;font-size:12px;">

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $hasVault ? 'var(--green)' : 'var(--orange)' ?>;"><?= $hasVault ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?= htmlspecialchars(t('checklist.vault.title')) ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;"><?= htmlspecialchars(t('checklist.vault.desc')) ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="vault_settings.php" style="width:auto;"><?= htmlspecialchars(t('action.open')) ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= ($hasTotp || $hasPasskey) ? 'var(--green)' : 'var(--orange)' ?>;"><?= ($hasTotp || $hasPasskey) ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?= htmlspecialchars(t('checklist.confirm.title')) ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;"><?= htmlspecialchars(t('checklist.confirm.desc')) ?></div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="account.php#totp-card" style="width:auto;"><?= htmlspecialchars(t('action.open')) ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $backupCount > 0 ? 'var(--green)' : 'var(--orange)' ?>;"><?= $backupCount > 0 ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?= htmlspecialchars(t('checklist.backup.title')) ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">
                <?php if ($backupCount > 0): ?>
                  <?= t('checklist.backup.count', ['count' => (string)(int)$backupCount]) ?>
                <?php else: ?>
                  <?= htmlspecialchars(t('checklist.backup.none')) ?>
                <?php endif; ?>
                <?php if ($lastBackupAt): ?>
                  <span class="utc-pill" title="<?= htmlspecialchars(t('checklist.backup.utc_title')) ?>" style="margin-left:8px;"><?= htmlspecialchars(t('checklist.backup.last', ['at' => (string)$lastBackupAt])) ?></span>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="backup.php" style="width:auto;"><?= htmlspecialchars(t('action.open')) ?></a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $lockCount > 0 ? 'var(--green)' : 'var(--orange)' ?>;"><?= $lockCount > 0 ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;"><?= htmlspecialchars(t('checklist.first_lock.title')) ?></div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">
                <?php if ($lockCount > 0): ?>
                  <?= t('checklist.first_lock.count', ['count' => (string)(int)$lockCount]) ?>
                <?php else: ?>
                  <?= htmlspecialchars(t('checklist.first_lock.none')) ?>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="create_code.php" style="width:auto;"><?= htmlspecialchars(t('action.create')) ?></a>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div><?= htmlspecialchars(t('dashboard.security')) ?></div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;"><?= t('dashboard.security_card') ?></div>
    </div>

  </div>
</div>

</body>
</html>
