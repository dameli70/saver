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

// Strict security headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title><?= htmlspecialchars(APP_NAME) ?> — Dashboard</title>
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
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle>Theme</button>
      <a class="btn btn-ghost btn-sm" href="create_code.php">Create Code</a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php">My Codes</a>
      <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
      <a class="btn btn-ghost btn-sm" href="notifications.php">Notifications</a>
      <a class="btn btn-ghost btn-sm" href="backup.php">Backup</a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php">Vault</a>
      <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="app-body">

    <?php if ($showSecurityBanner): ?>
    <div class="sec-banner">
      <div>
        <div class="sec-banner-title">Security setup required</div>
        <div class="sec-banner-sub">Enable TOTP or add a passkey to use sensitive actions (reveal, backups, vault rotation, admin actions).</div>
      </div>
      <a class="btn btn-ghost btn-sm" href="account.php#totp-card">Open account</a>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-title"><div class="dot"></div>Quick actions</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;">Create a code</a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;">My codes</a>
        <a class="btn btn-ghost" href="rooms.php" style="width:auto;">Rooms</a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;">Notifications</a>
        <a class="btn btn-ghost" href="backup.php" style="width:auto;">Backup</a>
        <a class="btn btn-ghost" href="vault_settings.php" style="width:auto;">Vault</a>
      </div>
      <div style="margin-top:12px;font-size:12px;color:var(--muted);line-height:1.7;">
        The vault passphrase never leaves your browser. Code creation and reveal are now separated into dedicated pages.
      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div>Setup checklist</div>
      <div style="display:flex;flex-direction:column;gap:10px;font-size:12px;">

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $hasVault ? 'var(--green)' : 'var(--orange)' ?>;"><?= $hasVault ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;">Vault initialized</div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">Create a browser-only vault check so the UI can detect vault readiness.</div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="vault_settings.php" style="width:auto;">Open</a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= ($hasTotp || $hasPasskey) ? 'var(--green)' : 'var(--orange)' ?>;"><?= ($hasTotp || $hasPasskey) ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;">Security setup</div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">Enable TOTP or add a passkey for step-up reauthentication.</div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="account.php#totp-card" style="width:auto;">Open</a>
        </div>

        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--b1);background:rgba(255,255,255,.02);">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <div style="font-size:12px;color:<?= $backupCount > 0 ? 'var(--green)' : 'var(--orange)' ?>;"><?= $backupCount > 0 ? '✓' : '•' ?></div>
            <div style="min-width:0;">
              <div style="font-family:var(--display);font-weight:800;font-size:12px;">First backup</div>
              <div style="color:var(--muted);font-size:11px;line-height:1.6;">
                <?= $backupCount > 0 ? 'Backups: <span style="color:var(--text);">' . (int)$backupCount . '</span>' : 'Create an encrypted snapshot (no plaintext ever stored).'; ?>
                <?php if ($lastBackupAt): ?>
                  <span class="utc-pill" title="Stored in UTC" style="margin-left:8px;">Last: <?= htmlspecialchars($lastBackupAt) ?> UTC</span>
                <?php endif; ?>
              </div>
            </div>
          </div>
          <a class="btn btn-ghost btn-sm" href="backup.php" style="width:auto;">Open</a>
        </div>

      </div>
    </div>

    <div class="card">
      <div class="card-title"><div class="dot"></div>Security</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;">
        In strong security mode, sensitive actions may require re-authentication (TOTP or passkey).
        Configure this in <a href="account.php" style="color:var(--text);">Account</a>.
      </div>
    </div>

  </div>
</div>

</body>
</html>
