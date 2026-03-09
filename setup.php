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

$userId = (int)(getCurrentUserId() ?? 0);
$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();
$lang      = getCurrentLang();

$hasTotp    = userHasTotp($userId);
$hasPasskey = userHasPasskeys($userId);
$hasVault   = userHasVaultPassphraseCheck($userId);

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

$nextSetupText = t('setup.next.review');
$nextSetupLabel = t('action.continue');
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
    $nextSetupLabel = t('action.go_dashboard');
    $nextSetupHref = 'dashboard.php';
}

$onboardingAvailable = hasOnboardingColumns();
$onboardingDone = isOnboardingComplete($userId);

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
<title><?= htmlspecialchars(t('nav.setup')) ?> — <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/panel.css">
<link rel="stylesheet" href="assets/panel_components.css">
<style>
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}
.wrap{max-width:980px;}
.h{font-size:18px;}
.step{border:1px solid var(--b1);background:rgba(0,0,0,.18);padding:14px;}
.step-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;}
.step-title{font-family:var(--display);font-weight:900;font-size:12px;letter-spacing:2px;text-transform:uppercase;}
.step-sub{color:var(--muted);font-size:12px;line-height:1.7;margin-top:8px;}
.badge{font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;border:1px solid rgba(255,255,255,.13);color:var(--muted);}
.badge.ok{border-color:rgba(71,255,176,.2);color:var(--green);background:rgba(71,255,176,.06);}
.grid2{display:grid;grid-template-columns:1fr;gap:12px;}
@media(min-width:760px){.grid2{grid-template-columns:repeat(2,1fr);} }
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php"><?= htmlspecialchars(APP_NAME) ?></a>
  <div class="nav-r">
    <span class="pill" style="display:none;"><?= htmlspecialchars($userEmail) ?></span>
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?= htmlspecialchars(t('nav.theme')) ?></button>
    <a class="btn btn-ghost btn-sm <?= ($lang === 'fr') ? 'btn-lang-active' : '' ?>" href="<?= htmlspecialchars(langUrl('fr')) ?>">FR</a>
    <a class="btn btn-ghost btn-sm <?= ($lang === 'en') ? 'btn-lang-active' : '' ?>" href="<?= htmlspecialchars(langUrl('en')) ?>">EN</a>
    <a class="btn btn-ghost btn-sm" href="dashboard.php"><?= htmlspecialchars(t('nav.dashboard')) ?></a>
    <a class="btn btn-ghost btn-sm" href="account.php"><?= htmlspecialchars(t('nav.account')) ?></a>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?= htmlspecialchars(t('nav.admin')) ?></a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="logout.php"><?= htmlspecialchars(t('nav.logout')) ?></a>
  </div>
</div>

<div class="wrap">
  <div class="h"><?= htmlspecialchars(t('setup.title')) ?></div>
  <div class="p">Get <?= htmlspecialchars(APP_NAME) ?> ready for daily use. This takes a few minutes and makes unlocking and backups safer.</div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title"><div class="dot"></div><?= htmlspecialchars(t('setup.progress')) ?></div>
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
    <div class="p" style="margin-top:10px;color:var(--muted);"><?= htmlspecialchars(t('setup.progress_note')) ?></div>
  </div>

  <?php if ($onboardingAvailable && $onboardingDone): ?>
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title">You’re all set</div>
      <div class="p" style="margin-top:-6px;">You can revisit this page anytime.</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="dashboard.php" style="width:auto;"><?= htmlspecialchars(t('action.go_dashboard')) ?></a>
        <a class="btn btn-ghost" href="create_code.php" style="width:auto;"><?= htmlspecialchars(t('action.create_time_lock')) ?></a>
      </div>
    </div>
  <?php endif; ?>

  <div class="grid2">

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title">1) Vault passphrase</div>
          <div class="step-sub">This is the key you use to lock and unlock your codes. Keep it safe. If you lose it, nobody can recover your locked codes.</div>
        </div>
        <div class="badge <?= $hasVault ? 'ok' : '' ?>"><?= $hasVault ? '✓ set' : 'not set' ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="vault_settings.php" style="width:auto;"><?= htmlspecialchars(t('action.open_vault')) ?></a>
        <a class="btn btn-ghost" href="account.php#vault-passphrase-card" style="width:auto;"><?= htmlspecialchars(t('nav.account')) ?></a>
      </div>
    </div>

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title">2) Extra confirmation</div>
          <div class="step-sub">Add a passkey or authenticator app. You’ll be asked for it before sensitive actions like unlocking and backups.</div>
        </div>
        <div class="badge <?= ($hasTotp || $hasPasskey) ? 'ok' : '' ?>"><?= ($hasTotp || $hasPasskey) ? '✓ ready' : 'recommended' ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="account.php#passkeys-card" style="width:auto;">Add passkey</a>
        <a class="btn btn-ghost" href="account.php#totp-card" style="width:auto;">Setup authenticator</a>
      </div>
    </div>

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title">3) Backup</div>
          <div class="step-sub">Download an encrypted backup file so you can restore on a new device.</div>
        </div>
        <div class="badge <?= $backupCount > 0 ? 'ok' : '' ?>"><?= $backupCount > 0 ? ('✓ ' . (int)$backupCount) : 'none yet' ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="backup.php" style="width:auto;"><?= htmlspecialchars(t('action.open_backup')) ?></a>
        <?php if ($lastBackupAt): ?><span class="utc-pill" title="<?= htmlspecialchars(t('checklist.backup.utc_title')) ?>" style="align-self:center;"><?= htmlspecialchars(t('checklist.backup.last', ['at' => (string)$lastBackupAt])) ?></span><?php endif; ?>
      </div>
    </div>

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title">4) Create your first time lock</div>
          <div class="step-sub">Start small: lock a wallet PIN or a spending code for 24 hours. The goal is to create a cool‑off period.</div>
        </div>
        <div class="badge <?= $lockCount > 0 ? 'ok' : '' ?>"><?= $lockCount > 0 ? ('✓ ' . (int)$lockCount) : 'todo' ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;"><?= htmlspecialchars(t('action.create_time_lock')) ?></a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;"><?= htmlspecialchars(t('nav.my_codes')) ?></a>
      </div>
    </div>

    <div class="step" style="grid-column:1/-1;">
      <div class="step-top">
        <div>
          <div class="step-title">5) Save together (optional)</div>
          <div class="step-sub">Create a Saving Room for a goal, invite trusted people, and lock the rules in before the start date.</div>
        </div>
        <div class="badge">optional</div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="rooms.php" style="width:auto;">Open Saving Rooms</a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;"><?= htmlspecialchars(t('nav.notifications')) ?></a>
      </div>
    </div>

  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title"><?= htmlspecialchars(t('action.continue')) ?></div>
    <div class="p" style="margin-top:-6px;">You can always come back to this page from Dashboard → Setup.</div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button class="btn btn-primary" id="finish" type="button" style="width:auto;"><?= htmlspecialchars(t('action.go_dashboard')) ?></button>
      <a class="btn btn-ghost" href="dashboard.php?skip_setup=1" style="width:auto;"><?= htmlspecialchars(t('action.remind_next_time')) ?></a>
    </div>

    <div id="msg" class="msg"></div>

    <?php if (!$onboardingAvailable): ?>
      <div class="p" style="margin-top:12px;color:var(--muted);">Note: onboarding tracking is unavailable on this server (missing database migrations). This page won’t auto-hide.</div>
    <?php endif; ?>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const ONBOARDING_AVAILABLE = <?= $onboardingAvailable ? 'true' : 'false' ?>;
const NETWORK_ERROR = <?= json_encode(t('js.network_error')) ?>;
const REQUEST_FAILED = <?= json_encode(t('js.request_failed')) ?>;

function setMsg(text, ok){
  const el=document.getElementById('msg');
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}

async function postCsrf(url, body){
  const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

document.getElementById('finish').addEventListener('click', async ()=>{
  if(!ONBOARDING_AVAILABLE){
    window.location.href='dashboard.php';
    return;
  }

  try{
    const j = await postCsrf('api/onboarding.php', {action:'complete'});
    if(!j.success){setMsg(j.error||REQUEST_FAILED, false);return;}
    window.location.href='dashboard.php';
  }catch{
    setMsg(NETWORK_ERROR, false);
  }
});
</script>
</body>
</html>
