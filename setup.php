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

$nextSetupTextKey = 'onboarding.next.review';
$nextSetupLabelKey = 'onboarding.action.continue';
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
    $nextSetupLabelKey = 'onboarding.action.go_to_dashboard';
    $nextSetupHref = 'dashboard.php';
}

$nextSetupText = t($nextSetupTextKey);
$nextSetupLabel = t($nextSetupLabelKey);

$onboardingAvailable = hasOnboardingColumns();
$onboardingDone = isOnboardingComplete($userId);

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.setup')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}

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

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">
    <div class="h"><?php e('page.setup'); ?></div>
    <div class="p"><?php e('setup.intro', ['app' => APP_NAME]); ?></div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title"><div class="dot"></div><?php e('setup.progress'); ?></div>
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
    <div class="p" style="margin-top:10px;color:var(--muted);"><?php e('setup.progress_sub'); ?></div>
  </div>
  <?php if ($onboardingAvailable && $onboardingDone): ?>
    <div class="card" style="margin-bottom:14px;">
      <div class="card-title"><?php e('setup.all_set_title'); ?></div>
      <div class="p" style="margin-top:-6px;"><?php e('setup.all_set_sub'); ?></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="dashboard.php" style="width:auto;"><?php e('onboarding.action.go_to_dashboard'); ?></a>
        <a class="btn btn-ghost" href="create_code.php" style="width:auto;"><?php e('onboarding.action.create_time_lock'); ?></a>
      </div>
    </div>
  <?php endif; ?>

  <div class="grid2">

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title"><?php e('setup.step1_title'); ?></div>
          <div class="step-sub"><?php e('setup.step1_sub'); ?></div>
        </div>
        <div class="badge <?= $hasVault ? 'ok' : '' ?>"><?= $hasVault ? t('setup.status.set') : t('setup.status.not_set') ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="vault_settings.php" style="width:auto;"><?php e('onboarding.action.open_vault'); ?></a>
        <a class="btn btn-ghost" href="account.php#vault-passphrase-card" style="width:auto;"><?php e('setup.manage_in_account'); ?></a>
      </div>
    </div>

    <?php if (!$hasTotp && !$hasPasskey): ?>
    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title"><?php e('setup.step2_title'); ?></div>
          <div class="step-sub"><?php e('setup.step2_sub'); ?></div>
        </div>
        <div class="badge <?= ($hasTotp || $hasPasskey) ? 'ok' : '' ?>"><?= ($hasTotp || $hasPasskey) ? t('setup.status.ready') : t('setup.status.recommended') ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="account.php#passkeys-card" style="width:auto;"><?php e('setup.add_passkey'); ?></a>
        <a class="btn btn-ghost" href="account.php#totp-card" style="width:auto;"><?php e('setup.setup_authenticator'); ?></a>
      </div>
    </div>
    <?php endif; ?>

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title"><?php e('setup.step3_title'); ?></div>
          <div class="step-sub"><?php e('setup.step3_sub'); ?></div>
        </div>
        <div class="badge <?= $backupCount > 0 ? 'ok' : '' ?>"><?= $backupCount > 0 ? (t('setup.status.count', ['count' => (int)$backupCount])) : t('setup.status.none_yet') ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="backup.php" style="width:auto;"><?php e('onboarding.action.open_backup'); ?></a>
        <?php if ($lastBackupAt): ?><span class="utc-pill" title="<?= htmlspecialchars(t('dashboard.stored_in_utc'), ENT_QUOTES, 'UTF-8') ?>" style="align-self:center;"><?php e('setup.last', ['ts' => $lastBackupAt]); ?></span><?php endif; ?>
      </div>
    </div>

    <div class="step">
      <div class="step-top">
        <div>
          <div class="step-title"><?php e('setup.step4_title'); ?></div>
          <div class="step-sub"><?php e('setup.step4_sub'); ?></div>
        </div>
        <div class="badge <?= $lockCount > 0 ? 'ok' : '' ?>"><?= $lockCount > 0 ? (t('setup.status.count', ['count' => (int)$lockCount])) : t('setup.status.todo') ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="create_code.php" style="width:auto;"><?php e('onboarding.action.create_time_lock'); ?></a>
        <a class="btn btn-ghost" href="my_codes.php" style="width:auto;"><?php e('setup.view_my_time_locks'); ?></a>
      </div>
    </div>

    <div class="step" style="grid-column:1/-1;">
      <div class="step-top">
        <div>
          <div class="step-title"><?php e('setup.step5_title'); ?></div>
          <div class="step-sub"><?php e('setup.step5_sub'); ?></div>
        </div>
        <div class="badge"><?php e('common.optional'); ?></div>
      </div>
      <div class="actions">
        <a class="btn btn-primary" href="rooms.php" style="width:auto;"><?php e('setup.open_saving_rooms'); ?></a>
        <a class="btn btn-ghost" href="notifications.php" style="width:auto;"><?php e('nav.notifications'); ?></a>
      </div>
    </div>

  </div>

  <div class="card" style="margin-top:14px;">
    <div class="card-title"><?php e('setup.continue_title'); ?></div>
    <div class="p" style="margin-top:-6px;"><?php e('setup.continue_sub'); ?></div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;">
      <button class="btn btn-primary" id="finish" type="button" style="width:auto;"><?php e('onboarding.action.go_to_dashboard'); ?></button>
      <a class="btn btn-ghost" href="dashboard.php?skip_setup=1" style="width:auto;"><?php e('setup.remind_next_time'); ?></a>
    </div>

    <div id="msg" class="msg"></div>

    <?php if (!$onboardingAvailable): ?>
      <div class="p" style="margin-top:12px;color:var(--muted);"><?php e('setup.note_tracking_unavailable'); ?></div>
    <?php endif; ?>
  </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const ONBOARDING_AVAILABLE = <?= $onboardingAvailable ? 'true' : 'false' ?>;

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
    if(!j.success){setMsg(j.error||<?= json_encode(t('common.failed')) ?>, false);return;}
    window.location.href='dashboard.php';
  }catch{
    setMsg(<?= json_encode(t('common.network_error')) ?>, false);
  }
});
</script>
</div>
</body>
</html>