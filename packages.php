<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/packages.php';

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
$isAdmin = isAdmin();
$verified = true;
$csrf = getCsrfToken();

$info = packagesGetUserInfo($userId);
$limits = $info['limits'];
$usage = $info['usage'];
$available = $info['available_packages'];

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?php e('packages.title'); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.wrap{max-width:980px;}
.grid{display:grid;grid-template-columns:1fr;gap:14px;}
@media(min-width:880px){.grid{grid-template-columns:1fr 1fr;}}
.cardx{background:linear-gradient(180deg, var(--s3), var(--s1));border:1px solid var(--b1);padding:18px;border-radius:var(--radius-card);box-shadow:var(--shadow-card);}
.h{font-family:var(--display);font-size:22px;font-weight:800;letter-spacing:-.6px;}
.k{color:var(--muted);font-size:11px;letter-spacing:1.6px;text-transform:uppercase;font-family:var(--mono);}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;}
.badge{display:inline-flex;align-items:center;gap:8px;border:1px solid rgb(var(--accent-rgb) / .35);color:var(--accent);
  padding:6px 10px;border-radius:var(--radius-pill);background:rgb(var(--accent-rgb) / .08);font-size:10px;letter-spacing:2px;text-transform:uppercase;font-family:var(--mono);
}
.limits{display:grid;grid-template-columns:1fr;gap:8px;margin-top:12px;}
.limits .it{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--b1);border-radius:14px;background:rgb(255 255 255 / .03);}
.limits .it b{font-weight:700;}
.msg{margin-top:12px;}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">
    <div class="page-head">
      <div>
        <div class="page-title"><?php e('packages.title'); ?></div>
        <div class="page-sub"><?php e('packages.subtitle'); ?></div>
      </div>
      <div class="page-actions">
        <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin_packages.php"><?php e('packages.admin_btn'); ?></a><?php endif; ?>
      </div>
    </div>

    <div class="card wrap">
      <div class="row">
        <div>
          <div class="k"><?php e('packages.current_plan'); ?></div>
          <div class="h"><?= htmlspecialchars((string)$limits['package_name'], ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <div class="badge"><?php e('packages.usage_badge'); ?>: <?= (int)$usage['active_locks'] ?>/<?= (int)$limits['max_active_locks'] ?> <?php e('packages.codes'); ?></div>
      </div>

      <div class="limits">
        <div class="it"><span><?php e('packages.active_codes'); ?></span><b><?= (int)$usage['active_locks'] ?>/<?= (int)$limits['max_active_locks'] ?></b></div>
        <div class="it"><span><?php e('packages.active_rooms'); ?></span><b><?= (int)$usage['active_rooms'] ?>/<?= (int)$limits['max_active_rooms'] ?></b></div>
        <div class="it"><span><?php e('packages.active_wallet_locks'); ?></span><b><?= (int)$usage['active_wallet_locks'] ?>/<?= (int)$limits['max_active_wallet_locks'] ?></b></div>
        <div class="it"><span><?php e('packages.fast_support'); ?></span><b><?= !empty($limits['fast_support']) ? htmlspecialchars(t('common.yes'), ENT_QUOTES, 'UTF-8') : htmlspecialchars(t('common.no'), ENT_QUOTES, 'UTF-8') ?></b></div>
      </div>

      <div class="msg msg-ok" id="ok"></div>
      <div class="msg msg-err" id="err"></div>
    </div>

    <div class="grid wrap" style="margin-top:16px;">
      <?php foreach ($available as $p):
        $pid = (int)$p['id'];
        $isCurrent = ((int)($limits['package_id'] ?? 0) === $pid);
      ?>
        <div class="cardx">
          <div class="row">
            <div>
              <div class="k"><?php e('packages.plan'); ?></div>
              <div class="h"><?= htmlspecialchars((string)$p['name'], ENT_QUOTES, 'UTF-8') ?></div>
            </div>
            <?php if ($isCurrent): ?>
              <span class="badge"><?php e('packages.current'); ?></span>
            <?php endif; ?>
          </div>

          <div class="limits">
            <div class="it"><span><?php e('packages.max_active_codes'); ?></span><b><?= (int)$p['max_active_locks'] ?></b></div>
            <div class="it"><span><?php e('packages.max_active_rooms'); ?></span><b><?= (int)$p['max_active_rooms'] ?></b></div>
            <div class="it"><span><?php e('packages.max_active_wallet_locks'); ?></span><b><?= (int)$p['max_active_wallet_locks'] ?></b></div>
            <div class="it"><span><?php e('packages.fast_support'); ?></span><b><?= !empty($p['fast_support']) ? htmlspecialchars(t('common.yes'), ENT_QUOTES, 'UTF-8') : htmlspecialchars(t('common.no'), ENT_QUOTES, 'UTF-8') ?></b></div>
          </div>

          <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
            <button class="btn btn-primary" type="button" data-purchase-btn data-package-id="<?= $pid ?>" <?= $isCurrent ? 'disabled' : '' ?>><?php e('packages.purchase'); ?></button>
            <span class="small"><?php e('packages.purchase_hint'); ?></span>
          </div>
        </div>
      <?php endforeach; ?>
    </div>

  </div>
</div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;
  const ok = document.getElementById('ok');
  const err = document.getElementById('err');

  function show(el, text){ if(!el) return; el.textContent = String(text||''); el.classList.add('show'); }
  function clear(el){ if(!el) return; el.textContent=''; el.classList.remove('show'); }

  async function postCsrf(url, body){
    const res = await fetch(url, {
      method:'POST',
      headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
      credentials:'same-origin',
      body: JSON.stringify(body||{}),
    });
    const j = await res.json().catch(() => null);
    if(!res.ok) {
      const msg = (j && j.error) ? j.error : 'Request failed';
      const e = new Error(msg);
      e.data = j;
      throw e;
    }
    return j;
  }

  async function purchase(packageId){
    clear(ok); clear(err);
    try{
      const j = await postCsrf('api/packages.php', {action:'purchase', package_id: packageId});
      if(j.already_pending){
        show(ok, <?= json_encode(t('packages.pending_already')) ?>);
      } else {
        show(ok, <?= json_encode(t('packages.pending_created')) ?>);
      }
    }catch(e){
      show(err, (e && e.message) ? e.message : 'Failed');
    }
  }

  document.querySelectorAll('[data-purchase-btn]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.getAttribute('data-package-id')||'0', 10);
      if(id > 0) purchase(id);
    });
  });
})();
</script>
</body>
</html>
