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

if (!isAdmin()) {
    header('Location: dashboard.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin = true;
$verified = true;
$csrf = getCsrfToken();

$db = getDB();
$packages = hasPackagesTables() ? packagesGetAll($db, false) : [];

$purchases = [];
$assignments = [];
if (hasPackagesTables()) {
    packagesSeedDefaults($db);

    $purchases = $db->query("SELECT pp.id, pp.user_id, u.email AS user_email, pp.package_id, p.name AS package_name, pp.status, pp.created_at
                             FROM package_purchases pp
                             JOIN users u ON u.id = pp.user_id
                             JOIN packages p ON p.id = pp.package_id
                             WHERE pp.status = 'pending'
                             ORDER BY pp.created_at DESC
                             LIMIT 500")->fetchAll();

    $assignments = $db->query("SELECT up.user_id, u.email AS user_email, up.package_id, p.name AS package_name, up.assigned_at
                               FROM user_packages up
                               JOIN users u ON u.id = up.user_id
                               JOIN packages p ON p.id = up.package_id
                               WHERE up.is_active = 1
                               ORDER BY up.assigned_at DESC
                               LIMIT 500")->fetchAll();
}

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?php e('packages.admin_title'); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<script src="assets/admin_shared.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.wrap{max-width:1100px;}
.table{width:100%;border-collapse:collapse;}
.table th,.table td{border-bottom:1px solid var(--b1);padding:10px 8px;text-align:left;vertical-align:top;}
.table th{font-size:11px;color:var(--muted);letter-spacing:1.6px;text-transform:uppercase;font-family:var(--mono);}
.input{width:100%;min-width:90px;}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
.small{color:var(--muted);font-size:12px;}
</style>
</head>
<body>
<div id="app">
  <?php $topbarBadgeText = 'SUPER ADMIN'; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">
    <div class="page-head">
      <div>
        <div class="page-title"><?php e('packages.admin_title'); ?></div>
        <div class="page-sub"><?php e('packages.admin_subtitle'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a>
        <a class="btn btn-ghost btn-sm" href="packages.php"><?php e('packages.title'); ?></a>
      </div>
    </div>

    <?php if (!hasPackagesTables()): ?>
      <div class="card wrap">
        <div class="msg msg-err show"><?php e('packages.migrations_required'); ?></div>
      </div>
    <?php else: ?>

    <div class="card wrap">
      <div class="card-title"><?php e('packages.admin_create_title'); ?></div>
      <div class="row">
        <div class="field" style="flex:1;min-width:160px;">
          <label><?php e('packages.slug'); ?></label>
          <input class="input" id="new-slug" placeholder="controle_plus">
        </div>
        <div class="field" style="flex:1;min-width:180px;">
          <label><?php e('packages.name'); ?></label>
          <input class="input" id="new-name" placeholder="Controle+">
        </div>
        <div class="field" style="width:140px;">
          <label><?php e('packages.max_active_codes'); ?></label>
          <input class="input" id="new-locks" type="number" min="0" value="1">
        </div>
        <div class="field" style="width:140px;">
          <label><?php e('packages.max_active_rooms'); ?></label>
          <input class="input" id="new-rooms" type="number" min="0" value="1">
        </div>
        <div class="field" style="width:170px;">
          <label><?php e('packages.max_active_wallet_locks'); ?></label>
          <input class="input" id="new-wallet" type="number" min="0" value="1">
        </div>
        <div class="field" style="width:140px;">
          <label><?php e('packages.fast_support'); ?></label>
          <select class="input" id="new-fast">
            <option value="0"><?php e('common.no'); ?></option>
            <option value="1"><?php e('common.yes'); ?></option>
          </select>
        </div>
        <button class="btn btn-primary" type="button" id="create-btn"><?php e('packages.create'); ?></button>
      </div>
      <div class="msg msg-ok" id="create-ok"></div>
      <div class="msg msg-err" id="create-err"></div>
    </div>

    <div class="card wrap">
      <div class="card-title"><?php e('packages.admin_packages_title'); ?></div>
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th><?php e('packages.slug'); ?></th>
            <th><?php e('packages.name'); ?></th>
            <th><?php e('packages.max_active_codes'); ?></th>
            <th><?php e('packages.max_active_rooms'); ?></th>
            <th><?php e('packages.max_active_wallet_locks'); ?></th>
            <th><?php e('packages.fast_support'); ?></th>
            <th><?php e('packages.active'); ?></th>
            <th></th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($packages as $p): ?>
          <tr data-package-row data-id="<?= (int)$p['id'] ?>">
            <td><?= (int)$p['id'] ?></td>
            <td><input class="input" data-f="slug" value="<?= htmlspecialchars((string)$p['slug'], ENT_QUOTES, 'UTF-8') ?>"></td>
            <td><input class="input" data-f="name" value="<?= htmlspecialchars((string)$p['name'], ENT_QUOTES, 'UTF-8') ?>"></td>
            <td><input class="input" data-f="max_active_locks" type="number" min="0" value="<?= (int)$p['max_active_locks'] ?>"></td>
            <td><input class="input" data-f="max_active_rooms" type="number" min="0" value="<?= (int)$p['max_active_rooms'] ?>"></td>
            <td><input class="input" data-f="max_active_wallet_locks" type="number" min="0" value="<?= (int)$p['max_active_wallet_locks'] ?>"></td>
            <td>
              <select class="input" data-f="fast_support">
                <option value="0" <?= empty($p['fast_support']) ? 'selected' : '' ?>><?php e('common.no'); ?></option>
                <option value="1" <?= !empty($p['fast_support']) ? 'selected' : '' ?>><?php e('common.yes'); ?></option>
              </select>
            </td>
            <td>
              <select class="input" data-f="is_active">
                <option value="0" <?= empty($p['is_active']) ? 'selected' : '' ?>><?php e('common.no'); ?></option>
                <option value="1" <?= !empty($p['is_active']) ? 'selected' : '' ?>><?php e('common.yes'); ?></option>
              </select>
            </td>
            <td><button class="btn btn-ghost btn-sm" type="button" data-save><?php e('common.save'); ?></button></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <div class="msg msg-ok" id="pkg-ok"></div>
      <div class="msg msg-err" id="pkg-err"></div>
    </div>

    <div class="card wrap">
      <div class="card-title"><?php e('packages.admin_assign_title'); ?></div>
      <div class="row">
        <div class="field" style="flex:1;min-width:220px;">
          <label><?php e('packages.user_email'); ?></label>
          <input class="input" id="assign-email" placeholder="user@example.com">
        </div>
        <div class="field" style="flex:1;min-width:200px;">
          <label><?php e('packages.package'); ?></label>
          <select class="input" id="assign-package">
            <?php foreach ($packages as $p): ?>
              <option value="<?= (int)$p['id'] ?>"><?= htmlspecialchars((string)$p['name'], ENT_QUOTES, 'UTF-8') ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <button class="btn btn-primary" type="button" id="assign-btn"><?php e('packages.assign'); ?></button>
      </div>
      <div class="msg msg-ok" id="assign-ok"></div>
      <div class="msg msg-err" id="assign-err"></div>

      <div class="hr"></div>
      <div class="small"><?php e('packages.admin_assign_current'); ?></div>
      <table class="table" style="margin-top:8px;">
        <thead><tr><th><?php e('packages.user_email'); ?></th><th><?php e('packages.package'); ?></th><th><?php e('packages.assigned_at'); ?></th></tr></thead>
        <tbody>
          <?php foreach ($assignments as $a): ?>
            <tr><td><?= htmlspecialchars((string)$a['user_email'], ENT_QUOTES, 'UTF-8') ?></td><td><?= htmlspecialchars((string)$a['package_name'], ENT_QUOTES, 'UTF-8') ?></td><td><?= htmlspecialchars((string)$a['assigned_at'], ENT_QUOTES, 'UTF-8') ?></td></tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>

    <div class="card wrap">
      <div class="card-title"><?php e('packages.admin_purchases_title'); ?></div>
      <?php if (!$purchases): ?>
        <div class="small"><?php e('packages.admin_none_pending'); ?></div>
      <?php else: ?>
        <table class="table">
          <thead><tr><th>ID</th><th><?php e('packages.user_email'); ?></th><th><?php e('packages.package'); ?></th><th><?php e('packages.created_at'); ?></th><th></th></tr></thead>
          <tbody>
            <?php foreach ($purchases as $pp): ?>
              <tr>
                <td><?= (int)$pp['id'] ?></td>
                <td><?= htmlspecialchars((string)$pp['user_email'], ENT_QUOTES, 'UTF-8') ?></td>
                <td><?= htmlspecialchars((string)$pp['package_name'], ENT_QUOTES, 'UTF-8') ?></td>
                <td><?= htmlspecialchars((string)$pp['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                <td><button class="btn btn-primary btn-sm" type="button" data-approve data-purchase-id="<?= (int)$pp['id'] ?>"><?php e('packages.approve'); ?></button></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>

      <div class="msg msg-ok" id="pur-ok"></div>
      <div class="msg msg-err" id="pur-err"></div>
    </div>

    <?php endif; ?>

  </div>
</div>

<script>
// Required by assets/admin_shared.js
const CSRF = <?= json_encode($csrf) ?>;

(() => {
  function show(el, text){ if(!el) return; el.textContent = String(text||''); el.classList.add('show'); }
  function clear(el){ if(!el) return; el.textContent=''; el.classList.remove('show'); }

  async function postAdmin(body){
    const j = await postCsrf('api/admin.php', body || {});
    if(!j || !j.success){
      const msg = (j && j.error) ? j.error : 'Request failed';
      throw new Error(msg);
    }
    return j;
  }

  // Create
  const createBtn = document.getElementById('create-btn');
  if(createBtn){
    createBtn.addEventListener('click', async () => {
      clear(document.getElementById('create-ok')); clear(document.getElementById('create-err'));
      try{
        await postAdmin({
          action:'package_create',
          slug: (document.getElementById('new-slug')||{}).value,
          name: (document.getElementById('new-name')||{}).value,
          max_active_locks: parseInt((document.getElementById('new-locks')||{}).value||'1',10),
          max_active_rooms: parseInt((document.getElementById('new-rooms')||{}).value||'1',10),
          max_active_wallet_locks: parseInt((document.getElementById('new-wallet')||{}).value||'1',10),
          fast_support: parseInt((document.getElementById('new-fast')||{}).value||'0',10),
        });
        show(document.getElementById('create-ok'), <?= json_encode(t('common.saved')) ?>);
        location.reload();
      }catch(e){
        show(document.getElementById('create-err'), e.message);
      }
    });
  }

  // Save package rows
  document.querySelectorAll('[data-package-row]').forEach(row => {
    const save = row.querySelector('[data-save]');
    if(!save) return;
    save.addEventListener('click', async () => {
      clear(document.getElementById('pkg-ok')); clear(document.getElementById('pkg-err'));
      try{
        const id = parseInt(row.getAttribute('data-id')||'0',10);
        const body = { action:'package_update', package_id:id };
        row.querySelectorAll('[data-f]').forEach(el => { body[el.getAttribute('data-f')] = el.value; });
        await postAdmin(body);
        show(document.getElementById('pkg-ok'), <?= json_encode(t('common.saved')) ?>);
      }catch(e){
        show(document.getElementById('pkg-err'), e.message);
      }
    });
  });

  // Assign
  const assignBtn = document.getElementById('assign-btn');
  if(assignBtn){
    assignBtn.addEventListener('click', async () => {
      clear(document.getElementById('assign-ok')); clear(document.getElementById('assign-err'));
      try{
        await postAdmin({
          action:'assign_package',
          email: (document.getElementById('assign-email')||{}).value,
          package_id: parseInt((document.getElementById('assign-package')||{}).value||'0',10),
        });
        show(document.getElementById('assign-ok'), <?= json_encode(t('common.saved')) ?>);
        location.reload();
      }catch(e){
        show(document.getElementById('assign-err'), e.message);
      }
    });
  }

  // Approve purchases
  document.querySelectorAll('[data-approve]').forEach(btn => {
    btn.addEventListener('click', async () => {
      clear(document.getElementById('pur-ok')); clear(document.getElementById('pur-err'));
      try{
        const purchaseId = parseInt(btn.getAttribute('data-purchase-id')||'0',10);
        await postAdmin({ action:'approve_package_purchase', purchase_id: purchaseId });
        show(document.getElementById('pur-ok'), <?= json_encode(t('common.saved')) ?>);
        location.reload();
      }catch(e){
        show(document.getElementById('pur-err'), e.message);
      }
    });
  });
})();
</script>
</body>
</html>
