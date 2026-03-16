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
<title><?= htmlspecialchars(APP_NAME) ?> — System Backups</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<script src="assets/admin_shared.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.wrap{max-width:1180px;}
.table-wrap{overflow:auto;border:1px solid var(--b1);background:var(--s1);}
.table{width:100%;border-collapse:collapse;min-width:820px;}
.table th,.table td{padding:10px 12px;border-bottom:1px solid var(--b1);text-align:left;font-size:12px;white-space:nowrap;}
.table th{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;background:var(--s2);}
</style>
</head>
<body>
<div id="app">
  <?php $topbarBadgeText = 'SUPER ADMIN'; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">
    <div class="page-head">
      <div>
        <div class="page-title">System backups</div>
        <div class="page-sub">Daily database dumps created by <code>scripts/daily_backup.php</code>.</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-ghost btn-sm" type="button" id="refresh">↻ <?php e('common.refresh'); ?></button>
        <a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a>
      </div>
    </div>

    <div class="card wrap">
      <div class="table-wrap">
        <table class="table" id="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Created (UTC)</th>
              <th>Size</th>
              <th></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="msg" class="msg"></div>
      <div class="small" style="margin-top:12px;color:var(--muted);line-height:1.6;">
        If downloads fail with “Re-authentication required”, open any sensitive action (e.g. Export on the Backups page) to complete step-up auth, then retry.
      </div>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

function fmtBytes(n){
  const b = Math.max(0, parseInt(n||'0',10)||0);
  if(b < 1024) return b + ' B';
  if(b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
  if(b < 1024*1024*1024) return (b/1024/1024).toFixed(1) + ' MB';
  return (b/1024/1024/1024).toFixed(1) + ' GB';
}

async function loadBackups(){
  const tbody = document.querySelector('#tbl tbody');
  const msg = document.getElementById('msg');
  if(!tbody) return;

  tbody.innerHTML = '<tr><td colspan="4" class="k">Loading…</td></tr>';
  if(msg){ msg.textContent=''; msg.className='msg'; }

  try{
    // Uses admin_shared.js get() which performs reauth if needed.
    const j = await get('api/system_backups.php?action=list');
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Failed to load backups');

    const rows = Array.isArray(j.backups) ? j.backups : [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="4" class="k">No backups found.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    rows.forEach(b => {
      const name = String(b.name||'');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${esc(name)}</code></td>
        <td>${esc(String(b.created_at||''))}</td>
        <td>${esc(fmtBytes(b.bytes))}</td>
        <td>
          <button class="btn btn-blue btn-sm" type="button">Download</button>
        </td>
      `;

      const btn = tr.querySelector('button');
      if(btn){
        btn.addEventListener('click', async ()=>{
          // Ensure step-up auth is present (list already required it, but keep it robust).
          const ok = await get('api/system_backups.php?action=list');
          if(!ok || !ok.success){
            setMsg('msg', (ok && ok.error) ? ok.error : 'Re-authentication required', false);
            return;
          }
          const url = 'api/system_backups.php?action=download&name=' + encodeURIComponent(name);
          const a = document.createElement('a');
          a.href = url;
          a.target = '_blank';
          a.rel = 'noopener';
          document.body.appendChild(a);
          a.click();
          a.remove();
        });
      }

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="4" class="k">Failed to load backups.</td></tr>';
    setMsg('msg', (e && e.message) ? e.message : 'Failed to load backups', false);
  }
}

document.getElementById('refresh').addEventListener('click', loadBackups);
loadBackups();
</script>
</body>
</html>
