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
$isAdmin = true;
$verified = true;
$csrf = getCsrfToken();

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
<title><?= htmlspecialchars(APP_NAME) ?> — Admin KYC</title>
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
.modal{position:fixed;inset:0;background:var(--overlay-bg);display:none;align-items:center;justify-content:center;z-index:999;padding:24px;}
.modal.show{display:flex;}
.sheet{width:100%;max-width:980px;background:var(--s1);border:1px solid var(--b2);padding:18px;max-height:85vh;overflow:auto;border-radius:var(--radius-card);}
</style>
</head>
<body>
<div id="app">
  <?php $topbarBadgeText = 'SUPER ADMIN'; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">
    <div class="page-head">
      <div>
        <div class="page-title">KYC review</div>
        <div class="page-sub">Review and approve/reject pending KYC submissions.</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-ghost btn-sm" type="button" id="refresh">↻ <?php e('common.refresh'); ?></button>
        <a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a>
      </div>
    </div>

    <div class="card wrap">
      <div class="table-wrap">
        <table class="table" id="tbl" style="min-width:980px;">
          <thead>
            <tr>
              <th>ID</th>
              <th>User</th>
              <th>Submitted</th>
              <th>Docs</th>
              <th>Address</th>
              <th></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="msg" class="msg"></div>
    </div>
  </div>
</div>

<div class="modal" id="modal" onclick="closeModal(event)">
  <div class="sheet">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px;">
      <div style="font-family:var(--display);font-weight:800;font-size:16px;letter-spacing:-.4px;">KYC submission</div>
      <button class="btn btn-ghost btn-sm" type="button" onclick="closeModal()"><?php e('common.close'); ?></button>
    </div>

    <div class="k">User</div>
    <div class="v" id="m-email" style="margin-bottom:10px;">—</div>

    <div class="k">Address</div>
    <div class="small" id="m-address" style="margin:6px 0 14px 0;">—</div>

    <div class="k">Documents</div>
    <div id="m-docs" style="margin:10px 0 14px 0;"></div>

    <div class="field" style="margin:0;">
      <label>Note (optional, shown to user)</label>
      <input id="m-note" placeholder="Reason / notes">
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
      <button class="btn btn-green" type="button" id="m-approve">Approve</button>
      <button class="btn btn-red" type="button" id="m-reject">Reject</button>
    </div>

    <div id="m-ok" class="msg msg-ok"></div>
    <div id="m-err" class="msg msg-err"></div>

    <input type="hidden" id="m-id" value="">
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

function show(el, text){ if(!el) return; el.textContent = String(text||''); el.classList.add('show'); }
function clear(el){ if(!el) return; el.textContent=''; el.classList.remove('show'); }

async function loadPending(){
  const tbody = document.querySelector('#tbl tbody');
  const msg = document.getElementById('msg');
  if(!tbody) return;

  clear(msg);
  tbody.innerHTML = '<tr><td colspan="6" class="k">Loading…</td></tr>';

  try{
    const r = await fetch('api/admin_kyc.php?action=pending', {credentials:'same-origin'});
    const j = await r.json();
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Failed to load');

    const rows = j.submissions || [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="6" class="k">No pending submissions.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    rows.forEach(s => {
      const addr = [s.address_line1, s.address_city, s.address_region, s.address_postal_code, s.address_country].filter(Boolean).join(', ');
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(s.id)}</td>
        <td>${esc(s.email||'')}</td>
        <td>${fmt(s.submitted_at||'')}</td>
        <td>${esc(String(s.docs_count||0))}</td>
        <td title="${esc(addr)}">${esc(addr.slice(0, 64) + (addr.length > 64 ? '…' : ''))}</td>
        <td><button class="btn btn-blue btn-sm" type="button" onclick="openReview(${esc(s.id)})">Review</button></td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="6" class="k">Failed to load submissions.</td></tr>';
    show(msg, (e && e.message) ? e.message : 'Failed');
    msg.className = 'msg msg-err show';
  }
}

function closeModal(e){
  if(e && e.target !== document.getElementById('modal')) return;
  document.getElementById('modal').classList.remove('show');
}

async function openReview(id){
  clear(document.getElementById('m-ok'));
  clear(document.getElementById('m-err'));
  document.getElementById('m-email').textContent = '—';
  document.getElementById('m-address').textContent = '—';
  document.getElementById('m-docs').innerHTML = '';
  document.getElementById('m-note').value = '';
  document.getElementById('m-id').value = String(id);

  document.getElementById('modal').classList.add('show');

  try{
    const r = await fetch('api/admin_kyc.php?action=submission&id=' + encodeURIComponent(String(id)), {credentials:'same-origin'});
    const j = await r.json();
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Failed');

    const sub = j.submission || {};
    document.getElementById('m-email').textContent = sub.email || '';

    const addr = [sub.address_line1, sub.address_line2, sub.address_city, sub.address_region, sub.address_postal_code, sub.address_country]
      .filter(Boolean).join(', ');
    document.getElementById('m-address').textContent = addr || '—';

    const docs = j.documents || [];
    const box = document.getElementById('m-docs');
    if(!docs.length){
      const d = document.createElement('div');
      d.className = 'small';
      d.textContent = 'No documents.';
      box.appendChild(d);
    } else {
      docs.forEach(doc => {
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.justifyContent = 'space-between';
        row.style.gap = '10px';
        row.style.flexWrap = 'wrap';
        row.style.border = '1px solid var(--b1)';
        row.style.borderRadius = 'var(--radius-card)';
        row.style.padding = '10px 12px';
        row.style.marginBottom = '10px';
        row.style.background = 'linear-gradient(180deg, var(--s2), var(--s1))';

        const left = document.createElement('div');
        left.style.minWidth = '240px';
        left.style.flex = '1';

        const k = document.createElement('div');
        k.className = 'k';
        k.textContent = (doc.doc_kind ? String(doc.doc_kind).toUpperCase() : 'DOCUMENT');

        const v = document.createElement('div');
        v.className = 'v';
        v.textContent = doc.original_filename || ('Document #' + String(doc.id||''));

        const sm = document.createElement('div');
        sm.className = 'small';
        sm.textContent = (doc.content_type || '') + (doc.size_bytes ? (' · ' + String(Math.ceil(doc.size_bytes/1024)) + ' KB') : '');

        left.appendChild(k);
        left.appendChild(v);
        left.appendChild(sm);

        const a = document.createElement('a');
        a.className = 'btn btn-ghost btn-sm';
        a.href = doc.download_url || ('api/kyc_doc.php?id=' + encodeURIComponent(String(doc.id||'')));
        a.textContent = 'Download';

        row.appendChild(left);
        row.appendChild(a);
        box.appendChild(row);
      });
    }

  }catch(e){
    show(document.getElementById('m-err'), (e && e.message) ? e.message : 'Failed');
  }
}

async function decide(action){
  clear(document.getElementById('m-ok'));
  clear(document.getElementById('m-err'));

  const submission_id = parseInt(document.getElementById('m-id').value || '0', 10);
  const note = document.getElementById('m-note').value || '';

  try{
    const j = await postCsrf('api/admin_kyc.php', {action, submission_id, note});
    if(!j || !j.success) throw new Error((j && j.error) ? j.error : 'Failed');

    show(document.getElementById('m-ok'), 'Saved.');
    await loadPending();
    setTimeout(() => closeModal(), 450);

  }catch(e){
    show(document.getElementById('m-err'), (e && e.message) ? e.message : 'Failed');
  }
}

document.getElementById('refresh').addEventListener('click', loadPending);
document.getElementById('m-approve').addEventListener('click', () => decide('approve'));
document.getElementById('m-reject').addEventListener('click', () => decide('reject'));

loadPending();
</script>
</body>
</html>
