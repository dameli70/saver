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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.notifications')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/notifications_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">
    <div class="h"><?php e('page.notifications'); ?></div>
    <div class="p"><?php e('notifications.intro'); ?></div>

  <div class="card">
    <div class="card-title">
      <span><?php e('notifications.inbox'); ?></span>
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;">
        <button class="btn btn-blue btn-sm" onclick="refresh()">↻ <?php e('common.refresh'); ?></button>
        <button class="btn btn-primary btn-sm" onclick="markAllRead()"><?php e('notifications.mark_all_read'); ?></button>
      </div>
    </div>

    <div class="k" id="meta"><?php e('common.loading'); ?></div>
    <div class="list" id="list" style="margin-top:12px;"></div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
      <button class="btn btn-ghost btn-sm" id="more" onclick="loadMore()" style="display:none;"><?php e('common.load_more'); ?></button>
    </div>

    <div id="msg" class="msg"></div>
  </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
let cursor = 0;
let loading = false;

const STR = {
  unread: <?= json_encode(t('notifications.unread')) ?>,
  none: <?= json_encode(t('notifications.none')) ?>,
  openRoom: <?= json_encode(t('notifications.open_room')) ?>,
  openLock: <?= json_encode(t('notifications.open_lock')) ?>,
  markRead: <?= json_encode(t('notifications.mark_read')) ?>,
  failed: <?= json_encode(t('common.failed')) ?>,
};

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function parseUtcDate(ts){
  const s = String(ts||'').trim();
  if(!s) return null;

  // API timestamps are stored in UTC as "YYYY-MM-DD HH:MM:SS".
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
    return new Date(s.replace(' ', 'T') + 'Z');
  }

  return new Date(s);
}
function fmt(ts){
  const d = parseUtcDate(ts);
  if(!d || isNaN(d.getTime())) return String(ts||'');
  return d.toLocaleString();
}
function setMsg(text, ok){
  const el = document.getElementById('msg');
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}

async function get(url){
  const r = await fetch(url, { credentials:'same-origin' });
  return r.json();
}
async function post(url, body){
  const r = await fetch(url, {
    method:'POST',
    credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},
    body: JSON.stringify(body)
  });
  return r.json();
}

function tierClass(t){
  if(t==='critical') return 'tier critical';
  if(t==='important') return 'tier important';
  return 'tier';
}

function actionLinkFromData(data){
  if(data && data.lock_id){
    const id = String(data.lock_id);
    if(id && id.length === 36) return {href:'my_codes.php#lock-' + encodeURIComponent(id), label: STR.openLock};
  }

  if(data && data.wallet_lock_id){
    const id = String(data.wallet_lock_id);
    if(id && id.length === 36) return {href:'my_codes.php#wallet-' + encodeURIComponent(id), label: STR.openLock};
  }

  const rid = data && data.room_id ? String(data.room_id) : '';
  if(rid && rid.length === 36) return {href:'room.php?id=' + encodeURIComponent(rid), label: STR.openRoom};

  return null;
}

function render(items, unreadCount){
  const meta = document.getElementById('meta');
  meta.textContent = `${STR.unread}: ${unreadCount}`;

  const list = document.getElementById('list');
  if(!items.length && !cursor){
    list.innerHTML = '<div class="k">'+esc(STR.none)+'</div>';
    document.getElementById('more').style.display='none';
    return;
  }

  items.forEach(n => {
    const div = document.createElement('div');
    div.className = 'item';

    const link = actionLinkFromData(n.data);
    const read = !!n.read_at;
    div.dataset.read = read ? '1' : '0';

    div.innerHTML = `
      <div class="item-top">
        <div style="flex:1;min-width:240px;">
          <div class="title">${esc(n.title)}${read ? '' : ' <span style="color:var(--accent);">•</span>'}</div>
          <div class="body">${esc(n.body)}</div>
        </div>
        <div class="${tierClass(n.tier)}">${esc(n.tier)}</div>
      </div>
      <div class="meta">
        <div class="ts">${fmt(n.created_at)}</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;">
          ${link ? `<a class="btn btn-ghost btn-sm" href="${link.href}">${esc(link.label)}</a>` : ''}
          ${read ? '' : `<button class="btn btn-blue btn-sm" data-id="${n.id}">${esc(STR.markRead)}</button>`}
        </div>
      </div>
    `;

    const btn = div.querySelector('button[data-id]');
    if(btn){
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        const id = parseInt(btn.getAttribute('data-id'), 10);
        await markRead([id]);
      });
    }

    list.appendChild(div);
  });

  const last = items[items.length - 1];
  if(last && last.id){ cursor = last.id; }
  document.getElementById('more').style.display = (items.length >= 50) ? 'inline-flex' : 'none';
}

async function load(reset){
  if(loading) return;
  loading = true;

  if(reset){
    cursor = 0;
    document.getElementById('list').innerHTML = '';
    setMsg('', true);
    document.getElementById('msg').className = 'msg';
  }

  try{
    const url = 'api/notifications.php?action=list&limit=50' + (cursor ? '&before_id=' + encodeURIComponent(cursor) : '');
    const r = await get(url);
    if(!r.success) throw new Error(r.error || STR.failed);

    render(r.notifications || [], r.unread_count || 0);
  }catch(e){
    setMsg(e.message || STR.failed, false);
  }finally{
    loading = false;
  }
}

async function markRead(ids){
  try{
    const r = await post('api/notifications.php', {action:'mark_read', ids});
    if(!r.success) throw new Error(r.error || STR.failed);
    await load(true);
  }catch(e){
    setMsg(e.message || STR.failed, false);
  }
}

async function markAllRead(){
  try{
    const r = await post('api/notifications.php', {action:'mark_read', all:1});
    if(!r.success) throw new Error(r.error || STR.failed);
    await load(true);
  }catch(e){
    setMsg(e.message || STR.failed, false);
  }
}

function refresh(){ load(true); }
function loadMore(){ load(false); }

load(true);
</script>
</div>
</body>
</html>