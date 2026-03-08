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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>LOCKSMITH — Notifications</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/panel.css">
<link rel="stylesheet" href="assets/panel_components.css">
<style>
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9998;opacity:.5;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.035'/%3E%3C/svg%3E");}
.orb1{width:520px;height:520px;top:-160px;right:-110px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}


.pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.pill{display:block;}}

.wrap{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:22px 16px 40px;}
.h{font-family:var(--display);font-weight:900;font-size:22px;letter-spacing:-.5px;margin:0 0 8px 0;}
.p{color:var(--muted);line-height:1.65;margin:0 0 18px 0;font-size:12px;}
.card-title{display:flex;align-items:center;justify-content:space-between;gap:10px;}



 

.list{display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:rgba(0,0,0,.22);padding:14px;}
.item-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;}
.title{font-family:var(--display);font-weight:800;font-size:12px;line-height:1.25;margin:0 0 6px 0;}
.body{color:var(--muted);font-size:12px;line-height:1.65;white-space:pre-wrap;}
.meta{margin-top:10px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;}
.tier{font-size:9px;letter-spacing:2px;text-transform:uppercase;border:1px solid rgba(232,255,71,.25);color:var(--accent);padding:5px 9px;}
.tier.important{border-color:rgba(71,184,255,.25);color:var(--blue);} 
.tier.critical{border-color:rgba(255,71,87,.28);color:var(--red);} 
.ts{font-size:10px;color:var(--muted);} 

.k{color:var(--muted);font-size:12px;line-height:1.6;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
  <div class="nav-r">
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle>Theme</button>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
    <a class="btn btn-ghost btn-sm" href="create_code.php">Create Code</a>
    <a class="btn btn-ghost btn-sm" href="my_codes.php">My Codes</a>
    <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
    <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
  </div>
</div>

<div class="wrap">
  <div class="h">Notifications</div>
  <div class="p">Your in-app notifications (critical / important / informational). Use “Mark all read” to clear the inbox.</div>

  <div class="card">
    <div class="card-title">
      <span>Inbox</span>
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;">
        <button class="btn btn-blue btn-sm" onclick="refresh()">↻ Refresh</button>
        <button class="btn btn-primary btn-sm" onclick="markAllRead()">Mark all read</button>
      </div>
    </div>

    <div class="k" id="meta">Loading…</div>
    <div class="list" id="list" style="margin-top:12px;"></div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
      <button class="btn btn-ghost btn-sm" id="more" onclick="loadMore()" style="display:none;">Load more</button>
    </div>

    <div id="msg" class="msg"></div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
let cursor = 0;
let loading = false;

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmt(ts){
  if(!ts) return '';
  try{ return new Date(ts).toLocaleString(); }catch{ return String(ts); }
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

function roomLinkFromData(data){
  const rid = data && data.room_id ? String(data.room_id) : '';
  if(rid && rid.length === 36) return 'room.php?id=' + encodeURIComponent(rid);
  return '';
}

function render(items, unreadCount){
  const meta = document.getElementById('meta');
  meta.textContent = `Unread: ${unreadCount}`;

  const list = document.getElementById('list');
  if(!items.length && !cursor){
    list.innerHTML = '<div class="k">No notifications.</div>';
    document.getElementById('more').style.display='none';
    return;
  }

  items.forEach(n => {
    const div = document.createElement('div');
    div.className = 'item';

    const link = roomLinkFromData(n.data);
    const read = !!n.read_at;

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
          ${link ? `<a class="btn btn-ghost btn-sm" href="${link}">Open room</a>` : ''}
          ${read ? '' : `<button class="btn btn-blue btn-sm" data-id="${n.id}">Mark read</button>`}
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
    if(!r.success) throw new Error(r.error || 'Failed');
    render(r.notifications || [], r.unread_count || 0);
  }catch(e){
    setMsg(e.message || 'Failed', false);
  }finally{
    loading = false;
  }
}

async function markRead(ids){
  try{
    const r = await post('api/notifications.php', {action:'mark_read', ids});
    if(!r.success) throw new Error(r.error || 'Failed');
    await load(true);
  }catch(e){
    setMsg(e.message || 'Failed', false);
  }
}

async function markAllRead(){
  try{
    const r = await post('api/notifications.php', {action:'mark_read', all:1});
    if(!r.success) throw new Error(r.error || 'Failed');
    await load(true);
  }catch(e){
    setMsg(e.message || 'Failed', false);
  }
}

function refresh(){ load(true); }
function loadMore(){ load(false); }

load(true);
</script>
</body>
</html>
