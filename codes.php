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
    header('Location: profile.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: clipboard-write=(self)");
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Codes — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="manifest" href="manifest.webmanifest">
<meta name="theme-color" content="#06070a">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--blue:#47b8ff;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
  --r:14px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;-webkit-tap-highlight-color:transparent;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:14px;min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}

.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:max(14px,var(--sat)) 20px 14px;border-bottom:1px solid var(--b1);
  position:sticky;top:0;background:rgba(6,7,10,.94);backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);z-index:100;}
.topbar-logo{font-family:var(--display);font-size:clamp(15px,4vw,19px);font-weight:900;letter-spacing:-1px;}
.topbar-logo span{color:var(--accent);} 
.topbar-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.user-pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.user-pill{display:block;}}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;
  border-radius:var(--r);-webkit-appearance:none;touch-action:manipulation;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:500;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:disabled{opacity:.4;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);}
.btn-ghost:hover{border-color:var(--text);} 
.btn-green{background:var(--green);color:#000;font-weight:500;}
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);}
.btn-sm{padding:10px 14px;font-size:11px;min-height:40px;}

.wrap{max-width:980px;margin:0 auto;padding:22px 16px 60px;}
@media(min-width:600px){.wrap{padding:30px 24px;}}

.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}

.tabs{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;}
.tab{padding:10px 12px;border-radius:999px;border:1px solid var(--b1);background:rgba(13,15,20,.9);color:var(--muted);font-size:11px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;}
.tab.sel{border-color:rgba(232,255,71,.35);color:var(--accent);background:rgba(232,255,71,.06);} 

.locks-grid{display:flex;flex-direction:column;gap:12px;}
.lock-card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:16px 18px;border-radius:var(--r);position:relative;transition:border-color .2s;}
.lock-card:hover{border-color:var(--b2);} 
.lock-card.st-locked{border-left:3px solid rgba(255,71,87,.5);} 
.lock-card.st-unlocked{border-left:3px solid rgba(71,255,176,.5);} 
.lock-card.st-pending{border-left:3px solid rgba(255,170,0,.5);} 
.lock-card.st-auto_saved{border-left:3px solid rgba(71,184,255,.4);} 
.lock-card.st-rejected{border-left:3px solid rgba(255,71,87,.2);opacity:.65;} 

.lc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;}
.lc-label{font-family:var(--display);font-size:14px;font-weight:700;word-break:break-word;}
.lc-badge{display:inline-flex;align-items:center;flex-shrink:0;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:4px 8px;border:1px solid;border-radius:999px;}
.lc-badge.locked{background:rgba(255,71,87,.07);border-color:rgba(255,71,87,.2);color:var(--red);} 
.lc-badge.unlocked{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);} 
.lc-badge.pending{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);} 
.lc-badge.auto_saved{background:rgba(71,184,255,.07);border-color:rgba(71,184,255,.2);color:var(--blue);} 
.lc-badge.rejected{background:rgba(255,71,87,.05);border-color:rgba(255,71,87,.1);color:var(--muted);} 

.lc-hint{font-size:11px;color:var(--muted);font-style:italic;margin-bottom:10px;padding:6px 10px;border-left:2px solid var(--b2);} 
.lc-meta{font-size:11px;color:var(--muted);line-height:1.7;margin-bottom:10px;} 
.lc-meta span{color:var(--text);} 
.lc-countdown{font-size:12px;color:var(--accent);margin-bottom:10px;letter-spacing:1px;} 
.lc-actions{display:flex;gap:8px;flex-wrap:wrap;} 

.empty{text-align:center;padding:60px 20px;color:var(--muted);} 

</style>
</head>
<body>
  <div class="topbar">
    <div class="topbar-logo">LOCK<span>SMITH</span></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
      <a class="btn btn-ghost btn-sm" href="backup.php">Backups</a>
      <a class="btn btn-ghost btn-sm" href="profile.php">Profile</a>
      <a class="btn btn-ghost btn-sm" href="security.php">Security</a>
      <a class="btn btn-ghost btn-sm" href="faq.php">FAQ</a>
      <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="wrap">
    <div class="h">Codes</div>
    <div class="p">Your codes are always encrypted on this server. Countdown is to the reveal date.</div>

    <div class="tabs" id="tabs">
      <button class="tab sel" data-tab="current" type="button">Current</button>
      <button class="tab" data-tab="revealed" type="button">Revealed</button>
      <button class="tab" data-tab="void" type="button">Void</button>
      <button class="btn btn-ghost btn-sm" id="refresh" type="button">↻ Refresh</button>
    </div>

    <div id="locks-wrap">
      <div class="empty">Loading…</div>
    </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function parseServerUtcDateTime(s){
  if(!s) return null;
  const str = String(s);
  let iso = str.includes(' ') ? str.replace(' ','T') : str;
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(iso)) iso += 'Z';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? null : d;
}

function fmtServerUtcDateTime(s){
  const d = parseServerUtcDateTime(s);
  if(!d) return String(s||'');
  return d.toLocaleString(undefined, {year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
}

function formatCountdown(totalSeconds){
  const sec = Math.max(0, parseInt(totalSeconds||0,10));
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const minutes = Math.floor((sec % 3600) / 60);
  if(sec <= 0) return '⏱ 0d 0h 0m';
  return `⏱ ${days}d ${hours}h ${minutes}m`;
}

async function postCsrf(url, body){
  const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

async function get(url){
  const r=await fetch(url,{credentials:'same-origin'});
  return r.json();
}

let activeTab = 'current';
let countdownTimer = null;

function setTab(tab){
  activeTab = tab;
  document.querySelectorAll('.tab[data-tab]').forEach(b => b.classList.toggle('sel', b.getAttribute('data-tab') === tab));
  render();
}

let allLocks = [];

function categorize(lock){
  if(lock.revealed_at) return 'revealed';
  if(lock.confirmation_status === 'rejected') return 'void';
  return 'current';
}

function buildCard(lock){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;

  const badges={locked:'🔒 Locked',unlocked:'🔓 Unlocked',pending:'⏳ Pending',auto_saved:'💾 Auto-saved',rejected:'✗ Void'};
  const rd=fmtServerUtcDateTime(lock.reveal_date);

  const top=document.createElement('div');
  top.className='lc-top';

  const label=document.createElement('div');
  label.className='lc-label';
  label.textContent=lock.label || '';

  const badge=document.createElement('div');
  badge.className=`lc-badge ${st}`;
  badge.textContent=badges[st]||st;

  top.appendChild(label);
  top.appendChild(badge);
  el.appendChild(top);

  if(lock.hint){
    const hint=document.createElement('div');
    hint.className='lc-hint';
    hint.textContent=`"${lock.hint}"`;
    el.appendChild(hint);
  }

  const t=lock.time_remaining || {};
  const countdown=document.createElement('div');
  countdown.className='lc-countdown';
  countdown.dataset.remaining = String(t.total_seconds ?? 0);
  countdown.textContent = `${formatCountdown(t.total_seconds)} remaining`;
  el.appendChild(countdown);

  const meta=document.createElement('div');
  meta.className='lc-meta';
  const copied = lock.copied_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">not copied</span>';
  meta.innerHTML=`Type: <span>${esc(lock.password_type)} · ${esc(lock.password_length)} chars</span><br>Reveal: <span>${esc(rd)}</span><br>Copied: ${copied}`;
  el.appendChild(meta);

  const actions=document.createElement('div');
  actions.className='lc-actions';

  if(st==='unlocked'){
    const b=document.createElement('a');
    b.className='btn btn-green btn-sm';
    b.href='dashboard.php';
    b.textContent='Reveal';
    actions.appendChild(b);
  } else if(st==='auto_saved'){
    const b=document.createElement('button');
    b.className='btn btn-ghost btn-sm';
    b.type='button';
    b.textContent='Activate';
    b.addEventListener('click', async ()=>{
      const r=await postCsrf('api/confirm.php',{lock_id:lock.id,action:'confirm'});
      if(r.success){await load();}
      else alert(r.error||'Failed');
    });
    actions.appendChild(b);
  }

  const del=document.createElement('button');
  del.className='btn btn-red btn-sm';
  del.type='button';
  del.textContent='Delete';
  del.addEventListener('click', async ()=>{
    if(!confirm('Permanently delete this lock?')) return;
    const r=await postCsrf('api/delete.php',{lock_id:lock.id});
    if(r.success){await load();}
    else alert(r.error||'Delete failed');
  });
  actions.appendChild(del);

  el.appendChild(actions);
  return el;
}

function render(){
  const wrap=document.getElementById('locks-wrap');
  const locks = allLocks.filter(l => categorize(l) === activeTab);

  if(!locks.length){
    wrap.innerHTML='<div class="empty">No codes in this section.</div>';
    return;
  }

  wrap.innerHTML='<div class="locks-grid" id="locks-grid"></div>';
  const grid=document.getElementById('locks-grid');
  locks.forEach(l=>grid.appendChild(buildCard(l)));

  if(countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(()=>{
    document.querySelectorAll('.lc-countdown').forEach(el=>{
      const cur = Math.max(0, parseInt(el.dataset.remaining||'0',10));
      const next = Math.max(0, cur - 1);
      el.dataset.remaining = String(next);
      el.textContent = `${formatCountdown(next)} remaining`;
    });
  }, 1000);
}

async function load(){
  const wrap=document.getElementById('locks-wrap');
  wrap.innerHTML='<div class="empty">Loading…</div>';
  try{
    const r=await get('api/locks.php');
    if(!r.success){wrap.innerHTML='<div class="empty">Failed to load.</div>';return;}
    allLocks = r.locks || [];
    render();
  }catch{
    wrap.innerHTML='<div class="empty">Network error.</div>';
  }
}

// events

document.getElementById('tabs').addEventListener('click', (e)=>{
  const t=e.target.closest('.tab[data-tab]');
  if(!t) return;
  setTab(t.getAttribute('data-tab'));
});

document.getElementById('refresh').addEventListener('click', load);

load();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}
</script>
</body>
</html>
