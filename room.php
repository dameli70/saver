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

$roomId = (string)($_GET['id'] ?? '');
if ($roomId === '' || strlen($roomId) !== 36) {
    header('Location: rooms.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Room — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--blue:#47b8ff;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}

.nav{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;color:inherit;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.pill{display:block;}}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-blue{background:rgba(71,184,255,.12);border:1px solid rgba(71,184,255,.25);color:var(--blue);} 
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);} 
.btn-sm{padding:10px 14px;min-height:38px;font-size:10px;}

.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.grid{display:grid;grid-template-columns:1fr;gap:14px;}
@media(min-width:980px){.grid{grid-template-columns:1fr 1fr;}}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:14px;}

.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 

.k{color:var(--muted);} 

.table-wrap{overflow:auto;border:1px solid var(--b1);background:rgba(0,0,0,.2);}
.table{width:100%;border-collapse:collapse;min-width:760px;}
.table th,.table td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;font-size:12px;white-space:nowrap;}
.table th{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;background:rgba(0,0,0,.25);} 

.feed{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.2);padding:12px;max-height:420px;overflow:auto;}
.feed-item{padding:10px 10px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px;line-height:1.6;}
.feed-item:last-child{border-bottom:none;}
.feed-meta{font-size:10px;color:var(--muted);letter-spacing:1px;margin-top:4px;}

</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
  <div class="nav-r">
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
    <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
  </div>
</div>

<div class="wrap">
  <div class="h" id="room-title">Room</div>
  <div class="p" id="room-sub">Loading…</div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Overview</div>
      <div id="room-overview" class="k">Loading…</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-primary btn-sm" id="join-btn" onclick="requestJoin()" style="display:none;">Request to join</button>
        <a class="btn btn-ghost btn-sm" href="rooms.php">Back to discovery</a>
      </div>
      <div id="room-msg" class="msg"></div>
    </div>

    <div class="card">
      <div class="card-title">Activity</div>
      <div class="feed" id="feed"></div>
      <div id="feed-msg" class="msg"></div>
    </div>

    <div class="card" id="maker-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Join requests (maker)</div>
      <div class="p">Review pending requests. You can see the applicant’s trust level and strikes summary.</div>
      <div class="table-wrap">
        <table class="table" id="req-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Snapshot</th>
              <th>Current</th>
              <th>Requested</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="maker-msg" class="msg"></div>
    </div>

  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const ROOM_ID = <?= json_encode($roomId) ?>;

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function setMsg(id, text, ok){
  const el=document.getElementById(id);
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}
function fmt(ts){
  try{return new Date(ts).toLocaleString();}catch{return String(ts||'');}
}

let roomCache = null;
let lastEventId = 0;

function renderRoom(){
  const r = roomCache;
  if(!r) return;

  document.getElementById('room-title').textContent = r.goal_text || 'Room';
  document.getElementById('room-sub').textContent = `Type ${r.saving_type} · Level ${r.required_trust_level} · ${r.periodicity} · Starts ${fmt(r.start_at)}`;

  const ov = document.getElementById('room-overview');
  ov.innerHTML = `
    <div style="font-size:12px;line-height:1.7;">
      <div><span class="k">Purpose:</span> ${esc(r.purpose_category)}</div>
      <div><span class="k">Visibility:</span> ${esc(r.visibility)}</div>
      <div><span class="k">Participation amount:</span> ${esc(r.participation_amount)}</div>
      <div><span class="k">Participants:</span> ${esc(r.approved_count)} / ${esc(r.max_participants)} (min ${esc(r.min_participants)})</div>
      <div><span class="k">Lobby:</span> ${esc(r.lobby_state)} · <span class="k">State:</span> ${esc(r.room_state)}</div>
      <div><span class="k">Reveal date:</span> ${esc(fmt(r.reveal_at))}</div>
      <div><span class="k">Your status:</span> ${esc(r.my_status||'none')}</div>
    </div>
  `;

  const joinBtn = document.getElementById('join-btn');
  const canJoin = (!r.my_status || r.my_status === 'declined') && r.room_state === 'lobby' && r.lobby_state === 'open' && r.visibility !== 'private';
  joinBtn.style.display = canJoin ? 'inline-flex' : 'none';

  if(r.is_maker){
    document.getElementById('maker-card').style.display='block';
    loadJoinRequests();
  }
}

async function loadRoom(){
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');
    roomCache = res.room;
    renderRoom();
  }catch(e){
    setMsg('room-msg', e.message||'Failed to load room', false);
  }
}

async function requestJoin(){
  document.getElementById('room-msg').className='msg';
  const btn = document.getElementById('join-btn');
  btn.disabled=true;
  try{
    const res = await postCsrf('/api/rooms.php', {action:'request_join', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('room-msg','Join request sent.', true);
    await loadRoom();
  }catch(e){
    setMsg('room-msg', e.message||'Failed', false);
  }finally{
    btn.disabled=false;
  }
}

function addFeedItem(ev){
  const feed = document.getElementById('feed');
  const el = document.createElement('div');
  el.className = 'feed-item';

  const payload = ev.payload || {};
  let line = '';
  if(ev.event_type === 'room_created') line = 'Room created';
  else if(ev.event_type === 'join_requested') line = 'New join request';
  else if(ev.event_type === 'join_approved') line = 'Join request approved';
  else if(ev.event_type === 'join_declined') line = 'Join request declined';
  else if(ev.event_type === 'lobby_locked') line = 'Lobby locked';
  else line = ev.event_type;

  const extra = payload && Object.keys(payload).length ? ' — ' + esc(JSON.stringify(payload)) : '';

  el.innerHTML = `<div>${esc(line)}${extra}</div><div class="feed-meta">${esc(fmt(ev.created_at))}</div>`;
  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

async function pollFeed(){
  try{
    const qs = new URLSearchParams({action:'activity', room_id: ROOM_ID, since_id: String(lastEventId), limit:'200'});
    const res = await get('/api/rooms.php?' + qs.toString());
    if(!res.success) throw new Error(res.error||'Failed');

    const evs = res.events || [];
    evs.forEach(ev => {
      lastEventId = Math.max(lastEventId, parseInt(ev.id||0,10));
      addFeedItem(ev);
    });
  }catch(e){
    const msg = document.getElementById('feed-msg');
    msg.className = 'msg msg-err show';
    msg.textContent = e.message||'Feed error';
  }
}

async function loadJoinRequests(){
  document.getElementById('maker-msg').className='msg';

  const tbody = document.querySelector('#req-table tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="k">Loading…</td></tr>';

  try{
    const res = await get('/api/rooms.php?action=maker_join_requests&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');

    const rows = res.requests || [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="5" class="k">No pending requests.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    rows.forEach(r => {
      const tr=document.createElement('tr');
      const snap = `L${r.snapshot_level} · strikes ${r.snapshot_strikes_6m}` + (r.snapshot_restricted_until ? ' · restricted' : '');
      const cur = `L${r.current_level||'?'} · strikes ${r.current_strikes_6m||0}` + (r.current_restricted_until ? ' · restricted' : '');

      tr.innerHTML = `
        <td>${esc(r.email)}</td>
        <td>${esc(snap)}</td>
        <td>${esc(cur)}</td>
        <td>${esc(fmt(r.created_at))}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="reviewJoin(${r.id}, 'approve')">Approve</button>
          <button class="btn btn-red btn-sm" onclick="reviewJoin(${r.id}, 'decline')">Decline</button>
        </td>
      `;

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="5" class="k">Failed to load requests.</td></tr>';
    setMsg('maker-msg', e.message||'Failed', false);
  }
}

async function reviewJoin(requestId, decision){
  document.getElementById('maker-msg').className='msg';

  const ok = confirm((decision==='approve') ? 'Approve this user?' : 'Decline this user?');
  if(!ok) return;

  try{
    const res = await postCsrf('/api/rooms.php', {action:'review_join', request_id: requestId, decision});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg('maker-msg', 'Saved.', true);
    await loadJoinRequests();
    await loadRoom();

  }catch(e){
    setMsg('maker-msg', e.message||'Failed', false);
  }
}

loadRoom().then(()=>pollFeed());
setInterval(pollFeed, 4000);
</script>
</body>
</html>
