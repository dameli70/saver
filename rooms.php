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

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Saving Rooms — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/base.css">
<style>
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;
  border-radius:0;-webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:hover{background:#f0ff60;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);} 
.btn-sm{padding:10px 14px;min-height:38px;font-size:10px;}

.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 

.nav{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;color:inherit;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.pill{display:block;}}

.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}

.grid{display:grid;grid-template-columns:1fr;gap:14px;}
@media(min-width:980px){.grid{grid-template-columns:1fr 1fr;}}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:14px;}

.field{margin-bottom:12px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:14px;padding:12px;outline:none;border-radius:0;-webkit-appearance:none;}
.field input:focus,.field select:focus{border-color:var(--accent);} 

.rooms{display:grid;grid-template-columns:1fr;gap:12px;}
@media(min-width:740px){.rooms{grid-template-columns:repeat(2,1fr);} }
.room{background:rgba(0,0,0,.22);border:1px solid rgba(255,255,255,.08);padding:16px;}
.room-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px;}
.room-goal{font-family:var(--display);font-weight:800;font-size:14px;line-height:1.25;}
.badge{font-size:9px;letter-spacing:2px;text-transform:uppercase;border:1px solid rgba(232,255,71,.25);color:var(--accent);padding:6px 10px;}
.meta{font-size:12px;line-height:1.7;color:var(--muted);}
.meta b{color:var(--text);font-weight:500;}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;}
.cat-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;}
.cat-btn{padding:10px 12px;min-height:38px;font-size:10px;}
.cat-btn.sel{border-color:var(--accent);color:var(--accent);background:rgba(232,255,71,.06);}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
  <div class="nav-r">
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
    <a class="btn btn-ghost btn-sm" href="create_code.php">Create Code</a>
    <a class="btn btn-ghost btn-sm" href="my_codes.php">My Codes</a>
    <a class="btn btn-ghost btn-sm" href="notifications.php">Notifications</a>
    <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
  </div>
</div>

<div class="wrap">
  <div class="h">Public Discovery Board</div>
  <div class="p">You only see rooms for which you meet the trust level requirement. Join requests must be approved by the room maker.</div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title">Categories</div>
    <div class="cat-row" id="cat-row"></div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column:1/-1;">
      <div class="card-title">My rooms</div>
      <div class="p" style="margin-top:-6px;">Your active, pending, and completed rooms.</div>
      <div id="myrooms-msg" class="msg"></div>
      <div id="myrooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title">Rooms</div>
      <div id="rooms-msg" class="msg"></div>
      <div id="rooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title">Create room</div>
      <div class="p" style="margin-top:-6px;">Define all terms before the start date. Once the lobby locks, terms cannot change.</div>

      <div class="field"><label>Purpose</label>
        <select id="cr-purpose">
          <option value="education">Education</option>
          <option value="travel">Travel</option>
          <option value="business">Business</option>
          <option value="emergency">Emergency</option>
          <option value="community">Community</option>
          <option value="other" selected>Other</option>
        </select>
      </div>

      <div class="field"><label>Goal</label>
        <input id="cr-goal" maxlength="500" placeholder="e.g. Group trip to Nairobi">
      </div>

      <div class="field"><label>Saving type</label>
        <select id="cr-type">
          <option value="A">Type A — Collective unlock</option>
          <option value="B">Type B — Rotating unlock</option>
        </select>
      </div>

      <div class="field"><label>Visibility</label>
        <select id="cr-vis">
          <option value="public">Public</option>
          <option value="unlisted">Unlisted</option>
          <option value="private">Private</option>
        </select>
      </div>

      <div class="field"><label>Required trust level</label>
        <select id="cr-level">
          <option value="1">Level 1</option>
          <option value="2">Level 2</option>
          <option value="3">Level 3</option>
        </select>
      </div>

      <div class="field"><label>Participants (min / max)</label>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <input id="cr-min" type="number" min="2" value="2">
          <input id="cr-max" type="number" min="2" value="6">
        </div>
      </div>

      <div class="field"><label>Participation amount per person</label>
        <input id="cr-amt" type="number" min="0" step="0.01" placeholder="e.g. 50.00">
      </div>

      <div class="field"><label>Contribution periodicity</label>
        <select id="cr-per">
          <option value="weekly">Weekly</option>
          <option value="biweekly">Bi-weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </div>

      <div class="field"><label>Start date</label>
        <input id="cr-start" type="datetime-local">
      </div>

      <div class="field"><label>Reveal date</label>
        <input id="cr-reveal" type="datetime-local">
      </div>

      <label style="display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;margin:10px 0;">
        <input type="checkbox" id="cr-privacy" checked style="width:16px;height:16px;">
        <span>Privacy mode (hide amounts in activity feed)</span>
      </label>

      <div class="field"><label>Escrow policy on strike removal</label>
        <select id="cr-escrow">
          <option value="redistribute">Proportional redistribution</option>
          <option value="refund_minus_fee">Return minus platform fee</option>
        </select>
      </div>

      <button class="btn btn-primary" onclick="createRoom()">Create room</button>
      <div id="cr-msg" class="msg"></div>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

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

let currentCategory = '';

function renderCategories(){
  const cats = [
    {k:'', t:'All'},
    {k:'education', t:'Education'},
    {k:'travel', t:'Travel'},
    {k:'business', t:'Business'},
    {k:'emergency', t:'Emergency'},
    {k:'community', t:'Community'},
    {k:'other', t:'Other'},
  ];

  const row = document.getElementById('cat-row');
  row.innerHTML='';
  cats.forEach(c => {
    const b=document.createElement('button');
    b.type='button';
    b.className='btn btn-ghost btn-sm cat-btn' + ((c.k===currentCategory) ? ' sel' : '');
    b.textContent=c.t;
    b.onclick=()=>{currentCategory=c.k;renderCategories();loadRooms();};
    row.appendChild(b);
  });
}

function fmtDate(ts){
  try{return new Date(ts).toLocaleString();}catch{return String(ts||'');}
}

function buildRoomCard(r){
  const el=document.createElement('div');
  el.className='room';

  const top=document.createElement('div');
  top.className='room-top';

  const goal=document.createElement('div');
  goal.className='room-goal';
  goal.textContent=r.goal || '';

  const badge=document.createElement('div');
  badge.className='badge';
  badge.textContent = `LEVEL ${r.required_level} · TYPE ${r.saving_type}`;

  top.appendChild(goal);
  top.appendChild(badge);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `Amount: <b>${esc(r.participation_amount)}</b><br>Period: <b>${esc(r.periodicity)}</b><br>Spots remaining: <b>${esc(r.spots_remaining)}</b><br>Starts: <b>${esc(fmtDate(r.start_at))}</b>`;

  const actions=document.createElement('div');
  actions.className='actions';

  const open=document.createElement('a');
  open.className='btn btn-ghost btn-sm';
  open.href='room.php?id=' + encodeURIComponent(r.id);
  open.textContent='Open';

  const join=document.createElement('button');
  join.className='btn btn-primary btn-sm';
  join.type='button';
  join.textContent='Request to join';
  join.onclick=async()=>{
    join.disabled=true;
    try{
      const res=await postCsrf('/api/rooms.php', {action:'request_join', room_id: r.id});
      if(!res.success) throw new Error(res.error||'Failed');
      setMsg('rooms-msg','Join request sent.', true);
    }catch(e){
      setMsg('rooms-msg', e.message||'Failed', false);
    }finally{
      join.disabled=false;
    }
  };

  actions.appendChild(open);
  actions.appendChild(join);

  el.appendChild(top);
  el.appendChild(meta);
  el.appendChild(actions);
  return el;
}

function buildMyRoomCard(r){
  const el=document.createElement('div');
  el.className='room';

  const top=document.createElement('div');
  top.className='room-top';

  const goal=document.createElement('div');
  goal.className='room-goal';
  goal.textContent=r.goal || '';

  const badge=document.createElement('div');
  badge.className='badge';
  badge.textContent = `${String((r.my_status||'').toUpperCase())} · TYPE ${r.saving_type}`;

  top.appendChild(goal);
  top.appendChild(badge);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `Amount: <b>${esc(r.participation_amount)}</b><br>Period: <b>${esc(r.periodicity)}</b><br>State: <b>${esc(r.room_state)} / ${esc(r.lobby_state)}</b><br>Starts: <b>${esc(fmtDate(r.start_at))}</b>`;

  const actions=document.createElement('div');
  actions.className='actions';

  const open=document.createElement('a');
  open.className='btn btn-ghost btn-sm';
  open.href='room.php?id=' + encodeURIComponent(r.id);
  open.textContent='Open';

  actions.appendChild(open);

  el.appendChild(top);
  el.appendChild(meta);
  el.appendChild(actions);
  return el;
}

async function loadMyRooms(){
  const wrap=document.getElementById('myrooms-wrap');
  wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">Loading…</div>';
  document.getElementById('myrooms-msg').className='msg';

  try{
    const r=await get('/api/rooms.php?action=my_rooms');
    if(!r.success) throw new Error(r.error||'Failed');

    const rooms=r.rooms||[];
    if(!rooms.length){
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">No rooms yet.</div>';
      return;
    }

    wrap.innerHTML='';
    rooms.forEach(x => wrap.appendChild(buildMyRoomCard(x)));

  }catch(e){
    wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">Failed to load.</div>';
    setMsg('myrooms-msg', e.message||'Failed', false);
  }
}

async function loadRooms(){
  const wrap=document.getElementById('rooms-wrap');
  wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">Loading…</div>';
  document.getElementById('rooms-msg').className='msg';

  try{
    const qs = new URLSearchParams({action:'discover'});
    if(currentCategory) qs.set('category', currentCategory);
    const r=await get('/api/rooms.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    const rooms=r.rooms||[];
    if(!rooms.length){
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">No rooms found for this category and trust level.</div>';
      return;
    }

    wrap.innerHTML='';
    rooms.forEach(x => wrap.appendChild(buildRoomCard(x)));

  }catch(e){
    wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">Failed to load rooms.</div>';
    setMsg('rooms-msg', e.message||'Failed', false);
  }
}

function toServerDateTimeLocal(v){
  // datetime-local gives local time; server expects parseable string.
  // We send the raw value; API uses strtotime() which interprets server timezone.
  // For now, keep consistent behavior with existing app pages.
  return String(v||'');
}

async function createRoom(){
  document.getElementById('cr-msg').className='msg';

  const goal = document.getElementById('cr-goal').value.trim();
  const purpose_category = document.getElementById('cr-purpose').value;
  const saving_type = document.getElementById('cr-type').value;
  const visibility = document.getElementById('cr-vis').value;
  const required_trust_level = parseInt(document.getElementById('cr-level').value||'1',10);
  const min_participants = parseInt(document.getElementById('cr-min').value||'2',10);
  const max_participants = parseInt(document.getElementById('cr-max').value||'0',10);
  const participation_amount = String(document.getElementById('cr-amt').value||'').trim();
  const periodicity = document.getElementById('cr-per').value;
  const start_at = toServerDateTimeLocal(document.getElementById('cr-start').value);
  const reveal_at = toServerDateTimeLocal(document.getElementById('cr-reveal').value);
  const privacy_mode = document.getElementById('cr-privacy').checked ? 1 : 0;
  const escrow_policy = document.getElementById('cr-escrow').value;

  try{
    const r = await postCsrf('/api/rooms.php', {
      action:'create_room',
      goal_text: goal,
      purpose_category,
      saving_type,
      visibility,
      required_trust_level,
      min_participants,
      max_participants,
      participation_amount,
      periodicity,
      start_at,
      reveal_at,
      privacy_mode,
      escrow_policy,
    });

    if(!r.success) throw new Error(r.error||'Failed');

    setMsg('cr-msg','Room created.', true);
    window.location.href = 'room.php?id=' + encodeURIComponent(r.room_id);

  }catch(e){
    setMsg('cr-msg', e.message||'Failed', false);
  }
}

renderCategories();
loadMyRooms();
loadRooms();
</script>
</body>
</html>
