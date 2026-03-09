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
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.rooms')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/panel.css">
<link rel="stylesheet" href="assets/panel_components.css">
<link rel="stylesheet" href="assets/ls_shared.css">
<style>
.orb1{width:520px;height:520px;top:-170px;right:-120px;}
.orb2{width:360px;height:360px;bottom:40px;left:-90px;}


.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.pill{display:block;}}

.wrap{max-width:1100px;}
.h{font-size:18px;} 

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
  <a class="logo" href="index.php"><?= htmlspecialchars(APP_NAME) ?></a>
  <div class="nav-r">
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
    <?php $curLang = currentLang(); ?>
    <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
    <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
    <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
    <a class="btn btn-ghost btn-sm" href="my_codes.php"><?php e('nav.my_codes'); ?></a>
    <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
    <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
    <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
  </div>
</div>

<div class="wrap">
  <div class="h"><?php e('page.rooms'); ?></div>
  <div class="p">Save together toward a goal. Browse rooms, request to join, or create your own with clear rules. Some rooms may be unavailable depending on your trust level or a cooldown period.</div>
  <div id="eligibility" style="color:var(--muted);font-size:12px;line-height:1.6;margin:-8px 0 18px 0;"></div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title">Categories</div>
    <div class="cat-row" id="cat-row"></div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column:1/-1;">
      <div class="card-title">My rooms</div>
      <div class="p" style="margin-top:-6px;">Rooms you created or joined — active, pending, or completed.</div>
      <div id="myrooms-msg" class="msg"></div>
      <div id="myrooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title">Discover rooms</div>
      <div id="rooms-msg" class="msg"></div>
      <div id="rooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title">Create a room</div>
      <div class="p" style="margin-top:-6px;">Set the goal, the rules, and the dates. Once the room starts, the rules lock in.</div>

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
        <div class="two-col">
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

function esc(s){
  if(window.LS && LS.esc) return LS.esc(s);
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setMsg(id, text, ok){
  const el=document.getElementById(id);
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}

function parseUtcDate(ts){
  if(window.LS && LS.parseUtc) return LS.parseUtc(ts);

  const s = String(ts||'').trim();
  if(!s) return null;

  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
    return new Date(s.replace(' ', 'T') + 'Z');
  }

  return new Date(s);
}

function fmtLocal(ts){
  const d = parseUtcDate(ts);
  if(!d || isNaN(d.getTime())) return String(ts||'');
  if(window.LS && LS.fmtLocal) return LS.fmtLocal(d);
  return d.toLocaleString();
}

function fmtUtc(ts){
  const d = parseUtcDate(ts);
  if(!d || isNaN(d.getTime())) return '';
  if(window.LS && LS.fmtUtc) return LS.fmtUtc(d);
  return d.toUTCString();
}

function fmtDate(ts){
  return fmtLocal(ts);
}

function renderRoomSkeletons(n){
  let s='';
  for(let i=0;i<(n||4);i++) s += '<div class="room skel" style="height:132px;"></div>';
  return s;
}

function b64uToBuf(b64url){
  const b64 = String(b64url||'').replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToB64u(buf){
  const bytes = new Uint8Array(buf);
  let s='';
  for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function ensureReauth(methods){
  if(window.LS && LS.reauth){
    return LS.reauth(methods||{}, {post: postCsrf});
  }

  if(methods && methods.passkey && window.PublicKeyCredential){
    try{
      const begin = await postCsrf('api/webauthn.php', {action:'reauth_begin'});
      if(begin.success){
        const pk = begin.publicKey || {};
        const allow = (pk.allowCredentials||[]).map(c => ({type:c.type, id: b64uToBuf(c.id)}));
        const cred = await navigator.credentials.get({publicKey:{
          challenge: b64uToBuf(pk.challenge),
          rpId: pk.rpId,
          timeout: pk.timeout||60000,
          userVerification: pk.userVerification||'required',
          allowCredentials: allow,
        }});

        const a = cred.response;
        const fin = await postCsrf('api/webauthn.php', {
          action:'reauth_finish',
          rawId: bufToB64u(cred.rawId),
          response:{
            clientDataJSON: bufToB64u(a.clientDataJSON),
            authenticatorData: bufToB64u(a.authenticatorData),
            signature: bufToB64u(a.signature),
            userHandle: a.userHandle ? bufToB64u(a.userHandle) : null,
          }
        });
        if(fin.success) return true;
      }
    }catch{}
  }

  if(methods && methods.totp){
    const code = prompt('Enter your 6-digit authenticator code');
    if(!code) return false;
    const r = await postCsrf('api/totp.php', {action:'reauth', code});
    return !!r.success;
  }

  return false;
}

async function postStrong(url, body){
  let j = await postCsrf(url, body);
  if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
    const ok = await ensureReauth(j.methods||{});
    if(!ok) return j;
    j = await postCsrf(url, body);
  }
  return j;
}

let currentCategory = '';
let myTrustLevel = null;
let myRestrictedUntil = '';

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

function updateEligibility(){
  const el = document.getElementById('eligibility');
  if(!el) return;

  const bits = [];
  if(myTrustLevel !== null){
    bits.push('Your room access level: Level ' + esc(myTrustLevel));
  }
  if(myRestrictedUntil){
    bits.push('Cooldown until <b>' + esc(fmtLocal(myRestrictedUntil)) + '</b> <span class="utc-pill" title="Stored/enforced in UTC">' + esc(fmtUtc(myRestrictedUntil)) + '</span> (you can’t join new rooms yet)');
  }

  el.innerHTML = bits.join(' · ');
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

  const startLocal = fmtLocal(r.start_at);
  const startUtc = fmtUtc(r.start_at);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `Amount: <b>${esc(r.participation_amount)}</b><br>Period: <b>${esc(r.periodicity)}</b><br>Spots remaining: <b>${esc(r.spots_remaining)}</b><br>Starts: <b>${esc(startLocal)}</b> <span class="utc-pill" title="Stored/enforced in UTC">${esc(startUtc)}</span>`;

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

  if(myRestrictedUntil){
    join.className='btn btn-ghost btn-sm';
    join.disabled=true;
    join.textContent='Restricted';
    join.title = 'You cannot join new rooms until ' + fmtLocal(myRestrictedUntil);
  } else {
    join.onclick=async()=>{
      join.disabled=true;
      try{
        const res=await postStrong('/api/rooms.php', {action:'request_join', room_id: r.id});
        if(!res.success) throw new Error(res.error||'Failed');
        setMsg('rooms-msg','Join request sent.', true);
      }catch(e){
        setMsg('rooms-msg', e.message||'Failed', false);
      }finally{
        join.disabled=false;
      }
    };
  }

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

  const startLocal = fmtLocal(r.start_at);
  const startUtc = fmtUtc(r.start_at);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `Amount: <b>${esc(r.participation_amount)}</b><br>Period: <b>${esc(r.periodicity)}</b><br>State: <b>${esc(r.room_state)} / ${esc(r.lobby_state)}</b><br>Starts: <b>${esc(startLocal)}</b> <span class="utc-pill" title="Stored/enforced in UTC">${esc(startUtc)}</span>`;

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
  wrap.innerHTML = renderRoomSkeletons(3);
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
  wrap.innerHTML = renderRoomSkeletons(4);
  document.getElementById('rooms-msg').className='msg';

  try{
    const qs = new URLSearchParams({action:'discover'});
    if(currentCategory) qs.set('category', currentCategory);
    const r=await get('/api/rooms.php?' + qs.toString());
    if(!r.success) throw new Error(r.error||'Failed');

    if(typeof r.your_trust_level !== 'undefined' && r.your_trust_level !== null){
      const lvl = parseInt(String(r.your_trust_level), 10);
      myTrustLevel = (lvl && lvl > 0) ? lvl : 1;
    }
    myRestrictedUntil = r.restricted_until ? String(r.restricted_until) : '';
    updateEligibility();

    const rooms=r.rooms||[];
    if(!rooms.length){
      const extra = myTrustLevel !== null ? (' Your trust level is Level ' + String(myTrustLevel) + '.') : '';
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">No eligible rooms found for this category.' + esc(extra) + '</div>';
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
  // datetime-local gives local time. Convert to an unambiguous UTC instant.
  const s = String(v||'').trim();
  if(!s) return '';
  const d = new Date(s);
  if(isNaN(d.getTime())) return '';
  return d.toISOString();
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
    const r = await postStrong('/api/rooms.php', {
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
