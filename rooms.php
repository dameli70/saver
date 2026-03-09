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
  <div class="p"><?php e('rooms.intro'); ?></div>
  <div id="eligibility" style="color:var(--muted);font-size:12px;line-height:1.6;margin:-8px 0 18px 0;"></div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title"><?php e('rooms.categories'); ?></div>
    <div class="cat-row" id="cat-row"></div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column:1/-1;">
      <div class="card-title"><?php e('rooms.my_rooms_title'); ?></div>
      <div class="p" style="margin-top:-6px;"><?php e('rooms.my_rooms_sub'); ?></div>
      <div id="myrooms-msg" class="msg"></div>
      <div id="myrooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title"><?php e('rooms.discover_title'); ?></div>
      <div id="rooms-msg" class="msg"></div>
      <div id="rooms-wrap" class="rooms"></div>
    </div>

    <div class="card">
      <div class="card-title"><?php e('rooms.create_title'); ?></div>
      <div class="p" style="margin-top:-6px;"><?php e('rooms.create_sub'); ?></div>

      <div class="field"><label><?php e('rooms.field.purpose'); ?></label>
        <select id="cr-purpose">
          <option value="education"><?php e('rooms.purpose.education'); ?></option>
          <option value="travel"><?php e('rooms.purpose.travel'); ?></option>
          <option value="business"><?php e('rooms.purpose.business'); ?></option>
          <option value="emergency"><?php e('rooms.purpose.emergency'); ?></option>
          <option value="community"><?php e('rooms.purpose.community'); ?></option>
          <option value="other" selected><?php e('rooms.purpose.other'); ?></option>
        </select>
      </div>

      <div class="field"><label><?php e('rooms.field.goal'); ?></label>
        <input id="cr-goal" maxlength="500" placeholder="<?= htmlspecialchars(t('rooms.goal_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
      </div>

      <div class="field"><label><?php e('rooms.field.saving_type'); ?></label>
        <select id="cr-type">
          <option value="A"><?php e('rooms.saving_type.a'); ?></option>
          <option value="B"><?php e('rooms.saving_type.b'); ?></option>
        </select>
      </div>

      <div class="field"><label><?php e('rooms.field.visibility'); ?></label>
        <select id="cr-vis">
          <option value="public"><?php e('rooms.visibility.public'); ?></option>
          <option value="unlisted"><?php e('rooms.visibility.unlisted'); ?></option>
          <option value="private"><?php e('rooms.visibility.private'); ?></option>
        </select>
      </div>

      <div class="field"><label><?php e('rooms.field.required_trust'); ?></label>
        <select id="cr-level">
          <option value="1"><?php e('rooms.trust_level.1'); ?></option>
          <option value="2"><?php e('rooms.trust_level.2'); ?></option>
          <option value="3"><?php e('rooms.trust_level.3'); ?></option>
        </select>
      </div>

      <div class="field"><label><?php e('rooms.field.participants'); ?></label>
        <div class="two-col">
          <input id="cr-min" type="number" min="2" value="2">
          <input id="cr-max" type="number" min="2" value="6">
        </div>
      </div>

      <div class="field"><label><?php e('rooms.field.participation_amount'); ?></label>
        <input id="cr-amt" type="number" min="0" step="0.01" placeholder="<?= htmlspecialchars(t('rooms.amount_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
      </div>

      <div class="field"><label><?php e('rooms.field.periodicity'); ?></label>
        <select id="cr-per">
          <option value="weekly"><?php e('rooms.periodicity.weekly'); ?></option>
          <option value="biweekly"><?php e('rooms.periodicity.biweekly'); ?></option>
          <option value="monthly"><?php e('rooms.periodicity.monthly'); ?></option>
        </select>
      </div>

      <div class="field"><label><?php e('rooms.field.start_date'); ?></label>
        <input id="cr-start" type="datetime-local">
      </div>

      <div class="field"><label><?php e('rooms.field.reveal_date'); ?></label>
        <input id="cr-reveal" type="datetime-local">
      </div>

      <label style="display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;margin:10px 0;">
        <input type="checkbox" id="cr-privacy" checked style="width:16px;height:16px;">
        <span><?php e('rooms.privacy_mode'); ?></span>
      </label>

      <div class="field"><label><?php e('rooms.field.escrow_policy'); ?></label>
        <select id="cr-escrow">
          <option value="redistribute"><?php e('rooms.escrow.redistribute'); ?></option>
          <option value="refund_minus_fee"><?php e('rooms.escrow.refund_minus_fee'); ?></option>
        </select>
      </div>

      <button class="btn btn-primary" onclick="createRoom()"><?php e('rooms.btn.create_room'); ?></button>
      <div id="cr-msg" class="msg"></div>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
function tr(key, fallback){
  return (I18N && typeof I18N[key] === 'string') ? I18N[key] : fallback;
}
function fmt(s, vars){
  return String(s||'').replace(/\{(\w+)\}/g, (m, k) => (vars && Object.prototype.hasOwnProperty.call(vars, k)) ? String(vars[k]) : m);
}
function tf(key, vars, fallback){
  return fmt(tr(key, fallback), vars);
}

const STR = {
  failed: tr('common.failed', 'Failed'),
  open: tr('common.open', 'Open'),

  cat_all: tr('rooms.cat.all', 'All'),
  cat_education: tr('rooms.cat.education', 'Education'),
  cat_travel: tr('rooms.cat.travel', 'Travel'),
  cat_business: tr('rooms.cat.business', 'Business'),
  cat_emergency: tr('rooms.cat.emergency', 'Emergency'),
  cat_community: tr('rooms.cat.community', 'Community'),
  cat_other: tr('rooms.cat.other', 'Other'),

  prompt_auth_code: tr('js.enter_6_digit_code', 'Enter a 6-digit code'),

  eligibility_level: tr('rooms.eligibility.level', 'Your room access level: Level {level}'),
  eligibility_cooldown_until: tr('rooms.eligibility.cooldown_until', 'Cooldown until {local} {utc} (you can’t join new rooms yet)'),
  stored_enforced_utc: tr('rooms.utc_title', 'Stored/enforced in UTC'),

  badge_level_type: tr('rooms.badge.level_type', 'LEVEL {level} · TYPE {type}'),
  badge_status_type: tr('rooms.badge.status_type', '{status} · TYPE {type}'),

  meta_amount: tr('rooms.meta.amount', 'Amount'),
  meta_period: tr('rooms.meta.period', 'Period'),
  meta_spots_remaining: tr('rooms.meta.spots_remaining', 'Spots remaining'),
  meta_starts: tr('rooms.meta.starts', 'Starts'),
  meta_state: tr('rooms.meta.state', 'State'),

  periodicity_weekly: tr('rooms.periodicity.weekly', 'Weekly'),
  periodicity_biweekly: tr('rooms.periodicity.biweekly', 'Bi-weekly'),
  periodicity_monthly: tr('rooms.periodicity.monthly', 'Monthly'),

  join_request: tr('rooms.action.request_join', 'Request to join'),
  restricted: tr('rooms.action.restricted', 'Restricted'),
  restricted_title: tr('rooms.action.restricted_title', 'You cannot join new rooms until {ts}'),
  join_request_sent: tr('rooms.msg.join_request_sent', 'Join request sent.'),

  no_rooms_yet: tr('rooms.msg.no_rooms_yet', 'No rooms yet.'),
  failed_to_load: tr('rooms.msg.failed_to_load', 'Failed to load.'),
  no_eligible_rooms: tr('rooms.msg.no_eligible_rooms', 'No eligible rooms found for this category.'),
  trust_level_extra: tr('rooms.msg.trust_level_extra', 'Your trust level is Level {level}.'),
  failed_to_load_rooms: tr('rooms.msg.failed_to_load_rooms', 'Failed to load rooms.'),

  room_created: tr('rooms.msg.room_created', 'Room created.'),
};

function periodicityLabel(k){
  if(k === 'weekly') return STR.periodicity_weekly;
  if(k === 'biweekly') return STR.periodicity_biweekly;
  if(k === 'monthly') return STR.periodicity_monthly;
  return String(k||'');
}

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
    const code = prompt(STR.prompt_auth_code);
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
    {k:'', t: STR.cat_all},
    {k:'education', t: STR.cat_education},
    {k:'travel', t: STR.cat_travel},
    {k:'business', t: STR.cat_business},
    {k:'emergency', t: STR.cat_emergency},
    {k:'community', t: STR.cat_community},
    {k:'other', t: STR.cat_other},
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
    bits.push(tf('rooms.eligibility.level', {level: myTrustLevel}, `Your room access level: Level ${esc(myTrustLevel)}`));
  }
  if(myRestrictedUntil){
    const local = '<b>' + esc(fmtLocal(myRestrictedUntil)) + '</b>';
    const utc = '<span class="utc-pill" title="' + esc(STR.stored_enforced_utc) + '">' + esc(fmtUtc(myRestrictedUntil)) + '</span>';
    bits.push(tf('rooms.eligibility.cooldown_until', {local, utc}, `Cooldown until ${local} ${utc} (you can’t join new rooms yet)`));
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
  badge.textContent = tf('rooms.badge.level_type', {level: r.required_level, type: r.saving_type}, `LEVEL ${r.required_level} · TYPE ${r.saving_type}`);

  top.appendChild(goal);
  top.appendChild(badge);

  const startLocal = fmtLocal(r.start_at);
  const startUtc = fmtUtc(r.start_at);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `${esc(STR.meta_amount)}: <b>${esc(r.participation_amount)}</b><br>${esc(STR.meta_period)}: <b>${esc(periodicityLabel(r.periodicity))}</b><br>${esc(STR.meta_spots_remaining)}: <b>${esc(r.spots_remaining)}</b><br>${esc(STR.meta_starts)}: <b>${esc(startLocal)}</b> <span class="utc-pill" title="${esc(STR.stored_enforced_utc)}">${esc(startUtc)}</span>`;

  const actions=document.createElement('div');
  actions.className='actions';

  const open=document.createElement('a');
  open.className='btn btn-ghost btn-sm';
  open.href='room.php?id=' + encodeURIComponent(r.id);
  open.textContent=STR.open;

  const join=document.createElement('button');
  join.className='btn btn-primary btn-sm';
  join.type='button';
  join.textContent=STR.join_request;

  if(myRestrictedUntil){
    join.className='btn btn-ghost btn-sm';
    join.disabled=true;
    join.textContent=STR.restricted;
    join.title = tf('rooms.action.restricted_title', {ts: fmtLocal(myRestrictedUntil)}, `You cannot join new rooms until ${fmtLocal(myRestrictedUntil)}`);
  } else {
    join.onclick=async()=>{
      join.disabled=true;
      try{
        const res=await postStrong('/api/rooms.php', {action:'request_join', room_id: r.id});
        if(!res.success) throw new Error(res.error||STR.failed);
        setMsg('rooms-msg', STR.join_request_sent, true);
      }catch(e){
        setMsg('rooms-msg', e.message||STR.failed, false);
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
  badge.textContent = tf('rooms.badge.status_type', {status: String((r.my_status||'').toUpperCase()), type: r.saving_type}, `${String((r.my_status||'').toUpperCase())} · TYPE ${r.saving_type}`);

  top.appendChild(goal);
  top.appendChild(badge);

  const startLocal = fmtLocal(r.start_at);
  const startUtc = fmtUtc(r.start_at);

  const meta=document.createElement('div');
  meta.className='meta';
  meta.innerHTML = `${esc(STR.meta_amount)}: <b>${esc(r.participation_amount)}</b><br>${esc(STR.meta_period)}: <b>${esc(periodicityLabel(r.periodicity))}</b><br>${esc(STR.meta_state)}: <b>${esc(r.room_state)} / ${esc(r.lobby_state)}</b><br>${esc(STR.meta_starts)}: <b>${esc(startLocal)}</b> <span class="utc-pill" title="${esc(STR.stored_enforced_utc)}">${esc(startUtc)}</span>`;

  const actions=document.createElement('div');
  actions.className='actions';

  const open=document.createElement('a');
  open.className='btn btn-ghost btn-sm';
  open.href='room.php?id=' + encodeURIComponent(r.id);
  open.textContent=STR.open;

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
    if(!r.success) throw new Error(r.error||STR.failed);

    const rooms=r.rooms||[];
    if(!rooms.length){
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">' + esc(STR.no_rooms_yet) + '</div>';
      return;
    }

    wrap.innerHTML='';
    rooms.forEach(x => wrap.appendChild(buildMyRoomCard(x)));

  }catch(e){
    wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">' + esc(STR.failed_to_load) + '</div>';
    setMsg('myrooms-msg', e.message||STR.failed, false);
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
    if(!r.success) throw new Error(r.error||STR.failed);

    if(typeof r.your_trust_level !== 'undefined' && r.your_trust_level !== null){
      const lvl = parseInt(String(r.your_trust_level), 10);
      myTrustLevel = (lvl && lvl > 0) ? lvl : 1;
    }
    myRestrictedUntil = r.restricted_until ? String(r.restricted_until) : '';
    updateEligibility();

    const rooms=r.rooms||[];
    if(!rooms.length){
      const extra = myTrustLevel !== null ? (' ' + tf('rooms.msg.trust_level_extra', {level: myTrustLevel}, `Your trust level is Level ${String(myTrustLevel)}.`)) : '';
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">' + esc(STR.no_eligible_rooms) + esc(extra) + '</div>';
      return;
    }

    wrap.innerHTML='';
    rooms.forEach(x => wrap.appendChild(buildRoomCard(x)));

  }catch(e){
    wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">' + esc(STR.failed_to_load_rooms) + '</div>';
    setMsg('rooms-msg', e.message||STR.failed, false);
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

    if(!r.success) throw new Error(r.error||STR.failed);

    setMsg('cr-msg', STR.room_created, true);
    window.location.href = 'room.php?id=' + encodeURIComponent(r.room_id);

  }catch(e){
    setMsg('cr-msg', e.message||STR.failed, false);
  }
}


renderCategories();
loadMyRooms();
loadRooms();
</script>
</body>
</html>
 