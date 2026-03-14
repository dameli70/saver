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
header("Permissions-Policy: clipboard-write=(self)");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.my_codes')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/my_codes_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
      <?php $curLang = currentLang(); ?>
      <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
      <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
      <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?php e('nav.backups'); ?></a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
    </div>
  </div>

  <div class="app-body">
    <div class="card">
      <div class="card-title"><div class="dot"></div><?php e('page.my_codes'); ?></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:space-between;align-items:center;">
        <div style="font-size:12px;color:var(--muted);line-height:1.7;">View your sealed codes. Unlocking/decryption happens in your browser.</div>
        <button class="btn btn-ghost btn-sm" onclick="loadLocks()">↻ Refresh</button>
      </div>
    </div>

    <div id="locks-wrap">
      <div class="empty"><div class="empty-icon">🔒</div><h3>Loading…</h3><p></p></div>
    </div>
  </div>
</div>

<!-- share overlay (pre-unlock) -->
<div id="share-overlay" class="ls-modal-overlay ls-sheet" onclick="closeShare(event)">
  <div class="ls-modal reveal-sheet" role="dialog" aria-modal="true" aria-labelledby="ps-title">
    <button class="ls-modal-x" type="button" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>" onclick="closeShare();event.stopPropagation();">×</button>
    <div class="ls-modal-title" id="ps-title">Share lock</div>
    <div class="ls-modal-sub">// create a share link even while sealed</div>

    <div class="small" id="ps-meta" style="margin-bottom:12px;"></div>

    <div class="vault-input-wrap">
      <label>Vault Passphrase</label>
      <input type="password" id="ps-vault" placeholder="Your vault passphrase…" autocomplete="current-password">
      <div class="small" style="margin-top:8px;">We’ll use your passphrase to unlock the share secret. The code itself stays sealed until the unlock date.</div>
    </div>

    <div id="ps-legacy" style="display:none;">
      <div class="hr" style="margin:14px 0;"></div>
      <div class="vault-input-wrap" style="margin:0;">
        <label>Code to share (legacy)</label>
        <input type="password" id="ps-code" placeholder="Paste the code you saved…" autocomplete="off">
        <div class="small" style="margin-top:8px;">If this lock was created before sealed sharing was initialized, you can still share by pasting the code you saved earlier.</div>
      </div>
    </div>

   
    <label class="chk" style="margin:0 0 12px 0;">
      <input type="checkbox" id="ps-allow" checked>
      <span>Reveal after the unlock date to anyone with the link</span>
    </label>

    <div id="ps-err" class="msg msg-err"></div>

    <button class="btn btn-primary" id="ps-btn" onclick="createShareFromPrep()"><span class="btn-ico" id="ps-ico" aria-hidden="true">🔗</span><span class="btn-txt" id="ps-txt">Create share link</span></button>

    <div id="ps-out" class="rv-share" style="display:none;">
      <div class="hr"></div>
      <div class="rv-share-grid" style="margin-top:12px;">
        <div>
          <div class="k">Link</div>
          <input class="ls-input" id="ps-url" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="ps-copy-url" style="margin-top:8px;">Copy link</button>
        </div>
        <div>
          <div class="k">Secret (save this)</div>
          <input class="ls-input" id="ps-secret" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="ps-copy-secret" style="margin-top:8px;">Copy secret</button>
        </div>
      </div>

      <div class="msg msg-ok" id="ps-ok"></div>
      <button class="btn btn-red btn-sm btn-inline" type="button" id="ps-revoke" style="display:none;margin-top:12px;">Revoke link</button>
    </div>
  </div>
</div>

<!-- reveal overlay -->
<div id="reveal-overlay" class="ls-modal-overlay ls-sheet" onclick="closeReveal(event)">
  <div class="ls-modal reveal-sheet" role="dialog" aria-modal="true" aria-labelledby="rv-label">
    <button class="ls-modal-x" type="button" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>" onclick="closeReveal();event.stopPropagation();">×</button>
    <div class="ls-modal-title" id="rv-label">Reveal</div>
    <div class="ls-modal-sub">// enter vault passphrase to decrypt</div>
    <div id="rv-hint" style="display:none;font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:12px;"></div>

    <div class="vault-input-wrap">
      <label>Vault Passphrase</label>
      <input type="password" id="rv-vault" placeholder="Your vault passphrase…" autocomplete="current-password">
    </div>

    <div class="reveal-pwd" id="rv-pwd"></div>

    <div id="rv-err" class="msg msg-err"></div>

    <button class="btn btn-primary" id="rv-btn" onclick="doReveal()"><span class="btn-ico" id="rv-btn-ico" aria-hidden="true">🔒</span><span class="btn-txt" id="rv-btn-txt">Decrypt &amp; Reveal</span></button>
    <button class="btn btn-ghost" id="rv-copy-btn" onclick="copyRevealed()" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">⧉</span><span class="btn-txt">Copy</span></button>
    <button class="btn btn-ghost" id="rv-share-btn" onclick="startShareFlow()" style="display:none;margin-top:10px;"><span class="btn-ico" aria-hidden="true">🔗</span><span class="btn-txt">Create share link</span></button>

    <div id="rv-share-wrap" class="rv-share" style="display:none;">
      <div class="hr"></div>
      <div class="k">Share link</div>
      <div class="small" style="margin-top:6px;">Anyone with the link + the secret can decrypt after your lock becomes eligible to reveal.</div>

      <label class="chk" style="margin:12px 0 0 0;">
        <input type="checkbox" id="rv-share-allow" checked>
        <span>Reveal after the unlock date to anyone with the link</span>
      </label>

      <div class="rv-share-grid" style="margin-top:12px;">
        <div>
          <div class="k">Link</div>
          <input class="ls-input" id="rv-share-url" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="rv-share-copy-url" style="margin-top:8px;">Copy link</button>
        </div>
        <div>
          <div class="k">Secret (save this)</div>
          <input class="ls-input" id="rv-share-secret" readonly value="" style="margin-top:6px;">
          <button class="btn btn-ghost btn-sm btn-inline" type="button" id="rv-share-copy-secret" style="margin-top:8px;">Copy secret</button>
        </div>
      </div>

      <div class="msg msg-ok" id="rv-share-ok"></div>
      <div class="msg msg-err" id="rv-share-err"></div>

      <button class="btn btn-red btn-sm btn-inline" type="button" id="rv-share-revoke" style="display:none;margin-top:12px;">Revoke link</button>
    </div>

    <div id="rv-zk-note" style="display:none;margin-top:10px;font-size:10px;color:var(--muted);letter-spacing:1px;line-height:1.6;">
      Zero-knowledge: only your browser decrypted this value.
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

let vaultPhraseSession = null;
let vaultSlotSession   = 1;

let revealedPwd = null;
let currentReveal = null; // {kind:'lock'|'wallet', id:string, label:string, hint:string, reveal_date:string, cipher_blob:string, iv:string, auth_tag:string, kdf_salt:string, kdf_iterations:int}

let currentShareId = null;
let shareAfterReveal = false;
let shareAfterPayload = null;

let currentShareLock = null;
let currentPreShareId = null;

let countdownTimer = null;
let countdownRefreshTimer = null;

const reduceMotion = (()=>{
  try{ return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
  catch{ return false; }
})();

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

function esc(s){
  if(window.LS && LS.esc) return LS.esc(s);
  return String(s||'')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
function toast(msg,type='ok'){
  if(window.LS && LS.toast) return LS.toast(msg, type);
  const t=document.createElement('div');t.className=`toast ${type}`;t.textContent=String(msg||'');document.body.appendChild(t);setTimeout(()=>t.remove(),3200);
}

function parseUtc(ts){
  return (window.LS && LS.parseUtc) ? LS.parseUtc(ts) : new Date(ts);
}

function fmtLocalTs(ts){
  const d = parseUtc(ts);
  return (window.LS && LS.fmtLocal) ? LS.fmtLocal(d) : (d && !isNaN(d.getTime()) ? d.toLocaleString() : '');
}

function fmtUtcTs(ts){
  const d = parseUtc(ts);
  return (window.LS && LS.fmtUtc) ? LS.fmtUtc(d) : (d && !isNaN(d.getTime()) ? d.toUTCString() : '');
}

function fmtCountdown(seconds){
  if(window.LS && LS.fmtCountdown) return LS.fmtCountdown(seconds);
  const s = Math.max(0, parseInt(seconds||'0', 10) || 0);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  return (h > 0 ? (String(h).padStart(2,'0') + ':') : '') + String(m).padStart(2,'0') + ':' + String(ss).padStart(2,'0');
}

function renderLoadingSkeleton(){
  return `
    <div class="locks-grid">
      <div class="skel" style="height:120px;"></div>
      <div class="skel" style="height:120px;"></div>
      <div class="skel" style="height:120px;"></div>
    </div>
  `;
}

function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}
function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}

function requireWebCrypto(){
  if (!window.crypto || !window.crypto.getRandomValues) {
    throw new Error('Secure cryptography is unavailable in this browser.');
  }
  if (!window.isSecureContext || !window.crypto.subtle) {
    throw new Error('Web Crypto API is unavailable. Use HTTPS (or localhost) to use the vault.');
  }
  return window.crypto;
}

async function deriveKey(passphrase, kdfSaltB64, iters){
  const c = requireWebCrypto();
  const enc = new TextEncoder();
  const baseKey = await c.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const saltBytes = b64ToBytes(kdfSaltB64);
  return c.subtle.deriveKey(
    {name:'PBKDF2', salt:saltBytes, iterations: iters, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function aesEncrypt(plain, key){
  const c = requireWebCrypto();
  const iv = new Uint8Array(12);
  c.getRandomValues(iv);
  const enc = new TextEncoder();
  const ct = new Uint8Array(await c.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, enc.encode(plain)));
  const tag = ct.slice(ct.length - 16);
  const cipher = ct.slice(0, ct.length - 16);
  return {cipher_blob: bytesToB64(cipher), iv: bytesToB64(iv), auth_tag: bytesToB64(tag)};
}

async function aesDecrypt(cipherBlobB64, ivB64, tagB64, key){
  const c = requireWebCrypto();
  const cipher = b64ToBytes(cipherBlobB64);
  const iv = b64ToBytes(ivB64);
  const tag = b64ToBytes(tagB64);
  const data = new Uint8Array(cipher.length + tag.length);
  data.set(cipher, 0);
  data.set(tag, cipher.length);
  const pt = await c.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, key, data);
  return new TextDecoder().decode(pt);
}

function startCountdownTicker(){
  if(countdownTimer) clearInterval(countdownTimer);

  function tick(){
    let shouldRefresh = false;

    document.querySelectorAll('[data-countdown-until]')
      .forEach(el => {
        const until = parseInt(el.getAttribute('data-countdown-until')||'0', 10) || 0;
        if(!until) return;

        const now = Date.now();
        const remainingMs = until - now;
        const seconds = Math.max(0, Math.floor(remainingMs / 1000));

        const totalAttr = parseInt(el.getAttribute('data-countdown-total')||'0', 10) || 0;
        const totalMs = totalAttr > 0 ? totalAttr : Math.max(1, until - now);
        if(!totalAttr) el.setAttribute('data-countdown-total', String(totalMs));

        const nextText = seconds > 0 ? `⏱ Reveals in ${fmtCountdown(seconds)}` : '⏱ Reveal eligible';
        const txtEl = el.querySelector('.cd-txt') || el;
        if(txtEl.textContent !== nextText){
          txtEl.textContent = nextText;
          if(!reduceMotion){
            txtEl.classList.remove('tick');
            void txtEl.offsetWidth;
            txtEl.classList.add('tick');
          }
        }

        const clampedRemaining = Math.max(0, remainingMs);
        const p = totalMs > 0 ? Math.max(0, Math.min(1, 1 - (clampedRemaining / totalMs))) : 1;
        el.style.setProperty('--p', String(p));

        const urg = (seconds <= 0) ? 0 : (seconds <= 10 ? 3 : (seconds <= 60 ? 2 : 1));
        el.setAttribute('data-urgency', String(urg));

        if(seconds <= 0 && el.getAttribute('data-hit-zero') !== '1'){
          el.setAttribute('data-hit-zero', '1');
          const card = el.closest ? el.closest('.lock-card') : null;
          if(card && card.classList.contains('st-locked')) shouldRefresh = true;
        }
      });

    if(shouldRefresh){
      if(countdownRefreshTimer) clearTimeout(countdownRefreshTimer);
      countdownRefreshTimer = setTimeout(()=>{ countdownRefreshTimer = null; loadLocks(); }, 1200);
    }
  }

  tick();
  countdownTimer = setInterval(tick, 1000);
}

async function loadLocks(){
  if(countdownRefreshTimer){
    clearTimeout(countdownRefreshTimer);
    countdownRefreshTimer = null;
  }

  const wrap=document.getElementById('locks-wrap');
  wrap.innerHTML=renderLoadingSkeleton();

  try{
    const [a,b] = await Promise.allSettled([
      get('api/locks.php'),
      get('api/wallet_locks.php'),
    ]);

    const locks = (a.status==='fulfilled' && a.value && a.value.success) ? (a.value.locks||[]) : [];
    const walletLocks = (b.status==='fulfilled' && b.value && b.value.success) ? (b.value.wallet_locks||[]) : [];

    try{
      localStorage.setItem('ls_my_codes_cache', JSON.stringify({ts: Date.now(), locks, wallet_locks: walletLocks}));
    }catch{}

    const mapped = [];

    locks.forEach(l => mapped.push(Object.assign({kind:'lock'}, l)));

    walletLocks.forEach(w => {
      const stRaw = String(w.display_status||'');
      const st = (stRaw === 'setup_pending') ? 'pending'
              : (stRaw === 'setup_failed') ? 'rejected'
              : (stRaw === 'inactive') ? 'rejected'
              : stRaw;

      mapped.push({
        kind: 'wallet',
        id: w.id,
        label: w.label || (w.carrier_name ? (w.carrier_name + ' wallet PIN') : 'Wallet PIN'),
        hint: null,
        password_type: w.carrier_pin_type || 'numeric',
        password_length: parseInt(w.carrier_pin_length||'4',10) || 4,
        reveal_date: w.unlock_at,
        created_at: w.created_at,
        copied_at: null,
        revealed_at: w.revealed_at,
        display_status: st,
        time_remaining: w.time_remaining || null,
        carrier_name: w.carrier_name || '',
      });
    });

    mapped.sort((x,y) => {
      const dx = parseUtc(x.created_at || x.reveal_date || '');
      const dy = parseUtc(y.created_at || y.reveal_date || '');
      const ax = (dx && !isNaN(dx.getTime())) ? dx.getTime() : 0;
      const ay = (dy && !isNaN(dy.getTime())) ? dy.getTime() : 0;
      return ay - ax;
    });

    if(!mapped.length){
      wrap.innerHTML='<div class="empty"><div class="empty-icon">🔒</div><h3>No codes yet</h3><p>Create one from the Create Code page.</p></div>';
      return;
    }

    wrap.innerHTML='<div class="locks-grid" id="locks-grid"></div>';
    const grid = document.getElementById('locks-grid');
    mapped.forEach(l=>grid.appendChild(buildCard(l)));

    startCountdownTicker();

  }catch{
    try{
      const cached = JSON.parse(localStorage.getItem('ls_my_codes_cache') || 'null');
      const locks = cached && cached.locks ? cached.locks : [];
      const walletLocks = cached && cached.wallet_locks ? cached.wallet_locks : [];

      const mapped = [];
      locks.forEach(l => mapped.push(Object.assign({kind:'lock'}, l)));
      walletLocks.forEach(w => {
        const stRaw = String(w.display_status||'');
        const st = (stRaw === 'setup_pending') ? 'pending'
                : (stRaw === 'setup_failed') ? 'rejected'
                : (stRaw === 'inactive') ? 'rejected'
                : stRaw;

        mapped.push({
          kind: 'wallet',
          id: w.id,
          label: w.label || (w.carrier_name ? (w.carrier_name + ' wallet PIN') : 'Wallet PIN'),
          hint: null,
          password_type: w.carrier_pin_type || 'numeric',
          password_length: parseInt(w.carrier_pin_length||'4',10) || 4,
          reveal_date: w.unlock_at,
          created_at: w.created_at,
          copied_at: null,
          revealed_at: w.revealed_at,
          display_status: st,
          time_remaining: w.time_remaining || null,
          carrier_name: w.carrier_name || '',
        });
      });

      mapped.sort((x,y) => {
        const dx = parseUtc(x.created_at || x.reveal_date || '');
        const dy = parseUtc(y.created_at || y.reveal_date || '');
        const ax = (dx && !isNaN(dx.getTime())) ? dx.getTime() : 0;
        const ay = (dy && !isNaN(dy.getTime())) ? dy.getTime() : 0;
        return ay - ax;
      });

      if(mapped.length){
        wrap.innerHTML = '<div class="card" style="margin-bottom:12px;"><div class="small">Offline mode: showing cached metadata. Reveal is disabled until you’re back online.</div></div>';
        const holder = document.createElement('div');
        holder.innerHTML = '<div class="locks-grid" id="locks-grid"></div>';
        wrap.appendChild(holder.firstChild);
        const grid = document.getElementById('locks-grid');
        mapped.forEach(l=>grid.appendChild(buildCard(l, {offline:true})));
        startCountdownTicker();
        return;
      }
    }catch{}

    wrap.innerHTML='<div class="empty"><p>Failed to load.</p></div>';
  }
}

function buildCard(lock, opts={}){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;

  const offline = !!(opts && opts.offline);

  try{
    if(lock && lock.id && String(lock.id).length === 36){
      if(lock.kind === 'lock') el.id = 'lock-' + String(lock.id);
      else if(lock.kind === 'wallet') el.id = 'wallet-' + String(lock.id);
    }
  }catch{}

  const badges={locked:'🔒 Locked',unlocked:'🔓 Unlocked',pending:'⏳ Pending',auto_saved:'💾 Auto-saved',rejected:'✗ Void'};

  const revealD = parseUtc(lock.reveal_date);
  const localStr = fmtLocalTs(lock.reveal_date);
  const utcStr = fmtUtcTs(lock.reveal_date);

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

  if(st==='auto_saved'){
    const note=document.createElement('div');
    note.className='lc-autosave-note';
    note.textContent='ℹ Auto-saved without confirmation. Tap "Activate" to enforce reveal date.';
    el.appendChild(note);
  }

  if((st==='locked' || st==='unlocked') && revealD && !isNaN(revealD.getTime())){
    const cd=document.createElement('div');
    cd.className='lc-countdown';

    const untilMs = revealD.getTime();
    cd.setAttribute('data-countdown-until', String(untilMs));
    cd.setAttribute('data-countdown-total', String(Math.max(1, untilMs - Date.now())));

    const txt=document.createElement('span');
    txt.className='cd-txt';
    txt.textContent='⏱';

    const bar=document.createElement('div');
    bar.className='cd-bar';

    cd.appendChild(txt);
    cd.appendChild(bar);
    el.appendChild(cd);
  }

  const meta=document.createElement('div');
  meta.className='lc-meta';

  const whenHtml = `<span>${esc(localStr)}</span> <span class="utc-pill" title="Stored & enforced in UTC">${esc(utcStr)}</span>`;

  if(lock.kind === 'wallet'){
    const revealed = lock.revealed_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--muted)">—</span>';
    meta.innerHTML=`Type: <span>Wallet PIN · ${esc(lock.password_length)} chars</span><br>Carrier: <span>${esc(lock.carrier_name||'')}</span><br>Unlock: ${whenHtml}<br>Revealed: ${revealed}`;
  } else {
    const copied = lock.copied_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">not copied</span>';
    meta.innerHTML=`Type: <span>${esc(lock.password_type)} · ${esc(lock.password_length)} chars</span><br>Reveal: ${whenHtml}<br>Copied: ${copied}`;
  }

  el.appendChild(meta);

  const actions=document.createElement('div');
  actions.className='lc-actions';

  if(st==='unlocked'){
    const b=document.createElement('button');
    b.className='btn btn-green btn-sm';
    b.type='button';
    b.textContent='Reveal';
    if(offline){
      b.disabled = true;
      b.style.opacity = '.45';
      b.textContent = 'Reveal (offline)';
    }else{
      b.addEventListener('click', ()=>openReveal(lock.kind, lock.id, lock.label||'Reveal', lock.hint||''));
    }
    actions.appendChild(b);

    if(lock.kind === 'lock'){
      const s=document.createElement('button');
      s.className='btn btn-ghost btn-sm';
      s.type='button';
      s.textContent='Share';
      if(offline){
        s.disabled = true;
        s.style.opacity = '.45';
      }else{
        s.addEventListener('click', ()=>{
          shareAfterReveal = true;
          openReveal(lock.kind, lock.id, lock.label||'Reveal', lock.hint||'');
        });
      }
      actions.appendChild(s);
    }
  } else if(st==='auto_saved'){
    const b=document.createElement('button');
    b.className='btn btn-sm';
    b.type='button';
    b.textContent='Activate';
    b.style.background='var(--blue)';
    b.style.color='#000';
    b.style.minHeight='40px';
    b.style.fontFamily='var(--mono)';
    b.style.fontSize='11px';
    b.style.letterSpacing='1px';
    b.style.cursor='pointer';
    b.style.border='none';
    b.addEventListener('click', ()=>reConfirm(lock.id));
    actions.appendChild(b);
  } else if(st==='locked'){
    const b=document.createElement('button');
    b.className='btn btn-ghost btn-sm';
    b.type='button';
    b.disabled=true;
    b.style.opacity='.3';
    b.style.cursor='not-allowed';
    b.textContent=`Sealed until ${localStr}`;
    b.title=`UTC: ${utcStr}`;
    actions.appendChild(b);

    if(lock.kind === 'lock'){
      const s=document.createElement('button');
      s.className='btn btn-ghost btn-sm';
      s.type='button';
      s.textContent='Share';
      if(offline){
        s.disabled = true;
        s.style.opacity = '.45';
        s.title = 'Offline';
      }else{
        s.addEventListener('click', ()=>openShare(lock));
        s.title = 'Create a share link (requires vault passphrase; legacy: paste saved code)';
      }
      actions.appendChild(s);
    }
  }

  const del=document.createElement('button');
  del.className='btn btn-red btn-sm';
  del.type='button';
  del.textContent='Delete';
  if(offline){
    del.disabled = true;
    del.style.opacity = '.45';
    del.textContent = 'Delete (offline)';
  }else{
    del.addEventListener('click', ()=>delLock(lock.kind, lock.id));
  }
  actions.appendChild(del);

  el.appendChild(actions);
  return el;
}

function setBtnState(btn, icoEl, txtEl, state, ico, txt){
  if(!btn) return;
  if(state) btn.setAttribute('data-state', state);
  else btn.removeAttribute('data-state');
  if(icoEl) icoEl.textContent = ico || '';
  if(txtEl) txtEl.textContent = txt || '';
}

function showRv(el){
  if(!el) return;
  el.style.display='block';
  if(!reduceMotion){
    el.classList.remove('rv-in');
    void el.offsetWidth;
    el.classList.add('rv-in');
  }
}

function hideRv(el){
  if(!el) return;
  el.style.display='none';
  el.classList.remove('rv-in');
}

function setRevealSheetState(state){
  const sheet = document.querySelector('#reveal-overlay .reveal-sheet');
  if(!sheet) return;
  if(state) sheet.setAttribute('data-state', state);
  else sheet.removeAttribute('data-state');
}

function openReveal(kind, id, label, hint){
  currentReveal = {kind, id, share_after: !!shareAfterReveal};
  shareAfterReveal = false;
  currentShareId = null;
  revealedPwd = null;

  const overlay = document.getElementById('reveal-overlay');
  const sheet = overlay ? overlay.querySelector('.reveal-sheet') : null;
  if(sheet) sheet.removeAttribute('data-state');

  document.getElementById('rv-label').textContent=label;
  document.getElementById('rv-vault').value=vaultPhraseSession||'';

  const pwdEl = document.getElementById('rv-pwd');
  pwdEl.textContent='';
  hideRv(pwdEl);
  hideRv(document.getElementById('rv-copy-btn'));
  hideRv(document.getElementById('rv-share-btn'));
  hideRv(document.getElementById('rv-share-wrap'));
  hideRv(document.getElementById('rv-zk-note'));

  const shareOk = document.getElementById('rv-share-ok');
  const shareErr = document.getElementById('rv-share-err');
  if(shareOk) shareOk.classList.remove('show');
  if(shareErr) shareErr.classList.remove('show');
  const shareUrl = document.getElementById('rv-share-url');
  const shareSecret = document.getElementById('rv-share-secret');
  if(shareUrl) shareUrl.value='';
  if(shareSecret) shareSecret.value='';
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(revokeBtn) revokeBtn.style.display='none';

  const btn = document.getElementById('rv-btn');
  const ico = document.getElementById('rv-btn-ico');
  const txt = document.getElementById('rv-btn-txt');
  btn.style.display='block';
  btn.disabled=false;
  setBtnState(btn, ico, txt, null, '🔒', currentReveal.share_after ? 'Decrypt & Share' : 'Decrypt & Reveal');

  const errEl = document.getElementById('rv-err');
  errEl.classList.remove('show');

  const hi=document.getElementById('rv-hint');
  if(hint){hi.textContent=`Hint: "${hint}"`;hi.style.display='block';}else hi.style.display='none';

  overlay.classList.add('show');
  document.body.style.overflow='hidden';
  setTimeout(()=>document.getElementById('rv-vault').focus(),200);
}

async function ensureReauth(methods){
  if(window.LS && LS.reauth){
    return LS.reauth(methods||{}, {post: postCsrf});
  }
  toast('Enable TOTP or add a passkey in Account', 'warn');
  return false;
}

async function doReveal(){
  const btn = document.getElementById('rv-btn');
  const ico = document.getElementById('rv-btn-ico');
  const txt = document.getElementById('rv-btn-txt');

  const vault=document.getElementById('rv-vault').value || vaultPhraseSession;
  const errEl=document.getElementById('rv-err');
  errEl.classList.remove('show');

  if(!vault){errEl.textContent='Enter your vault passphrase';errEl.classList.add('show');return;}
  if(!currentReveal || !currentReveal.id){errEl.textContent='No code selected';errEl.classList.add('show');return;}

  setBtnState(btn, ico, txt, 'working', '⏳', 'Decrypting…');
  btn.disabled=true;
  setRevealSheetState('working');

  try{
    const endpoint = (currentReveal.kind === 'wallet') ? 'api/wallet_reveal.php' : 'api/reveal.php';
    const body = (currentReveal.kind === 'wallet')
      ? {wallet_lock_id: currentReveal.id}
      : {lock_id: currentReveal.id};

    let r=await postCsrf(endpoint, body);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok = await ensureReauth(r.methods||{});
      if(!ok) throw new Error(r.error||'Re-authentication required');
      r=await postCsrf(endpoint, body);
    }
    if(!r.success) throw new Error(r.error||'Cannot reveal');

    const payload = (currentReveal.kind === 'wallet') ? (r.wallet_lock || {}) : r;

    const key=await deriveKey(vault, payload.kdf_salt, payload.kdf_iterations);
    const plain=await aesDecrypt(payload.cipher_blob, payload.iv, payload.auth_tag, key);

    revealedPwd=plain;

    const pwdEl = document.getElementById('rv-pwd');
    if(currentReveal && currentReveal.share_after){
      // Sharing does not require displaying the plaintext to the user.
      pwdEl.textContent='';
      hideRv(pwdEl);
      hideRv(document.getElementById('rv-copy-btn'));
      hideRv(document.getElementById('rv-share-btn'));
      showRv(document.getElementById('rv-zk-note'));
    } else {
      pwdEl.textContent=plain;
      showRv(pwdEl);
      showRv(document.getElementById('rv-copy-btn'));
      if(currentReveal.kind === 'lock') showRv(document.getElementById('rv-share-btn'));
      showRv(document.getElementById('rv-zk-note'));
    }

    vaultPhraseSession=vault;

    if(currentReveal.kind !== 'wallet'){
      vaultSlotSession=parseInt(r.vault_verifier_slot||1,10)||1;
      localStorage.setItem('vault_slot', String(vaultSlotSession));
    }

    setRevealSheetState('success');
    setBtnState(btn, ico, txt, 'success', '☺', currentReveal && currentReveal.share_after ? 'Decrypted' : 'Revealed');

    setTimeout(()=>{
      btn.style.display='none';
      setRevealSheetState(null);
      if(currentReveal && currentReveal.share_after && currentReveal.kind === 'lock'){
        startShareFlow();
      }
    }, 700);

  }catch(e){
    if(e && e.name==='OperationError') errEl.textContent='Decryption failed — wrong vault passphrase or tampered data';
    else errEl.textContent=(e && e.message) ? e.message : 'Decryption failed';
    errEl.classList.add('show');

    setRevealSheetState('error');
    setBtnState(btn, ico, txt, 'error', '⚠', 'Failed');

    setTimeout(()=>{
      setRevealSheetState(null);
      setBtnState(btn, ico, txt, null, '🔒', (currentReveal && currentReveal.share_after) ? 'Decrypt & Share' : 'Decrypt & Reveal');
      btn.disabled=false;
    }, 900);
  }
}

function closeReveal(e){
  const overlay = document.getElementById('reveal-overlay');
  if(e && e.target !== overlay) return;

  overlay.classList.remove('show');
  setRevealSheetState(null);

  const navOv = document.getElementById('ls-nav-overlay');
  const moreOv = document.getElementById('ls-overflow-overlay');
  if(!(navOv && navOv.classList.contains('show')) && !(moreOv && moreOv.classList.contains('show'))){
    document.body.style.overflow = '';
  }

  revealedPwd=null;
  currentReveal=null;
  currentShareId=null;
  shareAfterReveal=false;
}

function setShareSheetState(state){
  const sheet = document.querySelector('#share-overlay .reveal-sheet');
  if(!sheet) return;
  if(state) sheet.setAttribute('data-state', state);
  else sheet.removeAttribute('data-state');
}

function openShare(lock){
  if(!lock || lock.kind !== 'lock' || !lock.id) return;

  currentShareLock = lock;
  currentPreShareId = null;

  const overlay = document.getElementById('share-overlay');
  const sheet = overlay ? overlay.querySelector('.reveal-sheet') : null;
  if(sheet) sheet.removeAttribute('data-state');

  const title = document.getElementById('ps-title');
  if(title) title.textContent = lock.label ? String(lock.label) : 'Share lock';

  const meta = document.getElementById('ps-meta');
  if(meta){
    const localStr = fmtLocalTs(lock.reveal_date);
    const utcStr = fmtUtcTs(lock.reveal_date);
    meta.innerHTML = `Sealed until <span>${esc(localStr)}</span> <span class="utc-pill" title="Stored & enforced in UTC">${esc(utcStr)}</span>`;
  }

  const vp = document.getElementById('ps-vault');
  if(vp) vp.value = vaultPhraseSession || '';

  const legacy = document.getElementById('ps-legacy');
  if(legacy) legacy.style.display = 'none';
  const code = document.getElementById('ps-code');
  if(code) code.value = '';

  const allow = document.getElementById('ps-allow');
  if(allow) allow.checked = true;

  const err = document.getElementById('ps-err');
  if(err){ err.classList.remove('show'); err.textContent=''; }

  const out = document.getElementById('ps-out');
  if(out) out.style.display='none';

  const ok = document.getElementById('ps-ok');
  if(ok){ ok.className='msg msg-ok'; ok.textContent=''; ok.classList.remove('show'); }

  const revoke = document.getElementById('ps-revoke');
  if(revoke) revoke.style.display='none';

  const btn = document.getElementById('ps-btn');
  const ico = document.getElementById('ps-ico');
  const txt = document.getElementById('ps-txt');
  if(btn){ btn.disabled = false; setBtnState(btn, ico, txt, null, '🔗', 'Create share link'); }

  if(overlay){
    overlay.classList.add('show');
    document.body.style.overflow='hidden';
    setTimeout(()=>{ if(vp) vp.focus(); }, 150);
  }
}

function closeShare(e){
  const overlay = document.getElementById('share-overlay');
  if(!overlay) return;
  if(e && e.target !== overlay) return;

  overlay.classList.remove('show');
  setShareSheetState(null);

  const navOv = document.getElementById('ls-nav-overlay');
  const moreOv = document.getElementById('ls-overflow-overlay');
  const rvOv = document.getElementById('reveal-overlay');

  if(!(rvOv && rvOv.classList.contains('show'))
    && !(navOv && navOv.classList.contains('show'))
    && !(moreOv && moreOv.classList.contains('show'))){
    document.body.style.overflow = '';
  }

  currentShareLock = null;
  currentPreShareId = null;
}

function setPreShareMsg(el, txt, ok){
  if(!el) return;
  el.textContent = txt || '';
  if(!txt){ el.classList.remove('show'); return; }
  el.classList.add('show');
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
}

async function revokePreShare(){
  if(!currentPreShareId) return;
  if(!confirm('Revoke this share link? Anyone with it will lose access.')) return;

  const okEl = document.getElementById('ps-ok');
  const errEl = document.getElementById('ps-err');
  setPreShareMsg(okEl, '', true);
  setPreShareMsg(errEl, '', false);

  const r = await postCsrf('api/shares.php', {action:'revoke', share_id: currentPreShareId});
  if(!r.success){
    setPreShareMsg(errEl, r.error || 'Failed', false);
    return;
  }

  currentPreShareId = null;
  const revokeBtn = document.getElementById('ps-revoke');
  if(revokeBtn) revokeBtn.style.display='none';
  setPreShareMsg(okEl, 'Link revoked.', true);
}

async function createShareFromPrep(){
  if(!currentShareLock || currentShareLock.kind !== 'lock' || !currentShareLock.id){
    toast('Select a lock first','err');
    return;
  }

  const legacyWrap = document.getElementById('ps-legacy');
  const code = (document.getElementById('ps-code').value || '').trim();
  const vp = (document.getElementById('ps-vault').value || vaultPhraseSession || '').trim();

  if(!vp && !code){
    const err = document.getElementById('ps-err');
    if(err){ err.textContent = 'Enter your vault passphrase (or paste the saved code in legacy mode).'; err.classList.add('show'); }
    return;
  }

  const btn = document.getElementById('ps-btn');
  const ico = document.getElementById('ps-ico');
  const txt = document.getElementById('ps-txt');
  const errEl = document.getElementById('ps-err');
  const okEl = document.getElementById('ps-ok');

  if(errEl){ errEl.classList.remove('show'); errEl.textContent=''; }
  setPreShareMsg(okEl, '', true);

  setBtnState(btn, ico, txt, 'working', '⏳', 'Creating…');
  if(btn) btn.disabled = true;
  setShareSheetState('working');

  try{
    const allowEl = document.getElementById('ps-allow');
    const allow = allowEl ? !!allowEl.checked : true;

    // Legacy path: paste the plaintext code (for locks created before share precomputation).
    if(code){
      const secret = genShareSecret();
      const c = requireWebCrypto();
      const saltBytes = new Uint8Array(16);
      c.getRandomValues(saltBytes);
      const saltB64 = bytesToB64(saltBytes);

      const iters = 310000;
      const key = await deriveKey(secret, saltB64, iters);
      const enc = await aesEncrypt(code, key);

      const payloadLegacy = {
        action: 'create',
        lock_id: currentShareLock.id,
        share_cipher_blob: enc.cipher_blob,
        share_iv: enc.iv,
        share_auth_tag: enc.auth_tag,
        share_kdf_salt: saltB64,
        share_kdf_iterations: iters,
        allow_reveal_after_date: allow ? 1 : 0,
      };

      let r = await postCsrf('api/shares.php', payloadLegacy);
      if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
        const ok2 = await ensureReauth(r.methods||{});
        if(!ok2) throw new Error(r.error||'Re-authentication required');
        r = await postCsrf('api/shares.php', payloadLegacy);
      }
      if(!r.success) throw new Error(r.error || 'Failed');

      currentPreShareId = parseInt(r.share_id||'0', 10) || null;

      const out = document.getElementById('ps-out');
      if(out) out.style.display = 'block';

      const urlEl = document.getElementById('ps-url');
      const secEl = document.getElementById('ps-secret');
      if(urlEl) urlEl.value = String(r.share_url||'');
      if(secEl) secEl.value = secret;

      const revokeBtn = document.getElementById('ps-revoke');
      if(revokeBtn && currentPreShareId) revokeBtn.style.display = 'inline-flex';

      setShareSheetState('success');
      setBtnState(btn, ico, txt, 'success', '☺', 'Created');
      setPreShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);
      return;
    }

    // Preferred path: create from server-stored precomputation (no plaintext).
    const payload = {
      action: 'create_from_prep',
      lock_id: currentShareLock.id,
      allow_reveal_after_date: allow ? 1 : 0,
    };

    let r = await postCsrf('api/shares.php', payload);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok2 = await ensureReauth(r.methods||{});
      if(!ok2) throw new Error(r.error||'Re-authentication required');
      r = await postCsrf('api/shares.php', payload);
    }

    if(!r.success){
      const m = String(r.error||'Failed');
      if(legacyWrap && (m.includes('not initialized') || m.includes('precomputation') || m.includes('unavailable'))){
        legacyWrap.style.display = 'block';
        throw new Error('This lock can’t be shared without unlock. Paste the saved code below to create a legacy share link.');
      }
      throw new Error(m);
    }

    const wrap = r.share_secret_wrap || null;
    if(!wrap || !wrap.cipher_blob || !wrap.iv || !wrap.auth_tag || !wrap.kdf_salt){
      throw new Error('Missing share secret');
    }

    const iters = parseInt(wrap.kdf_iterations||310000, 10) || 310000;
    const key = await deriveKey(vp, wrap.kdf_salt, iters);
    const secret = await aesDecrypt(wrap.cipher_blob, wrap.iv, wrap.auth_tag, key);

    vaultPhraseSession = vp;

    currentPreShareId = parseInt(r.share_id||'0', 10) || null;

    const out = document.getElementById('ps-out');
    if(out) out.style.display = 'block';

    const urlEl = document.getElementById('ps-url');
    const secEl = document.getElementById('ps-secret');
    if(urlEl) urlEl.value = String(r.share_url||'');
    if(secEl) secEl.value = String(secret||'');

    const revokeBtn = document.getElementById('ps-revoke');
    if(revokeBtn && currentPreShareId) revokeBtn.style.display = 'inline-flex';

    setShareSheetState('success');
    setBtnState(btn, ico, txt, 'success', '☺', 'Created');
    setPreShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);

  }catch(e){
    setShareSheetState('error');

    const msg = (e && e.name==='OperationError')
      ? 'Incorrect vault passphrase or tampered data'
      : ((e && e.message) ? e.message : 'Failed');

    if(errEl){ errEl.textContent = msg; errEl.classList.add('show'); }
    setBtnState(btn, ico, txt, 'error', '⚠', 'Failed');

  }finally{
    setTimeout(()=>{
      setShareSheetState(null);
      setBtnState(btn, ico, txt, null, '🔗', 'Create share link');
      if(btn) btn.disabled = false;
    }, 900);
  }
}

async function copyRevealed(){
  if(!revealedPwd || !currentReveal || !currentReveal.id) return;
  try{
    let copied = false;
    if(window.LS && LS.copySensitive){
      copied = await LS.copySensitive(revealedPwd, {clearAfterMs: 30000});
    }else{
      await navigator.clipboard.writeText(revealedPwd);
      copied = true;
    }

    if(!copied) return;

    if(currentReveal.kind !== 'wallet'){
      await postCsrf('api/copied.php',{lock_id:currentReveal.id});
    }

    toast('Copied (will try to clear in ~30s)','ok');
    loadLocks();
  }catch{
    toast('Select the text manually','err');
  }
}

function bytesToHex(bytes){
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

function formatSecret(hex){
  const parts = String(hex||'').match(/.{1,4}/g);
  return parts ? parts.join('-') : String(hex||'');
}

function genShareSecret(){
  const c = requireWebCrypto();
  const b = new Uint8Array(16);
  c.getRandomValues(b);
  return formatSecret(bytesToHex(b));
}

function setShareMsg(el, txt, ok){
  if(!el) return;
  el.textContent = txt || '';
  if(!txt){ el.classList.remove('show'); return; }
  el.classList.add('show');
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
}

async function copyVal(id){
  const el = document.getElementById(id);
  const val = el ? (el.value || '') : '';
  if(!val) return;
  try{
    await navigator.clipboard.writeText(val);
    toast('Copied','ok');
  }catch{
    toast('Copy blocked','err');
  }
}

async function revokeShare(){
  if(!currentShareId) return;
  if(!confirm('Revoke this share link? Anyone with it will lose access.')) return;

  const okEl = document.getElementById('rv-share-ok');
  const errEl = document.getElementById('rv-share-err');
  setShareMsg(okEl, '', true);
  setShareMsg(errEl, '', false);

  const r = await postCsrf('api/shares.php', {action:'revoke', share_id: currentShareId});
  if(!r.success){
    setShareMsg(errEl, r.error || 'Failed', false);
    return;
  }

  currentShareId = null;
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(revokeBtn) revokeBtn.style.display='none';
  setShareMsg(okEl, 'Link revoked.', true);
}

async function startShareFlow(){
  if(!currentReveal || currentReveal.kind !== 'lock' || !currentReveal.id){
    toast('Select a lock first','err');
    return;
  }
  if(!revealedPwd){
    toast('Decrypt first to generate a share link','warn');
    return;
  }

  const wrap = document.getElementById('rv-share-wrap');
  showRv(wrap);

  const shareBtn = document.getElementById('rv-share-btn');
  if(shareBtn) shareBtn.disabled = true;

  const okEl = document.getElementById('rv-share-ok');
  const errEl = document.getElementById('rv-share-err');
  setShareMsg(okEl, '', true);
  setShareMsg(errEl, '', false);

  try{
    const secret = genShareSecret();
    const c = requireWebCrypto();
    const saltBytes = new Uint8Array(16);
    c.getRandomValues(saltBytes);
    const saltB64 = bytesToB64(saltBytes);

    const iters = 310000;
    const key = await deriveKey(secret, saltB64, iters);
    const enc = await aesEncrypt(revealedPwd, key);

    const allowEl = document.getElementById('rv-share-allow');
    const allow = allowEl ? !!allowEl.checked : true;

    const payload = {
      action: 'create',
      lock_id: currentReveal.id,
      share_cipher_blob: enc.cipher_blob,
      share_iv: enc.iv,
      share_auth_tag: enc.auth_tag,
      share_kdf_salt: saltB64,
      share_kdf_iterations: iters,
      allow_reveal_after_date: allow ? 1 : 0,
    };

    let r = await postCsrf('api/shares.php', payload);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok2 = await ensureReauth(r.methods||{});
      if(!ok2) throw new Error(r.error||'Re-authentication required');
      r = await postCsrf('api/shares.php', payload);
    }

    if(!r.success) throw new Error(r.error || 'Failed');

    currentShareId = parseInt(r.share_id||'0', 10) || null;

    const urlEl = document.getElementById('rv-share-url');
    const secEl = document.getElementById('rv-share-secret');
    if(urlEl) urlEl.value = String(r.share_url||'');
    if(secEl) secEl.value = secret;

    const revokeBtn = document.getElementById('rv-share-revoke');
    if(revokeBtn && currentShareId){
      revokeBtn.style.display='inline-flex';
    }

    setShareMsg(okEl, 'Share link created. Copy both the link and the secret.', true);

  }catch(e){
    setShareMsg(errEl, (e && e.message) ? e.message : 'Failed', false);

  }finally{
    if(shareBtn){
      shareBtn.disabled = false;
    }
  }
}

async function reConfirm(id){
  const r=await postCsrf('api/confirm.php',{lock_id:id,action:'confirm'});
  if(r.success){toast('Lock activated!','ok');loadLocks();}
  else toast(r.error||'Failed','err');
}
async function delLock(kind, id){
  const msg = (kind === 'wallet')
    ? 'Permanently delete this wallet code? Encrypted data will be removed.'
    : 'Permanently delete this lock? Encrypted data will be removed.';

  if(!confirm(msg))return;

  const endpoint = (kind === 'wallet') ? 'api/wallet_delete.php' : 'api/delete.php';
  const body = (kind === 'wallet') ? {wallet_lock_id:id} : {lock_id:id};

  const r=await postCsrf(endpoint, body);
  if(r.success){toast('Deleted','ok');loadLocks();}
  else toast(r.error||'Delete failed','err');
}

document.addEventListener('DOMContentLoaded', async ()=>{
  const storedSlot = parseInt(localStorage.getItem('vault_slot') || '1', 10);
  vaultSlotSession = ([1,2].includes(storedSlot) ? storedSlot : 1);

  const copyUrl = document.getElementById('rv-share-copy-url');
  const copySecret = document.getElementById('rv-share-copy-secret');
  const revokeBtn = document.getElementById('rv-share-revoke');
  if(copyUrl) copyUrl.addEventListener('click', ()=>copyVal('rv-share-url'));
  if(copySecret) copySecret.addEventListener('click', ()=>copyVal('rv-share-secret'));
  if(revokeBtn) revokeBtn.addEventListener('click', revokeShare);

  const psCopyUrl = document.getElementById('ps-copy-url');
  const psCopySecret = document.getElementById('ps-copy-secret');
  const psRevoke = document.getElementById('ps-revoke');
  if(psCopyUrl) psCopyUrl.addEventListener('click', ()=>copyVal('ps-url'));
  if(psCopySecret) psCopySecret.addEventListener('click', ()=>copyVal('ps-secret'));
  if(psRevoke) psRevoke.addEventListener('click', revokePreShare);

  await loadLocks();
});
</script>
</body>
</html> 
