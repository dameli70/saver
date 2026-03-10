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

<!-- reveal overlay -->
<div id="reveal-overlay" onclick="closeReveal(event)">
  <div class="reveal-sheet">
    <button class="modal-close" onclick="closeReveal()">×</button>
    <div class="reveal-title" id="rv-label">Reveal</div>
    <div class="reveal-sub">// enter vault passphrase to decrypt</div>
    <div id="rv-hint" style="display:none;font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:12px;"></div>

    <div class="vault-input-wrap">
      <label>Vault Passphrase</label>
      <input type="password" id="rv-vault" placeholder="Your vault passphrase…" autocomplete="current-password">
    </div>

    <div class="reveal-pwd" id="rv-pwd"></div>

    <div id="rv-err" class="msg msg-err"></div>

    <button class="btn btn-primary" id="rv-btn" onclick="doReveal()"><span id="rv-btn-txt">Decrypt &amp; Reveal</span></button>
    <button class="btn btn-ghost" id="rv-copy-btn" onclick="copyRevealed()" style="display:none;margin-top:10px;">Copy</button>
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
let currentReveal = null; // {kind:'lock'|'wallet', id:string}

let countdownTimer = null;

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
  countdownTimer = setInterval(()=>{
    document.querySelectorAll('[data-countdown-until]')
      .forEach(el => {
        const until = parseInt(el.getAttribute('data-countdown-until')||'0', 10) || 0;
        const now = Date.now();
        const seconds = Math.max(0, Math.floor((until - now)/1000));
        const label = (window.LS && LS.fmtCountdown) ? LS.fmtCountdown(seconds) : String(seconds);
        el.textContent = seconds > 0 ? `⏱ Reveals in ${label}` : '⏱ Reveal eligible';
      });
  }, 1000);
}

async function loadLocks(){
  const wrap=document.getElementById('locks-wrap');
  wrap.innerHTML=renderLoadingSkeleton();

  try{
    const [a,b] = await Promise.allSettled([
      get('api/locks.php'),
      get('api/wallet_locks.php'),
    ]);

    const locks = (a.status==='fulfilled' && a.value && a.value.success) ? (a.value.locks||[]) : [];
    const walletLocks = (b.status==='fulfilled' && b.value && b.value.success) ? (b.value.wallet_locks||[]) : [];

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
    wrap.innerHTML='<div class="empty"><p>Failed to load.</p></div>';
  }
}

function buildCard(lock){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;

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
    cd.setAttribute('data-countdown-until', String(revealD.getTime()));
    cd.textContent='⏱';
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
    b.addEventListener('click', ()=>openReveal(lock.kind, lock.id, lock.label||'Reveal', lock.hint||''));
    actions.appendChild(b);
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
  }

  const del=document.createElement('button');
  del.className='btn btn-red btn-sm';
  del.type='button';
  del.textContent='Delete';
  del.addEventListener('click', ()=>delLock(lock.kind, lock.id));
  actions.appendChild(del);

  el.appendChild(actions);
  return el;
}

function openReveal(kind, id, label, hint){
  currentReveal = {kind, id};
  document.getElementById('rv-label').textContent=label;
  document.getElementById('rv-vault').value=vaultPhraseSession||'';
  document.getElementById('rv-pwd').style.display='none';
  document.getElementById('rv-copy-btn').style.display='none';
  document.getElementById('rv-zk-note').style.display='none';
  document.getElementById('rv-btn').style.display='block';
  document.getElementById('rv-btn-txt').textContent='Decrypt & Reveal';
  document.getElementById('rv-err').classList.remove('show');
  const hi=document.getElementById('rv-hint');
  if(hint){hi.textContent=`Hint: "${hint}"`;hi.style.display='block';}else hi.style.display='none';
  document.getElementById('reveal-overlay').classList.add('show');
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
  const vault=document.getElementById('rv-vault').value || vaultPhraseSession;
  const errEl=document.getElementById('rv-err');
  errEl.classList.remove('show');
  if(!vault){errEl.textContent='Enter your vault passphrase';errEl.classList.add('show');return;}
  if(!currentReveal || !currentReveal.id){errEl.textContent='No code selected';errEl.classList.add('show');return;}

  document.getElementById('rv-btn-txt').innerHTML='<span class="spin"></span>';

  try{
    const endpoint = (currentReveal.kind === 'wallet') ? 'api/wallet_reveal.php' : 'api/reveal.php';
    const body = (currentReveal.kind === 'wallet')
      ? {wallet_lock_id: currentReveal.id}
      : {lock_id: currentReveal.id};

    let r=await postCsrf(endpoint, body);
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok = await ensureReauth(r.methods||{});
      if(!ok){errEl.textContent=r.error||'Re-authentication required';errEl.classList.add('show');return;}
      r=await postCsrf(endpoint, body);
    }
    if(!r.success){errEl.textContent=r.error||'Cannot reveal';errEl.classList.add('show');return;}

    const payload = (currentReveal.kind === 'wallet') ? (r.wallet_lock || {}) : r;

    const key=await deriveKey(vault, payload.kdf_salt, payload.kdf_iterations);
    const plain=await aesDecrypt(payload.cipher_blob, payload.iv, payload.auth_tag, key);

    revealedPwd=plain;
    document.getElementById('rv-pwd').textContent=plain;
    document.getElementById('rv-pwd').style.display='block';
    document.getElementById('rv-copy-btn').style.display='block';
    document.getElementById('rv-zk-note').style.display='block';
    document.getElementById('rv-btn').style.display='none';

    vaultPhraseSession=vault;

    if(currentReveal.kind !== 'wallet'){
      vaultSlotSession=parseInt(r.vault_verifier_slot||1,10)||1;
      localStorage.setItem('vault_slot', String(vaultSlotSession));
    }

  }catch(e){
    if(e.name==='OperationError') errEl.textContent='Decryption failed — wrong vault passphrase or tampered data';
    else errEl.textContent=e.message||'Decryption failed';
    errEl.classList.add('show');
  }finally{
    document.getElementById('rv-btn-txt').textContent='Decrypt & Reveal';
  }
}

function closeReveal(e){
  if(e&&e.target!==document.getElementById('reveal-overlay'))return;
  document.getElementById('reveal-overlay').classList.remove('show');
  revealedPwd=null;
  currentReveal=null;
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
  await loadLocks();
});
</script>
</body>
</html> 
