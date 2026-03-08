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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>LOCKSMITH — My Codes</title>
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
html{scroll-behavior:smooth;-webkit-tap-highlight-color:transparent;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);font-size:14px;
  min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
.orb{position:fixed;border-radius:50%;filter:blur(100px);pointer-events:none;z-index:0;}
.orb1{width:500px;height:500px;background:rgba(232,255,71,.035);top:-150px;right:-100px;}
.orb2{width:350px;height:350px;background:rgba(71,184,255,.03);bottom:50px;left:-80px;}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:15px 24px;font-family:var(--mono);font-size:12px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;
  border-radius:0;-webkit-appearance:none;touch-action:manipulation;min-height:48px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:500;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:active{transform:scale(.98);}
.btn-primary:disabled{opacity:.4;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);}
.btn-ghost:hover{border-color:var(--text);}
.btn-green{background:var(--green);color:#000;font-weight:500;}
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);}
.btn-sm{padding:10px 16px;font-size:11px;min-height:40px;}

.msg{padding:12px 14px;font-size:12px;margin-bottom:12px;display:none;letter-spacing:.4px;line-height:1.6;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}

#app{min-height:100vh;position:relative;z-index:1;padding-bottom:max(20px,var(--sab));}
.topbar{display:flex;align-items:center;justify-content:space-between;
  padding:max(14px,var(--sat)) 20px 14px;border-bottom:1px solid var(--b1);
  position:sticky;top:0;background:rgba(6,7,10,.94);backdrop-filter:blur(16px);
  -webkit-backdrop-filter:blur(16px);z-index:100;}
.topbar-logo{font-family:var(--display);font-size:clamp(15px,4vw,19px);font-weight:900;letter-spacing:-1px;}
.topbar-logo span{color:var(--accent);} 
.topbar-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.user-pill{font-size:10px;color:var(--muted);letter-spacing:1px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.user-pill{display:block;}}

.app-body{max-width:820px;margin:0 auto;padding:22px 16px;}
@media(min-width:600px){.app-body{padding:30px 24px;}}

.card{background:var(--s1);border:1px solid var(--b1);padding:20px;margin-bottom:16px;position:relative;}
@media(min-width:600px){.card{padding:24px 28px;}}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;
  text-transform:uppercase;color:var(--accent);margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.card-title .dot{width:5px;height:5px;background:var(--accent);flex-shrink:0;}

.locks-grid{display:flex;flex-direction:column;gap:12px;}
.lock-card{background:var(--s1);border:1px solid var(--b1);padding:16px 18px;position:relative;transition:border-color .2s;}
.lock-card:hover{border-color:var(--b2);}
.lock-card.st-locked{border-left:3px solid rgba(255,71,87,.5);}
.lock-card.st-unlocked{border-left:3px solid rgba(71,255,176,.5);}
.lock-card.st-pending{border-left:3px solid rgba(255,170,0,.5);}
.lock-card.st-auto_saved{border-left:3px solid rgba(71,184,255,.4);}
.lock-card.st-rejected{border-left:3px solid rgba(255,71,87,.2);opacity:.6;}
.lc-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px;}
.lc-label{font-family:var(--display);font-size:14px;font-weight:700;word-break:break-word;}
.lc-badge{display:inline-flex;align-items:center;flex-shrink:0;font-size:9px;
  letter-spacing:1px;text-transform:uppercase;padding:4px 8px;border:1px solid;}
.lc-badge.locked{background:rgba(255,71,87,.07);border-color:rgba(255,71,87,.2);color:var(--red);}
.lc-badge.unlocked{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);}
.lc-badge.pending{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);}
.lc-badge.auto_saved{background:rgba(71,184,255,.07);border-color:rgba(71,184,255,.2);color:var(--blue);}
.lc-badge.rejected{background:rgba(255,71,87,.05);border-color:rgba(255,71,87,.1);color:var(--muted);}
.lc-meta{font-size:11px;color:var(--muted);line-height:1.7;margin-bottom:10px;}
.lc-meta span{color:var(--text);}
.lc-hint{font-size:11px;color:var(--muted);font-style:italic;margin-bottom:10px;
  padding:6px 10px;border-left:2px solid var(--b2);}
.lc-countdown{font-size:12px;color:var(--accent);margin-bottom:10px;letter-spacing:1px;}
.lc-actions{display:flex;gap:8px;flex-wrap:wrap;}
.lc-autosave-note{font-size:10px;color:var(--blue);letter-spacing:.4px;
  padding:6px 10px;border:1px solid rgba(71,184,255,.15);background:rgba(71,184,255,.05);margin-bottom:8px;line-height:1.5;}

.empty{text-align:center;padding:60px 20px;color:var(--muted);}
.empty-icon{font-size:44px;margin-bottom:14px;}
.empty h3{font-family:var(--display);font-size:15px;font-weight:700;color:var(--text);margin-bottom:8px;}
.empty p{font-size:12px;line-height:1.6;}

#reveal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);
  display:none;align-items:flex-end;justify-content:center;z-index:500;padding:0 0 max(0px,var(--sab)) 0;}
#reveal-overlay.show{display:flex;}
.reveal-sheet{background:var(--s1);border:1px solid var(--b2);border-bottom:none;
  padding:28px 22px max(28px,var(--sab));width:100%;max-width:480px;position:relative;}
@media(min-width:600px){#reveal-overlay{align-items:center;}
  .reveal-sheet{border:1px solid var(--b2);max-width:480px;padding:32px;}}
.modal-close{position:absolute;top:12px;right:14px;background:none;border:none;color:var(--muted);
  font-size:22px;cursor:pointer;padding:4px;min-width:32px;min-height:32px;
  display:flex;align-items:center;justify-content:center;}
.modal-close:hover{color:var(--text);}

.reveal-title{font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:3px;}
.reveal-sub{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.reveal-pwd{font-size:clamp(16px,4vw,22px);color:var(--accent);letter-spacing:3px;
  word-break:break-all;background:#000;padding:16px;border:1px solid rgba(232,255,71,.12);
  margin-bottom:16px;line-height:1.5;user-select:all;-webkit-user-select:all;display:none;}
.vault-input-wrap{margin-bottom:16px;}
.vault-input-wrap label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:6px;}
.vault-input-wrap input{width:100%;background:#000;border:1px solid rgba(232,255,71,.2);
  color:var(--accent);font-family:var(--mono);font-size:15px;padding:13px;outline:none;
  border-radius:0;-webkit-appearance:none;}

.toast{position:fixed;bottom:max(24px,var(--sab));left:50%;transform:translateX(-50%);
  background:#000;border:1px solid var(--b2);padding:10px 14px;font-size:12px;letter-spacing:.4px;z-index:900;max-width:92vw;}
.toast.ok{border-color:rgba(71,255,176,.25);color:var(--green);}
.toast.err{border-color:rgba(255,71,87,.3);color:var(--red);}
.toast.warn{border-color:rgba(255,170,0,.35);color:var(--orange);}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo">LOCK<span>SMITH</span></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <a class="btn btn-ghost btn-sm" href="create_code.php">Create Code</a>
      <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
      <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
      <a class="btn btn-ghost btn-sm" href="notifications.php">Notifications</a>
      <a class="btn btn-ghost btn-sm" href="backup.php">Backup</a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php">Vault</a>
      <a class="btn btn-ghost btn-sm" href="account.php">Account</a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="app-body">
    <div class="card">
      <div class="card-title"><div class="dot"></div>My Codes</div>
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
let currentRevealLockId = null;

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function toast(msg,type='ok'){const t=document.createElement('div');t.className=`toast ${type}`;t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3200);} 

function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}
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

async function loadLocks(){
  const wrap=document.getElementById('locks-wrap');
  wrap.innerHTML='<div style="text-align:center;padding:40px;color:var(--muted);font-size:11px;letter-spacing:2px">LOADING…</div>';
  try{
    const r=await get('api/locks.php');
    if(!r.success||!r.locks||!r.locks.length){
      wrap.innerHTML='<div class="empty"><div class="empty-icon">🔒</div><h3>No codes yet</h3><p>Create one from the Create Code page.</p></div>';
      return;
    }
    wrap.innerHTML='<div class="locks-grid" id="locks-grid"></div>';
    r.locks.forEach(l=>document.getElementById('locks-grid').appendChild(buildCard(l)));
  }catch{
    wrap.innerHTML='<div class="empty"><p>Failed to load.</p></div>';
  }
}

function buildCard(lock){
  const el=document.createElement('div');
  const st=lock.display_status;
  el.className=`lock-card st-${st}`;

  const badges={locked:'🔒 Locked',unlocked:'🔓 Unlocked',pending:'⏳ Pending',auto_saved:'💾 Auto-saved',rejected:'✗ Void'};
  const rd=new Date(lock.reveal_date).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});

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

  if(st==='locked'&&lock.time_remaining){
    const t=lock.time_remaining;
    const countdown=document.createElement('div');
    countdown.className='lc-countdown';
    countdown.textContent=`⏱ ${t.days}d ${t.hours}h ${t.minutes}m remaining`;
    el.appendChild(countdown);
  }

  const meta=document.createElement('div');
  meta.className='lc-meta';

  const copied = lock.copied_at ? '<span style="color:var(--green)">✓</span>' : '<span style="color:var(--red)">not copied</span>';
  meta.innerHTML=`Type: <span>${esc(lock.password_type)} · ${esc(lock.password_length)} chars</span><br>Reveal: <span>${esc(rd)}</span><br>Copied: ${copied}`;
  el.appendChild(meta);

  const actions=document.createElement('div');
  actions.className='lc-actions';

  if(st==='unlocked'){
    const b=document.createElement('button');
    b.className='btn btn-green btn-sm';
    b.type='button';
    b.textContent='Reveal';
    b.addEventListener('click', ()=>openReveal(lock.id, lock.label, lock.hint||''));
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
    b.textContent=`Sealed until ${rd}`;
    actions.appendChild(b);
  }

  const del=document.createElement('button');
  del.className='btn btn-red btn-sm';
  del.type='button';
  del.textContent='Delete';
  del.addEventListener('click', ()=>delLock(lock.id));
  actions.appendChild(del);

  el.appendChild(actions);
  return el;
}

function openReveal(lockId, label, hint){
  currentRevealLockId=lockId;
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

  toast('Enable TOTP or add a passkey in Account', 'warn');
  return false;
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

async function doReveal(){
  const vault=document.getElementById('rv-vault').value || vaultPhraseSession;
  const errEl=document.getElementById('rv-err');
  errEl.classList.remove('show');
  if(!vault){errEl.textContent='Enter your vault passphrase';errEl.classList.add('show');return;}
  document.getElementById('rv-btn-txt').innerHTML='<span class="spin"></span>';

  try{
    let r=await postCsrf('api/reveal.php',{lock_id:currentRevealLockId});
    if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
      const ok = await ensureReauth(r.methods||{});
      if(!ok){errEl.textContent=r.error||'Re-authentication required';errEl.classList.add('show');return;}
      r=await postCsrf('api/reveal.php',{lock_id:currentRevealLockId});
    }
    if(!r.success){errEl.textContent=r.error||'Cannot reveal';errEl.classList.add('show');return;}

    const key=await deriveKey(vault, r.kdf_salt, r.kdf_iterations);
    const plain=await aesDecrypt(r.cipher_blob, r.iv, r.auth_tag, key);

    revealedPwd=plain;
    document.getElementById('rv-pwd').textContent=plain;
    document.getElementById('rv-pwd').style.display='block';
    document.getElementById('rv-copy-btn').style.display='block';
    document.getElementById('rv-zk-note').style.display='block';
    document.getElementById('rv-btn').style.display='none';

    vaultPhraseSession=vault;
    vaultSlotSession=parseInt(r.vault_verifier_slot||1,10)||1;
    localStorage.setItem('vault_slot', String(vaultSlotSession));

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
  currentRevealLockId=null;
}

async function copyRevealed(){
  if(!revealedPwd || !currentRevealLockId) return;
  try{
    await navigator.clipboard.writeText(revealedPwd);
    await postCsrf('api/copied.php',{lock_id:currentRevealLockId});
    toast('Copied!','ok');
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
async function delLock(id){
  if(!confirm('Permanently delete this lock? Encrypted data will be removed.'))return;
  const r=await postCsrf('api/delete.php',{lock_id:id});
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
