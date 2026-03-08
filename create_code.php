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
<title>LOCKSMITH — Create Code</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>

.type-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
@media(min-width:380px){.type-grid{grid-template-columns:repeat(4,1fr);}}
.type-opt{padding:12px 6px;border:1px solid var(--b1);background:transparent;
  color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:1px;
  text-transform:uppercase;cursor:pointer;text-align:center;transition:all .15s;
  min-height:44px;display:flex;align-items:center;justify-content:center;}
.type-opt:hover{border-color:var(--b2);color:var(--text);}
.type-opt.sel{border-color:var(--accent);color:var(--accent);background:rgba(232,255,71,.06);}
.type-opt:disabled{opacity:.45;cursor:not-allowed;}
.type-opt:disabled:hover{border-color:var(--b1);color:var(--muted);}

#wallet-action-grid{grid-template-columns:repeat(2,1fr);}

.slider-row{display:flex;align-items:center;gap:14px;}
.slider-val{font-family:var(--display);font-size:26px;font-weight:900;color:var(--accent);min-width:40px;text-align:right;}
input[type=range]{-webkit-appearance:none;flex:1;height:4px;background:var(--b2);outline:none;cursor:pointer;border-radius:2px;}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;background:var(--accent);cursor:pointer;border-radius:0;}

.kdf-progress{display:none;margin-top:12px;}
.kdf-progress.show{display:block;}
.kdf-bar-wrap{height:3px;background:var(--b2);overflow:hidden;margin-bottom:6px;}
.kdf-bar{height:100%;background:var(--accent);transition:width .1s linear;width:0%;}
.kdf-label{font-size:10px;color:var(--muted);letter-spacing:1px;text-align:center;}

#confirm-overlay{position:fixed;inset:0;background:var(--overlay-bg);
  display:none;align-items:flex-end;justify-content:center;z-index:500;padding:0 0 max(0px,var(--sab)) 0;}
#confirm-overlay.show{display:flex;}
.confirm-sheet{background:var(--s1);border:1px solid var(--b2);border-bottom:none;
  padding:28px 22px max(28px,var(--sab));width:100%;max-width:480px;position:relative;}
@media(min-width:600px){#confirm-overlay{align-items:center;}
  .confirm-sheet{border:1px solid var(--b2);max-width:480px;padding:32px;}}
.confirm-title{font-family:var(--display);font-size:16px;font-weight:700;margin-bottom:6px;}
.confirm-sub{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;}
.confirm-btns{display:grid;grid-template-columns:1fr;gap:10px;}
@media(min-width:480px){.confirm-btns{grid-template-columns:1fr 1fr;}}


</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo">LOCK<span>SMITH</span></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle>Theme</button>
      <a class="btn btn-ghost btn-sm" href="my_codes.php">My Codes</a>
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
    <div class="card" id="vault-unlock-card" style="display:none">
      <div class="card-title"><div class="dot" style="background:var(--orange)"></div><span style="color:var(--orange)">Vault</span></div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;margin-bottom:14px;">
        Your vault passphrase is used to derive encryption keys in your browser. It is never sent to the server. Code creation is hidden until your vault is unlocked.
      </div>

      <div id="vp-setup-note" class="msg msg-warn"></div>

      <div class="field"><label>Vault Passphrase</label>
        <input type="password" id="vp-input" placeholder="Your vault passphrase…" autocomplete="current-password">
      </div>

      <div class="field" id="vp2-field" style="display:none"><label>Confirm Vault Passphrase</label>
        <input type="password" id="vp-input2" placeholder="Confirm passphrase…" autocomplete="current-password">
      </div>

      <div id="vp-err" class="msg msg-err"></div>
      <button class="btn btn-primary" id="vp-btn" onclick="unlockVault()"><span id="vp-txt">Unlock Vault</span></button>
    </div>

    <div class="card" id="create-mode-card" style="display:none">
      <div class="card-title"><div class="dot"></div>Create mode</div>
      <div class="type-grid" id="mode-grid">
        <button class="type-opt sel" data-mode="scratch" type="button">From scratch</button>
        <button class="type-opt" data-mode="wallet" type="button">Mobile money wallet</button>
      </div>
    </div>

    <div class="card" id="wallet-card" style="display:none">
      <div class="card-title"><div class="dot" style="background:var(--blue)"></div>Mobile Money Wallet</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;margin-bottom:14px;">
        Use a carrier template to change your wallet PIN via USSD, then store the new PIN encrypted and time-locked.
      </div>

      <div class="field"><label>Template</label>
        <select id="w-carrier"></select>
      </div>

      <div class="field"><label>Label <span style="color:var(--muted);font-size:10px;">(optional)</span></label>
        <input id="w-label" type="text" placeholder="e.g. Moov Money wallet" maxlength="120">
      </div>

      <div class="field"><label>Your current wallet PIN</label>
        <input id="w-oldpin" type="password" inputmode="numeric" autocomplete="off" placeholder="4-digit PIN">
      </div>

      <div class="field"><label>Wallet setup action</label>
        <div class="type-grid" id="wallet-action-grid">
          <button class="type-opt" data-action="open_dialer" type="button">Send to phone app</button>
          <button class="type-opt" data-action="copy_ussd" type="button">Copy USSD</button>
        </div>
      </div>

      <div class="field"><label>Reveal Date &amp; Time</label>
        <input type="datetime-local" id="w-date">
      </div>

      <div id="w-err" class="msg msg-err"></div>

      <button class="btn btn-primary" id="w-btn" onclick="doWalletSetup()" style="margin-top:10px;">
        <span id="w-txt">Generate &amp; Copy USSD</span>
      </button>

      <div class="hr" style="border-top:1px solid var(--b1);margin:16px 0;"></div>
      <div class="card-title" style="margin-bottom:10px;">Pending wallet setups</div>
      <div id="wallet-pending-msg" class="msg"></div>
      <div id="wallet-pending-wrap" style="display:flex;flex-direction:column;gap:10px;"></div>
    </div>

    <div class="card" id="gen-card" style="display:none">
      <div class="card-title"><div class="dot"></div>Create a Code</div>

      <div class="field"><label>Label</label>
        <input id="g-label" type="text" placeholder="e.g. Bank PIN" maxlength="120">
      </div>

      <div class="field"><label>Type</label>
        <div class="type-grid" id="type-grid">
          <button class="type-opt sel" data-type="alphanumeric" type="button">A-Z0-9</button>
          <button class="type-opt" data-type="alpha" type="button">A-Z</button>
          <button class="type-opt" data-type="numeric" type="button">0-9</button>
          <button class="type-opt" data-type="custom" type="button">Custom</button>
        </div>
      </div>

      <div class="field"><label>Length</label>
        <div class="slider-row">
          <input type="range" min="4" max="64" value="16" id="g-len" oninput="document.getElementById('len-val').textContent=this.value;">
          <div class="slider-val" id="len-val">16</div>
        </div>
      </div>

      <div class="field"><label>Reveal Date &amp; Time</label>
        <input type="datetime-local" id="g-date">
      </div>

      <div class="field"><label>Memory Hint <span style="color:var(--muted);font-size:10px;">(optional — never the code)</span></label>
        <input type="text" id="g-hint" placeholder="e.g. Set before my summer trip" maxlength="500">
      </div>

      <div id="g-err" class="msg msg-err"></div>

      <div class="kdf-progress" id="kdf-progress">
        <div class="kdf-bar-wrap"><div class="kdf-bar" id="kdf-bar"></div></div>
        <div class="kdf-label" id="kdf-label">Deriving encryption key in your browser…</div>
      </div>

      <button class="btn btn-primary" id="g-btn" onclick="doGenerate()" style="margin-top:10px;">
        <span id="g-txt">Generate &amp; Lock</span>
      </button>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <a class="btn btn-ghost btn-sm" href="my_codes.php">View my codes</a>
      </div>
    </div>
  </div>
</div>

<!-- confirm overlay -->
<div id="confirm-overlay" onclick="closeConfirm(event)">
  <div class="confirm-sheet">
    <div class="confirm-title" id="confirm-title">Did you save the code?</div>
    <div class="confirm-sub" id="cs-sub">Code was copied to your clipboard.</div>
    <div class="msg msg-warn" id="autosave-bar" style="display:none">Auto-saved. Code stored but not time-locked until you confirm.</div>

    <div class="confirm-btns" id="confirm-btns">
      <button class="btn btn-green" id="confirm-yes-btn" onclick="doConfirm('confirm')">✓ Yes, I saved it</button>
      <button class="btn btn-red" id="confirm-no-btn" onclick="doConfirm('reject')">✗ No, discard</button>
    </div>

    <div id="confirm-wallet-actions" style="display:none;margin-top:10px;">
      <a class="btn btn-ghost btn-sm" id="confirm-open-dialer-again" href="#" onclick="openDialerAgain(event)">Open dialer again</a>
    </div>

    <div id="confirm-done" style="display:none;margin-top:12px;font-size:12px;color:var(--muted);line-height:1.6;"><div id="confirm-done-msg"></div></div>

    <div id="confirm-safe-close" style="display:none;margin-top:10px;">
      <button class="btn btn-ghost btn-sm" id="confirm-safe-close-btn" onclick="safeCloseConfirm()">Close &amp; clear clipboard</button>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
const VAULT_CHECK_PLAIN = 'LOCKSMITH_VAULT_CHECK_v1';

let vaultPhraseSession = null;
let vaultSlotSession   = 1;
let vaultCheckAvailable = false;
let vaultCheckInitialized = false;
let vaultCheck = null;

let pendingLock = null;
let pendingWallet = null;
let confirmMode = 'lock';

let createMode = (localStorage.getItem('create_mode') || 'scratch');
let carriers = [];
let walletAction = (localStorage.getItem('wallet_action') || 'copy_ussd');

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
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

async function postCsrfWithReauth(url, body){
  let r = await postCsrf(url, body);
  if(!r.success && (r.error_code==='reauth_required' || r.error_code==='security_setup_required')){
    const ok = await ensureReauth(r.methods||{});
    if(!ok) return r;
    r = await postCsrf(url, body);
  }
  return r;
}

const ClipboardManager = (() => {
  // Different wipe timers by flow.
  const WIPE_MS = {
    lock:   120000,
    wallet: 300000,
  };

  let wipeTimer = null;
  let sensitive = false;
  let sensitiveFlow = null;
  let hiddenWhileSensitive = false;

  function canWrite(){
    return !!(navigator.clipboard && navigator.clipboard.writeText);
  }

  function clearTimer(){
    if(wipeTimer){
      clearTimeout(wipeTimer);
      wipeTimer = null;
    }
  }

  function schedule(flow){
    clearTimer();
    const ms = WIPE_MS[flow] || WIPE_MS.lock;
    wipeTimer = setTimeout(() => {
      // Timer-based wipe is best-effort; do not throw.
      void wipe('timer');
    }, ms);
  }

  async function writeSensitive(text, flow){
    try{
      if(!canWrite()) return false;
      await navigator.clipboard.writeText(String(text||''));
      sensitive = true;
      sensitiveFlow = (flow === 'wallet') ? 'wallet' : 'lock';
      hiddenWhileSensitive = false;
      schedule(sensitiveFlow);
      return true;
    }catch{
      return false;
    }
  }

  async function wipe(reason){
    clearTimer();
    sensitive = false;
    sensitiveFlow = null;
    hiddenWhileSensitive = false;
    try{
      if(!canWrite()) return;
      await navigator.clipboard.writeText('');
    }catch{}
  }

  function wipeBestEffort(reason){
    if(!sensitive) return;

    // Wallet flow may trigger pagehide/beforeunload when opening a tel: URI.
    // Do not wipe in that case or we can break the paste/dialer step.
    if(sensitiveFlow === 'wallet' && (reason === 'pagehide' || reason === 'beforeunload')){
      return;
    }

    clearTimer();
    sensitive = false;
    sensitiveFlow = null;
    hiddenWhileSensitive = false;
    try{
      if(!canWrite()) return;
      navigator.clipboard.writeText('').catch(()=>{});
    }catch{}
  }

  function onVisibilityChange(){
    if(!sensitive) return;

    if(document.hidden){
      hiddenWhileSensitive = true;
      return;
    }

    // When returning to the page after being hidden, assume the user has pasted
    // and wipe quickly to reduce clipboard dwell time. For wallet flow, avoid
    // wiping on app switching; keep the timer/manual wipe.
    if(hiddenWhileSensitive && sensitiveFlow !== 'wallet'){
      void wipe('visibilitychange');
    }
  }

  document.addEventListener('visibilitychange', onVisibilityChange);
  window.addEventListener('pagehide', () => wipeBestEffort('pagehide'));
  window.addEventListener('beforeunload', () => wipeBestEffort('beforeunload'));

  return {writeSensitive, wipe, wipeBestEffort};
})();

async function wipeClipboard(){
  await ClipboardManager.wipe('manual');
}

function buildTelUriFromUssd(ussd){
  const clean = String(ussd||'').trim().replace(/\s+/g,'');
  return 'tel:' + clean.replace(/#/g, '%23');
}

function attemptOpenDialer(telUri){
  if(!telUri) return;
  const a = document.createElement('a');
  a.href = telUri;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function openDialerAgain(e){
  if(e) e.preventDefault();
  if(pendingWallet && pendingWallet.tel_uri){
    attemptOpenDialer(pendingWallet.tel_uri);
  }
  return false;
}

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

function genPassword(type, length) {
  const chars = {
    numeric:      '0123456789',
    alpha:        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    custom:       'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?',
  }[type] || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  const c = requireWebCrypto();
  const arr = new Uint8Array(length * 4);
  c.getRandomValues(arr);
  let result = '', i = 0;
  while (result.length < length) {
    const byte = arr[i++ % arr.length];
    const idx  = byte % chars.length;
    if (byte < Math.floor(256 / chars.length) * chars.length) {
      result += chars[idx];
    }
  }
  return result;
}

function showKdfProgress(show){
  const el=document.getElementById('kdf-progress');
  if(show){ el.classList.add('show'); document.getElementById('kdf-bar').style.width='0%'; }
  else el.classList.remove('show');
}
function animateKdfBar(iterations){
  const totalMs = Math.min(2000, iterations / 200);
  const steps   = 60;
  const stepMs  = totalMs / steps;
  let i = 0;
  const t = setInterval(() => {
    i++;
    const pct = Math.min(90, (i/steps)*100);
    document.getElementById('kdf-bar').style.width = pct + '%';
    if (i >= steps) clearInterval(t);
  }, stepMs);
}

async function loadVaultSetup(){
  try{
    const r = await postCsrf('api/vault.php', {action:'setup_status'});
    if(!r.success) return;

    vaultCheckAvailable = !!r.available;
    vaultCheckInitialized = !!r.initialized;
    vaultCheck = r.vault_check || null;

    const slot = parseInt(r.active_slot || '1', 10);
    if([1,2].includes(slot)){
      vaultSlotSession = slot;
      localStorage.setItem('vault_slot', String(vaultSlotSession));
    }

    const note = document.getElementById('vp-setup-note');
    const vp2Field = document.getElementById('vp2-field');
    const btnTxt = document.getElementById('vp-txt');

    if(note){
      note.classList.remove('show');
      note.textContent='';
    }

    if(vaultCheckAvailable && !vaultCheckInitialized){
      if(note){
        note.textContent = 'No vault passphrase is set yet. Choose one now (min 10 chars). If you lose it, your codes cannot be recovered.';
        note.classList.add('show');
        note.style.display='block';
      }
      if(vp2Field) vp2Field.style.display = 'block';
      if(btnTxt) btnTxt.textContent = 'Set Vault';
      return;
    }

    if(!vaultCheckAvailable){
      if(note){
        note.textContent = 'Vault validation is unavailable (missing migrations). You can still unlock and use the app, but it cannot validate your passphrase.';
        note.classList.add('show');
        note.style.display='block';
      }
    }

    if(vp2Field) vp2Field.style.display = 'none';
    if(btnTxt) btnTxt.textContent = 'Unlock Vault';
  }catch{}
}

async function unlockVault() {
  const vp = document.getElementById('vp-input').value;
  const vp2 = (document.getElementById('vp-input2')||{}).value || '';
  const errEl = document.getElementById('vp-err');
  errEl.classList.remove('show');

  if (!vp || vp.length < 10) { errEl.textContent='Passphrase must be at least 10 characters'; errEl.classList.add('show'); return; }

  const setMode = (vaultCheckAvailable && !vaultCheckInitialized);
  if (setMode) {
    if (vp !== vp2) { errEl.textContent='Passphrases do not match'; errEl.classList.add('show'); return; }
  }

  const btnTxt = document.getElementById('vp-txt');
  btnTxt.innerHTML = '<span class="spin light"></span> ' + (setMode ? 'Setting…' : 'Unlocking…');

  try {
    if (setMode) {
      const c = requireWebCrypto();
      const saltBytes = new Uint8Array(32);
      c.getRandomValues(saltBytes);
      const kdf_salt = bytesToB64(saltBytes);

      const key = await deriveKey(vp, kdf_salt, PBKDF2_ITERS);
      const enc = await aesEncrypt(VAULT_CHECK_PLAIN, key);

      const j = await postCsrf('api/vault.php', {
        action:'setup_save',
        cipher_blob: enc.cipher_blob,
        iv: enc.iv,
        auth_tag: enc.auth_tag,
        kdf_salt,
        kdf_iterations: PBKDF2_ITERS,
      });

      if(!j.success){
        throw new Error(j.error || 'Failed to set vault passphrase');
      }

      vaultCheckAvailable = true;
      vaultCheckInitialized = true;
      vaultCheck = {
        cipher_blob: enc.cipher_blob,
        iv: enc.iv,
        auth_tag: enc.auth_tag,
        kdf_salt,
        kdf_iterations: PBKDF2_ITERS,
      };
      vaultSlotSession = 1;
      localStorage.setItem('vault_slot', '1');
    }

    if (vaultCheckAvailable && vaultCheckInitialized && vaultCheck) {
      const key = await deriveKey(vp, vaultCheck.kdf_salt, vaultCheck.kdf_iterations);
      const plain = await aesDecrypt(vaultCheck.cipher_blob, vaultCheck.iv, vaultCheck.auth_tag, key);
      if (plain !== VAULT_CHECK_PLAIN) throw new Error('Incorrect vault passphrase');
    }

    vaultPhraseSession = vp;

    toast(setMode ? 'Vault passphrase set and unlocked' : 'Vault unlocked — passphrase held in memory only', 'ok');
    await loadVaultSetup();
    checkVaultUnlock();

    setTimeout(() => {
      const first = (createMode === 'wallet') ? document.getElementById('w-oldpin') : document.getElementById('g-label');
      if (first) first.focus();
    }, 150);

  } catch (e) {
    if (e && e.name === 'OperationError') errEl.textContent = 'Incorrect vault passphrase or tampered data';
    else errEl.textContent = e.message || 'Unlock failed';
    errEl.classList.add('show');
  } finally {
    btnTxt.textContent = setMode ? 'Set Vault' : 'Unlock Vault';
  }
}

async function doGenerate(){
  const errEl=document.getElementById('g-err');
  errEl.classList.remove('show');

  if(!vaultPhraseSession){toast('Enter your vault passphrase first','err');return;}

  const label=document.getElementById('g-label').value.trim();
  const typeEl=document.querySelector('#type-grid .type-opt.sel');
  const type=(typeEl ? typeEl.dataset.type : 'alphanumeric');
  const length=parseInt(document.getElementById('g-len').value,10)||16;
  const revealDate=document.getElementById('g-date').value;
  const hint=document.getElementById('g-hint').value.trim();

  if(!label){errEl.textContent='Label is required';errEl.classList.add('show');return;}
  if(!revealDate){errEl.textContent='Reveal date required';errEl.classList.add('show');return;}

  const btn=document.getElementById('g-btn');
  const txt=document.getElementById('g-txt');
  btn.disabled=true;
  txt.innerHTML='<span class="spin light"></span> Sealing…';

  try{
    const plainPwd = genPassword(type, length);

    const saltResp = await get('api/salt.php');
    if(!saltResp.success) throw new Error(saltResp.error||'Failed to get KDF salt');

    const kdf_salt = saltResp.kdf_salt;
    const kdf_iterations = saltResp.kdf_iterations;

    showKdfProgress(true);
    animateKdfBar(kdf_iterations);

    const key = await deriveKey(vaultPhraseSession, kdf_salt, kdf_iterations);
    document.getElementById('kdf-bar').style.width='100%';

    const enc = await aesEncrypt(plainPwd, key);

    const r = await postCsrf('api/generate.php',{
      label,
      type,
      length,
      reveal_date: new Date(revealDate).toISOString(),
      hint,
      vault_verifier_slot: vaultSlotSession,
      cipher_blob: enc.cipher_blob,
      iv: enc.iv,
      auth_tag: enc.auth_tag,
      kdf_salt,
    });

    if(!r.success){throw new Error(r.error||'Generation failed');}

    const copied = await ClipboardManager.writeSensitive(plainPwd, 'lock');
    if(copied){
      await postCsrf('api/copied.php',{lock_id:r.lock_id});
    }

    pendingLock = {
      lock_id: r.lock_id, label: r.label, reveal_date: r.reveal_date,
      kdf_salt, kdf_iterations,
      cipher_blob: enc.cipher_blob, iv: enc.iv, auth_tag: enc.auth_tag,
    };

    document.getElementById('g-label').value='';
    document.getElementById('g-hint').value='';

    openConfirmSheet(r.lock_id, r.label);

  }catch(e){
    errEl.textContent=e.message||'Error during generation';
    errEl.classList.add('show');
  }finally{
    txt.textContent='Generate & Lock';
    btn.disabled=false;
    showKdfProgress(false);
  }
}

function openConfirmSheet(lockId, label){
  confirmMode = 'lock';
  document.getElementById('confirm-title').textContent = 'Did you save the code?';
  document.getElementById('cs-sub').textContent=`"${label}" — blind-copied to clipboard.`;
  document.getElementById('confirm-yes-btn').textContent='✓ Yes, I saved it';
  document.getElementById('confirm-no-btn').textContent='✗ No, discard';
  document.getElementById('confirm-btns').style.display='grid';
  document.getElementById('confirm-done').style.display='none';

  const sc = document.getElementById('confirm-safe-close');
  if(sc) sc.style.display='none';

  const wa = document.getElementById('confirm-wallet-actions');
  if(wa) wa.style.display='none';

  const bar = document.getElementById('autosave-bar');
  bar.style.display='none';

  document.getElementById('confirm-overlay').classList.add('show');

  setTimeout(async ()=>{
    if(!pendingLock || confirmMode !== 'lock' || pendingLock.lock_id !== lockId) return;
    await postCsrf('api/confirm.php',{lock_id:lockId,action:'auto_save'});
    bar.style.display='block';
  }, 120000);
}

function openConfirmSheetWallet(opts){
  const carrierName = (opts && opts.carrierName) ? opts.carrierName : 'Wallet';
  const action = normalizeWalletAction(opts && opts.action);
  const telUri = (opts && opts.telUri) ? String(opts.telUri) : '';

  confirmMode = 'wallet';
  document.getElementById('confirm-title').textContent = 'Did you complete the USSD PIN change?';

  const wa = document.getElementById('confirm-wallet-actions');
  const dialAgain = document.getElementById('confirm-open-dialer-again');

  if(action === 'open_dialer'){
    document.getElementById('cs-sub').textContent = `${carrierName} — new PIN blind-copied to clipboard. Your dialer should open with the USSD command. Finish the change, then confirm here.`;
    if(dialAgain) dialAgain.href = telUri || '#';
    if(wa) wa.style.display = 'block';
  } else {
    document.getElementById('cs-sub').textContent = `${carrierName} — USSD command copied to your clipboard. Paste it into your phone dialer, finish the change, then confirm here.`;
    if(dialAgain) dialAgain.href = '#';
    if(wa) wa.style.display = 'none';
  }

  document.getElementById('confirm-yes-btn').textContent='✓ Yes, I entered it';
  document.getElementById('confirm-no-btn').textContent='✗ No, discard';
  document.getElementById('confirm-btns').style.display='grid';
  document.getElementById('confirm-done').style.display='none';

  const sc = document.getElementById('confirm-safe-close');
  if(sc) sc.style.display='none';

  document.getElementById('autosave-bar').style.display='none';
  document.getElementById('confirm-overlay').classList.add('show');

  // Basic accessibility: move focus into the dialog.
  setTimeout(() => {
    const y = document.getElementById('confirm-yes-btn');
    if(y) y.focus();
  }, 50);
}

function closeConfirmSheetUi(){
  document.getElementById('confirm-overlay').classList.remove('show');

  const wa = document.getElementById('confirm-wallet-actions');
  if(wa) wa.style.display='none';

  const sc = document.getElementById('confirm-safe-close');
  if(sc) sc.style.display='none';

  const btns = document.getElementById('confirm-btns');
  if(btns) btns.style.display='grid';

  const done = document.getElementById('confirm-done');
  if(done) done.style.display='none';

  const msg = document.getElementById('confirm-done-msg');
  if(msg) msg.textContent = '';

  const y = document.getElementById('confirm-yes-btn');
  const n = document.getElementById('confirm-no-btn');
  if(y) y.disabled = false;
  if(n) n.disabled = false;
}

async function safeCloseConfirm(){
  await wipeClipboard();
  pendingWallet = null;
  confirmMode = 'lock';
  closeConfirmSheetUi();
}

function closeConfirm(e){
  if(e&&e.target!==document.getElementById('confirm-overlay'))return;

  // In wallet mode, avoid letting users dismiss the sheet while the clipboard
  // may still contain sensitive material.
  if(confirmMode === 'wallet'){
    toast('Please confirm or discard to finish wallet setup (this will clear your clipboard).', 'err');
    return;
  }

  closeConfirmSheetUi();
}

async function doConfirm(action){
  const btns = document.getElementById('confirm-btns');
  const done = document.getElementById('confirm-done');
  const msg = document.getElementById('confirm-done-msg');
  const safeClose = document.getElementById('confirm-safe-close');

  const y = document.getElementById('confirm-yes-btn');
  const n = document.getElementById('confirm-no-btn');
  if(y) y.disabled = true;
  if(n) n.disabled = true;

  if(btns) btns.style.display = 'grid';
  if(done) done.style.display = 'block';
  if(safeClose) safeClose.style.display = 'none';
  if(msg) msg.textContent = 'Working…';

  try{
    if(confirmMode === 'wallet'){
      if(!pendingWallet) throw new Error('No pending wallet setup');
      const walletLockId = pendingWallet.wallet_lock_id;

      if(action === 'confirm'){
        const r = await postCsrfWithReauth('api/wallet_confirm.php', {wallet_lock_id: walletLockId});
        if(!r.success) throw new Error(r.error || 'Failed to confirm');
        if(msg) msg.textContent = '✓ Wallet PIN locked and time-gated.';
      } else {
        const r = await postCsrfWithReauth('api/wallet_fail.php', {wallet_lock_id: walletLockId});
        if(!r.success) throw new Error(r.error || 'Failed to discard');
        if(msg) msg.textContent = '✗ Discarded.';
      }

      await wipeClipboard();
      pendingWallet = null;

      const wa = document.getElementById('confirm-wallet-actions');
      if(wa) wa.style.display='none';

      await loadWalletPending(true);

      // Allow dismissal and auto-close.
      confirmMode = 'lock';
      if(btns) btns.style.display = 'none';
      if(y) y.disabled = false;
      if(n) n.disabled = false;

      setTimeout(() => {
        closeConfirmSheetUi();
      }, 900);
      return;
    }

    if(!pendingLock) throw new Error('No pending lock');
    const r = await postCsrf('api/confirm.php', {lock_id: pendingLock.lock_id, action});
    if(!r.success) throw new Error(r.error||'Failed');

    if(action==='confirm') msg.textContent='✓ Lock activated.';
    else msg.textContent='✗ Discarded.';

    await wipeClipboard();
    pendingLock=null;

    if(btns) btns.style.display = 'none';
    if(y) y.disabled = false;
    if(n) n.disabled = false;

  }catch(e){
    if(msg) msg.textContent = e.message || 'Failed';
    if(y) y.disabled = false;
    if(n) n.disabled = false;
    if(btns) btns.style.display = 'grid';

    if(confirmMode === 'wallet' && safeClose){
      safeClose.style.display = 'block';
    }
  }
}

function setCreateMode(mode){
  createMode = (mode === 'wallet') ? 'wallet' : 'scratch';
  localStorage.setItem('create_mode', createMode);

  document.querySelectorAll('#mode-grid .type-opt').forEach(b => {
    b.classList.toggle('sel', b.dataset.mode === createMode);
  });

  const genCard = document.getElementById('gen-card');
  const walletCard = document.getElementById('wallet-card');
  if (genCard) genCard.style.display = (createMode === 'scratch') ? 'block' : 'none';
  if (walletCard) walletCard.style.display = (createMode === 'wallet') ? 'block' : 'none';
}

function checkVaultUnlock() {
  const vaultCard = document.getElementById('vault-unlock-card');
  const modeCard = document.getElementById('create-mode-card');
  const genBtn = document.getElementById('g-btn');
  const wBtn = document.getElementById('w-btn');
  const genCard = document.getElementById('gen-card');
  const walletCard = document.getElementById('wallet-card');

  if (!vaultPhraseSession) {
    if (vaultCard) vaultCard.style.display = 'block';
    if (modeCard) modeCard.style.display = 'none';
    if (genCard) genCard.style.display = 'none';
    if (walletCard) walletCard.style.display = 'none';
    if (genBtn) genBtn.disabled = true;
    if (wBtn) wBtn.disabled = true;
    return;
  }

  if (vaultCard) vaultCard.style.display = 'none';
  if (modeCard) modeCard.style.display = 'block';
  if (genBtn) genBtn.disabled = false;
  if (wBtn) wBtn.disabled = false;

  setCreateMode(createMode);
}

function normalizeWalletAction(action){
  return (action === 'open_dialer' || action === 'copy_ussd') ? action : 'copy_ussd';
}

function getCarrierWalletPolicy(carrier){
  // Server-provided policy (if migration 019 is applied) or safe defaults.
  let allowOpenDialer = (carrier && (carrier.wallet_allow_open_dialer ?? carrier.walletAllowOpenDialer)) ?? true;
  let allowCopyUssd = (carrier && (carrier.wallet_allow_copy_ussd ?? carrier.walletAllowCopyUssd)) ?? true;
  const def = normalizeWalletAction((carrier && (carrier.wallet_default_action ?? carrier.walletDefaultAction)) ?? walletAction);

  const tpl = String((carrier && (carrier.ussd_change_pin_template ?? carrier.ussdChangePinTemplate)) ?? '');

  // Safety/UI consistency:
  // - if the template embeds {new_pin}, "open dialer" would leak the new PIN into the dialer prefill
  // - if the template doesn't include both placeholders, "copy USSD" can't work
  if (tpl.includes('{new_pin}')) allowOpenDialer = false;
  if (!tpl.includes('{old_pin}') || !tpl.includes('{new_pin}')) allowCopyUssd = false;

  return {
    allowOpenDialer: !!allowOpenDialer,
    allowCopyUssd: !!allowCopyUssd,
    defaultAction: def,
  };
}

function syncWalletPrimaryButtonText(){
  const txt = document.getElementById('w-txt');
  if(!txt) return;
  txt.textContent = (walletAction === 'open_dialer') ? 'Generate & Send to phone app' : 'Generate & Copy USSD';
}

function setWalletAction(action){
  walletAction = normalizeWalletAction(action);
  localStorage.setItem('wallet_action', walletAction);

  const grid = document.getElementById('wallet-action-grid');
  if(grid){
    grid.querySelectorAll('.type-opt').forEach(b => {
      b.classList.toggle('sel', b.dataset.action === walletAction);
    });
  }

  syncWalletPrimaryButtonText();
}

function applyWalletActionPolicy(carrier, preferCarrierDefault=false){
  const grid = document.getElementById('wallet-action-grid');
  const btn = document.getElementById('w-btn');
  if(!grid) return;

  const policy = getCarrierWalletPolicy(carrier);
  const openBtn = grid.querySelector('[data-action="open_dialer"]');
  const copyBtn = grid.querySelector('[data-action="copy_ussd"]');

  if(openBtn){
    openBtn.disabled = !policy.allowOpenDialer;
    openBtn.style.display = policy.allowOpenDialer ? '' : 'none';
  }
  if(copyBtn){
    copyBtn.disabled = !policy.allowCopyUssd;
    copyBtn.style.display = policy.allowCopyUssd ? '' : 'none';
  }

  const allowed = [];
  if(policy.allowOpenDialer) allowed.push('open_dialer');
  if(policy.allowCopyUssd) allowed.push('copy_ussd');

  if(!allowed.length){
    if(btn) btn.disabled = true;
    setWalletAction('copy_ussd');
    return;
  }

  let next = normalizeWalletAction(walletAction);
  if(preferCarrierDefault && allowed.includes(policy.defaultAction)){
    next = policy.defaultAction;
  }
  if(!allowed.includes(next)){
    next = allowed.includes(policy.defaultAction) ? policy.defaultAction : allowed[0];
  }

  if(btn && vaultPhraseSession) btn.disabled = false;
  setWalletAction(next);
}

async function loadCarriersForWallet(){
  const sel = document.getElementById('w-carrier');
  const errEl = document.getElementById('w-err');
  if(errEl) errEl.classList.remove('show');

  if(!sel) return;
  sel.innerHTML = '<option value="">Loading…</option>';

  try{
    const r = await get('api/carriers.php');
    if(!r.success){
      sel.innerHTML = '<option value="">No templates available</option>';
      if(errEl){ errEl.textContent = r.error || 'Failed to load templates'; errEl.classList.add('show'); }
      carriers = [];
      return;
    }

    carriers = r.carriers || [];
    if(!carriers.length){
      sel.innerHTML = '<option value="">No templates available</option>';
      return;
    }

    sel.innerHTML = '<option value="">Select a template…</option>';
    carriers.forEach(c => {
      const opt = document.createElement('option');
      opt.value = String(c.id);
      opt.textContent = c.name + (c.country ? ` (${c.country})` : '');
      sel.appendChild(opt);
    });

  }catch(e){
    sel.innerHTML = '<option value="">No templates available</option>';
    if(errEl){ errEl.textContent = e.message || 'Failed to load templates'; errEl.classList.add('show'); }
    carriers = [];
  }
}

function renderWalletPending(list){
  const wrap = document.getElementById('wallet-pending-wrap');
  const msg = document.getElementById('wallet-pending-msg');
  if(msg){ msg.className='msg'; msg.textContent=''; }
  if(!wrap) return;

  wrap.innerHTML = '';
  if(!list.length){
    wrap.innerHTML = '<div style="font-size:12px;color:var(--muted);">No pending setups.</div>';
    return;
  }

  list.forEach(w => {
    const el = document.createElement('div');
    el.style.border = '1px solid var(--b1)';
    el.style.background = 'var(--s1)';
    el.style.padding = '12px 14px';
    el.style.display = 'flex';
    el.style.flexDirection = 'column';
    el.style.gap = '10px';

    const title = document.createElement('div');
    title.style.fontFamily = 'var(--display)';
    title.style.fontSize = '13px';
    title.style.fontWeight = '700';
    title.textContent = (w.label || w.carrier_name || 'Wallet') + ' · ' + (w.display_status || 'setup_pending');

    const meta = document.createElement('div');
    meta.style.fontSize = '11px';
    meta.style.color = 'var(--muted)';
    meta.textContent = `Unlock at: ${w.unlock_at} · Carrier: ${w.carrier_name}`;

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '8px';
    actions.style.flexWrap = 'wrap';

    const btnOk = document.createElement('button');
    btnOk.className = 'btn btn-green btn-sm';
    btnOk.type = 'button';
    btnOk.textContent = 'Confirm setup';
    btnOk.onclick = async () => {
      try{
        const r = await postCsrfWithReauth('api/wallet_confirm.php', {wallet_lock_id: w.id});
        if(!r.success) throw new Error(r.error||'Failed');
        await wipeClipboard();
        toast('Setup confirmed', 'ok');
        await loadWalletPending(true);
      }catch(e){
        toast(e.message||'Failed', 'err');
      }
    };

    const btnFail = document.createElement('button');
    btnFail.className = 'btn btn-red btn-sm';
    btnFail.type = 'button';
    btnFail.textContent = 'Mark failed';
    btnFail.onclick = async () => {
      const ok = confirm('Mark this setup as failed?');
      if(!ok) return;
      try{
        const r = await postCsrfWithReauth('api/wallet_fail.php', {wallet_lock_id: w.id});
        if(!r.success) throw new Error(r.error||'Failed');
        await wipeClipboard();
        toast('Marked failed', 'ok');
        await loadWalletPending(true);
      }catch(e){
        toast(e.message||'Failed', 'err');
      }
    };

    actions.appendChild(btnOk);
    actions.appendChild(btnFail);

    el.appendChild(title);
    el.appendChild(meta);
    el.appendChild(actions);
    wrap.appendChild(el);
  });
}

async function loadWalletPending(force=false){
  const msg = document.getElementById('wallet-pending-msg');
  if(msg){ msg.className='msg'; msg.textContent=''; }

  try{
    const r = await get('api/wallet_locks.php');
    if(!r.success) throw new Error(r.error||'Failed to load wallet locks');

    const rows = r.wallet_locks || [];
    const pending = rows.filter(x => x.display_status === 'setup_pending' || x.setup_status === 'pending');
    renderWalletPending(pending);

  }catch(e){
    const wrap = document.getElementById('wallet-pending-wrap');
    if(wrap) wrap.innerHTML = '<div style="font-size:12px;color:var(--muted);">Failed to load.</div>';
    if(msg){ msg.className='msg msg-err show'; msg.textContent = e.message||'Failed'; }
  }
}

async function doWalletSetup(){
  const errEl=document.getElementById('w-err');
  errEl.classList.remove('show');

  if(!vaultPhraseSession){toast('Enter your vault passphrase first','err');return;}

  const carrierId = parseInt((document.getElementById('w-carrier')||{}).value || '0', 10);
  const carrier = carriers.find(c => parseInt(c.id,10) === carrierId);

  const label = (document.getElementById('w-label')||{}).value?.trim() || '';
  const oldPin = (document.getElementById('w-oldpin')||{}).value?.trim() || '';
  const revealDate = (document.getElementById('w-date')||{}).value || '';

  if(!carrier){ errEl.textContent='Select a template'; errEl.classList.add('show'); return; }
  if(!revealDate){ errEl.textContent='Reveal date required'; errEl.classList.add('show'); return; }

  const requiredLen = parseInt((carrier.pin_length ?? carrier.pinLength ?? '4'), 10) || 4;
  if(!/^[0-9]+$/.test(oldPin) || oldPin.length !== requiredLen){
    errEl.textContent = `Current PIN must be ${requiredLen} digits`;
    errEl.classList.add('show');
    return;
  }

  const policy = getCarrierWalletPolicy(carrier);
  const allowed = [];
  if(policy.allowOpenDialer) allowed.push('open_dialer');
  if(policy.allowCopyUssd) allowed.push('copy_ussd');

  if(!allowed.length){
    errEl.textContent = 'Wallet setup actions are disabled for this template.';
    errEl.classList.add('show');
    return;
  }

  let action = normalizeWalletAction(walletAction);
  if(!allowed.includes(action)){
    action = allowed.includes(policy.defaultAction) ? policy.defaultAction : allowed[0];
  }

  const btn=document.getElementById('w-btn');
  const txt=document.getElementById('w-txt');
  btn.disabled=true;
  txt.innerHTML='<span class="spin light"></span> Sealing…';

  try{
    const tpl = String(carrier.ussd_change_pin_template || carrier.ussdChangePinTemplate || '');
    if(!tpl.trim()) throw new Error('This template is not configured yet. Ask an admin to set the USSD code.');

    // Template validation depends on flow:
    // - copy_ussd: must embed both old and new PIN
    // - open_dialer: should NOT embed the new PIN (it will be copied separately)
    if(action === 'copy_ussd'){
      if(!tpl.includes('{old_pin}') || !tpl.includes('{new_pin}')){
        throw new Error('This template is misconfigured for “Copy USSD”: it must include {old_pin} and {new_pin}.');
      }
    } else {
      if(tpl.includes('{new_pin}')){
        throw new Error('This template is misconfigured for “Send to phone app”: it must NOT include {new_pin}. Use “Copy USSD” instead, or ask an admin to provide an interactive USSD template that prompts for the new PIN.');
      }
    }

    const newPin = genPassword((carrier.pin_type || carrier.pinType || 'numeric'), requiredLen);

    const saltResp = await get('api/salt.php');
    if(!saltResp.success) throw new Error(saltResp.error||'Failed to get KDF salt');

    const kdf_salt = saltResp.kdf_salt;
    const kdf_iterations = saltResp.kdf_iterations;

    const key = await deriveKey(vaultPhraseSession, kdf_salt, kdf_iterations);
    const enc = await aesEncrypt(newPin, key);

    const createRes = await postCsrfWithReauth('api/wallet_create.php', {
      carrier_id: carrierId,
      label,
      unlock_at: new Date(revealDate).toISOString(),
      cipher_blob: enc.cipher_blob,
      iv: enc.iv,
      auth_tag: enc.auth_tag,
      kdf_salt,
      kdf_iterations,
    });

    if(!createRes.success) throw new Error(createRes.error || 'Failed to create wallet lock');

    const walletLockId = createRes.wallet_lock_id;
    if(!walletLockId) throw new Error('Invalid response');

    // Build USSD command locally (never send PINs to server)
    const ussdDial = tpl.replace(/\{old_pin\}/g, oldPin);
    const ussdFull = tpl
      .replace(/\{old_pin\}/g, oldPin)
      .replace(/\{new_pin\}/g, newPin);

    const telUri = buildTelUriFromUssd((action === 'open_dialer') ? ussdDial : ussdFull);

    const clipText = (action === 'open_dialer') ? newPin : ussdFull;
    const copied = await ClipboardManager.writeSensitive(clipText, 'wallet');
    if(!copied){
      // We cannot display the PIN, so we must abort if clipboard isn't available.
      await postCsrfWithReauth('api/wallet_fail.php', {wallet_lock_id: walletLockId});
      throw new Error('Clipboard write blocked. Use HTTPS and allow clipboard access.');
    }

    if(action === 'open_dialer'){
      attemptOpenDialer(telUri);
    }

    pendingWallet = {
      wallet_lock_id: walletLockId,
      carrier_name: carrier.name || 'Wallet',
      unlock_at: createRes.unlock_at || '',
      action,
      tel_uri: telUri,
    };
    openConfirmSheetWallet({carrierName: carrier.name || 'Wallet', action, telUri});

    document.getElementById('w-label').value='';
    document.getElementById('w-oldpin').value='';

    await loadWalletPending(true);

  }catch(e){
    errEl.textContent=e.message||'Failed';
    errEl.classList.add('show');
  }finally{
    syncWalletPrimaryButtonText();
    btn.disabled=false;
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  const d = new Date(); d.setDate(d.getDate()+1); d.setSeconds(0,0);
  document.getElementById('g-date').value = d.toISOString().slice(0,16);
  const wDate = document.getElementById('w-date');
  if(wDate) wDate.value = d.toISOString().slice(0,16);

  document.querySelectorAll('#type-grid .type-opt').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('#type-grid .type-opt').forEach(x => x.classList.remove('sel'));
      b.classList.add('sel');
    });
  });

  document.querySelectorAll('#mode-grid .type-opt').forEach(b => {
    b.addEventListener('click', () => {
      setCreateMode(b.dataset.mode);
      setTimeout(() => {
        const first = (createMode === 'wallet') ? document.getElementById('w-oldpin') : document.getElementById('g-label');
        if(first) first.focus();
      }, 50);
    });
  });

  const wag = document.getElementById('wallet-action-grid');
  if(wag){
    wag.querySelectorAll('.type-opt').forEach(b => {
      b.addEventListener('click', () => {
        if(b.disabled) return;
        setWalletAction(b.dataset.action);
      });
    });
  }
  setWalletAction(walletAction);

  const wCarrierSel = document.getElementById('w-carrier');
  if(wCarrierSel){
    wCarrierSel.addEventListener('change', () => {
      const carrierId = parseInt(wCarrierSel.value || '0', 10);
      const carrier = carriers.find(c => parseInt(c.id,10) === carrierId);
      applyWalletActionPolicy(carrier, true);

      if(carrier){
        const requiredLen = parseInt((carrier.pin_length ?? carrier.pinLength ?? '4'), 10) || 4;
        const inp = document.getElementById('w-oldpin');
        if(inp) inp.placeholder = `${requiredLen}-digit PIN`;
      }
    });
  }

  document.getElementById('vp-input').addEventListener('keydown', e => { if(e.key==='Enter') unlockVault(); });
  const vp2 = document.getElementById('vp-input2');
  if(vp2) vp2.addEventListener('keydown', e => { if(e.key==='Enter') unlockVault(); });

  const storedSlot = parseInt(localStorage.getItem('vault_slot') || '1', 10);
  vaultSlotSession = ([1,2].includes(storedSlot) ? storedSlot : 1);

  await loadVaultSetup();
  await loadCarriersForWallet();
  await loadWalletPending(true);

  applyWalletActionPolicy(null, false);
  syncWalletPrimaryButtonText();

  checkVaultUnlock();

  // Usability: initial focus to speed up unlock on desktop/mobile.
  if(!vaultPhraseSession){
    const vp = document.getElementById('vp-input');
    if(vp) vp.focus();
  }
});
</script>
</body>
</html>
