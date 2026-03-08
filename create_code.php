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
.btn-primary{background:var(--accent);color:#000;font-weight:500;width:100%;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:active{transform:scale(.98);}
.btn-primary:disabled{opacity:.4;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);}
.btn-ghost:hover{border-color:var(--text);}
.btn-green{background:var(--green);color:#000;font-weight:500;}
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);}
.btn-sm{padding:10px 16px;font-size:11px;min-height:40px;}

.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
.spin.light{border-color:rgba(255,255,255,.25);border-top-color:var(--accent);}
@keyframes spin{to{transform:rotate(360deg);}}

.msg{padding:12px 14px;font-size:12px;margin-bottom:12px;display:none;letter-spacing:.4px;line-height:1.6;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}
.msg-warn{background:rgba(255,170,0,.08);border:1px solid rgba(255,170,0,.2);color:var(--orange);}

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

.app-body{max-width:680px;margin:0 auto;padding:22px 16px;}
@media(min-width:600px){.app-body{padding:30px 24px;}}

.card{background:var(--s1);border:1px solid var(--b1);padding:20px;margin-bottom:16px;position:relative;}
@media(min-width:600px){.card{padding:24px 28px;}}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;
  text-transform:uppercase;color:var(--accent);margin-bottom:18px;display:flex;align-items:center;gap:8px;}
.card-title .dot{width:5px;height:5px;background:var(--accent);flex-shrink:0;}

.field{margin-bottom:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);
  font-family:var(--mono);font-size:15px;padding:14px;outline:none;transition:border-color .2s;
  -webkit-appearance:none;border-radius:0;-webkit-text-size-adjust:100%;}
.field input:focus,.field select:focus{border-color:var(--accent);}

.type-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;}
@media(min-width:380px){.type-grid{grid-template-columns:repeat(4,1fr);}}
.type-opt{padding:12px 6px;border:1px solid var(--b1);background:transparent;
  color:var(--muted);font-family:var(--mono);font-size:10px;letter-spacing:1px;
  text-transform:uppercase;cursor:pointer;text-align:center;transition:all .15s;
  min-height:44px;display:flex;align-items:center;justify-content:center;}
.type-opt:hover{border-color:var(--b2);color:var(--text);}
.type-opt.sel{border-color:var(--accent);color:var(--accent);background:rgba(232,255,71,.06);}

.slider-row{display:flex;align-items:center;gap:14px;}
.slider-val{font-family:var(--display);font-size:26px;font-weight:900;color:var(--accent);min-width:40px;text-align:right;}
input[type=range]{-webkit-appearance:none;flex:1;height:4px;background:var(--b2);outline:none;cursor:pointer;border-radius:2px;}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:22px;height:22px;background:var(--accent);cursor:pointer;border-radius:0;}

.kdf-progress{display:none;margin-top:12px;}
.kdf-progress.show{display:block;}
.kdf-bar-wrap{height:3px;background:var(--b2);overflow:hidden;margin-bottom:6px;}
.kdf-bar{height:100%;background:var(--accent);transition:width .1s linear;width:0%;}
.kdf-label{font-size:10px;color:var(--muted);letter-spacing:1px;text-align:center;}

#confirm-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);
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
        Your vault passphrase is used to derive encryption keys in your browser. It is never sent to the server.
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

    <div class="card" id="gen-card">
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
    <div class="confirm-title">Did you save the code?</div>
    <div class="confirm-sub" id="cs-sub">Code was copied to your clipboard.</div>
    <div class="msg msg-warn" id="autosave-bar" style="display:none">Auto-saved. Code stored but not time-locked until you confirm.</div>

    <div class="confirm-btns" id="confirm-btns">
      <button class="btn btn-green" onclick="doConfirm('confirm')">✓ Yes, I saved it</button>
      <button class="btn btn-red" onclick="doConfirm('reject')">✗ No, discard</button>
    </div>
    <div id="confirm-done" style="display:none;margin-top:12px;font-size:12px;color:var(--muted);line-height:1.6;"><div id="confirm-done-msg"></div></div>
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

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
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

function checkVaultUnlock() {
  const genBtn = document.getElementById('g-btn');

  if (!vaultPhraseSession) {
    document.getElementById('vault-unlock-card').style.display = 'block';
    if(genBtn) genBtn.disabled = true;
    return;
  }

  document.getElementById('vault-unlock-card').style.display = 'none';
  if(genBtn) genBtn.disabled = false;
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

    let copied=false;
    try{await navigator.clipboard.writeText(plainPwd);copied=true;}catch{}
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
  document.getElementById('cs-sub').textContent=`"${label}" — blind-copied to clipboard.`;
  document.getElementById('confirm-btns').style.display='grid';
  document.getElementById('confirm-done').style.display='none';

  const bar = document.getElementById('autosave-bar');
  bar.style.display='none';

  document.getElementById('confirm-overlay').classList.add('show');

  setTimeout(async ()=>{
    if(!pendingLock) return;
    await postCsrf('api/confirm.php',{lock_id:lockId,action:'auto_save'});
    bar.style.display='block';
  }, 120000);
}

function closeConfirm(e){
  if(e&&e.target!==document.getElementById('confirm-overlay'))return;
  document.getElementById('confirm-overlay').classList.remove('show');
  pendingLock=null;
}

async function doConfirm(action){
  if(!pendingLock)return;

  const r=await postCsrf('api/confirm.php',{lock_id:pendingLock.lock_id,action});
  document.getElementById('confirm-btns').style.display='none';
  document.getElementById('confirm-done').style.display='block';
  const msg=document.getElementById('confirm-done-msg');

  if(action==='confirm'){
    msg.textContent='✓ Lock activated.';
  } else if(action==='reject'){
    msg.textContent='✗ Discarded.';
  }

  pendingLock=null;
}

document.addEventListener('DOMContentLoaded', async () => {
  const d = new Date(); d.setDate(d.getDate()+1); d.setSeconds(0,0);
  document.getElementById('g-date').value = d.toISOString().slice(0,16);

  document.querySelectorAll('#type-grid .type-opt').forEach(b => {
    b.addEventListener('click', () => {
      document.querySelectorAll('#type-grid .type-opt').forEach(x => x.classList.remove('sel'));
      b.classList.add('sel');
    });
  });

  document.getElementById('vp-input').addEventListener('keydown', e => { if(e.key==='Enter') unlockVault(); });
  const vp2 = document.getElementById('vp-input2');
  if(vp2) vp2.addEventListener('keydown', e => { if(e.key==='Enter') unlockVault(); });

  const storedSlot = parseInt(localStorage.getItem('vault_slot') || '1', 10);
  vaultSlotSession = ([1,2].includes(storedSlot) ? storedSlot : 1);

  await loadVaultSetup();
  checkVaultUnlock();
});
</script>
</body>
</html>
