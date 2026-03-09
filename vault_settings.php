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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.vault_settings')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
</style>
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
      <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php"><?php e('nav.my_codes'); ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?php e('nav.backups'); ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
    </div>
  </div>

  <div class="app-body">
    <div class="card">
      <div class="card-title"><div class="dot"></div>Vault rotation</div>
      <div style="font-size:12px;color:var(--muted);line-height:1.7;margin-bottom:14px;">
        Rotate your vault passphrase by re-encrypting <strong>already-unlocked</strong> codes (reveal date has passed).
        Locked codes cannot be rotated until they unlock.
      </div>

      <div id="rot-ok" class="msg msg-ok"></div>
      <div id="rot-err" class="msg msg-err"></div>

      <div class="field"><label>Current vault passphrase</label>
        <input type="password" id="rot-cur" autocomplete="current-password">
      </div>
      <div class="field"><label>New vault passphrase</label>
        <input type="password" id="rot-new" autocomplete="new-password">
      </div>
      <div class="field"><label>Confirm new vault passphrase</label>
        <input type="password" id="rot-new2" autocomplete="new-password">
      </div>

      <button class="btn btn-primary" id="rot-btn" onclick="rotateVaultPassphrase()" style="width:100%;">
        <span id="rot-txt">Rotate vault passphrase</span>
      </button>

      <div style="margin-top:12px;font-size:11px;color:var(--muted);line-height:1.7;">
        Note: rotation requires decrypting eligible ciphertext in your browser. The server never learns your passphrase.
      </div>
    </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
const VAULT_CHECK_PLAIN = 'LOCKSMITH_VAULT_CHECK_v1';

let vaultCheckAvailable = false;
let vaultCheckInitialized = false;
let vaultCheck = null;

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

function showMsg(el, text){
  el.textContent = text;
  el.classList.add('show');
}
function clearMsgs(){
  const ok = document.getElementById('rot-ok');
  const err = document.getElementById('rot-err');
  ok.classList.remove('show'); ok.textContent='';
  err.classList.remove('show'); err.textContent='';
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

async function loadVaultSetup(){
  try{
    const r = await postCsrf('api/vault.php', {action:'setup_status'});
    if(!r.success) return;
    vaultCheckAvailable = !!r.available;
    vaultCheckInitialized = !!r.initialized;
    vaultCheck = r.vault_check || null;
  }catch{}
}

async function rotateVaultPassphrase(){
  clearMsgs();

  const errEl=document.getElementById('rot-err');
  const okEl=document.getElementById('rot-ok');

  const cur=document.getElementById('rot-cur').value;
  const p1=document.getElementById('rot-new').value;
  const p2=document.getElementById('rot-new2').value;

  if(!cur || cur.length<10){showMsg(errEl,'Current passphrase must be at least 10 characters');return;}
  if(!p1 || p1.length<10){showMsg(errEl,'New passphrase must be at least 10 characters');return;}
  if(p1!==p2){showMsg(errEl,'Passphrases do not match');return;}
  if(p1===cur){showMsg(errEl,'New passphrase must differ from current');return;}

  const btn=document.getElementById('rot-btn');
  const txt=document.getElementById('rot-txt');
  btn.disabled=true;
  txt.innerHTML='<span class="spin light"></span> Rotating…';

  try{
    if (vaultCheckAvailable && vaultCheckInitialized && vaultCheck) {
      const key = await deriveKey(cur, vaultCheck.kdf_salt, vaultCheck.kdf_iterations);
      const plain = await aesDecrypt(vaultCheck.cipher_blob, vaultCheck.iv, vaultCheck.auth_tag, key);
      if (plain !== VAULT_CHECK_PLAIN) throw new Error('Incorrect vault passphrase');
    }

    const prep=await postCsrf('api/vault.php',{action:'rotate_prepare'});
    if(!prep.success){throw new Error(prep.error||'Failed to load eligible codes');}

    const locks=prep.locks||[];
    const toSlot=parseInt(prep.to_slot||2,10)||2;
    if(!locks.length){toast('No eligible codes to rotate yet','warn');return;}

    const updates=[];
    for(const l of locks){
      const keyOld=await deriveKey(cur, l.kdf_salt, l.kdf_iterations);
      const plain=await aesDecrypt(l.cipher_blob, l.iv, l.auth_tag, keyOld);
      const keyNew=await deriveKey(p1, l.kdf_salt, l.kdf_iterations);
      const enc=await aesEncrypt(plain, keyNew);
      updates.push({id:l.id, cipher_blob:enc.cipher_blob, iv:enc.iv, auth_tag:enc.auth_tag});
    }

    const body = {action:'rotate_commit', updates};

    let nextVaultCheck = null;
    if (vaultCheckAvailable) {
      const c = requireWebCrypto();
      const saltBytes = new Uint8Array(32);
      c.getRandomValues(saltBytes);
      const kdf_salt = bytesToB64(saltBytes);
      const keyVc = await deriveKey(p1, kdf_salt, PBKDF2_ITERS);
      const encVc = await aesEncrypt(VAULT_CHECK_PLAIN, keyVc);
      nextVaultCheck = {
        cipher_blob: encVc.cipher_blob,
        iv: encVc.iv,
        auth_tag: encVc.auth_tag,
        kdf_salt,
        kdf_iterations: PBKDF2_ITERS,
      };
      body.vault_check = nextVaultCheck;
    }

    let apply = await postCsrf('api/vault.php', body);
    if(!apply.success && (apply.error_code==='reauth_required' || apply.error_code==='security_setup_required')){
      const ok = await ensureReauth(apply.methods||{});
      if(!ok){throw new Error(apply.error||'Re-authentication required');}
      apply = await postCsrf('api/vault.php', body);
    }

    if(!apply.success){throw new Error(apply.error||'Rotation failed');}

    if (nextVaultCheck) {
      vaultCheckInitialized = true;
      vaultCheck = nextVaultCheck;
    }

    localStorage.setItem('vault_slot', String(toSlot));

    document.getElementById('rot-cur').value='';
    document.getElementById('rot-new').value='';
    document.getElementById('rot-new2').value='';

    showMsg(okEl, 'Vault passphrase rotated (eligible codes updated).');

  }catch(e){
    showMsg(errEl, e.message || 'Rotation failed');
  }finally{
    btn.disabled=false;
    txt.textContent='Rotate vault passphrase';
  }
}

document.addEventListener('DOMContentLoaded', async ()=>{
  await loadVaultSetup();
});
</script>
</body>
</html>
