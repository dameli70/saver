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
    header('Location: profile.php');
    exit;
}

$userId = getCurrentUserId();
$db     = getDB();

$hasTotp = hasTotpColumns();
$hasPasskeys = hasWebauthnCredentialsTable();

$hasReqWebauthn = false;
try {
    $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'require_webauthn' LIMIT 1");
    $hasReqWebauthn = (bool)$stmt->fetchColumn();
} catch (Throwable) {
    $hasReqWebauthn = false;
}

$sel = 'email' . ($hasTotp ? ', totp_enabled_at' : ', NULL AS totp_enabled_at') . ($hasReqWebauthn ? ', require_webauthn' : ', 0 AS require_webauthn');
$stmt = $db->prepare("SELECT {$sel} FROM users WHERE id = ?");
$stmt->execute([(int)$userId]);
$u = $stmt->fetch();

if (!$u) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

$isAdmin = isAdmin();
$csrf    = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Security — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="manifest" href="manifest.webmanifest">
<meta name="theme-color" content="#06070a">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--blue:#47b8ff;--orange:#ffaa00;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
  --r:14px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;}
a{color:inherit;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:var(--r);
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:hover{background:#f0ff60;}
.btn-primary:disabled{opacity:.45;pointer-events:none;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-red{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 

.wrap{max-width:860px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;margin-bottom:14px;border-radius:var(--r);}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
.k{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;}
.v{color:var(--text);font-size:12px;letter-spacing:.4px;}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;border:1px solid;border-radius:999px;}
.badge.ok{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);} 
.badge.wait{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);} 
.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;border-radius:var(--r);}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.field{margin-top:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);
  font-size:15px;padding:14px;outline:none;transition:border-color .2s;border-radius:var(--r);-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.hr{border-top:1px solid var(--b1);margin:16px 0;}
.list{margin-top:10px;display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:rgba(19,22,29,.55);padding:12px 14px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;border-radius:var(--r);}
.small{font-size:11px;color:var(--muted);line-height:1.6;}
.btn-row{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;}
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
code{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);padding:2px 6px;border-radius:8px;}
</style>
</head>
<body>
  <div class="nav">
    <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
    <div class="nav-r">
      <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
      <a class="btn btn-ghost" href="codes.php">Codes</a>
      <a class="btn btn-ghost" href="backup.php">Backups</a>
      <a class="btn btn-ghost" href="profile.php">Profile</a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost" href="admin.php">Admin</a><?php endif; ?>
      <a class="btn btn-ghost" href="faq.php">FAQ</a>
      <a class="btn btn-ghost" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="wrap">
    <div class="h">Security</div>
    <div class="p">Protect sensitive actions (reveal, backups, vault changes).</div>

    <div class="card" id="vault-passphrase-card">
      <div class="row">
        <div>
          <div class="k">Vault passphrase</div>
          <div class="v">Zero-knowledge encryption key (browser-only)</div>
        </div>
        <div class="badge wait" id="vault-passphrase-status">⏳</div>
      </div>

      <div class="small" style="margin-top:12px;">
        Required to encrypt/decrypt codes. The passphrase is never stored or recoverable by the server.
      </div>

      <div id="vault-passphrase-unavailable" class="small" style="margin-top:12px;display:none;">
        Vault passphrase setup is unavailable (missing migrations). Apply migrations in <code>config/migrations/</code>.
      </div>

      <div id="vault-passphrase-set" class="small" style="margin-top:12px;display:none;">
        A vault passphrase is set. Keep it safe — if you lose it, your codes cannot be recovered.
      </div>

      <div id="vault-passphrase-form" style="display:none;">
        <div class="hr"></div>
        <div class="field"><label>New vault passphrase <span style="color:var(--muted)">(min 10 chars)</span></label>
          <input type="password" id="vp1" autocomplete="new-password" placeholder="Something memorable only you know">
        </div>
        <div class="field"><label>Confirm vault passphrase</label>
          <input type="password" id="vp2" autocomplete="new-password" placeholder="Confirm passphrase">
        </div>
        <button class="btn btn-primary" id="vp-save"><span id="vp-save-txt">Set vault passphrase</span></button>
        <div id="vp-ok" class="msg msg-ok"></div>
        <div id="vp-err" class="msg msg-err"></div>
      </div>
    </div>

    <div class="card" id="totp-card">
      <div class="row">
        <div>
          <div class="k">Two-factor authentication (TOTP)</div>
          <div class="v">Authenticator app codes</div>
        </div>
        <?php if ($hasTotp): ?>
          <?php if (!empty($u['totp_enabled_at'])): ?>
            <div class="badge ok">✓ Enabled</div>
          <?php else: ?>
            <div class="badge wait">⏳ Not enabled</div>
          <?php endif; ?>
        <?php else: ?>
          <div class="badge wait">⏳ Unavailable</div>
        <?php endif; ?>
      </div>

      <?php if (!$hasTotp): ?>
        <div class="small" style="margin-top:12px;">TOTP is not available. Apply migrations in <code>config/migrations/</code>.</div>
      <?php else: ?>
        <div class="small" style="margin-top:12px;">Used for step-up authentication (reveal, vault rotation, backups).</div>

        <div id="totp-setup" style="display:none;">
          <div class="hr"></div>
          <div class="small">Scan this secret in your authenticator app:</div>
          <div class="small" style="margin-top:6px;word-break:break-all;"><code id="totp-secret"></code></div>
          <div class="small" style="margin-top:6px;word-break:break-all;"><a id="totp-otpauth" href="#" style="color:var(--orange)">otpauth:// link</a></div>
          <div class="field"><label>6-digit code</label><input id="totp-code" inputmode="numeric" placeholder="123456"></div>
          <button class="btn btn-primary" id="totp-enable"><span id="totp-enable-txt">Enable TOTP</span></button>
        </div>

        <div id="totp-disable" style="display:none;">
          <div class="hr"></div>
          <div class="field"><label>6-digit code</label><input id="totp-disable-code" inputmode="numeric" placeholder="123456"></div>
          <button class="btn btn-red" id="totp-disable-btn">Disable TOTP</button>
        </div>

        <div class="btn-row">
          <button class="btn btn-ghost" id="totp-begin">Setup TOTP</button>
          <button class="btn btn-ghost" id="totp-reauth">Re-auth now</button>
        </div>

        <div id="totp-ok" class="msg msg-ok"></div>
        <div id="totp-err" class="msg msg-err"></div>
      <?php endif; ?>
    </div>

    <div class="card" id="passkeys-card">
      <div class="row">
        <div>
          <div class="k">Passkeys</div>
          <div class="v">Face ID / Touch ID / security keys</div>
        </div>
        <div class="badge wait" id="passkeys-status">⏳</div>
      </div>

      <?php if (!$hasPasskeys): ?>
        <div class="small" style="margin-top:12px;">Passkeys are not available. Apply migrations in <code>config/migrations/</code>.</div>
      <?php else: ?>
        <div class="small" style="margin-top:12px;">Passkeys can be used for passwordless login and step-up authentication.</div>

        <div class="hr"></div>

        <div class="row">
          <div>
            <div class="k">Require passkey for login</div>
            <div class="small">If enabled, password login is blocked.</div>
          </div>
          <label class="small" style="display:flex;align-items:center;gap:10px;">
            <input type="checkbox" id="passkey-required" <?= $hasReqWebauthn ? '' : 'disabled' ?> <?= !empty($u['require_webauthn']) ? 'checked' : '' ?> >
            <span><?= $hasReqWebauthn ? '' : 'Unavailable' ?></span>
          </label>
        </div>

        <div class="list" id="passkeys-list"></div>

        <div class="btn-row">
          <button class="btn btn-ghost" id="passkey-refresh">Refresh</button>
          <button class="btn btn-primary" id="passkey-add"><span id="passkey-add-txt">Add passkey</span></button>
        </div>

        <div id="passkey-ok" class="msg msg-ok"></div>
        <div id="passkey-err" class="msg msg-err"></div>
      <?php endif; ?>
    </div>

  </div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;
  const VERIFIED = true;
  const TOTP_AVAILABLE = <?= $hasTotp ? 'true' : 'false' ?>;
  const PASSKEYS_AVAILABLE = <?= $hasPasskeys ? 'true' : 'false' ?>;
  const TOTP_ENABLED = <?= (!empty($u['totp_enabled_at'])) ? 'true' : 'false' ?>;
  const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
  const VAULT_CHECK_PLAIN = 'LOCKSMITH_VAULT_CHECK_v1';

  function showMsg(el,m){el.textContent=m;el.classList.add('show');}
  function clearMsg(el){el.textContent='';el.classList.remove('show');}

  async function postCsrf(url, body){
    const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
    return r.json();
  }

  function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}
  function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}

  function requireWebCrypto(){
    if (!window.crypto || !window.crypto.getRandomValues) {
      throw new Error('Secure cryptography is unavailable in this browser.');
    }
    if (!window.isSecureContext || !window.crypto.subtle) {
      throw new Error('Web Crypto API is unavailable. Use HTTPS (or localhost) to set a vault passphrase.');
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

  // ── VAULT PASSPHRASE SETUP ────────────────────
  const vaultStatus = document.getElementById('vault-passphrase-status');
  if (vaultStatus) {
    const unavailable = document.getElementById('vault-passphrase-unavailable');
    const setNote = document.getElementById('vault-passphrase-set');
    const form = document.getElementById('vault-passphrase-form');
    const ok = document.getElementById('vp-ok');
    const err = document.getElementById('vp-err');
    const saveBtn = document.getElementById('vp-save');
    const saveTxt = document.getElementById('vp-save-txt');

    function setBadge(text, ok){
      vaultStatus.textContent = text;
      vaultStatus.className = 'badge ' + (ok ? 'ok' : 'wait');
    }

    async function loadVaultStatus(){
      clearMsg(ok); clearMsg(err);
      setBadge('⏳', false);
      if(unavailable) unavailable.style.display='none';
      if(setNote) setNote.style.display='none';
      if(form) form.style.display='none';

      try{
        const j = await postCsrf('api/vault.php', {action:'setup_status'});
        if(!j.success){setBadge('⏳', false);return;}

        if(!j.available){
          setBadge('⏳ Unavailable', false);
          if(unavailable) unavailable.style.display='block';
          return;
        }

        if(j.initialized){
          setBadge('✓ Set', true);
          if(setNote) setNote.style.display='block';
          return;
        }

        setBadge('⏳ Not set', false);
        if(form) form.style.display='block';

      }catch{
        setBadge('⏳', false);
      }
    }

    if(saveBtn){
      saveBtn.addEventListener('click', async ()=>{
        clearMsg(ok); clearMsg(err);

        const p1 = (document.getElementById('vp1')||{}).value || '';
        const p2 = (document.getElementById('vp2')||{}).value || '';

        if(!p1 || p1.length < 10){showMsg(err,'Passphrase must be at least 10 characters');return;}
        if(p1 !== p2){showMsg(err,'Passphrases do not match');return;}

        saveBtn.disabled=true;
        if(saveTxt) saveTxt.innerHTML='<span class="spin"></span>';

        try{
          const c = requireWebCrypto();
          const saltBytes = new Uint8Array(32);
          c.getRandomValues(saltBytes);
          const kdf_salt = bytesToB64(saltBytes);

          const key = await deriveKey(p1, kdf_salt, PBKDF2_ITERS);
          const enc = await aesEncrypt(VAULT_CHECK_PLAIN, key);

          const j = await postCsrf('api/vault.php', {
            action:'setup_save',
            cipher_blob: enc.cipher_blob,
            iv: enc.iv,
            auth_tag: enc.auth_tag,
            kdf_salt,
            kdf_iterations: PBKDF2_ITERS,
          });

          if(!j.success){showMsg(err,j.error||'Failed to set vault passphrase');return;}
          showMsg(ok,'Vault passphrase set.');
          if(document.getElementById('vp1')) document.getElementById('vp1').value='';
          if(document.getElementById('vp2')) document.getElementById('vp2').value='';
          localStorage.setItem('vault_slot', '1');
          loadVaultStatus();

        }catch(e){
          showMsg(err,(e && e.message) ? e.message : 'Failed to set vault passphrase');
        }finally{
          saveBtn.disabled=false;
          if(saveTxt) saveTxt.textContent='Set vault passphrase';
        }
      });
    }

    loadVaultStatus();
  }

  // base64url helpers for WebAuthn
  function b64uToBuf(b64url){
    const b64 = String(b64url||'').replace(/-/g,'+').replace(/_/g,'/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const bin = atob(b64 + pad);
    const bytes = new Uint8Array(bin.length);
    for(let i=0;i<bytes.length;i++) bytes[i]=bin.charCodeAt(i);
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
        return !!fin.success;
      }
    }

    if(methods && methods.totp){
      const code = prompt('Enter your 6-digit authenticator code');
      if(!code) return false;
      const r = await postCsrf('api/totp.php', {action:'reauth', code});
      return !!r.success;
    }

    return false;
  }

  // ── TOTP ─────────────────────────────────────
  if(VERIFIED && TOTP_AVAILABLE){
    const ok=document.getElementById('totp-ok');
    const err=document.getElementById('totp-err');
    const setup=document.getElementById('totp-setup');
    const dis=document.getElementById('totp-disable');

    function totpSetUi(enabled){
      document.getElementById('totp-begin').style.display = enabled ? 'none' : 'inline-flex';
      setup.style.display = 'none';
      dis.style.display = enabled ? 'block' : 'none';
    }

    totpSetUi(TOTP_ENABLED);

    document.getElementById('totp-begin').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const j=await postCsrf('api/totp.php', {action:'begin'});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      document.getElementById('totp-secret').textContent = j.secret;
      const a=document.getElementById('totp-otpauth');
      a.href=j.otpauth; a.textContent=j.otpauth;
      setup.style.display='block';
    });

    document.getElementById('totp-enable').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=document.getElementById('totp-code').value.trim();
      if(!code){showMsg(err,'Code required');return;}
      const btn=document.getElementById('totp-enable');
      const txt=document.getElementById('totp-enable-txt');
      btn.disabled=true; txt.innerHTML='<span class="spin"></span>';
      try{
        const j=await postCsrf('api/totp.php', {action:'enable', code});
        if(!j.success){showMsg(err,j.error||'Failed');return;}
        showMsg(ok,'TOTP enabled.');
        totpSetUi(true);
      }finally{
        btn.disabled=false; txt.textContent='Enable TOTP';
      }
    });

    document.getElementById('totp-disable-btn').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=document.getElementById('totp-disable-code').value.trim();
      if(!code){showMsg(err,'Code required');return;}
      const j=await postCsrf('api/totp.php', {action:'disable', code});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'TOTP disabled.');
      totpSetUi(false);
    });

    document.getElementById('totp-reauth').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=prompt('Enter your 6-digit authenticator code');
      if(!code) return;
      const j=await postCsrf('api/totp.php', {action:'reauth', code});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'Re-auth successful.');
    });
  }

  // ── PASSKEYS ─────────────────────────────────
  if(VERIFIED && PASSKEYS_AVAILABLE){
    const ok=document.getElementById('passkey-ok');
    const err=document.getElementById('passkey-err');
    const list=document.getElementById('passkeys-list');
    const status=document.getElementById('passkeys-status');

    function setStatus(text, ok){
      status.textContent = text;
      status.className = 'badge ' + (ok ? 'ok' : 'wait');
    }

    async function loadPasskeys(){
      clearMsg(ok); clearMsg(err);
      list.innerHTML='<div class="small">Loading…</div>';
      const j=await postCsrf('api/webauthn.php', {action:'list'});
      if(!j.success){showMsg(err,j.error||'Failed');list.innerHTML='';setStatus('⏳',false);return;}
      const keys=j.passkeys||[];
      setStatus(keys.length ? '✓ Enabled' : '⏳ None', !!keys.length);
      if(!keys.length){list.innerHTML='<div class="small">No passkeys registered.</div>';return;}

      list.innerHTML='';
      keys.forEach(k=>{
        const el=document.createElement('div');
        el.className='item';
        const label=k.label ? k.label : 'Passkey';
        el.innerHTML=`
          <div>
            <div class="small" style="color:var(--text)">${label}</div>
            <div class="small">Created: ${k.created_at||''}</div>
            <div class="small">Last used: ${k.last_used_at||'—'}</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <button class="btn btn-red" data-id="${k.id}">Delete</button>
          </div>
        `;
        el.querySelector('button').addEventListener('click', ()=>deletePasskey(k.id));
        list.appendChild(el);
      });
    }

    async function deletePasskey(id){
      clearMsg(ok); clearMsg(err);
      if(!confirm('Delete this passkey?')) return;

      let j=await postCsrf('api/webauthn.php', {action:'delete', id});
      if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
        const ok2 = await ensureReauth(j.methods||{});
        if(!ok2){showMsg(err,j.error||'Re-auth required');return;}
        j=await postCsrf('api/webauthn.php', {action:'delete', id});
      }
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'Deleted.');
      loadPasskeys();
    }

    async function addPasskey(){
      clearMsg(ok); clearMsg(err);
      if(!window.PublicKeyCredential){showMsg(err,'Passkeys not supported in this browser');return;}

      const label = prompt('Label for this passkey (optional)') || '';
      const btn=document.getElementById('passkey-add');
      const txt=document.getElementById('passkey-add-txt');
      btn.disabled=true; txt.innerHTML='<span class="spin"></span>';

      try{
        const begin=await postCsrf('api/webauthn.php', {action:'register_begin'});
        if(!begin.success){showMsg(err,begin.error||'Failed');return;}

        const pk=begin.publicKey||{};
        const exclude=(pk.excludeCredentials||[]).map(c => ({type:c.type, id: b64uToBuf(c.id)}));

        const cred=await navigator.credentials.create({publicKey:{
          challenge: b64uToBuf(pk.challenge),
          rp: pk.rp,
          user: {
            id: b64uToBuf(pk.user.id),
            name: pk.user.name,
            displayName: pk.user.displayName,
          },
          pubKeyCredParams: pk.pubKeyCredParams,
          timeout: pk.timeout||60000,
          attestation: pk.attestation||'none',
          authenticatorSelection: pk.authenticatorSelection||{userVerification:'required'},
          excludeCredentials: exclude,
        }});

        const a=cred.response;
        const fin=await postCsrf('api/webauthn.php', {
          action:'register_finish',
          label,
          rawId: bufToB64u(cred.rawId),
          response:{
            clientDataJSON: bufToB64u(a.clientDataJSON),
            attestationObject: bufToB64u(a.attestationObject),
          }
        });

        if(!fin.success){showMsg(err,fin.error||'Failed');return;}
        showMsg(ok,'Passkey added.');
        loadPasskeys();

      }catch(e){
        showMsg(err,(e && e.message) ? e.message : 'Passkey failed');
      }finally{
        btn.disabled=false; txt.textContent='Add passkey';
      }
    }

    document.getElementById('passkey-refresh').addEventListener('click', loadPasskeys);
    document.getElementById('passkey-add').addEventListener('click', addPasskey);

    const req=document.getElementById('passkey-required');
    if(req){
      req.addEventListener('change', async ()=>{
        clearMsg(ok); clearMsg(err);
        const enabled = req.checked ? 1 : 0;

        let j=await postCsrf('api/webauthn.php', {action:'require_for_login', enabled});
        if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
          const ok2 = await ensureReauth(j.methods||{});
          if(!ok2){showMsg(err,j.error||'Re-auth required');req.checked=!req.checked;return;}
          j=await postCsrf('api/webauthn.php', {action:'require_for_login', enabled});
        }

        if(!j.success){showMsg(err,j.error||'Failed');req.checked=!req.checked;return;}
        showMsg(ok, enabled ? 'Passkey required for login.' : 'Password login allowed.');
      });
    }

    loadPasskeys();
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
</script>
</body>
</html>
