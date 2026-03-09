<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (isLoggedIn()) {
    if (isEmailVerified()) {
        header('Location: dashboard.php');
        exit;
    }
    header('Location: account.php');
    exit;
}

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(getCurrentLang()) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(t('auth.signup.title')) ?> — <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/auth.css">
<style>
.box{max-width:520px;}
.sub{margin-bottom:10px;}
.callout{background:rgba(71,255,176,.05);border:1px solid rgba(71,255,176,.14);padding:12px 14px;margin:14px 0 16px;color:var(--muted);font-size:11px;line-height:1.7;}
.callout strong{color:var(--green);} 
.note{font-size:10px;color:var(--muted);margin-top:6px;line-height:1.6;}
.dev{margin-top:12px;border:1px dashed rgba(255,170,0,.35);background:rgba(255,170,0,.06);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;}
.dev a{color:var(--orange);} 
</style>
</head>
<body>
  <button class="theme-toggle" type="button" data-theme-toggle><?= htmlspecialchars(t('nav.theme')) ?></button>
  <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub">// <?= htmlspecialchars(t('auth.signup.title')) ?></div>

    <div class="callout">
      <?= t('auth.signup.callout') ?>
    </div>

    <div id="err" class="msg msg-err"></div>
    <div id="ok" class="msg msg-ok"></div>

    <form id="f">
      <div class="field"><label><?= htmlspecialchars(t('field.email')) ?></label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="<?= htmlspecialchars(t('placeholder.email')) ?>" required>
      </div>
      <div class="field"><label><?= htmlspecialchars(t('field.login_password')) ?> <span style="color:var(--muted)"><?= htmlspecialchars(t('hint.min_8_chars')) ?></span></label>
        <input type="password" id="pwd" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('placeholder.pass')) ?>" required>
      </div>
      <div class="field"><label><?= htmlspecialchars(t('field.vault_passphrase')) ?> <span style="color:var(--muted)"><?= htmlspecialchars(t('hint.min_10_chars')) ?></span></label>
        <input type="password" id="vault" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('placeholder.vault')) ?>" required>
        <div class="note"><?= htmlspecialchars(t('auth.signup.vault_note')) ?></div>
      </div>
      <div class="field"><label><?= htmlspecialchars(t('field.confirm_vault_passphrase')) ?></label>
        <input type="password" id="vault2" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('placeholder.confirm_passphrase')) ?>" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?= htmlspecialchars(t('auth.signup.button')) ?></span></button>
    </form>

    <div id="dev" class="dev" style="display:none"></div>

    <div class="links">
      <a href="index.php"><?= htmlspecialchars(t('nav.home')) ?></a>
      <a href="login.php"><?= htmlspecialchars(t('auth.signup.have_account')) ?></a>
    </div>

    <div class="links" style="justify-content:center;gap:14px;">
      <?php $lang = getCurrentLang(); ?>
      <a href="<?= htmlspecialchars(langUrl('fr')) ?>" class="<?= ($lang === 'fr') ? 'btn-lang-active' : '' ?>">FR</a>
      <a href="<?= htmlspecialchars(langUrl('en')) ?>" class="<?= ($lang === 'en') ? 'btn-lang-active' : '' ?>">EN</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const ok=document.getElementById('ok');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const dev=document.getElementById('dev');

const TXT = <?= json_encode([
  'fill_all_fields' => t('js.fill_all_fields'),
  'login_pwd_min' => t('js.login_pwd_min'),
  'vault_pwd_min' => t('js.vault_pwd_min'),
  'vault_mismatch' => t('js.vault_mismatch'),
  'registration_failed' => t('js.registration_failed'),
  'account_created_check_email' => t('js.account_created_check_email'),
  'network_error' => t('js.network_error'),
  'signup_button' => t('auth.signup.button'),
  'crypto_unavailable' => t('js.crypto_unavailable'),
  'crypto_need_https' => t('js.crypto_need_https'),
], JSON_UNESCAPED_UNICODE) ?>;

const CSRF = <?= json_encode(getCsrfToken()) ?>;
const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
const VAULT_CHECK_PLAIN = 'LOCKSMITH_VAULT_CHECK_v1';

function showErr(m){err.textContent=m;err.classList.add('show');}
function showOk(m){ok.textContent=m;ok.classList.add('show');}
function clearMsgs(){err.textContent='';ok.textContent='';err.classList.remove('show');ok.classList.remove('show');}

function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}
function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}

function requireWebCrypto(){
  // WebCrypto (crypto.subtle) is only available in secure contexts (HTTPS or localhost).
  if (!window.crypto || !window.crypto.getRandomValues) {
    throw new Error(TXT.crypto_unavailable);
  }
  if (!window.isSecureContext || !window.crypto.subtle) {
    throw new Error(TXT.crypto_need_https);
  }
  return window.crypto;
}

async function postCsrf(url, body){
  const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
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

async function setupVaultCheck(passphrase){
  const c = requireWebCrypto();
  const saltBytes = new Uint8Array(32);
  c.getRandomValues(saltBytes);
  const kdf_salt = bytesToB64(saltBytes);

  const key = await deriveKey(passphrase, kdf_salt, PBKDF2_ITERS);
  const enc = await aesEncrypt(VAULT_CHECK_PLAIN, key);

  return postCsrf('api/vault.php', {
    action:'setup_save',
    cipher_blob: enc.cipher_blob,
    iv: enc.iv,
    auth_tag: enc.auth_tag,
    kdf_salt,
    kdf_iterations: PBKDF2_ITERS,
  });
}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clearMsgs();

  const email=document.getElementById('email').value.trim();
  const pwd=document.getElementById('pwd').value;
  const vault=document.getElementById('vault').value;
  const vault2=document.getElementById('vault2').value;

  if(!email||!pwd||!vault||!vault2){showErr(TXT.fill_all_fields);return;}
  if(pwd.length<8){showErr(TXT.login_pwd_min);return;}
  if(vault.length<10){showErr(TXT.vault_pwd_min);return;}
  if(vault!==vault2){showErr(TXT.vault_mismatch);return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'register',email,login_password:pwd})});
    const j=await r.json();
    if(!j.success){showErr(j.error||TXT.registration_failed);return;}

    showOk(TXT.account_created_check_email);

    // Initialize vault passphrase check so you can unlock on any device.
    try{
      const vc = await setupVaultCheck(vault);
      if(!vc.success && vc.error){
        // If this fails (e.g., missing migrations), the Account page can still guide setup.
        console.warn('Vault setup failed:', vc.error);
      }
    }catch(e){
      console.warn('Vault setup failed:', e);
    }

    if(j.dev_verify_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Email sending is often disabled locally. Use this verification link: <br><a href="'+j.dev_verify_url+'">'+j.dev_verify_url+'</a>';
    }

    setTimeout(()=>{window.location='account.php';}, 900);

  }catch{
    showErr(TXT.network_error);
  }finally{
    btn.disabled=false;
    btnTxt.textContent=TXT.signup_button;
  }
});

</script>
</body>
</html>
