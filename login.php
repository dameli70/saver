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
<title><?= htmlspecialchars(t('auth.login.title')) ?> — <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/auth.css">
<style>
.box{max-width:420px;}
</style>
</head>
<body>
  <button class="theme-toggle" type="button" data-theme-toggle><?= htmlspecialchars(t('nav.theme')) ?></button>
  <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub">// <?= htmlspecialchars(t('auth.login.title')) ?></div>

    <div id="err" class="msg msg-err"></div>

    <form id="f">
      <div class="field"><label><?= htmlspecialchars(t('field.email')) ?></label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="<?= htmlspecialchars(t('placeholder.email')) ?>" required>
      </div>
      <div class="field"><label><?= htmlspecialchars(t('field.login_password')) ?></label>
        <input type="password" id="pwd" autocomplete="current-password" placeholder="<?= htmlspecialchars(t('placeholder.pass')) ?>" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?= htmlspecialchars(t('auth.login.title')) ?></span></button>
    </form>

    <div style="height:10px"></div>

    <button class="btn btn-primary" id="passkey-btn" type="button" style="background:transparent;border:1px solid var(--b2);color:var(--text);">
      <?= htmlspecialchars(t('auth.login.use_passkey')) ?>
    </button>

    <div class="links">
      <a href="index.php"><?= htmlspecialchars(t('nav.home')) ?></a>
      <a href="forgot.php"><?= htmlspecialchars(t('auth.login.forgot')) ?></a>
      <a href="signup.php"><?= htmlspecialchars(t('auth.login.create_account')) ?></a>
    </div>

    <div class="links" style="justify-content:center;gap:14px;">
      <?php $lang = getCurrentLang(); ?>
      <a href="<?= htmlspecialchars(langUrl('fr')) ?>" class="<?= ($lang === 'fr') ? 'btn-lang-active' : '' ?>">FR</a>
      <a href="<?= htmlspecialchars(langUrl('en')) ?>" class="<?= ($lang === 'en') ? 'btn-lang-active' : '' ?>">EN</a>
    </div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const passkeyBtn=document.getElementById('passkey-btn');

const TXT = <?= json_encode([
  'required_email_password' => t('js.required_email_password'),
  'passkey_required' => t('js.passkey_required'),
  'login_failed' => t('js.login_failed'),
  'enter_totp' => t('js.enter_totp'),
  'code_required' => t('js.code_required'),
  'network_error' => t('js.network_error'),
  'passkeys_not_supported' => t('js.passkeys_not_supported'),
  'passkey_failed' => t('js.passkey_failed'),
  'passkey_login_failed' => t('js.passkey_login_failed'),
  'login_btn' => t('auth.login.title'),
  'use_passkey' => t('auth.login.use_passkey'),
], JSON_UNESCAPED_UNICODE) ?>;

function showErr(m){err.textContent=m;err.classList.add('show');}
function clearErr(){err.textContent='';err.classList.remove('show');}

function b64ToBuf(b64url){
  const b64 = b64url.replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
  return bytes.buffer;
}
function bufToB64(buf){
  const bytes = new Uint8Array(buf);
  let s='';
  for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function doPasswordLogin(e){
  e.preventDefault();
  clearErr();

  const email=document.getElementById('email').value.trim();
  const pwd=document.getElementById('pwd').value;
  if(!email||!pwd){showErr(TXT.required_email_password);return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login',email,login_password:pwd})});
    const j=await r.json();

    if(!j.success){
      if(j.error_code==='passkey_required'){
        showErr(TXT.passkey_required);
        return;
      }
      showErr(j.error||TXT.login_failed);
      return;
    }

    if(j.needs_totp){
      const code = prompt(TXT.enter_totp);
      if(!code){showErr(TXT.code_required);return;}

      const r2=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'login_totp',code})});
      const j2=await r2.json();
      if(!j2.success){showErr(j2.error||TXT.login_failed);return;}

      if(j2.verified){window.location='dashboard.php';}
      else window.location='account.php';
      return;
    }

    if(j.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr(TXT.network_error);
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    btnTxt.textContent=TXT.login_btn;
  }
}

async function doPasskeyLogin(){
  clearErr();
  if(!window.PublicKeyCredential){showErr(TXT.passkeys_not_supported);return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  passkeyBtn.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/webauthn.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login_begin'})});
    const j=await r.json();
    if(!j.success){showErr(j.error||TXT.passkey_failed);return;}

    const pk=j.publicKey||{};
    const cred=await navigator.credentials.get({publicKey:{
      challenge: b64ToBuf(pk.challenge),
      rpId: pk.rpId,
      timeout: pk.timeout||60000,
      userVerification: pk.userVerification||'required'
    }});

    const a=cred.response;
    const finish=await fetch('api/webauthn.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        action:'login_finish',
        id: cred.id,
        rawId: bufToB64(cred.rawId),
        type: cred.type,
        response:{
          clientDataJSON: bufToB64(a.clientDataJSON),
          authenticatorData: bufToB64(a.authenticatorData),
          signature: bufToB64(a.signature),
          userHandle: a.userHandle ? bufToB64(a.userHandle) : null,
        }
      })});
    const j2=await finish.json();
    if(!j2.success){showErr(j2.error||TXT.passkey_login_failed);return;}

    if(j2.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch(e){
    showErr((e && e.message) ? e.message : TXT.passkey_login_failed);
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    passkeyBtn.textContent=TXT.use_passkey;
  }
}

f.addEventListener('submit', doPasswordLogin);
passkeyBtn.addEventListener('click', doPasskeyLogin);
</script>
</body>
</html>
