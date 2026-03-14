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
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?php e('login.title', ['app' => APP_NAME]); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/auth.css">
<style>
.box{max-width:420px;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <div class="auth-wrap">
    <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub"><?php e('login.subtitle'); ?></div>

    <div id="err" class="msg msg-err"></div>

    <form id="f">
      <div class="field"><label><?php e('common.email'); ?></label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
      </div>
      <div class="field"><label><?php e('login.login_password'); ?></label>
        <input type="password" id="pwd" autocomplete="current-password" placeholder="••••••••" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?php e('login.btn'); ?></span></button>
    </form>

    <div style="height:10px"></div>

    <button class="btn btn-primary" id="passkey-btn" type="button" style="background:transparent;border:1px solid var(--b2);color:var(--text);">
      <?php e('login.use_passkey'); ?>
    </button>

    <div class="links">
      <a href="index.php"><?php e('common.home'); ?></a>
      <a href="forgot.php"><?php e('login.forgot'); ?></a>
      <a href="signup.php"><?php e('common.create_account'); ?></a>
    </div>
  </div>
</div>
</div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const passkeyBtn=document.getElementById('passkey-btn');

const STR={
  emailPwdRequired: <?= json_encode(t('login.email_pwd_required')) ?>,
  passkeyRequired: <?= json_encode(t('login.passkey_required')) ?>,
  failed: <?= json_encode(t('login.failed')) ?>,
  enterTotp: <?= json_encode(t('login.enter_totp')) ?>,
  codeRequired: <?= json_encode(t('login.code_required')) ?>,
  networkError: <?= json_encode(t('login.network_error')) ?>,
  btnLogin: <?= json_encode(t('login.btn')) ?>,
  usePasskey: <?= json_encode(t('login.use_passkey')) ?>,
  passkeysUnsupported: <?= json_encode(t('login.passkeys_unsupported')) ?>,
  passkeyFailed: <?= json_encode(t('login.passkey_failed')) ?>,
  passkeyLoginFailed: <?= json_encode(t('login.passkey_login_failed')) ?>,
};

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
  if(!email||!pwd){showErr(STR.emailPwdRequired);return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login',email,login_password:pwd})});
    const j=await r.json();

    if(!j.success){
      if(j.error_code==='passkey_required'){
        showErr(STR.passkeyRequired);
        return;
      }
      showErr(j.error||STR.failed);
      return;
    }

    if(j.needs_totp){
      const code = prompt(STR.enterTotp);
      if(!code){showErr(STR.codeRequired);return;}

      const r2=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'login_totp',code})});
      const j2=await r2.json();
      if(!j2.success){showErr(j2.error||STR.failed);return;}

      if(j2.verified){window.location='dashboard.php';}
      else window.location='account.php';
      return;
    }

    if(j.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr(STR.networkError);
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    btnTxt.textContent=STR.btnLogin;
  }
}

async function doPasskeyLogin(){
  clearErr();
  if(!window.PublicKeyCredential){showErr(STR.passkeysUnsupported);return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  passkeyBtn.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/webauthn.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login_begin'})});
    const j=await r.json();
    if(!j.success){showErr(j.error||STR.passkeyFailed);return;}

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
    if(!j2.success){showErr(j2.error||STR.passkeyLoginFailed);return;}

    if(j2.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch(e){
    showErr((e && e.message) ? e.message : STR.passkeyLoginFailed);
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    passkeyBtn.textContent=STR.usePasskey;
  }
}

f.addEventListener('submit', doPasswordLogin);
passkeyBtn.addEventListener('click', doPasskeyLogin);
</script>
</body>
</html> 
