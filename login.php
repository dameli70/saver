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

$demoSeed = null;
if (!empty($_SESSION['install_demo_seed']) && is_array($_SESSION['install_demo_seed'])) {
    $demoSeed = $_SESSION['install_demo_seed'];
    unset($_SESSION['install_demo_seed']);
} else if (!empty($_GET['demo'])) {
    // Fallback hint if the installer redirected with ?demo=1 but the session was lost.
    $demoSeed = ['demo_password' => 'DemoPass123!'];
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
</head>
<body class="auth auth-login">
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar_public.php'; ?>

  <div class="auth-wrap">
    <div class="box box-login">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub"><?php e('login.subtitle'); ?></div>

    <div id="err" class="msg msg-err"></div>

    <?php if (!empty($demoSeed)): ?>
      <div class="msg msg-ok show auth-demo">
        <strong>Demo data seeded.</strong><br>
        Demo users password: <code><?= htmlspecialchars((string)($demoSeed['demo_password'] ?? 'DemoPass123!')) ?></code><br>
        <?php
          $demoEmails = [];
          if (!empty($demoSeed['users']) && is_array($demoSeed['users'])) {
              foreach ($demoSeed['users'] as $u) {
                  if (!empty($u['email'])) $demoEmails[] = (string)$u['email'];
              }
          }
          $demoEmails = array_values(array_unique($demoEmails));
          $sample = array_slice($demoEmails, 0, 5);
        ?>
        <?php if ($sample): ?>
          Example emails: <span class="auth-demo-examples"><?= htmlspecialchars(implode(', ', $sample)) ?></span>
          <?php if (count($demoEmails) > 5): ?>…<?php endif; ?>
        <?php else: ?>
          Example email: <span class="auth-demo-examples">kossi.mensah@example.com</span>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <div class="auth-stage" id="auth-stage">
      <form id="f" class="auth-form">
        <div class="field"><label><?php e('common.email'); ?></label>
          <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
        </div>
        <div class="field"><label><?php e('login.login_password'); ?></label>
          <input type="password" id="pwd" autocomplete="current-password" placeholder="••••••••" required>
        </div>
        <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?php e('login.btn'); ?></span></button>
      </form>

      <form id="totp-form" class="auth-form is-hidden">
        <div id="totp-info" class="auth-help"></div>
        <div class="field"><label><?php e('login.totp_code_label'); ?></label>
          <input type="text" id="totp-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required>
        </div>
        <div class="field"><label><?php e('login.totp_authenticator_label'); ?></label>
          <input type="text" id="totp-provider" autocomplete="off" placeholder="<?php e('login.totp_authenticator_placeholder'); ?>">
        </div>
        <button class="btn btn-primary" id="totp-verify-btn" type="submit"><span id="totp-verify-txt"><?php e('login.verify_code_btn'); ?></span></button>

        <div class="auth-btn-stack">
          <button class="btn btn-ghost" id="open-auth-btn" type="button"><?php e('login.open_authenticator'); ?></button>
          <button class="btn btn-ghost" id="totp-start-over" type="button"><?php e('login.start_over'); ?></button>
        </div>

        <div id="totp-last" class="auth-footnote is-hidden"></div>
      </form>
    </div>

    <div class="auth-alt" id="auth-alt">
      <button class="btn btn-ghost btn-passkey" id="passkey-btn" type="button">
        <?php e('login.use_passkey'); ?>
      </button>
      <div id="passkey-hint" class="auth-footnote auth-center is-hidden"></div>
    </div>

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
const totpForm=document.getElementById('totp-form');
const totpInfo=document.getElementById('totp-info');
const totpCode=document.getElementById('totp-code');
const totpProvider=document.getElementById('totp-provider');
const totpVerifyBtn=document.getElementById('totp-verify-btn');
const totpVerifyTxt=document.getElementById('totp-verify-txt');
const openAuthBtn=document.getElementById('open-auth-btn');
const totpStartOver=document.getElementById('totp-start-over');
const totpLast=document.getElementById('totp-last');

const err=document.getElementById('err');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const authAlt=document.getElementById('auth-alt');
const passkeyBtn=document.getElementById('passkey-btn');
const passkeyHint=document.getElementById('passkey-hint');
const links=document.querySelector('.links');

function hideEl(el){
  if(!el) return;
  el.classList.add('is-hidden');
}
function showEl(el){
  if(!el) return;
  el.classList.remove('is-hidden');
}

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

  totpInfo: <?= json_encode(t('login.totp_info')) ?>,
  enter6Digits: <?= json_encode(t('js.enter_6_digit_code')) ?>,
  verify: <?= json_encode(t('login.verify_code_btn')) ?>,
  openAuthenticatorHint: <?= json_encode(t('login.open_authenticator_hint')) ?>,
  lastUsed: <?= json_encode(t('login.last_used')) ?>,
  lastUsedPasskeyHint: <?= json_encode(t('login.last_used_passkey_hint')) ?>,
};

const STORAGE={
  lastMethod: 'ls_last_auth_method',
  lastTotpProvider: 'ls_last_totp_provider',
};

function fmt(s, vars){
  return String(s||'').replace(/\{(\w+)\}/g, (m,k)=>{
    const v = vars && Object.prototype.hasOwnProperty.call(vars, k) ? vars[k] : null;
    return (v == null) ? m : String(v);
  });
}

function toast(msg, type='ok'){
  if(window.LS && typeof window.LS.toast === 'function'){
    LS.toast(msg, type);
    return;
  }
  const t=document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = String(msg||'');
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3200);
}

function showErr(m){err.textContent=m;err.classList.add('show');}
function clearErr(){err.textContent='';err.classList.remove('show');}

let stage='creds';
function setStage(next){
  stage = next;

  if(stage === 'totp'){
    hideEl(f);
    showEl(totpForm);
    hideEl(authAlt);
    hideEl(links);
    setTimeout(()=>totpCode.focus(), 0);
    return;
  }

  showEl(f);
  hideEl(totpForm);
  showEl(authAlt);
  if(passkeyHint.textContent) showEl(passkeyHint);
  else hideEl(passkeyHint);
  showEl(links);
}

function rememberLast(method, provider){
  try{
    localStorage.setItem(STORAGE.lastMethod, String(method||''));
    if(typeof provider === 'string'){
      const p = provider.trim();
      if(p) localStorage.setItem(STORAGE.lastTotpProvider, p);
    }
  }catch{}
}

function applyLastHints(){
  try{
    const method = localStorage.getItem(STORAGE.lastMethod) || '';
    if(method === 'passkey'){
      passkeyHint.textContent = STR.lastUsedPasskeyHint;
      showEl(passkeyHint);
      return;
    }

    const p = localStorage.getItem(STORAGE.lastTotpProvider) || '';
    if(method === 'totp' && p){
      passkeyHint.textContent = fmt(STR.lastUsed, {name: p});
      showEl(passkeyHint);
      return;
    }
  }catch{}

  passkeyHint.textContent = '';
  hideEl(passkeyHint);
}

applyLastHints();

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

function setupTotpStage(payload){
  totpInfo.textContent = STR.totpInfo;
  totpCode.value = '';

  let provider = '';
  try{ provider = localStorage.getItem(STORAGE.lastTotpProvider) || ''; }catch{}

  if(payload && typeof payload.totp_provider === 'string' && payload.totp_provider.trim()){
    provider = payload.totp_provider.trim();
  }
  totpProvider.value = provider;

  if(provider){
    totpLast.textContent = fmt(STR.lastUsed, {name: provider});
    showEl(totpLast);
  }else{
    totpLast.textContent = '';
    hideEl(totpLast);
  }

  setStage('totp');
}

async function doPasswordLogin(e){
  e.preventDefault();
  if(stage !== 'creds') return;
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
      setupTotpStage(j);
      return;
    }

    rememberLast('password');

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

async function doTotpVerify(e){
  e.preventDefault();
  if(stage !== 'totp') return;
  clearErr();

  const code = (totpCode.value || '').trim().replace(/\s+/g,'');
  if(!/^\d{6}$/.test(code)){
    showErr(STR.enter6Digits);
    totpCode.focus();
    return;
  }

  totpVerifyBtn.disabled = true;
  totpVerifyTxt.innerHTML = '<span class="spin"></span>';

  const provider = (totpProvider.value || '').trim();

  try{
    const r2=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login_totp',code,provider})});
    const j2=await r2.json();

    if(!j2.success){
      const msg = j2.error || STR.failed;
      showErr(msg);
      if(/expired/i.test(msg)){
        setStage('creds');
      } else {
        totpCode.select();
        totpCode.focus();
      }
      return;
    }

    rememberLast('totp', provider);

    if(j2.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr(STR.networkError);
  }finally{
    totpVerifyBtn.disabled = false;
    totpVerifyTxt.textContent = STR.verify;
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

    rememberLast('passkey');

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

openAuthBtn.addEventListener('click', ()=>{
  toast(STR.openAuthenticatorHint, 'ok');
  totpCode.focus();
});

totpStartOver.addEventListener('click', ()=>{
  clearErr();
  setStage('creds');
});

totpCode.addEventListener('input', ()=>{
  const c = (totpCode.value || '').replace(/\s+/g,'');
  if(c.length === 6) totpCode.value = c;
});

totpForm.addEventListener('submit', doTotpVerify);
f.addEventListener('submit', doPasswordLogin);
passkeyBtn.addEventListener('click', doPasskeyLogin);
</script>
</body>
</html> 
