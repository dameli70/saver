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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Login — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:max(40px,var(--sat)) 18px max(40px,var(--sab));}
.box{width:100%;max-width:420px;background:var(--s1);border:1px solid var(--b1);padding:22px 22px 18px;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:4px;}
.logo span{color:var(--accent);} 
.sub{color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.field{margin-bottom:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);
  font-size:15px;padding:14px;outline:none;transition:border-color .2s;border-radius:0;-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;
  padding:14px 18px;font-family:var(--mono);font-size:12px;letter-spacing:2px;text-transform:uppercase;
  cursor:pointer;border:none;transition:all .15s;border-radius:0;-webkit-appearance:none;min-height:48px;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:disabled{opacity:.45;pointer-events:none;}
.msg{display:none;margin-bottom:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;
  background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);}
.msg.show{display:block;}
.links{display:flex;justify-content:space-between;gap:10px;margin-top:14px;font-size:11px;color:var(--muted);} 
.links a{color:var(--text);text-decoration:none;border-bottom:1px solid transparent;}
.links a:hover{border-bottom-color:var(--text);} 
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
  <div class="box">
    <div class="logo">LOCK<span>SMITH</span></div>
    <div class="sub">// Login</div>

    <div id="err" class="msg"></div>

    <form id="f">
      <div class="field"><label>Email</label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
      </div>
      <div class="field"><label>Login Password</label>
        <input type="password" id="pwd" autocomplete="current-password" placeholder="••••••••" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt">Login</span></button>
    </form>

    <div style="height:10px"></div>

    <button class="btn btn-primary" id="passkey-btn" type="button" style="background:transparent;border:1px solid var(--b2);color:var(--text);">
      Use passkey
    </button>

    <div class="links">
      <a href="index.php">Home</a>
      <a href="forgot.php">Forgot password</a>
      <a href="signup.php">Create account</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const passkeyBtn=document.getElementById('passkey-btn');

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
  if(!email||!pwd){showErr('Email and password required');return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login',email,login_password:pwd})});
    const j=await r.json();

    if(!j.success){
      if(j.error_code==='passkey_required'){
        showErr('This account requires a passkey. Use the passkey button below.');
        return;
      }
      showErr(j.error||'Login failed');
      return;
    }

    if(j.needs_totp){
      const code = prompt('Enter your 6-digit authenticator code');
      if(!code){showErr('Code required');return;}

      const r2=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({action:'login_totp',code})});
      const j2=await r2.json();
      if(!j2.success){showErr(j2.error||'Login failed');return;}

      if(j2.verified){window.location='dashboard.php';}
      else window.location='account.php';
      return;
    }

    if(j.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr('Network error');
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    btnTxt.textContent='Login';
  }
}

async function doPasskeyLogin(){
  clearErr();
  if(!window.PublicKeyCredential){showErr('Passkeys not supported in this browser');return;}

  btn.disabled=true;
  passkeyBtn.disabled=true;
  passkeyBtn.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/webauthn.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login_begin'})});
    const j=await r.json();
    if(!j.success){showErr(j.error||'Passkey failed');return;}

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
    if(!j2.success){showErr(j2.error||'Passkey login failed');return;}

    if(j2.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch(e){
    showErr((e && e.message) ? e.message : 'Passkey login failed');
  }finally{
    btn.disabled=false;
    passkeyBtn.disabled=false;
    passkeyBtn.textContent='Use passkey';
  }
}

f.addEventListener('submit', doPasswordLogin);
passkeyBtn.addEventListener('click', doPasskeyLogin);
</script>
</body>
</html>
