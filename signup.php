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
<title>Create account — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:max(40px,var(--sat)) 18px max(40px,var(--sab));}
.box{width:100%;max-width:520px;background:var(--s1);border:1px solid var(--b1);padding:22px 22px 18px;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:4px;}
.logo span{color:var(--accent);} 
.sub{color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;}
.callout{background:rgba(71,255,176,.05);border:1px solid rgba(71,255,176,.14);padding:12px 14px;margin:14px 0 16px;color:var(--muted);font-size:11px;line-height:1.7;}
.callout strong{color:var(--green);} 
.field{margin-bottom:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);
  font-size:15px;padding:14px;outline:none;transition:border-color .2s;border-radius:0;-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.note{font-size:10px;color:var(--muted);margin-top:6px;line-height:1.6;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;width:100%;
  padding:14px 18px;font-family:var(--mono);font-size:12px;letter-spacing:2px;text-transform:uppercase;
  cursor:pointer;border:none;transition:all .15s;border-radius:0;-webkit-appearance:none;min-height:48px;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-primary:disabled{opacity:.45;pointer-events:none;}
.msg{display:none;margin-bottom:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.links{display:flex;justify-content:space-between;gap:10px;margin-top:14px;font-size:11px;color:var(--muted);} 
.links a{color:var(--text);text-decoration:none;border-bottom:1px solid transparent;}
.links a:hover{border-bottom-color:var(--text);} 
.dev{margin-top:12px;border:1px dashed rgba(255,170,0,.35);background:rgba(255,170,0,.06);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;}
.dev a{color:var(--orange);} 
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
  <div class="box">
    <div class="logo">LOCK<span>SMITH</span></div>
    <div class="sub">// Create account</div>

    <div class="callout">
      Your <strong>login password</strong> authenticates you to this site.<br>
      Your <strong>vault passphrase</strong> is used only in your browser to encrypt/decrypt codes and is never stored by the server — you will enter it when you generate or reveal codes.
    </div>

    <div id="err" class="msg msg-err"></div>
    <div id="ok" class="msg msg-ok"></div>

    <form id="f">
      <div class="field"><label>Email</label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
      </div>
      <div class="field"><label>Login Password <span style="color:var(--muted)">(min 8 chars)</span></label>
        <input type="password" id="pwd" autocomplete="new-password" placeholder="••••••••" required>
      </div>
      <div class="field"><label>Vault Passphrase <span style="color:var(--muted)">(min 10 chars)</span></label>
        <input type="password" id="vault" autocomplete="new-password" placeholder="Something memorable only you know" required>
        <div class="note">Write this down somewhere physical. If you lose it, your codes cannot be recovered.</div>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt">Create account</span></button>
    </form>

    <div id="dev" class="dev" style="display:none"></div>

    <div class="links">
      <a href="index.php">Home</a>
      <a href="login.php">I already have an account</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const ok=document.getElementById('ok');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');
const dev=document.getElementById('dev');

function showErr(m){err.textContent=m;err.classList.add('show');}
function showOk(m){ok.textContent=m;ok.classList.add('show');}
function clearMsgs(){err.textContent='';ok.textContent='';err.classList.remove('show');ok.classList.remove('show');}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clearMsgs();

  const email=document.getElementById('email').value.trim();
  const pwd=document.getElementById('pwd').value;

  if(!email||!pwd){showErr('Fill in all fields');return;}
  if(pwd.length<8){showErr('Login password must be at least 8 characters');return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'register',email,login_password:pwd})});
    const j=await r.json();
    if(!j.success){showErr(j.error||'Registration failed');return;}

    showOk('Account created. Check your email to verify before using the dashboard.');

    if(j.dev_verify_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Email sending is often disabled locally. Use this verification link: <br><a href="'+j.dev_verify_url+'">'+j.dev_verify_url+'</a>';
    }

    setTimeout(()=>{window.location='account.php';}, 900);

  }catch{
    showErr('Network error');
  }finally{
    btn.disabled=false;
    btnTxt.textContent='Create account';
  }
});
</script>
</body>
</html>
