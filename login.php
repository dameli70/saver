<?php
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

    <div class="links">
      <a href="index.php">Home</a>
      <a href="signup.php">Create account</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const err=document.getElementById('err');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');

function showErr(m){err.textContent=m;err.classList.add('show');}
function clearErr(){err.textContent='';err.classList.remove('show');}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clearErr();

  const email=document.getElementById('email').value.trim();
  const pwd=document.getElementById('pwd').value;
  if(!email||!pwd){showErr('Email and password required');return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'login',email,login_password:pwd})});
    const j=await r.json();
    if(!j.success){showErr(j.error||'Login failed');return;}

    if(j.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr('Network error');
  }finally{
    btn.disabled=false;
    btnTxt.textContent='Login';
  }
});
</script>
</body>
</html>
