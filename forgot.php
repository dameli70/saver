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
<title>Reset password — LOCKSMITH</title>
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
.box{width:100%;max-width:460px;background:var(--s1);border:1px solid var(--b1);padding:22px 22px 18px;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:28px;margin-bottom:4px;}
.logo span{color:var(--accent);} 
.sub{color:var(--muted);font-size:11px;letter-spacing:2px;text-transform:uppercase;margin-bottom:18px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:14px;}
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
.msg{display:none;margin-bottom:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.links{display:flex;justify-content:space-between;gap:10px;margin-top:14px;font-size:11px;color:var(--muted);} 
.links a{color:var(--text);text-decoration:none;border-bottom:1px solid transparent;}
.links a:hover{border-bottom-color:var(--text);} 
.dev{margin-top:12px;border:1px dashed rgba(255,170,0,.35);background:rgba(255,170,0,.06);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;display:none;}
.dev a{color:var(--orange);} 
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
  <div class="box">
    <div class="logo">LOCK<span>SMITH</span></div>
    <div class="sub">// Password reset</div>

    <div class="p">We’ll email you a reset link for your <strong>login password</strong>. Your vault passphrase is never recoverable.</div>

    <div id="ok" class="msg msg-ok"></div>
    <div id="err" class="msg msg-err"></div>
    <div id="dev" class="dev"></div>

    <form id="f">
      <div class="field"><label>Email</label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt">Send reset link</span></button>
    </form>

    <div class="links">
      <a href="login.php">Back to login</a>
      <a href="index.php">Home</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const ok=document.getElementById('ok');
const err=document.getElementById('err');
const dev=document.getElementById('dev');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');

function show(el,m){el.textContent=m;el.classList.add('show');}
function clear(){[ok,err].forEach(e=>{e.textContent='';e.classList.remove('show');});dev.style.display='none';dev.textContent='';}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clear();

  const email=document.getElementById('email').value.trim();
  if(!email){show(err,'Email required');return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/password_reset.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'request',email})});
    const j=await r.json();
    if(!j.success){show(err,j.error||'Request failed');return;}

    show(ok,'If that email exists, a reset link has been sent.');

    if(j.dev_reset_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Reset link: <br><a href="'+j.dev_reset_url+'">'+j.dev_reset_url+'</a>';
    }
  }catch{
    show(err,'Network error');
  }finally{
    btn.disabled=false;
    btnTxt.textContent='Send reset link';
  }
});
</script>
</body>
</html>
