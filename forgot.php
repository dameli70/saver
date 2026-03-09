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
<title>Reset password — <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/auth.css">
<style>
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:14px;}
.dev{margin-top:12px;border:1px dashed rgba(255,170,0,.35);background:rgba(255,170,0,.06);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;display:none;}
.dev a{color:var(--orange);} 
</style>
</head>
<body>
  <button class="theme-toggle" type="button" data-theme-toggle>Theme</button>
  <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
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
