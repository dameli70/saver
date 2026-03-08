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

$email = strtolower(trim((string)($_GET['email'] ?? '')));
$token = trim((string)($_GET['token'] ?? ''));

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
<title>Choose new password — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<script src="assets/theme.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/auth.css">
<style>
</style>
</head>
<body>
  <button class="theme-toggle" type="button" data-theme-toggle></button>
  <div class="box">
    <div class="logo">LOCK<span>SMITH</span></div>
    <div class="sub">// Choose new login password</div>

    <div id="err" class="msg msg-err"></div>


    <form id="f">
      <input type="hidden" id="email" value="<?= htmlspecialchars($email) ?>">
      <input type="hidden" id="token" value="<?= htmlspecialchars($token) ?>">

      <div class="field"><label>New login password</label>
        <input type="password" id="p1" autocomplete="new-password" placeholder="••••••••" required>
      </div>
      <div class="field"><label>Confirm new password</label>
        <input type="password" id="p2" autocomplete="new-password" placeholder="••••••••" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt">Reset password</span></button>
    </form>

    <div class="links">
      <a href="login.php">Back to login</a>
      <a href="index.php">Home</a>
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
  const token=document.getElementById('token').value.trim();
  const p1=document.getElementById('p1').value;
  const p2=document.getElementById('p2').value;

  if(!email||!token){showErr('Invalid reset link');return;}
  if(p1.length<8){showErr('Password must be at least 8 characters');return;}
  if(p1!==p2){showErr('Passwords do not match');return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/password_reset.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'reset',email,token,new_password:p1})});
    const j=await r.json();
    if(!j.success){showErr(j.error||'Reset failed');return;}

    if(j.verified){window.location='dashboard.php';}
    else window.location='account.php';

  }catch{
    showErr('Network error');
  }finally{
    btn.disabled=false;
    btnTxt.textContent='Reset password';
  }
});
</script>
</body>
</html>
