<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

$userId = getCurrentUserId();
$db     = getDB();
$stmt   = $db->prepare("SELECT email, email_verified_at, verification_sent_at FROM users WHERE id = ?");
$stmt->execute([$userId]);
$u = $stmt->fetch();

if (!$u) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

$verified = !empty($u['email_verified_at']);
$_SESSION['email_verified'] = $verified ? 1 : 0;
$isAdmin = isAdmin();

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
<title>Account — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.wrap{max-width:760px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;margin-bottom:14px;}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
.k{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;}
.v{color:var(--text);font-size:12px;letter-spacing:.4px;}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;border:1px solid;}
.badge.ok{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);} 
.badge.wait{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);} 
.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.dev{margin-top:12px;border:1px dashed rgba(255,170,0,.35);background:rgba(255,170,0,.06);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;display:none;}
.dev a{color:var(--orange);} 
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
  <div class="nav">
    <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
    <div class="nav-r">
      <?php if ($verified): ?>
        <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
        <?php if ($isAdmin): ?>
          <a class="btn btn-ghost" href="admin.php">Admin</a>
        <?php endif; ?>
      <?php endif; ?>
      <a class="btn btn-ghost" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="wrap">
    <div class="h">Account</div>
    <div class="p">Your email must be verified before you can generate or reveal codes.</div>

    <div class="card">
      <div class="row">
        <div>
          <div class="k">Email</div>
          <div class="v"><?= htmlspecialchars($u['email']) ?></div>
        </div>
        <?php if ($verified): ?>
          <div class="badge ok">✓ Verified</div>
        <?php else: ?>
          <div class="badge wait">⏳ Pending</div>
        <?php endif; ?>
      </div>

      <?php if (!$verified): ?>
      <div style="margin-top:14px;color:var(--muted);font-size:12px;line-height:1.7;">
        We sent a verification email. If you don’t see it, check spam/junk. You can resend it below.
      </div>

      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-primary" id="resend"><span id="resend-txt">Resend verification email</span></button>
        <a class="btn btn-ghost" href="logout.php">Use a different email</a>
      </div>

      <div id="msg-ok" class="msg msg-ok"></div>
      <div id="msg-err" class="msg msg-err"></div>
      <div id="dev" class="dev"></div>
      <?php else: ?>
      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="dashboard.php">Go to dashboard</a>
        <a class="btn btn-ghost" href="index.php">Home</a>
      </div>
      <?php endif; ?>
    </div>
  </div>

<?php if (!$verified): ?>
<script>
const btn=document.getElementById('resend');
const btnTxt=document.getElementById('resend-txt');
const ok=document.getElementById('msg-ok');
const err=document.getElementById('msg-err');
const dev=document.getElementById('dev');

function show(el,m){el.textContent=m;el.classList.add('show');}
function clear(){[ok,err].forEach(e=>{e.textContent='';e.classList.remove('show');});dev.style.display='none';dev.textContent='';}

btn.addEventListener('click', async ()=>{
  clear();
  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'resend_verification'})});
    const j=await r.json();
    if(!j.success){show(err,j.error||'Failed to resend');return;}
    show(ok,'Verification email sent.');
    if(j.dev_verify_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Verification link: <br><a href="'+j.dev_verify_url+'">'+j.dev_verify_url+'</a>';
    }
  }catch{
    show(err,'Network error');
  }finally{
    btn.disabled=false;
    btnTxt.textContent='Resend verification email';
  }
});
</script>
<?php endif; ?>
</body>
</html>
