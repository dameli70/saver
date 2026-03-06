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

$hasPhotoCol = false;
try {
    $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'profile_photo' LIMIT 1");
    $hasPhotoCol = (bool)$stmt->fetchColumn();
} catch (Throwable) {
    $hasPhotoCol = false;
}

$sel = 'email, email_verified_at, verification_sent_at' . ($hasPhotoCol ? ', profile_photo' : ", '' AS profile_photo");
$stmt = $db->prepare("SELECT {$sel} FROM users WHERE id = ?");
$stmt->execute([(int)$userId]);
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
$csrf    = getCsrfToken();
$appBaseUrl = getAppBaseUrl();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Profile — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<link rel="manifest" href="manifest.webmanifest">
<meta name="theme-color" content="#06070a">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--green:#47ffb0;--orange:#ffaa00;--text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
  --r:14px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;}
a{color:inherit;}
.nav{display:flex;align-items:center;justify-content:space-between;padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);position:sticky;top:0;}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:var(--r);
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-red{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 

.wrap{max-width:940px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.grid{display:grid;grid-template-columns:1fr;gap:12px;}
@media(min-width:920px){.grid{grid-template-columns:1fr 1fr;}}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;border-radius:var(--r);}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
.k{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;}
.v{color:var(--text);font-size:12px;letter-spacing:.4px;}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;border:1px solid;border-radius:999px;}
.badge.ok{background:rgba(71,255,176,.07);border-color:rgba(71,255,176,.2);color:var(--green);} 
.badge.wait{background:rgba(255,170,0,.07);border-color:rgba(255,170,0,.2);color:var(--orange);} 
.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;border-radius:var(--r);}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 
.field{margin-top:14px;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);
  font-size:15px;padding:14px;outline:none;transition:border-color .2s;border-radius:var(--r);-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.hr{border-top:1px solid var(--b1);margin:16px 0;}
.list{margin-top:10px;display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:rgba(19,22,29,.55);padding:12px 14px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;border-radius:var(--r);}
.small{font-size:11px;color:var(--muted);line-height:1.6;}
code{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);padding:2px 6px;border-radius:8px;}
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.35);border-top-color:#000;border-radius:50%;animation:spin .5s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}

.avatar{display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
.avatar-img{width:64px;height:64px;border-radius:18px;border:1px solid var(--b1);background:rgba(0,0,0,.35);object-fit:cover;}
</style>
</head>
<body>
  <div class="nav">
    <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
    <div class="nav-r">
      <?php if ($verified): ?>
        <a class="btn btn-ghost" href="dashboard.php">Dashboard</a>
        <a class="btn btn-ghost" href="codes.php">Codes</a>
        <a class="btn btn-ghost" href="backup.php">Backups</a>
        <a class="btn btn-ghost" href="security.php">Security</a>
        <?php if ($isAdmin): ?><a class="btn btn-ghost" href="admin.php">Admin</a><?php endif; ?>
      <?php endif; ?>
      <a class="btn btn-ghost" href="faq.php">FAQ</a>
      <a class="btn btn-ghost" href="logout.php">Logout</a>
    </div>
  </div>

  <div class="wrap">
    <div class="h">Profile</div>
    <div class="p">Account basics and device sessions.</div>

    <div class="grid">
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
          We sent a verification email. If you don’t see it, check spam/junk.
        </div>

        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-primary" id="resend"><span id="resend-txt">Resend verification email</span></button>
          <a class="btn btn-ghost" href="logout.php">Use a different email</a>
        </div>

        <div id="msg-ok" class="msg msg-ok"></div>
        <div id="msg-err" class="msg msg-err"></div>
        <div id="dev" class="small" style="margin-top:12px;display:none;"></div>
        <?php else: ?>
        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
          <a class="btn btn-primary" href="dashboard.php">Go to dashboard</a>
          <a class="btn btn-ghost" href="security.php">Security settings</a>
        </div>
        <?php endif; ?>
      </div>

      <div class="card">
        <div class="k" style="margin-bottom:8px;">Mobile app base URL</div>
        <div class="small">Use this in the Android app settings:</div>
        <div style="margin-top:10px;"><code><?= htmlspecialchars($appBaseUrl) ?></code></div>
        <div class="small" style="margin-top:10px;">If this is wrong, set <code>APP_BASE_URL</code> in <code>config/database.php</code>.</div>
      </div>

      <div class="card">
        <div class="k" style="margin-bottom:8px;">Profile picture</div>
        <?php if (!$hasPhotoCol): ?>
          <div class="small">Unavailable (missing migrations). Apply migrations in <code>config/migrations/</code>.</div>
        <?php else: ?>
          <div class="avatar">
            <img class="avatar-img" id="avatar" alt="Profile" src="<?= $u['profile_photo'] ? htmlspecialchars((string)$u['profile_photo']) : 'assets/icon-192.svg' ?>">
            <div style="flex:1;min-width:220px;">
              <div class="small">PNG/JPG/WEBP, max 2MB.</div>
              <div style="height:10px"></div>
              <input type="file" id="photo" accept="image/png,image/jpeg,image/webp" style="color:var(--muted)">
              <div style="height:10px"></div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <button class="btn btn-primary" id="photo-upload"><span id="photo-upload-txt">Upload</span></button>
                <button class="btn btn-red" id="photo-del" type="button">Remove</button>
              </div>
              <div id="photo-ok" class="msg msg-ok"></div>
              <div id="photo-err" class="msg msg-err"></div>
            </div>
          </div>
        <?php endif; ?>
      </div>

      <div class="card">
        <div class="k" style="margin-bottom:8px;">Change login password</div>
        <form id="pw-form">
          <div class="field"><label>Current password</label><input id="pw-cur" type="password" autocomplete="current-password" placeholder="••••••••" required></div>
          <div class="field"><label>New password</label><input id="pw-new" type="password" autocomplete="new-password" placeholder="min 8 chars" required></div>
          <div class="field"><label>Confirm new password</label><input id="pw-new2" type="password" autocomplete="new-password" placeholder="repeat new password" required></div>
          <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
            <button class="btn btn-primary" id="pw-btn" type="submit"><span id="pw-btn-txt">Update password</span></button>
          </div>
          <div id="pw-ok" class="msg msg-ok"></div>
          <div id="pw-err" class="msg msg-err"></div>
        </form>
      </div>

      <div class="card">
        <div class="row">
          <div>
            <div class="k">Active sessions</div>
            <div class="small">If you changed devices or suspect a stolen cookie, log out everywhere.</div>
          </div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button class="btn btn-ghost" id="sess-refresh" type="button">Refresh</button>
            <button class="btn btn-red" id="logout-all" type="button">Logout all</button>
          </div>
        </div>

        <div id="sess" class="list"></div>
        <div id="sess-err" class="msg msg-err"></div>
      </div>

    </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;

function show(el,m){el.textContent=m;el.classList.add('show');}
function clearMsg(el){el.textContent='';el.classList.remove('show');}

async function postCsrf(url, body){
  const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}

<?php if (!$verified): ?>
const resend=document.getElementById('resend');
const resendTxt=document.getElementById('resend-txt');
const ok=document.getElementById('msg-ok');
const err=document.getElementById('msg-err');
const dev=document.getElementById('dev');

function clearResend(){[ok,err].forEach(e=>{e.textContent='';e.classList.remove('show');});dev.style.display='none';dev.textContent='';}

resend.addEventListener('click', async ()=>{
  clearResend();
  resend.disabled=true;
  resendTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'resend_verification'})});
    const j=await r.json();
    if(!j.success){show(err,j.error||'Failed to resend');return;}
    show(ok,'Verification email sent.');
    if(j.dev_verify_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Verification link: <br><a href="'+j.dev_verify_url+'" style="color:var(--orange)">'+j.dev_verify_url+'</a>';
    }
  }catch{
    show(err,'Network error');
  }finally{
    resend.disabled=false;
    resendTxt.textContent='Resend verification email';
  }
});
<?php endif; ?>

// Password change
const pwForm=document.getElementById('pw-form');
if(pwForm){
  const ok=document.getElementById('pw-ok');
  const err=document.getElementById('pw-err');
  const btn=document.getElementById('pw-btn');
  const btnTxt=document.getElementById('pw-btn-txt');

  pwForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    clearMsg(ok); clearMsg(err);

    const cur=document.getElementById('pw-cur').value;
    const p1=document.getElementById('pw-new').value;
    const p2=document.getElementById('pw-new2').value;

    if(!cur||!p1||!p2){show(err,'Fill in all fields');return;}
    if(p1.length<8){show(err,'New password must be at least 8 characters');return;}
    if(p1!==p2){show(err,'Passwords do not match');return;}

    btn.disabled=true;
    btnTxt.innerHTML='<span class="spin"></span>';

    try{
      const j=await postCsrf('api/account.php',{action:'change_login_password',current_password:cur,new_password:p1});
      if(!j.success){show(err,j.error||'Update failed');return;}
      show(ok,'Login password updated.');
      pwForm.reset();
    }catch{
      show(err,'Network error');
    }finally{
      btn.disabled=false;
      btnTxt.textContent='Update password';
    }
  });
}

// Sessions
async function loadSessions(){
  const wrap=document.getElementById('sess');
  const err=document.getElementById('sess-err');
  if(!wrap||!err) return;
  clearMsg(err);
  wrap.innerHTML='<div class="small">Loading…</div>';

  try{
    const j=await postCsrf('api/account.php',{action:'sessions'});
    if(!j.success){show(err,j.error||'Failed to load sessions');wrap.innerHTML='';return;}

    if(!j.sessions||!j.sessions.length){
      wrap.innerHTML='<div class="small">No tracked sessions yet (apply migrations to enable session tracking).</div>';
      return;
    }

    wrap.innerHTML='';
    j.sessions.forEach(s=>{
      const el=document.createElement('div');
      el.className='item';
      const cur=s.is_current?'<span style="color:var(--green)">CURRENT</span>':'<span style="color:var(--muted)">OTHER</span>';
      const ua=(s.user_agent||'').slice(0,160);
      el.innerHTML=`
        <div>
          <div class="small">${cur} · Last seen: <span style="color:var(--text)">${s.last_seen_at||''}</span></div>
          <div class="small">IP: <span style="color:var(--text)">${s.ip_address||''}</span></div>
          <div class="small">UA: <span style="color:var(--text)">${ua}</span></div>
        </div>
        <div class="small">Created: <span style="color:var(--text)">${s.created_at||''}</span></div>
      `;
      wrap.appendChild(el);
    });
  }catch{
    show(err,'Network error');
    wrap.innerHTML='';
  }
}

const logoutAll=document.getElementById('logout-all');
if(logoutAll){
  logoutAll.addEventListener('click', async ()=>{
    if(!confirm('Log out all sessions (including this one)?')) return;
    logoutAll.disabled=true;
    try{
      const j=await postCsrf('api/account.php',{action:'logout_all_sessions'});
      if(j.success){window.location='login.php';}
      else alert(j.error||'Failed');
    }catch{
      alert('Network error');
    }finally{
      logoutAll.disabled=false;
    }
  });
}

const sessRefresh=document.getElementById('sess-refresh');
if(sessRefresh){sessRefresh.addEventListener('click', loadSessions);}
loadSessions();

// Profile photo
<?php if ($hasPhotoCol): ?>
const photoOk=document.getElementById('photo-ok');
const photoErr=document.getElementById('photo-err');
const avatar=document.getElementById('avatar');

function clearPhotoMsgs(){[photoOk,photoErr].forEach(clearMsg);}

document.getElementById('photo-upload')?.addEventListener('click', async ()=>{
  clearPhotoMsgs();
  const fileInput=document.getElementById('photo');
  if(!fileInput.files || !fileInput.files[0]){show(photoErr,'Select an image.');return;}

  const btn=document.getElementById('photo-upload');
  const txt=document.getElementById('photo-upload-txt');
  btn.disabled=true;
  txt.innerHTML='<span class="spin"></span>';

  try{
    const fd=new FormData();
    fd.append('photo', fileInput.files[0]);
    const r=await fetch('api/profile.php',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':CSRF},body:fd});
    const j=await r.json();
    if(!j.success){show(photoErr,j.error||'Upload failed');return;}
    avatar.src = j.profile_photo + '?t=' + Date.now();
    fileInput.value='';
    show(photoOk,'Uploaded.');
  }catch{
    show(photoErr,'Network error');
  }finally{
    btn.disabled=false;
    txt.textContent='Upload';
  }
});

document.getElementById('photo-del')?.addEventListener('click', async ()=>{
  clearPhotoMsgs();
  if(!confirm('Remove profile picture?')) return;
  try{
    const j=await postCsrf('api/profile.php',{action:'delete_photo'});
    if(!j.success){show(photoErr,j.error||'Failed');return;}
    avatar.src = 'assets/icon-192.svg';
    show(photoOk,'Removed.');
  }catch{
    show(photoErr,'Network error');
  }
});
<?php endif; ?>

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}
</script>
</body>
</html>
