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
<html lang="<?= htmlspecialchars(getCurrentLang()) ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(t('auth.reset_request.title')) ?> — <?= htmlspecialchars(APP_NAME) ?></title>
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
  <button class="theme-toggle" type="button" data-theme-toggle><?= htmlspecialchars(t('nav.theme')) ?></button>
  <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub">// <?= htmlspecialchars(t('auth.reset_request.subtitle')) ?></div>

    <div class="p"><?= t('auth.reset_request.desc') ?></div>

    <div id="ok" class="msg msg-ok"></div>
    <div id="err" class="msg msg-err"></div>
    <div id="dev" class="dev"></div>

    <form id="f">
      <div class="field"><label><?= htmlspecialchars(t('field.email')) ?></label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="<?= htmlspecialchars(t('placeholder.email')) ?>" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?= htmlspecialchars(t('auth.reset_request.send')) ?></span></button>
    </form>

    <div class="links">
      <a href="login.php"><?= htmlspecialchars(t('auth.reset_request.back')) ?></a>
      <a href="index.php"><?= htmlspecialchars(t('nav.home')) ?></a>
    </div>

    <div class="links" style="justify-content:center;gap:14px;">
      <?php $lang = getCurrentLang(); ?>
      <a href="<?= htmlspecialchars(langUrl('fr')) ?>" class="<?= ($lang === 'fr') ? 'btn-lang-active' : '' ?>">FR</a>
      <a href="<?= htmlspecialchars(langUrl('en')) ?>" class="<?= ($lang === 'en') ? 'btn-lang-active' : '' ?>">EN</a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const ok=document.getElementById('ok');
const err=document.getElementById('err');
const dev=document.getElementById('dev');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');

const TXT = <?= json_encode([
  'email_required' => t('js.email_required'),
  'request_failed' => t('js.request_failed'),
  'reset_link_sent_if_exists' => t('js.reset_link_sent_if_exists'),
  'network_error' => t('js.network_error'),
  'send_reset_link' => t('auth.reset_request.send'),
], JSON_UNESCAPED_UNICODE) ?>;

function show(el,m){el.textContent=m;el.classList.add('show');}
function clear(){[ok,err].forEach(e=>{e.textContent='';e.classList.remove('show');});dev.style.display='none';dev.textContent='';}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clear();

  const email=document.getElementById('email').value.trim();
  if(!email){show(err,TXT.email_required);return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/password_reset.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'request',email})});
    const j=await r.json();
    if(!j.success){show(err,j.error||TXT.request_failed);return;}

    show(ok,TXT.reset_link_sent_if_exists);

    if(j.dev_reset_url){
      dev.style.display='block';
      dev.innerHTML='DEV: Reset link: <br><a href="'+j.dev_reset_url+'">'+j.dev_reset_url+'</a>';
    }
  }catch{
    show(err,TXT.network_error);
  }finally{
    btn.disabled=false;
    btnTxt.textContent=TXT.send_reset_link;
  }
});
</script>
</body>
</html>
