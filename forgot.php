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
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.forgot')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
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
  <a class="lang-toggle fr<?= currentLang() === 'fr' ? ' active' : '' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_fr'); ?></a>
  <a class="lang-toggle en<?= currentLang() === 'en' ? ' active' : '' ?>" href="<?= htmlspecialchars(langSwitchUrl('en'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_en'); ?></a>
  <button class="theme-toggle" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
  <div class="box">
    <div class="logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="sub"><?php e('forgot.subtitle'); ?></div>

    <div class="p"><?= t('forgot.intro_html'); ?></div>

    <div id="ok" class="msg msg-ok"></div>
    <div id="err" class="msg msg-err"></div>
    <div id="dev" class="dev"></div>

    <form id="f">
      <div class="field"><label><?php e('common.email'); ?></label>
        <input type="email" id="email" autocomplete="email" inputmode="email" placeholder="you@example.com" required>
      </div>
      <button class="btn btn-primary" id="btn" type="submit"><span id="btn-txt"><?php e('forgot.send_link'); ?></span></button>
    </form>

    <div class="links">
      <a href="login.php"><?php e('forgot.back_to_login'); ?></a>
      <a href="index.php"><?php e('common.home'); ?></a>
    </div>
  </div>

<script>
const f=document.getElementById('f');
const ok=document.getElementById('ok');
const err=document.getElementById('err');
const dev=document.getElementById('dev');
const btn=document.getElementById('btn');
const btnTxt=document.getElementById('btn-txt');

const STR={
  emailRequired: <?= json_encode(t('forgot.email_required')) ?>,
  requestFailed: <?= json_encode(t('forgot.request_failed')) ?>,
  sentGeneric: <?= json_encode(t('forgot.sent_generic')) ?>,
  networkError: <?= json_encode(t('common.network_error')) ?>,
  sendLink: <?= json_encode(t('forgot.send_link')) ?>,
};

function show(el,m){el.textContent=m;el.classList.add('show');}
function clear(){[ok,err].forEach(e=>{e.textContent='';e.classList.remove('show');});dev.style.display='none';dev.textContent='';}

f.addEventListener('submit', async (e)=>{
  e.preventDefault();
  clear();

  const email=document.getElementById('email').value.trim();
  if(!email){show(err, STR.emailRequired);return;}

  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/password_reset.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'request',email})});
    const j=await r.json();
    if(!j.success){show(err,j.error||STR.requestFailed);return;}

    show(ok, STR.sentGeneric);

    if(j.dev_reset_url){
      dev.style.display='block';
      dev.textContent='';
      dev.appendChild(document.createTextNode(<?= json_encode(t('forgot.dev_reset_link')) ?>));
      dev.appendChild(document.createElement('br'));
      const a=document.createElement('a');
      a.href=String(j.dev_reset_url);
      a.textContent=String(j.dev_reset_url);
      dev.appendChild(a);
    }
  }catch{
    show(err, STR.networkError);
  }finally{
    btn.disabled=false;
    btnTxt.textContent=STR.sendLink;
  }
});
</script>
</body>
</html> 
