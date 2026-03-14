<?php
require_once __DIR__ . '/includes/security_page.php';
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.security_password')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script>window.LS_SECURITY={csrf:<?= json_encode($csrf) ?>};</script>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<script src="assets/security.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/security_page.css">
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.security_password'); ?></div>
        <div class="page-sub"><?php e('account.change_login_password_title'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="security.php"><?php e('common.back'); ?></a>
      </div>
    </div>

    <div class="card">
      <form id="pw-form">
        <div class="field"><label><?php e('account.current_password_label'); ?></label><input id="pw-cur" type="password" autocomplete="current-password" placeholder="<?= htmlspecialchars(t('account.current_password_placeholder'), ENT_QUOTES, 'UTF-8') ?>" required></div>
        <div class="field"><label><?php e('account.new_password_label'); ?></label><input id="pw-new" type="password" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('account.new_password_placeholder'), ENT_QUOTES, 'UTF-8') ?>" required></div>
        <div class="field"><label><?php e('account.confirm_new_password_label'); ?></label><input id="pw-new2" type="password" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('account.confirm_new_password_placeholder'), ENT_QUOTES, 'UTF-8') ?>" required></div>
        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-primary" id="pw-btn" type="submit"><span id="pw-btn-txt"><?php e('account.update_password_btn'); ?></span></button>
        </div>
        <div id="pw-ok" class="msg msg-ok"></div>
        <div id="pw-err" class="msg msg-err"></div>
      </form>
    </div>

  </div>

<script>
(() => {
  const api = window.LS_SECURITY_API;
  if(!api) return;

  const pwForm = document.getElementById('pw-form');
  if(!pwForm) return;

  const ok = document.getElementById('pw-ok');
  const err = document.getElementById('pw-err');
  const btn = document.getElementById('pw-btn');
  const btnTxt = document.getElementById('pw-btn-txt');
  const btnDefault = btnTxt ? btnTxt.textContent : '';

  pwForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    api.clearMsg(ok);
    api.clearMsg(err);

    const cur = (document.getElementById('pw-cur')||{}).value || '';
    const p1 = (document.getElementById('pw-new')||{}).value || '';
    const p2 = (document.getElementById('pw-new2')||{}).value || '';

    if(!cur || !p1 || !p2){ api.showMsg(err, 'Fill in all fields'); return; }
    if(p1.length < 8){ api.showMsg(err, 'New password must be at least 8 characters'); return; }
    if(p1 !== p2){ api.showMsg(err, 'Passwords do not match'); return; }

    btn.disabled = true;
    if(btnTxt) btnTxt.innerHTML = '<span class="spin"></span>';

    try{
      const j = await api.postCsrf('api/account.php', {action:'change_login_password', current_password: cur, new_password: p1});
      if(!j.success){ api.showMsg(err, j.error || 'Update failed'); return; }
      api.showMsg(ok, 'Login password updated.');
      pwForm.reset();
    }catch{
      api.showMsg(err, 'Network error');
    }finally{
      btn.disabled = false;
      if(btnTxt) btnTxt.textContent = btnDefault;
    }
  });
})();
</script>
</div>
</body>
</html>
