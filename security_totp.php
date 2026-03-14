<?php
require_once __DIR__ . '/includes/security_page.php';

$totpEnabled = !empty($securityUser['totp_enabled_at']);
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.security_totp')) ?></title>
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
<style>
code{background:var(--code-bg);border:1px solid var(--b1);padding:2px 6px;border-radius:10px;}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.security_totp'); ?></div>
        <div class="page-sub"><?php e('account.totp_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="security.php"><?php e('common.back'); ?></a>
      </div>
    </div>

    <div class="card" id="totp-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.totp_title'); ?></div>
          <div class="v"><?php e('account.totp_sub'); ?></div>
        </div>
        <?php if ($hasTotp): ?>
          <?php if ($totpEnabled): ?>
            <div class="badge ok" id="totp-status-badge"><?= htmlspecialchars(t('account.totp_enabled'), ENT_QUOTES, 'UTF-8') ?></div>
          <?php else: ?>
            <div class="badge wait" id="totp-status-badge"><?= htmlspecialchars(t('account.totp_not_enabled'), ENT_QUOTES, 'UTF-8') ?></div>
          <?php endif; ?>
        <?php else: ?>
          <div class="badge wait" id="totp-status-badge"><?= htmlspecialchars(t('account.totp_unavailable'), ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
      </div>

      <?php if (!$hasTotp): ?>
        <div class="small" style="margin-top:12px;"><?php e('account.totp_unavailable_desc'); ?></div>
      <?php else: ?>
        <div class="small" style="margin-top:12px;"><?php e('account.totp_desc'); ?></div>

        <div id="totp-setup" style="display:none;">
          <div class="hr"></div>
          <div class="small"><?php e('account.totp_scan_secret'); ?></div>
          <div class="small" style="margin-top:6px;word-break:break-all;"><code id="totp-secret"></code></div>
          <div class="small" style="margin-top:6px;word-break:break-all;"><a id="totp-otpauth" href="#" style="color:var(--orange)"><?php e('account.totp_otpauth_link'); ?></a></div>
          <div class="field"><label><?php e('account.totp_code_label'); ?></label><input id="totp-code" inputmode="numeric" placeholder="123456"></div>
          <button class="btn btn-primary" id="totp-enable"><span id="totp-enable-txt"><?php e('account.totp_enable_btn'); ?></span></button>
        </div>

        <div id="totp-disable" style="display:none;">
          <div class="hr"></div>
          <div class="field"><label><?php e('account.totp_code_label'); ?></label><input id="totp-disable-code" inputmode="numeric" placeholder="123456"></div>
          <button class="btn btn-red" id="totp-disable-btn"><?php e('account.totp_disable_btn'); ?></button>
        </div>

        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-ghost" id="totp-begin"><?php e('account.totp_setup_btn'); ?></button>
          <button class="btn btn-ghost" id="totp-reauth"><?php e('account.totp_reauth_btn'); ?></button>
        </div>

        <div id="totp-ok" class="msg msg-ok"></div>
        <div id="totp-err" class="msg msg-err"></div>
      <?php endif; ?>
    </div>

  </div>

<script>
(() => {
  const api = window.LS_SECURITY_API;
  if(!api) return;

  const TOTP_AVAILABLE = <?= $hasTotp ? 'true' : 'false' ?>;
  const TOTP_ENABLED = <?= $totpEnabled ? 'true' : 'false' ?>;

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (Object.prototype.hasOwnProperty.call(I18N, key) ? I18N[key] : null) || fallback || key;
  }

  if(!TOTP_AVAILABLE) return;

  const ok = document.getElementById('totp-ok');
  const err = document.getElementById('totp-err');
  const setup = document.getElementById('totp-setup');
  const dis = document.getElementById('totp-disable');
  const badge = document.getElementById('totp-status-badge');

  const enableTxtDefault = (document.getElementById('totp-enable-txt') || {}).textContent || '';

  function totpSetUi(enabled){
    const begin = document.getElementById('totp-begin');
    if(begin) begin.style.display = enabled ? 'none' : 'inline-flex';
    if(setup) setup.style.display = 'none';
    if(dis) dis.style.display = enabled ? 'block' : 'none';
    if(badge){
      badge.className = 'badge ' + (enabled ? 'ok' : 'wait');
      badge.textContent = enabled ? tr('account.totp_enabled', '✓ Enabled') : tr('account.totp_not_enabled', '⏳ Not enabled');
    }
  }

  totpSetUi(TOTP_ENABLED);

  const beginBtn = document.getElementById('totp-begin');
  if(beginBtn){
    beginBtn.addEventListener('click', async () => {
      api.clearMsg(ok); api.clearMsg(err);
      const j = await api.postCsrf('api/totp.php', {action:'begin'});
      if(!j.success){ api.showMsg(err, j.error || 'Failed'); return; }
      const sec = document.getElementById('totp-secret');
      if(sec) sec.textContent = j.secret;
      const a = document.getElementById('totp-otpauth');
      if(a){ a.href = j.otpauth; a.textContent = j.otpauth; }
      if(setup) setup.style.display = 'block';
    });
  }

  const enableBtn = document.getElementById('totp-enable');
  if(enableBtn){
    enableBtn.addEventListener('click', async () => {
      api.clearMsg(ok); api.clearMsg(err);
      const code = (document.getElementById('totp-code')||{}).value?.trim() || '';
      if(!code){ api.showMsg(err, 'Code required'); return; }

      const txt = document.getElementById('totp-enable-txt');
      enableBtn.disabled = true;
      if(txt) txt.innerHTML = '<span class="spin"></span>';

      try{
        const j = await api.postCsrf('api/totp.php', {action:'enable', code});
        if(!j.success){ api.showMsg(err, j.error || 'Failed'); return; }
        api.showMsg(ok, 'TOTP enabled.');
        totpSetUi(true);
      }finally{
        enableBtn.disabled = false;
        if(txt) txt.textContent = enableTxtDefault;
      }
    });
  }

  const disableBtn = document.getElementById('totp-disable-btn');
  if(disableBtn){
    disableBtn.addEventListener('click', async () => {
      api.clearMsg(ok); api.clearMsg(err);
      const code = (document.getElementById('totp-disable-code')||{}).value?.trim() || '';
      if(!code){ api.showMsg(err, 'Code required'); return; }
      const j = await api.postCsrf('api/totp.php', {action:'disable', code});
      if(!j.success){ api.showMsg(err, j.error || 'Failed'); return; }
      api.showMsg(ok, 'TOTP disabled.');
      totpSetUi(false);
    });
  }

  const reauthBtn = document.getElementById('totp-reauth');
  if(reauthBtn){
    reauthBtn.addEventListener('click', async () => {
      api.clearMsg(ok); api.clearMsg(err);
      const promptText = tr('login.enter_totp', 'Enter your 6-digit authenticator code');
      const code = prompt(promptText);
      if(!code) return;
      const j = await api.postCsrf('api/totp.php', {action:'reauth', code});
      if(!j.success){ api.showMsg(err, j.error || 'Failed'); return; }
      api.showMsg(ok, 'Re-auth successful.');
    });
  }
})();
</script>
</div>
</body>
</html>
