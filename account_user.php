<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
    exit;
}

if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.account_user')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.list{display:flex;flex-direction:column;gap:var(--ls-space-3);}
.item{border:1px solid var(--b1);background:linear-gradient(180deg, var(--s2), var(--s1));padding:var(--ls-space-3) var(--ls-space-4);display:flex;justify-content:space-between;align-items:flex-start;gap:var(--ls-space-3);flex-wrap:wrap;border-radius:var(--radius-card);}
.item-actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.account_user'); ?></div>
        <div class="page-sub"><?php e('account_user.subtitle'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      </div>
    </div>

    <div class="card">
      <div class="row" style="display:flex;align-items:flex-start;justify-content:space-between;gap:var(--ls-space-3);flex-wrap:wrap;">
        <div>
          <div class="k"><?php e('account_user.trust_level_label'); ?></div>
          <div class="v" id="trust-level">—</div>
        </div>
        <div class="badge wait" id="nickname-badge"><?= htmlspecialchars(t('common.loading'), ENT_QUOTES, 'UTF-8') ?></div>
      </div>

      <div id="profile-unavailable" class="msg msg-err" style="display:none;"></div>

      <div class="hr"></div>

      <div class="list">
        <div class="item" id="password">
          <div>
            <div class="k"><?php e('account_user.login_password_title'); ?></div>
            <div class="small"><?php e('account_user.login_password_sub'); ?></div>
          </div>
          <div class="item-actions">
            <a class="btn btn-primary btn-sm" href="security_password.php"><?php e('common.open'); ?></a>
          </div>
        </div>

        <div class="item" id="profile-picture">
          <div style="flex:1;min-width:240px;">
            <div class="k"><?php e('account_user.profile_picture_title'); ?></div>
            <div class="small"><?php e('account_user.profile_picture_sub'); ?></div>
            <div class="field" style="margin-top:10px;">
              <label><?php e('account_user.profile_image_url_label'); ?></label>
              <input type="url" id="profile-image-url" placeholder="<?= htmlspecialchars(t('account_user.profile_image_url_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="msg msg-ok" id="img-ok"></div>
            <div class="msg msg-err" id="img-err"></div>
          </div>
          <div class="item-actions">
            <button class="btn btn-blue btn-sm" type="button" id="img-save"><?php e('common.save'); ?></button>
          </div>
        </div>

        <div class="item" id="rooms-nickname">
          <div style="flex:1;min-width:240px;">
            <div class="k"><?php e('account_user.room_nickname_title'); ?></div>
            <div class="small" id="nickname-sub"><?php e('account_user.room_nickname_sub'); ?></div>
            <div class="field" style="margin-top:10px;">
              <label><?php e('account_user.room_display_name_label'); ?></label>
              <input type="text" id="room-display-name" maxlength="60" placeholder="<?= htmlspecialchars(t('account_user.room_display_name_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
            </div>
            <div class="msg msg-ok" id="name-ok"></div>
            <div class="msg msg-err" id="name-err"></div>
          </div>
          <div class="item-actions">
            <button class="btn btn-blue btn-sm" type="button" id="name-save"><?php e('common.save'); ?></button>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (Object.prototype.hasOwnProperty.call(I18N, key) ? I18N[key] : null) || fallback || key;
  }

  async function postCsrf(url, body){
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CSRF},
      body: JSON.stringify(body)
    });
    return r.json();
  }

  function showMsg(el, text){
    if(!el) return;
    el.textContent = text;
    el.classList.add('show');
  }

  function clearMsg(el){
    if(!el) return;
    el.textContent = '';
    el.classList.remove('show');
  }

  const trustEl = document.getElementById('trust-level');
  const badge = document.getElementById('nickname-badge');
  const unavailable = document.getElementById('profile-unavailable');

  const imgInput = document.getElementById('profile-image-url');
  const imgSave = document.getElementById('img-save');
  const imgOk = document.getElementById('img-ok');
  const imgErr = document.getElementById('img-err');

  const nameInput = document.getElementById('room-display-name');
  const nameSave = document.getElementById('name-save');
  const nameOk = document.getElementById('name-ok');
  const nameErr = document.getElementById('name-err');

  let state = {trust_level: 1, nickname_locked: 0, profile_fields_available: 1};

  function setAvailability(){
    const ok = !!state.profile_fields_available;

    if(unavailable){
      unavailable.style.display = ok ? 'none' : 'block';
      unavailable.textContent = ok ? '' : tr('account_user.unavailable_migrations', 'This feature is unavailable on this server. Apply database migrations.');
    }

    if(imgInput) imgInput.disabled = !ok;
    if(imgSave) imgSave.disabled = !ok;

    const locked = !!state.nickname_locked;
    if(nameInput) nameInput.disabled = !ok || locked;
    if(nameSave) nameSave.disabled = !ok || locked;

    if(badge){
      if(!ok){
        badge.textContent = tr('common.unavailable', 'Unavailable');
        badge.className = 'badge wait';
      } else if(locked){
        badge.textContent = tr('account_user.nickname_locked_badge', 'Locked');
        badge.className = 'badge ok';
      } else {
        badge.textContent = tr('account_user.nickname_editable_badge', 'Editable');
        badge.className = 'badge wait';
      }
    }
  }

  async function loadProfile(){
    clearMsg(imgOk); clearMsg(imgErr);
    clearMsg(nameOk); clearMsg(nameErr);

    try{
      const j = await postCsrf('api/profile.php', {action: 'get_profile'});
      if(!j.success) throw new Error(j.error || tr('common.failed', 'Failed'));

      state.trust_level = parseInt(String(j.trust_level || '1'), 10) || 1;
      state.nickname_locked = !!j.nickname_locked;
      state.profile_fields_available = !!j.profile_fields_available;

      if(trustEl) trustEl.textContent = 'Level ' + String(state.trust_level);

      if(imgInput) imgInput.value = j.profile_image_url || '';
      if(nameInput) nameInput.value = j.room_display_name || '';

      setAvailability();
    }catch(e){
      if(unavailable){
        unavailable.style.display = 'block';
        unavailable.textContent = (e && e.message) ? e.message : tr('common.failed', 'Failed');
      }
      if(badge){
        badge.textContent = '⏳';
        badge.className = 'badge wait';
      }
      state.profile_fields_available = 0;
      setAvailability();
    }
  }

  if(imgSave){
    imgSave.addEventListener('click', async () => {
      clearMsg(imgOk); clearMsg(imgErr);
      imgSave.disabled = true;

      try{
        const profile_image_url = (imgInput ? imgInput.value : '').trim();
        const j = await postCsrf('api/profile.php', {action:'set_profile', profile_image_url});
        if(!j.success) throw new Error(j.error || tr('common.failed', 'Failed'));
        if(imgInput) imgInput.value = j.profile_image_url || '';
        showMsg(imgOk, tr('common.saved', 'Saved.'));
      }catch(e){
        showMsg(imgErr, (e && e.message) ? e.message : tr('common.failed', 'Failed'));
      }finally{
        imgSave.disabled = false;
      }
    });
  }

  if(nameSave){
    nameSave.addEventListener('click', async () => {
      clearMsg(nameOk); clearMsg(nameErr);
      nameSave.disabled = true;

      try{
        const room_display_name = (nameInput ? nameInput.value : '').trim();
        const j = await postCsrf('api/profile.php', {action:'set_profile', room_display_name});
        if(!j.success) throw new Error(j.error || tr('common.failed', 'Failed'));
        if(nameInput) nameInput.value = j.room_display_name || '';

        state.trust_level = parseInt(String(j.trust_level || state.trust_level || '1'), 10) || 1;
        state.nickname_locked = !!j.nickname_locked;
        setAvailability();

        showMsg(nameOk, tr('common.saved', 'Saved.'));
      }catch(e){
        showMsg(nameErr, (e && e.message) ? e.message : tr('common.failed', 'Failed'));
      }finally{
        nameSave.disabled = !!state.nickname_locked ? true : false;
      }
    });
  }

  loadProfile();
})();
</script>
</body>
</html>
