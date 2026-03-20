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

            <div style="display:flex;align-items:center;gap:14px;margin-top:12px;flex-wrap:wrap;">
              <div class="ls-avatar ls-avatar-lg" id="profile-image-preview-wrap">
                <img class="ls-avatar-img" id="profile-image-preview" src="api/profile_image.php?v=<?= (int)time() ?>" alt="<?= htmlspecialchars(t('account_user.profile_picture_title'), ENT_QUOTES, 'UTF-8') ?>" onload="if(this.nextElementSibling){this.nextElementSibling.style.display='none';}" onerror="this.style.display='none';if(this.nextElementSibling){this.nextElementSibling.style.display='flex';}">
                <span class="ls-avatar-initials" id="profile-image-initials"></span>
              </div>

              <div style="flex:1;min-width:220px;">
                <div class="field" style="margin:0;">
                  <label><?php e('account_user.profile_image_upload_label'); ?></label>
                  <input type="file" id="profile-image-file" accept="image/png,image/jpeg,image/webp">
                </div>
                <div class="small"><?php e('account_user.profile_image_upload_hint'); ?></div>
              </div>
            </div>

            <div class="msg msg-ok" id="img-ok"></div>
            <div class="msg msg-err" id="img-err"></div>
          </div>
          <div class="item-actions">
            <button class="btn btn-blue btn-sm" type="button" id="img-upload"><?php e('account_user.profile_image_upload_btn'); ?></button>
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

        <div class="item" id="contact">
          <div style="flex:1;min-width:240px;">
            <div class="k"><?php e('account_user.contact_title'); ?></div>
            <div class="small"><?php e('account_user.contact_sub'); ?></div>

            <div class="field" style="margin-top:10px;">
              <label><?php e('account_user.neighborhood_label'); ?></label>
              <input type="text" id="user-neighborhood" maxlength="120" placeholder="<?= htmlspecialchars(t('account_user.neighborhood_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px;">
              <div class="field" style="margin:0;">
                <label><?php e('account_user.phone_primary_label'); ?></label>
                <input type="text" id="user-phone-primary" maxlength="30" placeholder="<?= htmlspecialchars(t('account_user.phone_primary_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
              </div>
              <div class="field" style="margin:0;">
                <label><?php e('account_user.phone_secondary_label'); ?></label>
                <input type="text" id="user-phone-secondary" maxlength="30" placeholder="<?= htmlspecialchars(t('account_user.phone_secondary_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
              </div>
            </div>

            <div class="msg msg-ok" id="contact-ok"></div>
            <div class="msg msg-err" id="contact-err"></div>
          </div>
          <div class="item-actions">
            <button class="btn btn-blue btn-sm" type="button" id="contact-save"><?php e('common.save'); ?></button>
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

  const USER_EMAIL = <?= json_encode($userEmail) ?>;

  const imgFile = document.getElementById('profile-image-file');
  const imgUpload = document.getElementById('img-upload');
  const imgPreview = document.getElementById('profile-image-preview');
  const imgInitials = document.getElementById('profile-image-initials');
  const imgOk = document.getElementById('img-ok');
  const imgErr = document.getElementById('img-err');

  let avatarBlob = null;
  let avatarPreviewUrl = null;

  const nameInput = document.getElementById('room-display-name');
  const nameSave = document.getElementById('name-save');
  const nameOk = document.getElementById('name-ok');
  const nameErr = document.getElementById('name-err');

  const neighborhoodInput = document.getElementById('user-neighborhood');
  const phonePrimaryInput = document.getElementById('user-phone-primary');
  const phoneSecondaryInput = document.getElementById('user-phone-secondary');
  const contactSave = document.getElementById('contact-save');
  const contactOk = document.getElementById('contact-ok');
  const contactErr = document.getElementById('contact-err');

  let state = {trust_level: 1, nickname_locked: 0, profile_fields_available: 1};

  function initialsFromEmail(email){
    const s = String(email || '').trim();
    if(!s) return 'U';

    const local = (s.split('@')[0] || '').trim();
    const parts = local.split(/[^A-Za-z0-9]+/).filter(Boolean);

    let out = '';
    for(const p of parts){
      if(!p) continue;
      out += p[0];
      if(out.length >= 2) break;
    }

    if(out.length < 2){
      const compact = local.replace(/[^A-Za-z0-9]/g, '');
      out = (compact.slice(0, 2) || 'U');
    }

    return out.toUpperCase();
  }

  function setAvatarInitials(){
    if(imgInitials) imgInitials.textContent = initialsFromEmail(USER_EMAIL);
  }

  function canvasSupports(type){
    try{
      const c = document.createElement('canvas');
      return (c.toDataURL(type) || '').indexOf('data:' + type) === 0;
    }catch(e){
      return false;
    }
  }

  const AVATAR_OUT_TYPE = canvasSupports('image/webp') ? 'image/webp' : 'image/jpeg';

  function refreshAvatarFromServer(){
    if(!imgPreview) return;
    if(avatarPreviewUrl){
      try{ URL.revokeObjectURL(avatarPreviewUrl); }catch(e){}
      avatarPreviewUrl = null;
    }
    avatarBlob = null;

    imgPreview.style.display = 'block';
    imgPreview.src = 'api/profile_image.php?v=' + String(Date.now());
  }

  function refreshTopbarAvatars(){
    const v = String(Date.now());
    document.querySelectorAll('img[data-user-avatar="1"]').forEach(el => {
      try{ el.style.display = ''; }catch(e){}
      el.src = 'api/profile_image.php?v=' + v;
    });
  }

  async function centerCropToSquare(file, outSize){
    const f = file;
    const size = outSize || 512;

    if(!f) throw new Error(tr('common.failed', 'Failed'));

    const allowed = {'image/png':1,'image/jpeg':1,'image/webp':1};
    if(!allowed[f.type]) throw new Error(tr('account_user.profile_image_err_type', 'Unsupported image type'));

    const url = URL.createObjectURL(f);
    const img = new Image();
    img.decoding = 'async';

    const loaded = new Promise((resolve, reject) => {
      img.onload = () => resolve(true);
      img.onerror = () => reject(new Error(tr('account_user.profile_image_err_decode', 'Could not read image')));
    });

    img.src = url;
    await loaded;

    const w = img.naturalWidth || img.width;
    const h = img.naturalHeight || img.height;

    const s = Math.min(w, h);
    const sx = Math.floor((w - s) / 2);
    const sy = Math.floor((h - s) / 2);

    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;

    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, sx, sy, s, s, 0, 0, size, size);

    URL.revokeObjectURL(url);

    const blob = await new Promise(resolve => canvas.toBlob(resolve, AVATAR_OUT_TYPE, 0.9));
    if(!blob) throw new Error(tr('common.failed', 'Failed'));

    return blob;
  }

  setAvatarInitials();

  function setAvailability(){
    const ok = !!state.profile_fields_available;

    if(unavailable){
      unavailable.style.display = ok ? 'none' : 'block';
      unavailable.textContent = ok ? '' : tr('account_user.unavailable_migrations', 'This feature is unavailable on this server. Apply database migrations.');
    }

    if(imgFile) imgFile.disabled = !ok;
    if(imgUpload) imgUpload.disabled = !ok;

    const locked = !!state.nickname_locked;
    if(nameInput) nameInput.disabled = !ok || locked;
    if(nameSave) nameSave.disabled = !ok || locked;

    if(neighborhoodInput) neighborhoodInput.disabled = !ok;
    if(phonePrimaryInput) phonePrimaryInput.disabled = !ok;
    if(phoneSecondaryInput) phoneSecondaryInput.disabled = !ok;
    if(contactSave) contactSave.disabled = !ok;

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
    clearMsg(contactOk); clearMsg(contactErr);

    try{
      const j = await postCsrf('api/profile.php', {action: 'get_profile'});
      if(!j.success) throw new Error(j.error || tr('common.failed', 'Failed'));

      state.trust_level = parseInt(String(j.trust_level || '1'), 10) || 1;
      state.nickname_locked = !!j.nickname_locked;
      state.profile_fields_available = !!j.profile_fields_available;

      if(trustEl) trustEl.textContent = 'Level ' + String(state.trust_level);

      if(nameInput) nameInput.value = j.room_display_name || '';
      if(neighborhoodInput) neighborhoodInput.value = j.neighborhood || '';
      if(phonePrimaryInput) phonePrimaryInput.value = j.phone_primary || '';
      if(phoneSecondaryInput) phoneSecondaryInput.value = j.phone_secondary || '';

      setAvailability();
      refreshAvatarFromServer();
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

  if(imgFile){
    imgFile.addEventListener('change', async () => {
      clearMsg(imgOk); clearMsg(imgErr);

      const f = (imgFile.files && imgFile.files[0]) ? imgFile.files[0] : null;
      if(!f){
        avatarBlob = null;
        if(avatarPreviewUrl){
          try{ URL.revokeObjectURL(avatarPreviewUrl); }catch(e){}
          avatarPreviewUrl = null;
        }
        refreshAvatarFromServer();
        return;
      }

      try{
        const blob = await centerCropToSquare(f, 512);
        avatarBlob = blob;

        if(avatarPreviewUrl){
          try{ URL.revokeObjectURL(avatarPreviewUrl); }catch(e){}
          avatarPreviewUrl = null;
        }

        avatarPreviewUrl = URL.createObjectURL(blob);
        if(imgPreview){
          imgPreview.style.display = 'block';
          imgPreview.src = avatarPreviewUrl;
        }
      }catch(e){
        avatarBlob = null;
        showMsg(imgErr, (e && e.message) ? e.message : tr('common.failed', 'Failed'));
      }
    });
  }

  if(imgUpload){
    imgUpload.addEventListener('click', async () => {
      clearMsg(imgOk); clearMsg(imgErr);
      imgUpload.disabled = true;

      try{
        if(!avatarBlob) throw new Error(tr('account_user.profile_image_err_select', 'Select an image first'));

        const fd = new FormData();
        const ext = (AVATAR_OUT_TYPE === 'image/webp') ? 'webp' : 'jpg';
        fd.append('image', avatarBlob, 'avatar.' + ext);

        const r = await fetch('api/profile_image_upload.php', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {'X-CSRF-Token': CSRF},
          body: fd,
        });

        let j = null;
        try{ j = await r.json(); }catch(e){ j = null; }

        if(!r.ok || !j || !j.success) {
          throw new Error((j && j.error) ? j.error : tr('common.failed', 'Failed'));
        }

        showMsg(imgOk, tr('common.saved', 'Saved.'));
        refreshAvatarFromServer();
        refreshTopbarAvatars();
      }catch(e){
        showMsg(imgErr, (e && e.message) ? e.message : tr('common.failed', 'Failed'));
      }finally{
        imgUpload.disabled = false;
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

  if(contactSave){
    contactSave.addEventListener('click', async () => {
      clearMsg(contactOk); clearMsg(contactErr);
      contactSave.disabled = true;

      try{
        const neighborhood = (neighborhoodInput ? neighborhoodInput.value : '').trim();
        const phone_primary = (phonePrimaryInput ? phonePrimaryInput.value : '').trim();
        const phone_secondary = (phoneSecondaryInput ? phoneSecondaryInput.value : '').trim();

        const j = await postCsrf('api/profile.php', {action:'set_profile', neighborhood, phone_primary, phone_secondary});
        if(!j.success) throw new Error(j.error || tr('common.failed', 'Failed'));

        if(neighborhoodInput) neighborhoodInput.value = j.neighborhood || '';
        if(phonePrimaryInput) phonePrimaryInput.value = j.phone_primary || '';
        if(phoneSecondaryInput) phoneSecondaryInput.value = j.phone_secondary || '';

        state.profile_fields_available = !!j.profile_fields_available;
        setAvailability();

        showMsg(contactOk, tr('common.saved', 'Saved.'));
      }catch(e){
        showMsg(contactErr, (e && e.message) ? e.message : tr('common.failed', 'Failed'));
      }finally{
        contactSave.disabled = !state.profile_fields_available;
      }
    });
  }

  loadProfile();
})();
</script>
</body>
</html>
