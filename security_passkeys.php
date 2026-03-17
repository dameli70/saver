<?php
require_once __DIR__ . '/includes/security_page.php';

$requirePasskeyForLogin = !empty($securityUser['require_webauthn']);
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.security_passkeys')) ?></title>
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
        <div class="page-title"><?php e('page.security_passkeys'); ?></div>
        <div class="page-sub"><?php e('account.passkeys_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="security.php"><?php e('common.back'); ?></a>
      </div>
    </div>

    <div class="card" id="passkeys-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.passkeys_title'); ?></div>
          <div class="v"><?php e('account.passkeys_sub'); ?></div>
        </div>
        <div class="badge wait" id="passkeys-status">⏳</div>
      </div>

      <?php if (!$hasPasskeys): ?>
        <div class="small" style="margin-top:12px;"><?php e('account.passkeys_unavailable_desc'); ?></div>
      <?php else: ?>
        <div class="small" style="margin-top:12px;"><?php e('account.passkeys_desc'); ?></div>

        <div class="hr"></div>

        <div class="row">
          <div>
            <div class="k"><?php e('account.passkeys_require_login'); ?></div>
            <div class="small"><?php e('account.passkeys_require_login_sub'); ?></div>
          </div>
          <label class="small" style="display:flex;align-items:center;gap:10px;">
            <input type="checkbox" id="passkey-required" <?= $hasReqWebauthn ? '' : 'disabled' ?> <?= $requirePasskeyForLogin ? 'checked' : '' ?> >
            <span><?= $hasReqWebauthn ? '' : htmlspecialchars(t('common.unavailable'), ENT_QUOTES, 'UTF-8') ?></span>
          </label>
        </div>

        <div class="list" id="passkeys-list"></div>

        <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-ghost" id="passkey-refresh"><?php e('common.refresh'); ?></button>
          <button class="btn btn-primary" id="passkey-add"><span id="passkey-add-txt"><?php e('setup.add_passkey'); ?></span></button>
        </div>

        <div id="passkey-ok" class="msg msg-ok"></div>
        <div id="passkey-err" class="msg msg-err"></div>
      <?php endif; ?>
    </div>

  </div>

<script>
(() => {
  const api = window.LS_SECURITY_API;
  if(!api) return;

  const PASSKEYS_AVAILABLE = <?= $hasPasskeys ? 'true' : 'false' ?>;
  if(!PASSKEYS_AVAILABLE) return;

  const ok = document.getElementById('passkey-ok');
  const err = document.getElementById('passkey-err');
  const list = document.getElementById('passkeys-list');
  const status = document.getElementById('passkeys-status');
  const addBtnDefault = (document.getElementById('passkey-add-txt') || {}).textContent || '';

  function setStatus(text, isOk){
    if(!status) return;
    status.textContent = text;
    status.className = 'badge ' + (isOk ? 'ok' : 'wait');
  }

  async function loadPasskeys(){
    api.clearMsg(ok); api.clearMsg(err);
    if(list) list.innerHTML = '<div class="small">Loading…</div>';

    const j = await api.postCsrf('api/webauthn.php', {action:'list'});
    if(!j.success){
      api.showMsg(err, j.error || 'Failed');
      if(list) list.innerHTML = '';
      setStatus('⏳', false);
      return;
    }

    const keys = j.passkeys || [];
    setStatus(keys.length ? '✓ Enabled' : '⏳ None', !!keys.length);

    if(!keys.length){
      if(list) list.innerHTML = '<div class="small">No passkeys registered.</div>';
      return;
    }

    if(list) list.innerHTML = '';

    keys.forEach(k => {
      const el = document.createElement('div');
      el.className = 'item';
      const label = k.label ? k.label : 'Passkey';
      el.innerHTML = `
        <div>
          <div class="small" style="color:var(--text)">${label}</div>
          <div class="small">Created: ${k.created_at||''}</div>
          <div class="small">Last used: ${k.last_used_at||'—'}</div>
        </div>
        <div class="item-actions">
          <button class="btn btn-red" type="button" data-id="${k.id}">Delete</button>
        </div>
      `;
      const btn = el.querySelector('button');
      if(btn) btn.addEventListener('click', () => deletePasskey(k.id));
      if(list) list.appendChild(el);
    });
  }

  async function deletePasskey(id){
    api.clearMsg(ok); api.clearMsg(err);

    let shouldDelete = false;
    if(window.LS && typeof window.LS.confirm === 'function'){
      shouldDelete = await window.LS.confirm('Delete this passkey?', {
        title: <?= json_encode(t('common.confirm')) ?>,
        confirmText: 'Delete',
        cancelText: <?= json_encode(t('common.cancel')) ?>,
        danger: true,
      });
    }else{
      shouldDelete = confirm('Delete this passkey?');
    }

    if(!shouldDelete) return;

    const j = await api.postCsrfWithReauth('api/webauthn.php', {action:'delete', id});
    if(!j.success){ api.showMsg(err, j.error || 'Failed'); return; }

    api.showMsg(ok, 'Deleted.');
    loadPasskeys();
  }

  async function addPasskey(){
    api.clearMsg(ok); api.clearMsg(err);

    if(!window.PublicKeyCredential){ api.showMsg(err, 'Passkeys not supported in this browser'); return; }

    const label = prompt('Label for this passkey (optional)') || '';
    const btn = document.getElementById('passkey-add');
    const txt = document.getElementById('passkey-add-txt');

    if(btn) btn.disabled = true;
    if(txt) txt.innerHTML = '<span class="spin"></span>';

    try{
      const begin = await api.postCsrf('api/webauthn.php', {action:'register_begin'});
      if(!begin.success){ api.showMsg(err, begin.error || 'Failed'); return; }

      const pk = begin.publicKey || {};
      const exclude = (pk.excludeCredentials || []).map(c => ({type:c.type, id: window.LS ? LS.b64uToBuf(c.id) : null})).filter(x => x.id);

      const cred = await navigator.credentials.create({publicKey:{
        challenge: window.LS ? LS.b64uToBuf(pk.challenge) : null,
        rp: pk.rp,
        user: {
          id: window.LS ? LS.b64uToBuf(pk.user.id) : null,
          name: pk.user.name,
          displayName: pk.user.displayName,
        },
        pubKeyCredParams: pk.pubKeyCredParams,
        timeout: pk.timeout || 60000,
        attestation: pk.attestation || 'none',
        authenticatorSelection: pk.authenticatorSelection || {userVerification:'required'},
        excludeCredentials: exclude,
      }});

      const a = cred.response;
      const fin = await api.postCsrf('api/webauthn.php', {
        action:'register_finish',
        label,
        rawId: window.LS ? LS.bufToB64u(cred.rawId) : '',
        response:{
          clientDataJSON: window.LS ? LS.bufToB64u(a.clientDataJSON) : '',
          attestationObject: window.LS ? LS.bufToB64u(a.attestationObject) : '',
        }
      });

      if(!fin.success){ api.showMsg(err, fin.error || 'Failed'); return; }
      api.showMsg(ok, 'Passkey added.');
      loadPasskeys();

    }catch(e){
      api.showMsg(err, (e && e.message) ? e.message : 'Passkey failed');
    }finally{
      if(btn) btn.disabled = false;
      if(txt) txt.textContent = addBtnDefault;
    }
  }

  const refresh = document.getElementById('passkey-refresh');
  if(refresh) refresh.addEventListener('click', loadPasskeys);

  const add = document.getElementById('passkey-add');
  if(add) add.addEventListener('click', addPasskey);

  const req = document.getElementById('passkey-required');
  if(req){
    req.addEventListener('change', async () => {
      api.clearMsg(ok); api.clearMsg(err);
      const enabled = req.checked ? 1 : 0;

      const j = await api.postCsrfWithReauth('api/webauthn.php', {action:'require_for_login', enabled});
      if(!j.success){
        api.showMsg(err, j.error || 'Failed');
        req.checked = !req.checked;
        return;
      }

      api.showMsg(ok, enabled ? 'Passkey required for login.' : 'Password login allowed.');
    });
  }

  loadPasskeys();
})();
</script>
</div>
</body>
</html>
