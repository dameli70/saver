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

$sel = 'email, email_verified_at, verification_sent_at';

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

// Match the topbar logic: hide the Setup shortcut once onboarding is complete.
$showSetupShortcut = $verified;
if ($verified) {
    $uid = (int)$userId;
    if ($uid && hasOnboardingColumns() && isOnboardingComplete($uid)) {
        $showSetupShortcut = false;
    }
}

$emailLockReminders = false;
if ($verified && hasNotificationPreferencesTable()) {
    $emailLockReminders = userWantsEmailTimeLockReminders((int)$userId);
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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.account')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>

.row{display:flex;align-items:flex-start;justify-content:space-between;gap:var(--ls-space-3);flex-wrap:wrap;}
.k{color:var(--muted);font-family:var(--mono);font-size:var(--ls-type-label-size);letter-spacing:var(--ls-type-label-track);text-transform:uppercase;line-height:1.2;}
.v{color:var(--text);font-size:var(--ls-type-value-size);letter-spacing:var(--ls-type-value-track);line-height:1.35;}

.dev{margin-top:var(--ls-space-3);border:1px dashed color-mix(in srgb, var(--orange) 35%, transparent);background:color-mix(in srgb, var(--orange) 6%, transparent);padding:var(--ls-space-2) var(--ls-space-3);font-size:var(--ls-type-small-size);color:var(--muted);line-height:var(--ls-type-small-line);display:none;}
.dev a{color:var(--orange);}

.list{margin-top:var(--ls-space-3);display:flex;flex-direction:column;gap:var(--ls-space-3);}
.item{border:1px solid var(--b1);background:linear-gradient(180deg, var(--s2), var(--s1));padding:var(--ls-space-3) var(--ls-space-4);display:flex;justify-content:space-between;align-items:flex-start;gap:var(--ls-space-3);flex-wrap:wrap;border-radius:var(--radius-card);}

code{background:var(--code-bg);border:1px solid var(--b1);padding:2px 6px;border-radius:10px;}

</style>
</head>
<body>
<div id="app">
  <?php $userEmail = getCurrentUserEmail() ?? ''; include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('page.account'); ?></div>
        <div class="page-sub"><?= $verified ? t('account.sub_verified') : t('account.sub_unverified') ?></div>
      </div>
      <div class="page-actions">
        <?php if ($showSetupShortcut): ?>
          <a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a>
        <?php endif; ?>
        <?php if ($verified): ?>
          <a class="btn btn-ghost btn-sm" href="security.php"><?php e('nav.security'); ?></a>
        <?php endif; ?>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <div>
          <div class="k"><?php e('common.email'); ?></div>
          <div class="v"><?= htmlspecialchars($u['email']) ?></div>
        </div>
        <?php if ($verified): ?>
          <div class="badge ok"><?= htmlspecialchars(t('account.email_status_verified'), ENT_QUOTES, 'UTF-8') ?></div>
        <?php else: ?>
          <div class="badge wait"><?= htmlspecialchars(t('account.email_status_pending'), ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
      </div>

      <?php if (!$verified): ?>
      <div style="margin-top:14px;color:var(--muted);font-size:12px;line-height:1.7;">
        <?php e('account.verify_notice'); ?>
      </div>

      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <button class="btn btn-primary" id="resend"><span id="resend-txt"><?php e('account.resend_verification'); ?></span></button>
        <a class="btn btn-ghost" href="logout.php"><?php e('account.use_different_email'); ?></a>
      </div>

      <div id="msg-ok" class="msg msg-ok"></div>
      <div id="msg-err" class="msg msg-err"></div>
      <div id="dev" class="dev"></div>
      <?php else: ?>
      <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <a class="btn btn-primary" href="dashboard.php"><?php e('onboarding.action.go_to_dashboard'); ?></a>
        <a class="btn btn-ghost" href="index.php"><?php e('common.home'); ?></a>
      </div>
      <?php endif; ?>
    </div>

    <?php if ($verified): ?>
    <div class="card" id="trust-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.trust_title'); ?></div>
          <div class="v"><?php e('account.trust_sub'); ?></div>
        </div>
        <div class="badge wait" id="trust-level-badge">⏳</div>
      </div>

      <div class="small" style="margin-top:12px;">
        <?php e('account.trust_desc'); ?>
      </div>

      <div class="hr"></div>

      <div style="display:grid;grid-template-columns:1fr;gap:10px;">
        <div class="item" style="align-items:center;">
          <div>
            <div class="k"><?php e('account.trust.strikes_label'); ?></div>
            <div class="v" id="trust-strikes">—</div>
          </div>
          <div>
            <div class="k"><?php e('account.trust.restricted_label'); ?></div>
            <div class="v" id="trust-restricted">—</div>
          </div>
        </div>

        <div class="item" style="align-items:center;">
          <div>
            <div class="k"><?php e('account.trust.progress_label'); ?></div>
            <div class="v" id="trust-next">—</div>
          </div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="k"><?php e('account.trust.completed_title'); ?></div>
      <div class="small" style="margin-top:6px;"><?php e('account.trust.completed_sub'); ?></div>
      <div id="trust-completed" style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;"></div>

      <div class="hr"></div>

      <div class="k"><?php e('account.trust.active_rooms_title'); ?></div>
      <div class="small" style="margin-top:6px;"><?php e('account.trust.active_rooms_sub'); ?></div>
      <div id="trust-active" class="list"></div>

      <div id="trust-msg" class="msg msg-err"></div>
    </div>
    <?php endif; ?>

    <?php if ($verified): ?>
    <div class="card" id="notif-prefs-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.email_reminders_title'); ?></div>
          <div class="v"><?php e('account.email_reminders_sub'); ?></div>
        </div>
        <div class="badge <?= $emailLockReminders ? 'ok' : 'wait' ?>" id="email-reminders-badge"><?= $emailLockReminders ? htmlspecialchars(t('account.email_reminders_badge_on'), ENT_QUOTES, 'UTF-8') : htmlspecialchars(t('account.email_reminders_badge_off'), ENT_QUOTES, 'UTF-8') ?></div>
      </div>

      <div class="small" style="margin-top:12px;">
        <?php e('account.email_reminders_desc'); ?>
      </div>

      <div class="hr"></div>

      <div class="item" style="align-items:center;">
        <div style="flex:1;min-width:220px;">
          <div class="k"><?php e('account.email_reminders_toggle_title'); ?></div>
          <div class="v"><?php e('account.email_reminders_toggle_sub'); ?></div>
        </div>
        <label style="display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text);">
          <input type="checkbox" id="pref-email-lock-reminders" <?= $emailLockReminders ? 'checked' : '' ?> style="width:20px;height:20px;accent-color:var(--accent);">
          <span><?= $emailLockReminders ? htmlspecialchars(t('common.on'), ENT_QUOTES, 'UTF-8') : htmlspecialchars(t('common.off'), ENT_QUOTES, 'UTF-8') ?></span>
        </label>
      </div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-primary btn-sm" type="button" id="pref-save-email-reminders"><?php e('common.save'); ?></button>
        <div class="msg msg-ok" id="pref-email-ok"></div>
        <div class="msg msg-err" id="pref-email-err"></div>
      </div>
    </div>
    <?php endif; ?>

    <div class="card" id="vault-passphrase-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.vault_title'); ?></div>
          <div class="v"><?php e('account.vault_sub'); ?></div>
        </div>
        <div class="badge wait" id="vault-passphrase-status">⏳</div>
      </div>

      <div class="small" style="margin-top:12px;">
        <?php e('account.vault_desc'); ?>
      </div>

      <div id="vault-passphrase-unavailable" class="small" style="margin-top:12px;display:none;">
        <?php e('account.vault_unavailable'); ?>
      </div>

      <div id="vault-passphrase-set" class="small" style="margin-top:12px;display:none;">
        <?php e('account.vault_set'); ?>
      </div>

      <div id="vault-passphrase-form" style="display:none;">
        <div class="hr"></div>
        <div class="field"><label><?php e('account.vault_new_label'); ?> <span style="color:var(--muted)"><?php e('account.vault_new_hint'); ?></span></label>
          <input type="password" id="vp1" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('account.vault_new_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
        </div>
        <div class="field"><label><?php e('account.vault_confirm_label'); ?></label>
          <input type="password" id="vp2" autocomplete="new-password" placeholder="<?= htmlspecialchars(t('account.vault_confirm_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
        </div>
        <button class="btn btn-primary" id="vp-save"><span id="vp-save-txt"><?php e('account.vault_set_btn'); ?></span></button>
        <div id="vp-ok" class="msg msg-ok"></div>
        <div id="vp-err" class="msg msg-err"></div>
      </div>
    </div>

    <?php if ($verified): ?>
    <div class="card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.security_title'); ?></div>
          <div class="v"><?php e('security.hub_sub'); ?></div>
        </div>
        <a class="btn btn-primary btn-sm" href="security.php"><?php e('common.open'); ?></a>
      </div>

      <div class="small" style="margin-top:12px;"><?php e('account.security_note_html'); ?></div>

      <div class="hr"></div>

      <div class="two-col">
        <a class="btn btn-ghost btn-sm" href="security_totp.php"><?php e('account.totp_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="security_passkeys.php"><?php e('account.passkeys_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="security_password.php"><?php e('account.change_login_password_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="security_sessions.php"><?php e('account.active_sessions_title'); ?></a>
      </div>
    </div>
    <?php endif; ?>
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

const STR={
  resendFailed: <?= json_encode(t('account.resend_failed')) ?>,
  verificationSent: <?= json_encode(t('account.verification_sent')) ?>,
  networkError: <?= json_encode(t('common.network_error')) ?>,
  resendBtn: <?= json_encode(t('account.resend_verification')) ?>,
  devVerifyHtml: <?= json_encode(t('account.dev_verify_html')) ?>,
};

function tpl(s, vars){
  s = String(s||'');
  Object.keys(vars||{}).forEach(k => {
    s = s.split('{' + k + '}').join(String(vars[k]));
  });
  return s;
}

btn.addEventListener('click', async ()=>{
  clear();
  btn.disabled=true;
  btnTxt.innerHTML='<span class="spin"></span>';

  try{
    const r=await fetch('api/auth.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'resend_verification'})});
    const j=await r.json();
    if(!j.success){show(err,j.error||STR.resendFailed);return;}
    show(ok,STR.verificationSent);
    if(j.dev_verify_url){
      dev.style.display='block';
      dev.innerHTML=tpl(STR.devVerifyHtml,{url:j.dev_verify_url});
    }
  }catch{
    show(err,STR.networkError);
  }finally{
    btn.disabled=false;
    btnTxt.textContent=STR.resendBtn;
  }
});
</script>
<?php endif; ?>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;
  const VERIFIED = <?= $verified ? 'true' : 'false' ?>;
  const PBKDF2_ITERS = <?= (int)PBKDF2_ITERATIONS ?>;
  const VAULT_CHECK_PLAIN = 'LOCKSMITH_VAULT_CHECK_v1';

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (Object.prototype.hasOwnProperty.call(I18N, key) ? I18N[key] : null) || fallback || key;
  }
  function tf(key, vars, fallback){
    let s = tr(key, fallback);
    Object.keys(vars||{}).forEach(k => { s = String(s).split('{' + k + '}').join(String(vars[k])); });
    return s;
  }

  function showMsg(el,m){el.textContent=m;el.classList.add('show');}
  function clearMsg(el){el.textContent='';el.classList.remove('show');}

  async function postCsrf(url, body){
    const r=await fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
    return r.json();
  }

  async function getJson(url){
    const r=await fetch(url,{credentials:'same-origin'});
    return r.json();
  }

  // ── TRUST PASSPORT ────────────────────────────
  async function loadTrustPassport(){
    if(!VERIFIED) return;

    const badge = document.getElementById('trust-level-badge');
    const strikes = document.getElementById('trust-strikes');
    const restricted = document.getElementById('trust-restricted');
    const next = document.getElementById('trust-next');
    const completed = document.getElementById('trust-completed');
    const active = document.getElementById('trust-active');
    const msg = document.getElementById('trust-msg');

    if(!badge || !strikes || !restricted || !next || !completed || !active) return;

    msg.classList.remove('show');
    badge.textContent = '⏳';
    badge.className = 'badge wait';

    try{
      const j = await getJson('api/trust.php?action=passport');
      if(!j.success) throw new Error(j.error||tr('account.trust.failed_to_load', 'Failed to load trust passport'));

      const t = j.trust || {};
      const level = parseInt(t.level||'1',10) || 1;
      badge.textContent = tf('account.trust.level_fmt', {level}, `LEVEL ${level}`);
      badge.className = 'badge ' + (level >= 2 ? 'ok' : 'wait');

      strikes.textContent = String(t.strike_count_6m ?? '0');
      restricted.textContent = t.restricted_until
        ? tf('account.trust.restricted_until_fmt', {ts: String(t.restricted_until)}, `Until ${String(t.restricted_until)}`)
        : '—';
      next.textContent = String(t.next_level_hint || '—');

      const cr = j.completed_reveals || [];
      completed.innerHTML = '';
      if(!cr.length){
        const d = document.createElement('div');
        d.className = 'small';
        d.textContent = tr('account.trust.completed_none', 'No completed time locks yet.');
        completed.appendChild(d);
      } else {
        cr.forEach(x => {
          const b = document.createElement('div');
          b.className = 'badge';
          b.style.borderColor = 'var(--b2)';
          b.style.background = 'var(--s1)';
          b.style.color = 'var(--text)';
          b.textContent = '🔒 ' + (x.duration_days ? (String(x.duration_days) + 'd') : 'sealed');
          b.title = 'Unlocked at ' + (x.unlocked_at || '');
          completed.appendChild(b);
        });
      }

      const ar = j.active_rooms || [];
      active.innerHTML = '';
      if(!ar.length){
        const d = document.createElement('div');
        d.className = 'small';
        d.textContent = tr('account.trust.active_rooms_none', 'No active rooms.');
        active.appendChild(d);
      } else {
        ar.forEach(r => {
          const it = document.createElement('div');
          it.className = 'item';

          const now = Date.now();
          const startAt = r.start_at ? new Date(r.start_at).getTime() : null;
          const revealAt = r.reveal_at ? new Date(r.reveal_at).getTime() : null;

          let cd = '';
          if(r.room_state === 'lobby' && startAt){
            const ms = Math.max(0, startAt - now);
            const n = Math.ceil(ms/1000/60);
            cd = tf('account.trust.starts_in_minutes', {n}, `Starts in ${n} min`);
          } else if(r.room_state === 'active' && revealAt){
            const ms = Math.max(0, revealAt - now);
            const n = Math.ceil(ms/1000/60);
            cd = tf('account.trust.reveal_in_minutes', {n}, `Reveal in ${n} min`);
          }

          it.innerHTML = `
            <div>
              <div class="k">${tr('account.trust.saving_room_label', 'Saving Room')}</div>
              <div class="v">${String(r.goal_text||r.id||'Room')}</div>
              <div class="small">${String(cd||'')}</div>
            </div>
            <div>
              <a class="btn btn-ghost btn-sm" href="room.php?id=${encodeURIComponent(r.id)}">${tr('common.open', 'Open')}</a>
            </div>
          `;
          active.appendChild(it);
        });
      }

    }catch(e){
      msg.textContent = (e && e.message) ? e.message : tr('account.trust.failed_to_load', 'Failed to load trust passport');
      msg.classList.add('show');
    }
  }

  function bytesToB64(bytes){return btoa(String.fromCharCode(...bytes));}
  function b64ToBytes(b64){return Uint8Array.from(atob(b64), c => c.charCodeAt(0));}

  function requireWebCrypto(){
    if (!window.crypto || !window.crypto.getRandomValues) {
      throw new Error('Secure cryptography is unavailable in this browser.');
    }
    if (!window.isSecureContext || !window.crypto.subtle) {
      throw new Error('Web Crypto API is unavailable. Use HTTPS (or localhost) to set a vault passphrase.');
    }
    return window.crypto;
  }

  async function deriveKey(passphrase, kdfSaltB64, iters){
    const c = requireWebCrypto();
    const enc = new TextEncoder();
    const baseKey = await c.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    const saltBytes = b64ToBytes(kdfSaltB64);
    return c.subtle.deriveKey(
      {name:'PBKDF2', salt:saltBytes, iterations: iters, hash:'SHA-256'},
      baseKey,
      {name:'AES-GCM', length:256},
      false,
      ['encrypt','decrypt']
    );
  }

  async function aesEncrypt(plain, key){
    const c = requireWebCrypto();
    const iv = new Uint8Array(12);
    c.getRandomValues(iv);
    const enc = new TextEncoder();
    const ct = new Uint8Array(await c.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, enc.encode(plain)));
    const tag = ct.slice(ct.length - 16);
    const cipher = ct.slice(0, ct.length - 16);
    return {cipher_blob: bytesToB64(cipher), iv: bytesToB64(iv), auth_tag: bytesToB64(tag)};
  }

  // ── VAULT PASSPHRASE SETUP ────────────────────
  const vaultStatus = document.getElementById('vault-passphrase-status');
  if (vaultStatus) {
    const unavailable = document.getElementById('vault-passphrase-unavailable');
    const setNote = document.getElementById('vault-passphrase-set');
    const form = document.getElementById('vault-passphrase-form');
    const ok = document.getElementById('vp-ok');
    const err = document.getElementById('vp-err');
    const saveBtn = document.getElementById('vp-save');
    const saveTxt = document.getElementById('vp-save-txt');

    function setBadge(text, ok){
      vaultStatus.textContent = text;
      vaultStatus.className = 'badge ' + (ok ? 'ok' : 'wait');
    }

    async function loadVaultStatus(){
      clearMsg(ok); clearMsg(err);
      setBadge('⏳', false);
      if(unavailable) unavailable.style.display='none';
      if(setNote) setNote.style.display='none';
      if(form) form.style.display='none';

      try{
        const j = await postCsrf('api/vault.php', {action:'setup_status'});
        if(!j.success){setBadge('⏳', false);return;}

        if(!j.available){
          setBadge('⏳ Unavailable', false);
          if(unavailable) unavailable.style.display='block';
          return;
        }

        if(j.initialized){
          setBadge('✓ Set', true);
          if(setNote) setNote.style.display='block';
          return;
        }

        setBadge('⏳ Not set', false);
        if(form) form.style.display='block';

      }catch{
        setBadge('⏳', false);
      }
    }

    if(saveBtn){
      saveBtn.addEventListener('click', async ()=>{
        clearMsg(ok); clearMsg(err);

        const p1 = (document.getElementById('vp1')||{}).value || '';
        const p2 = (document.getElementById('vp2')||{}).value || '';

        if(!p1 || p1.length < 10){showMsg(err,'Passphrase must be at least 10 characters');return;}
        if(p1 !== p2){showMsg(err,'Passphrases do not match');return;}

        saveBtn.disabled=true;
        if(saveTxt) saveTxt.innerHTML='<span class="spin"></span>';

        try{
          const c = requireWebCrypto();
          const saltBytes = new Uint8Array(32);
          c.getRandomValues(saltBytes);
          const kdf_salt = bytesToB64(saltBytes);

          const key = await deriveKey(p1, kdf_salt, PBKDF2_ITERS);
          const enc = await aesEncrypt(VAULT_CHECK_PLAIN, key);

          const j = await postCsrf('api/vault.php', {
            action:'setup_save',
            cipher_blob: enc.cipher_blob,
            iv: enc.iv,
            auth_tag: enc.auth_tag,
            kdf_salt,
            kdf_iterations: PBKDF2_ITERS,
          });

          if(!j.success){showMsg(err,j.error||'Failed to set vault passphrase');return;}
          showMsg(ok,'Vault passphrase set.');
          if(document.getElementById('vp1')) document.getElementById('vp1').value='';
          if(document.getElementById('vp2')) document.getElementById('vp2').value='';
          localStorage.setItem('vault_slot', '1');
          loadVaultStatus();

        }catch(e){
          showMsg(err,(e && e.message) ? e.message : 'Failed to set vault passphrase');
        }finally{
          saveBtn.disabled=false;
          if(saveTxt) saveTxt.textContent='Set vault passphrase';
        }
      });
    }

    loadVaultStatus();
  }

  

  // ── NOTIFICATION PREFS (time lock email reminders) ─────────────────
  if(VERIFIED){
    const cb = document.getElementById('pref-email-lock-reminders');
    const save = document.getElementById('pref-save-email-reminders');
    const ok = document.getElementById('pref-email-ok');
    const err = document.getElementById('pref-email-err');
    const badge = document.getElementById('email-reminders-badge');

    function showPrefMsg(el, text){
      if(!el) return;
      el.textContent = text;
      el.classList.add('show');
    }

    if(save && cb){
      save.addEventListener('click', async ()=>{
        if(ok) ok.classList.remove('show');
        if(err) err.classList.remove('show');

        save.disabled = true;
        const enabled = cb.checked ? 1 : 0;

        const j = await postCsrf('api/account.php', {action:'set_email_time_lock_reminders', enabled});
        save.disabled = false;

        if(!j.success){
          showPrefMsg(err, j.error || 'Failed');
          return;
        }

        showPrefMsg(ok, 'Saved.');
        if(badge){
          badge.textContent = enabled ? '✓ Email on' : '⏳ Email off';
          badge.className = 'badge ' + (enabled ? 'ok' : 'wait');
        }
      });

      cb.addEventListener('change', ()=>{
        const s = cb.parentNode ? cb.parentNode.querySelector('span') : null;
        if(s) s.textContent = cb.checked ? 'On' : 'Off';
      });
    }
  }

  loadTrustPassport();
})();
</script>
</div>
</body>
</html>
