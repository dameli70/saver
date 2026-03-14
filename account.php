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

$hasTotp = hasTotpColumns();
$hasPasskeys = hasWebauthnCredentialsTable();

$hasReqWebauthn = false;
try {
    $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'require_webauthn' LIMIT 1");
    $hasReqWebauthn = (bool)$stmt->fetchColumn();
} catch (Throwable) {
    $hasReqWebauthn = false;
}

$sel = 'email, email_verified_at, verification_sent_at'
     . ($hasTotp ? ', totp_enabled_at' : ', NULL AS totp_enabled_at')
     . ($hasReqWebauthn ? ', require_webauthn' : ', 0 AS require_webauthn');

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

.card{margin-bottom:14px;}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
.k{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;}
.v{color:var(--text);font-size:12px;letter-spacing:.4px;}
.badge{display:inline-flex;align-items:center;gap:8px;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:5px 10px;border:1px solid;border-radius:var(--radius-pill);}
.badge.ok{background:color-mix(in srgb, var(--green) 7%, transparent);border-color:color-mix(in srgb, var(--green) 20%, transparent);color:var(--green);} 
.badge.wait{background:color-mix(in srgb, var(--orange) 7%, transparent);border-color:color-mix(in srgb, var(--orange) 20%, transparent);color:var(--orange);} 
 
.dev{margin-top:12px;border:1px dashed color-mix(in srgb, var(--orange) 35%, transparent);background:color-mix(in srgb, var(--orange) 6%, transparent);padding:10px 12px;font-size:11px;color:var(--muted);line-height:1.6;display:none;}
.dev a{color:var(--orange);} 
.field{margin-top:14px;margin-bottom:0;}
.field label{display:block;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin-bottom:6px;}
.field input{width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);
  font-size:15px;padding:14px;outline:none;transition:border-color .2s;border-radius:var(--radius-input);-webkit-appearance:none;}
.field input:focus{border-color:var(--accent);} 
.hr{border-top:1px solid var(--b1);margin:16px 0;}
.list{margin-top:10px;display:flex;flex-direction:column;gap:10px;}
.item{border:1px solid var(--b1);background:linear-gradient(180deg, var(--s2), var(--s1));padding:12px 14px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;border-radius:var(--radius-card);}
.small{font-size:11px;color:var(--muted);line-height:1.6;}
.btn-red{background:color-mix(in srgb, var(--red) 10%, transparent);border:1px solid color-mix(in srgb, var(--red) 28%, transparent);color:var(--red);} 
.btn-red:hover{background:color-mix(in srgb, var(--red) 16%, transparent);} 
code{background:var(--s2);border:1px solid var(--b1);padding:2px 6px;border-radius:10px;}

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
        <?php if ($verified): ?>
          <a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a>
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
    <div class="card" id="totp-card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.totp_title'); ?></div>
          <div class="v"><?php e('account.totp_sub'); ?></div>
        </div>
        <?php if ($hasTotp): ?>
          <?php if (!empty($u['totp_enabled_at'])): ?>
            <div class="badge ok"><?= htmlspecialchars(t('account.totp_enabled'), ENT_QUOTES, 'UTF-8') ?></div>
          <?php else: ?>
            <div class="badge wait"><?= htmlspecialchars(t('account.totp_not_enabled'), ENT_QUOTES, 'UTF-8') ?></div>
          <?php endif; ?>
        <?php else: ?>
          <div class="badge wait"><?= htmlspecialchars(t('account.totp_unavailable'), ENT_QUOTES, 'UTF-8') ?></div>
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
            <input type="checkbox" id="passkey-required" <?= $hasReqWebauthn ? '' : 'disabled' ?> <?= !empty($u['require_webauthn']) ? 'checked' : '' ?> >
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
    <?php endif; ?>

    <div class="card">
      <div class="row" style="margin-bottom:4px;">
        <div>
          <div class="k"><?php e('account.security_title'); ?></div>
          <div class="v"><?php e('account.security_sub'); ?></div>
        </div>
      </div>

      <div class="small"><?php e('account.security_note_html'); ?></div>

      <div class="hr"></div>

      <div class="k"><?php e('account.change_login_password_title'); ?></div>
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

      <div class="hr"></div>

      <div class="row">
        <div>
          <div class="k"><?php e('account.active_sessions_title'); ?></div>
          <div class="small"><?php e('account.active_sessions_sub'); ?></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-ghost" id="sess-refresh" type="button"><?php e('common.refresh'); ?></button>
          <button class="btn btn-red" id="logout-all" type="button"><?php e('account.logout_all_sessions_btn'); ?></button>
        </div>
      </div>

      <div id="sess" class="list"></div>
      <div id="sess-err" class="msg msg-err"></div>
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
  const TOTP_AVAILABLE = <?= $hasTotp ? 'true' : 'false' ?>;
  const PASSKEYS_AVAILABLE = <?= $hasPasskeys ? 'true' : 'false' ?>;
  const TOTP_ENABLED = <?= (!empty($u['totp_enabled_at'])) ? 'true' : 'false' ?>;
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

  // base64url helpers for WebAuthn
  function b64uToBuf(b64url){
    const b64 = String(b64url||'').replace(/-/g,'+').replace(/_/g,'/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const bin = atob(b64 + pad);
    const bytes = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64u(buf){
    const bytes = new Uint8Array(buf);
    let s='';
    for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }

  async function ensureReauth(methods){
    if(methods && methods.passkey && window.PublicKeyCredential){
      const begin = await postCsrf('api/webauthn.php', {action:'reauth_begin'});
      if(begin.success){
        const pk = begin.publicKey || {};
        const allow = (pk.allowCredentials||[]).map(c => ({type:c.type, id: b64uToBuf(c.id)}));
        const cred = await navigator.credentials.get({publicKey:{
          challenge: b64uToBuf(pk.challenge),
          rpId: pk.rpId,
          timeout: pk.timeout||60000,
          userVerification: pk.userVerification||'required',
          allowCredentials: allow,
        }});

        const a = cred.response;
        const fin = await postCsrf('api/webauthn.php', {
          action:'reauth_finish',
          rawId: bufToB64u(cred.rawId),
          response:{
            clientDataJSON: bufToB64u(a.clientDataJSON),
            authenticatorData: bufToB64u(a.authenticatorData),
            signature: bufToB64u(a.signature),
            userHandle: a.userHandle ? bufToB64u(a.userHandle) : null,
          }
        });
        return !!fin.success;
      }
    }

    if(methods && methods.totp){
      const code = prompt(tr('login.enter_totp', 'Enter your 6-digit authenticator code'));
      if(!code) return false;
      const r = await postCsrf('api/totp.php', {action:'reauth', code});
      return !!r.success;
    }

    return false;
  }

  async function loadSessions(){
    const wrap=document.getElementById('sess');
    const err=document.getElementById('sess-err');
    if(!wrap||!err) return;
    clearMsg(err);
    wrap.innerHTML='<div class="small">Loading…</div>';

    try{
      const j=await postCsrf('api/account.php',{action:'sessions'});
      if(!j.success){showMsg(err,j.error||'Failed to load sessions');wrap.innerHTML='';return;}

      if(!j.sessions||!j.sessions.length){
        wrap.innerHTML='<div class="small">No tracked sessions yet (apply migrations to enable session tracking).</div>';
        return;
      }

      wrap.innerHTML='';
      j.sessions.forEach(s=>{
        const el=document.createElement('div');
        el.className='item';

        const left=document.createElement('div');
        const right=document.createElement('div');
        right.className='small';

        const line1=document.createElement('div');
        line1.className='small';

        const curSpan=document.createElement('span');
        curSpan.style.color = s.is_current ? 'var(--green)' : 'var(--muted)';
        curSpan.textContent = s.is_current ? 'CURRENT' : 'OTHER';
        line1.appendChild(curSpan);
        line1.append(' · Last seen: ');

        const lastSeen=document.createElement('span');
        lastSeen.style.color='var(--text)';
        lastSeen.textContent = s.last_seen_at || '';
        line1.appendChild(lastSeen);

        const line2=document.createElement('div');
        line2.className='small';
        line2.append('IP: ');
        const ip=document.createElement('span');
        ip.style.color='var(--text)';
        ip.textContent = s.ip_address || '';
        line2.appendChild(ip);

        const line3=document.createElement('div');
        line3.className='small';
        line3.append('UA: ');
        const ua=document.createElement('span');
        ua.style.color='var(--text)';
        ua.textContent = String(s.user_agent || '').slice(0, 160);
        line3.appendChild(ua);

        left.appendChild(line1);
        left.appendChild(line2);
        left.appendChild(line3);

        right.append('Created: ');
        const created=document.createElement('span');
        created.style.color='var(--text)';
        created.textContent = s.created_at || '';
        right.appendChild(created);

        el.appendChild(left);
        el.appendChild(right);
        wrap.appendChild(el);
      });
    }catch{
      showMsg(err,'Network error');
      wrap.innerHTML='';
    }
  }

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

      if(!cur||!p1||!p2){showMsg(err,'Fill in all fields');return;}
      if(p1.length<8){showMsg(err,'New password must be at least 8 characters');return;}
      if(p1!==p2){showMsg(err,'Passwords do not match');return;}

      btn.disabled=true;
      btnTxt.innerHTML='<span class="spin"></span>';

      try{
        const j=await postCsrf('api/account.php',{action:'change_login_password',current_password:cur,new_password:p1});
        if(!j.success){showMsg(err,j.error||'Update failed');return;}
        showMsg(ok,'Login password updated.');
        pwForm.reset();
      }catch{
        showMsg(err,'Network error');
      }finally{
        btn.disabled=false;
        btnTxt.textContent='Update password';
      }
    });
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
  if(sessRefresh){
    sessRefresh.addEventListener('click', loadSessions);
  }

  // ── TOTP ─────────────────────────────────────
  if(VERIFIED && TOTP_AVAILABLE){
    const ok=document.getElementById('totp-ok');
    const err=document.getElementById('totp-err');
    const setup=document.getElementById('totp-setup');
    const dis=document.getElementById('totp-disable');

    function totpSetUi(enabled){
      document.getElementById('totp-begin').style.display = enabled ? 'none' : 'inline-flex';
      setup.style.display = 'none';
      dis.style.display = enabled ? 'block' : 'none';
    }

    totpSetUi(TOTP_ENABLED);

    document.getElementById('totp-begin').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const j=await postCsrf('api/totp.php', {action:'begin'});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      document.getElementById('totp-secret').textContent = j.secret;
      const a=document.getElementById('totp-otpauth');
      a.href=j.otpauth; a.textContent=j.otpauth;
      setup.style.display='block';
    });

    document.getElementById('totp-enable').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=document.getElementById('totp-code').value.trim();
      if(!code){showMsg(err,'Code required');return;}
      const btn=document.getElementById('totp-enable');
      const txt=document.getElementById('totp-enable-txt');
      btn.disabled=true; txt.innerHTML='<span class="spin"></span>';
      try{
        const j=await postCsrf('api/totp.php', {action:'enable', code});
        if(!j.success){showMsg(err,j.error||'Failed');return;}
        showMsg(ok,'TOTP enabled.');
        totpSetUi(true);
      }finally{
        btn.disabled=false; txt.textContent='Enable TOTP';
      }
    });

    document.getElementById('totp-disable-btn').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=document.getElementById('totp-disable-code').value.trim();
      if(!code){showMsg(err,'Code required');return;}
      const j=await postCsrf('api/totp.php', {action:'disable', code});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'TOTP disabled.');
      totpSetUi(false);
    });

    document.getElementById('totp-reauth').addEventListener('click', async ()=>{
      clearMsg(ok); clearMsg(err);
      const code=prompt(tr('login.enter_totp', 'Enter your 6-digit authenticator code'));
      if(!code) return;
      const j=await postCsrf('api/totp.php', {action:'reauth', code});
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'Re-auth successful.');
    });
  }

  // ── PASSKEYS ─────────────────────────────────
  if(VERIFIED && PASSKEYS_AVAILABLE){
    const ok=document.getElementById('passkey-ok');
    const err=document.getElementById('passkey-err');
    const list=document.getElementById('passkeys-list');
    const status=document.getElementById('passkeys-status');

    function setStatus(text, ok){
      status.textContent = text;
      status.className = 'badge ' + (ok ? 'ok' : 'wait');
    }

    async function loadPasskeys(){
      clearMsg(ok); clearMsg(err);
      list.innerHTML='<div class="small">Loading…</div>';
      const j=await postCsrf('api/webauthn.php', {action:'list'});
      if(!j.success){showMsg(err,j.error||'Failed');list.innerHTML='';setStatus('⏳',false);return;}
      const keys=j.passkeys||[];
      setStatus(keys.length ? '✓ Enabled' : '⏳ None', !!keys.length);
      if(!keys.length){list.innerHTML='<div class="small">No passkeys registered.</div>';return;}

      list.innerHTML='';
      keys.forEach(k=>{
        const el=document.createElement('div');
        el.className='item';
        const label=k.label ? k.label : 'Passkey';
        el.innerHTML=`
          <div>
            <div class="small" style="color:var(--text)">${label}</div>
            <div class="small">Created: ${k.created_at||''}</div>
            <div class="small">Last used: ${k.last_used_at||'—'}</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <button class="btn btn-red" data-id="${k.id}">Delete</button>
          </div>
        `;
        el.querySelector('button').addEventListener('click', ()=>deletePasskey(k.id));
        list.appendChild(el);
      });
    }

    async function deletePasskey(id){
      clearMsg(ok); clearMsg(err);
      if(!confirm('Delete this passkey?')) return;

      let j=await postCsrf('api/webauthn.php', {action:'delete', id});
      if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
        const ok2 = await ensureReauth(j.methods||{});
        if(!ok2){showMsg(err,j.error||'Re-auth required');return;}
        j=await postCsrf('api/webauthn.php', {action:'delete', id});
      }
      if(!j.success){showMsg(err,j.error||'Failed');return;}
      showMsg(ok,'Deleted.');
      loadPasskeys();
    }

    async function addPasskey(){
      clearMsg(ok); clearMsg(err);
      if(!window.PublicKeyCredential){showMsg(err,'Passkeys not supported in this browser');return;}

      const label = prompt('Label for this passkey (optional)') || '';
      const btn=document.getElementById('passkey-add');
      const txt=document.getElementById('passkey-add-txt');
      btn.disabled=true; txt.innerHTML='<span class="spin"></span>';

      try{
        const begin=await postCsrf('api/webauthn.php', {action:'register_begin'});
        if(!begin.success){showMsg(err,begin.error||'Failed');return;}

        const pk=begin.publicKey||{};
        const exclude=(pk.excludeCredentials||[]).map(c => ({type:c.type, id: b64uToBuf(c.id)}));

        const cred=await navigator.credentials.create({publicKey:{
          challenge: b64uToBuf(pk.challenge),
          rp: pk.rp,
          user: {
            id: b64uToBuf(pk.user.id),
            name: pk.user.name,
            displayName: pk.user.displayName,
          },
          pubKeyCredParams: pk.pubKeyCredParams,
          timeout: pk.timeout||60000,
          attestation: pk.attestation||'none',
          authenticatorSelection: pk.authenticatorSelection||{userVerification:'required'},
          excludeCredentials: exclude,
        }});

        const a=cred.response;
        const fin=await postCsrf('api/webauthn.php', {
          action:'register_finish',
          label,
          rawId: bufToB64u(cred.rawId),
          response:{
            clientDataJSON: bufToB64u(a.clientDataJSON),
            attestationObject: bufToB64u(a.attestationObject),
          }
        });

        if(!fin.success){showMsg(err,fin.error||'Failed');return;}
        showMsg(ok,'Passkey added.');
        loadPasskeys();

      }catch(e){
        showMsg(err,(e && e.message) ? e.message : 'Passkey failed');
      }finally{
        btn.disabled=false; txt.textContent='Add passkey';
      }
    }

    document.getElementById('passkey-refresh').addEventListener('click', loadPasskeys);
    document.getElementById('passkey-add').addEventListener('click', addPasskey);

    const req=document.getElementById('passkey-required');
    if(req){
      req.addEventListener('change', async ()=>{
        clearMsg(ok); clearMsg(err);
        const enabled = req.checked ? 1 : 0;

        let j=await postCsrf('api/webauthn.php', {action:'require_for_login', enabled});
        if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
          const ok2 = await ensureReauth(j.methods||{});
          if(!ok2){showMsg(err,j.error||'Re-auth required');req.checked=!req.checked;return;}
          j=await postCsrf('api/webauthn.php', {action:'require_for_login', enabled});
        }

        if(!j.success){showMsg(err,j.error||'Failed');req.checked=!req.checked;return;}
        showMsg(ok, enabled ? 'Passkey required for login.' : 'Password login allowed.');
      });
    }

    loadPasskeys();
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
  loadSessions();
})();
</script>
</div>
</body>
</html>
