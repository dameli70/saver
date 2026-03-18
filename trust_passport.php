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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('account.trust_title')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<style>
.row{display:flex;align-items:flex-start;justify-content:space-between;gap:var(--ls-space-3);flex-wrap:wrap;}
.list{margin-top:var(--ls-space-3);display:flex;flex-direction:column;gap:var(--ls-space-3);}
.item{border:1px solid var(--b1);background:linear-gradient(180deg, var(--s2), var(--s1));padding:var(--ls-space-3) var(--ls-space-4);display:flex;justify-content:space-between;align-items:flex-start;gap:var(--ls-space-3);flex-wrap:wrap;border-radius:var(--radius-card);}
</style>
</head>
<body>
<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('account.trust_title'); ?></div>
        <div class="page-sub"><?php e('account.trust_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      </div>
    </div>

    <div class="card">
      <div class="row">
        <div>
          <div class="k"><?php e('account.trust_title'); ?></div>
          <div class="v" id="trust-next">—</div>
        </div>
        <div class="badge wait" id="trust-level-badge">⏳</div>
      </div>

      <div class="hr"></div>

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

  </div>
</div>

<script>
(() => {
  const CSRF = <?= json_encode($csrf) ?>;

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (Object.prototype.hasOwnProperty.call(I18N, key) ? I18N[key] : null) || fallback || key;
  }
  function tf(key, vars, fallback){
    let s = tr(key, fallback);
    if(vars){
      Object.keys(vars).forEach(k => {
        s = String(s).split('{' + k + '}').join(String(vars[k]));
      });
    }
    return s;
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

  async function loadPassport(){
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
      const r = await fetch('api/trust.php?action=passport', {credentials:'same-origin'});
      const j = await r.json();
      if(!j.success) throw new Error(j.error || tr('account.trust.failed_to_load', 'Failed to load trust passport.'));

      const t = j.trust || {};
      const level = parseInt(String(t.level || '1'), 10) || 1;

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

          function parseUtcDate(ts){
            const s = String(ts||'').trim();
            if(!s) return null;
            if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
              return new Date(s.replace(' ', 'T') + 'Z');
            }
            return new Date(s);
          }

          const now = Date.now();
          const startAt = r.start_at ? parseUtcDate(r.start_at).getTime() : null;
          const revealAt = r.reveal_at ? parseUtcDate(r.reveal_at).getTime() : null;

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
      badge.textContent = '—';
      badge.className = 'badge wait';
      msg.textContent = (e && e.message) ? e.message : tr('account.trust.failed_to_load', 'Failed to load trust passport.');
      msg.classList.add('show');
    }
  }

  loadPassport();
})();
</script>
</body>
</html>
