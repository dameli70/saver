<?php
require_once __DIR__ . '/includes/security_page.php';
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.security_sessions')) ?></title>
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
        <div class="page-title"><?php e('page.security_sessions'); ?></div>
        <div class="page-sub"><?php e('account.active_sessions_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="security.php"><?php e('common.back'); ?></a>
      </div>
    </div>

    <div class="card">
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

<script>
(() => {
  const api = window.LS_SECURITY_API;
  if(!api) return;

  const wrap = document.getElementById('sess');
  const err = document.getElementById('sess-err');

  async function loadSessions(){
    if(!wrap || !err) return;

    api.clearMsg(err);
    wrap.innerHTML = '<div class="small">Loading…</div>';

    try{
      const j = await api.postCsrf('api/account.php', {action:'sessions'});
      if(!j.success){
        api.showMsg(err, j.error || 'Failed to load sessions');
        wrap.innerHTML = '';
        return;
      }

      if(!j.sessions || !j.sessions.length){
        wrap.innerHTML = '<div class="small">No tracked sessions yet (apply migrations to enable session tracking).</div>';
        return;
      }

      wrap.innerHTML = '';
      j.sessions.forEach(s => {
        const el = document.createElement('div');
        el.className = 'item';

        const left = document.createElement('div');
        const right = document.createElement('div');
        right.className = 'small';

        const line1 = document.createElement('div');
        line1.className = 'small';

        const curSpan = document.createElement('span');
        curSpan.style.color = s.is_current ? 'var(--green)' : 'var(--muted)';
        curSpan.textContent = s.is_current ? 'CURRENT' : 'OTHER';
        line1.appendChild(curSpan);
        line1.append(' · Last seen: ');

        const lastSeen = document.createElement('span');
        lastSeen.style.color = 'var(--text)';
        lastSeen.textContent = s.last_seen_at || '';
        line1.appendChild(lastSeen);

        const line2 = document.createElement('div');
        line2.className = 'small';
        line2.append('IP: ');
        const ip = document.createElement('span');
        ip.style.color = 'var(--text)';
        ip.textContent = s.ip_address || '';
        line2.appendChild(ip);

        const line3 = document.createElement('div');
        line3.className = 'small';
        line3.append('UA: ');
        const ua = document.createElement('span');
        ua.style.color = 'var(--text)';
        ua.textContent = String(s.user_agent || '').slice(0, 160);
        line3.appendChild(ua);

        left.appendChild(line1);
        left.appendChild(line2);
        left.appendChild(line3);

        right.append('Created: ');
        const created = document.createElement('span');
        created.style.color = 'var(--text)';
        created.textContent = s.created_at || '';
        right.appendChild(created);

        el.appendChild(left);
        el.appendChild(right);
        wrap.appendChild(el);
      });

    }catch{
      api.showMsg(err, 'Network error');
      wrap.innerHTML = '';
    }
  }

  const logoutAll = document.getElementById('logout-all');
  if(logoutAll){
    logoutAll.addEventListener('click', async () => {
      let ok = false;

      const msg = 'Log out all sessions (including this one)?';
      const title = <?= json_encode(t('account.logout_all_sessions_btn')) ?>;
      const confirmText = <?= json_encode(t('common.logout')) ?>;
      const cancelText = <?= json_encode(t('common.cancel')) ?>;

      if(window.LS && typeof window.LS.confirm === 'function'){
        ok = await window.LS.confirm(msg, {title, danger:true, confirmText, cancelText});
      } else {
        ok = confirm(msg);
      }

      if(!ok) return;

      logoutAll.disabled = true;
      try{
        const j = await api.postCsrf('api/account.php', {action:'logout_all_sessions'});
        if(j.success){
          window.location = 'login.php';
          return;
        }

        const m = j.error || 'Failed';
        if(window.LS && typeof window.LS.toast === 'function') window.LS.toast(m, 'err');
        api.showMsg(err, m);

      }catch{
        const m = 'Network error';
        if(window.LS && typeof window.LS.toast === 'function') window.LS.toast(m, 'err');
        api.showMsg(err, m);

      }finally{
        logoutAll.disabled = false;
      }
    });
  }

  const refresh = document.getElementById('sess-refresh');
  if(refresh) refresh.addEventListener('click', loadSessions);

  loadSessions();
})();
</script>
</div>
</body>
</html>
