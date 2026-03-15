(function(){
  'use strict';

  // Optional helper used by admin_add_user.php.
  // Depends on global postCsrf/setMsg/esc being provided by assets/admin_shared.js.

  async function createUser(){
    const emailEl = document.getElementById('nu-email');
    const loginEl = document.getElementById('nu-login');
    const trustEl = document.getElementById('nu-trust');
    const verifiedEl = document.getElementById('nu-verified');
    const adminEl = document.getElementById('nu-admin');

    if(!emailEl || !loginEl) return;

    const email = String(emailEl.value || '').trim();
    const login = String(loginEl.value || '');
    const trustLevel = trustEl ? parseInt(String(trustEl.value || '1'), 10) : 1;
    const markVerified = !!(verifiedEl && verifiedEl.checked);
    const makeAdmin = !!(adminEl && adminEl.checked);

    const msg = document.getElementById('nu-msg');
    const dev = document.getElementById('nu-dev');

    if(msg) msg.className = 'msg';
    if(dev) dev.style.display = 'none';

    try{
      const r = await window.postCsrf('/api/admin.php', {
        action: 'create_user',
        email,
        login_password: login,
        trust_level: (trustLevel === 2 || trustLevel === 3) ? trustLevel : 1,
        mark_verified: markVerified ? 1 : 0,
        is_admin: makeAdmin ? 1 : 0,
      });
      if(!r || !r.success) throw new Error((r && r.error) ? r.error : 'Failed');

      if(window.setMsg) window.setMsg('nu-msg', 'User created.', true);

      emailEl.value = '';
      loginEl.value = '';
      if(trustEl) trustEl.value = '1';

      if(r.dev_verify_url && dev){
        dev.style.display = 'block';
        dev.className = 'msg show';
        dev.innerHTML = `DEV verify URL: <a href="${window.esc ? esc(r.dev_verify_url) : r.dev_verify_url}">${window.esc ? esc(r.dev_verify_url) : r.dev_verify_url}</a>`;
      }

    }catch(e){
      if(window.setMsg) window.setMsg('nu-msg', (e && e.message) ? e.message : 'Failed', false);
    }
  }

  // Expose for inline onclick handlers.
  window.createUser = window.createUser || createUser;
})();
