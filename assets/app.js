(function(){
  'use strict';

  const LS = {};

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function t(key, fallback){
    return (I18N && typeof I18N[key] === 'string') ? I18N[key] : fallback;
  }

  const STR = {
    reauth_title: t('js.reauth_title', 'Re-authentication required'),
    reauth_sub: t('js.reauth_sub', 'Confirm it’s you to continue. Choose a method below.'),
    authenticator_code: t('js.authenticator_code', 'Authenticator code'),
    use_passkey: t('js.use_passkey', 'Use passkey'),
    use_auth_code: t('js.use_auth_code', 'Use authenticator code'),
    waiting: t('js.waiting', 'Waiting for confirmation…'),
    internal_error_missing_auth: t('js.internal_error_missing_auth', 'Internal error: missing auth handler'),
    enable_totp_or_passkey: t('js.enable_totp_or_passkey', 'Enable TOTP or add a passkey in Security'),
    passkey_reauth_failed: t('js.passkey_reauth_failed', 'Passkey re-auth failed'),
    enter_6_digit_code: t('js.enter_6_digit_code', 'Enter a 6-digit code'),
    invalid_code: t('js.invalid_code', 'Invalid code'),
    cancelled: t('js.cancelled', 'Cancelled'),
    unsupported_reauth: t('js.unsupported_reauth', 'Unsupported re-auth method'),
    reauth_failed: t('js.reauth_failed', 'Re-auth failed'),
    copy_confirm: t('js.copy_confirm', 'Copy to clipboard? Clipboard contents may be readable by other apps until overwritten.'),

    confirm: t('common.confirm', 'Confirm'),
    cancel: t('common.cancel', 'Cancel'),
    back: t('common.back', 'Back'),
    close: t('common.close', 'Close'),
    open: t('common.open', 'Open'),
    logout: t('common.logout', 'Log out'),
    install: t('common.install', 'Install'),
    copy: t('common.copy', 'Copy'),
  };

  LS.esc = function(s){
    return String(s||'')
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  };

  LS._defaultLocale = 'fr';

  LS._defaultStrings = {
    'js.reauth.close': 'Close',
    'js.reauth.title': 'Re-authentication required',
    'js.reauth.subtitle': 'Confirm it’s you to continue. Choose a method below.',
    'js.reauth.authenticator_code_label': 'Authenticator code',
    'js.reauth.authenticator_code_placeholder': '123456',
    'js.reauth.confirm': 'Confirm',
    'js.reauth.back': 'Back',
    'js.reauth.waiting': 'Waiting for confirmation…',
    'js.reauth.use_passkey': 'Use passkey',
    'js.reauth.use_authenticator_code': 'Use authenticator code',
    'js.common.cancel': 'Cancel',

    'js.errors.missing_auth_handler': 'Internal error: missing auth handler',
    'js.reauth.enable_totp_or_passkey': 'Enable TOTP or add a passkey in Security',
    'js.reauth.passkey_failed': 'Passkey re-auth failed',
    'js.reauth.enter_6_digit_code': 'Enter a 6-digit code',
    'js.reauth.invalid_code': 'Invalid code',
    'js.reauth.cancelled': 'Cancelled',
    'js.reauth.unsupported_method': 'Unsupported re-auth method',
    'js.reauth.failed': 'Re-auth failed',

    'js.copy.confirm_sensitive': 'Copy to clipboard? Clipboard contents may be readable by other apps until overwritten.',
    'js.pwa_install_confirm': 'Install this app?',
  };

  LS.getI18n = function(){
    const raw = (window && window.LS_I18N && typeof window.LS_I18N === 'object') ? window.LS_I18N : null;
    const strings = (raw && raw.strings && typeof raw.strings === 'object') ? raw.strings : {};

    const lang = (raw && typeof raw.lang === 'string' && raw.lang) ? raw.lang :
      (document && document.documentElement && document.documentElement.lang ? document.documentElement.lang : LS._defaultLocale);

    return {
      lang: lang || LS._defaultLocale,
      strings,
    };
  };

  LS.locale = function(){
    return LS.getI18n().lang || LS._defaultLocale;
  };

  LS.t = function(key){
    const i18n = LS.getI18n();

    let val = null;
    if(i18n.strings && Object.prototype.hasOwnProperty.call(i18n.strings, key)){
      val = i18n.strings[key];
    }else if(Object.prototype.hasOwnProperty.call(LS._defaultStrings, key)){
      val = LS._defaultStrings[key];
    }else{
      val = key;
    }

    return String(val == null ? '' : val);
  };

  LS.toast = function(msg, type='ok', ms=3200){
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = String(msg||'');
    document.body.appendChild(t);
    setTimeout(()=>t.remove(), ms);
  };

  

  LS.confirm = function(message, opts){
    const o = (opts && typeof opts === 'object') ? opts : {};

    const title = (o.title != null) ? String(o.title) : STR.confirm;
    const confirmText = (o.confirmText != null) ? String(o.confirmText) : STR.confirm;
    const cancelText = (o.cancelText != null) ? String(o.cancelText) : STR.cancel;
    const danger = !!o.danger;

    let overlay = document.getElementById('ls-confirm-overlay');
    if(!overlay){
      overlay = document.createElement('div');
      overlay.id = 'ls-confirm-overlay';
      overlay.className = 'ls-modal-overlay';
      overlay.innerHTML = `
        <div class="ls-modal" role="dialog" aria-modal="true" aria-labelledby="ls-confirm-title">
          <button class="ls-modal-x" type="button" aria-label="${LS.esc(STR.close)}">×</button>
          <div class="ls-modal-title" id="ls-confirm-title"></div>
          <div class="ls-modal-sub" id="ls-confirm-msg" style="white-space:pre-wrap;"></div>
          <div class="ls-modal-actions" id="ls-confirm-actions" style="display:flex;flex-direction:column;gap:10px;margin-top:18px;"></div>
        </div>
      `;
      document.body.appendChild(overlay);
    }

    const modal = overlay.querySelector('.ls-modal');
    const titleEl = overlay.querySelector('#ls-confirm-title');
    const msgEl = overlay.querySelector('#ls-confirm-msg');
    const actions = overlay.querySelector('#ls-confirm-actions');
    const closeBtn = overlay.querySelector('.ls-modal-x');

    if(titleEl) titleEl.textContent = title;
    if(msgEl) msgEl.textContent = String(message || '');

    if(actions){
      actions.innerHTML = '';

      const okBtn = document.createElement('button');
      okBtn.type = 'button';
      okBtn.className = danger ? 'btn btn-red' : 'btn btn-primary';
      okBtn.textContent = confirmText;
      okBtn.style.width = '100%';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn btn-ghost';
      cancelBtn.textContent = cancelText;
      cancelBtn.style.width = '100%';

      actions.appendChild(okBtn);
      actions.appendChild(cancelBtn);

      overlay.classList.add('show');

      const prevFocus = document.activeElement;

      let releaseTrap = null;
      let resolved = false;

      return new Promise(resolve => {
        function cleanup(){
          overlay.classList.remove('show');

          if(releaseTrap) releaseTrap();

          overlay.removeEventListener('click', onClickOut);
          if(closeBtn) closeBtn.removeEventListener('click', onCancel);
          cancelBtn.removeEventListener('click', onCancel);
          okBtn.removeEventListener('click', onOk);

          if(prevFocus && prevFocus.focus) setTimeout(()=>prevFocus.focus(), 0);
        }

        function onCancel(){
          if(resolved) return;
          resolved = true;
          cleanup();
          resolve(false);
        }

        function onOk(){
          if(resolved) return;
          resolved = true;
          cleanup();
          resolve(true);
        }

        function onClickOut(e){
          if(e.target === overlay) onCancel();
        }

        try{ if(modal) releaseTrap = trapFocus(modal, onCancel); }catch{}

        overlay.addEventListener('click', onClickOut);
        if(closeBtn) closeBtn.addEventListener('click', onCancel);
        cancelBtn.addEventListener('click', onCancel);
        okBtn.addEventListener('click', onOk);

        setTimeout(()=>{ okBtn.focus(); }, 10);
      });
    }

    return Promise.resolve(false);
  };

  LS.parseUtc = function(ts){
    if(!ts) return null;
    const s = String(ts);

    // ISO strings are safe to pass through.
    if (/\dT\d/.test(s)) {
      const d = new Date(s);
      return isNaN(d.getTime()) ? null : d;
    }

    // MySQL DATETIME: "YYYY-MM-DD HH:MM:SS" — treat as UTC.
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) {
      const d = new Date(s.replace(' ', 'T') + 'Z');
      return isNaN(d.getTime()) ? null : d;
    }

    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  };

  LS.fmtLocal = function(d){
    if(!(d instanceof Date) || isNaN(d.getTime())) return '';
    return d.toLocaleString(LS.locale(), {year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  };

  LS.fmtUtc = function(d){
    if(!(d instanceof Date) || isNaN(d.getTime())) return '';
    return new Intl.DateTimeFormat(LS.locale(), {
      year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',
      timeZone:'UTC',
      timeZoneName:'short'
    }).format(d);
  };

  LS.fmtCountdown = function(totalSeconds){
    const s = Math.max(0, Math.floor(Number(totalSeconds)||0));
    const days = Math.floor(s/86400);
    const hours = Math.floor((s%86400)/3600);
    const minutes = Math.floor((s%3600)/60);
    const seconds = s%60;

    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  };

  LS.b64uToBuf = function(b64url){
    const b64 = String(b64url||'').replace(/-/g,'+').replace(/_/g,'/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const bin = atob(b64 + pad);
    const bytes = new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i);
    return bytes.buffer;
  };

  LS.bufToB64u = function(buf){
    const bytes = new Uint8Array(buf);
    let s='';
    for(let i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  };

  function getReauthEl(){
    let el = document.getElementById('ls-reauth-overlay');
    if(el) return el;

    el = document.createElement('div');
    el.id = 'ls-reauth-overlay';
    el.className = 'ls-modal-overlay';
    el.innerHTML = `
      <div class="ls-modal" role="dialog" aria-modal="true" aria-labelledby="ls-reauth-title">
        <button class="ls-modal-x" type="button" aria-label="${LS.esc(STR.close)}">×</button>
        <div class="ls-modal-title" id="ls-reauth-title">${LS.esc(STR.reauth_title)}</div>
        <div class="ls-modal-sub">${LS.esc(STR.reauth_sub)}</div>

        <div class="msg msg-err" id="ls-reauth-err"></div>

        <div id="ls-reauth-choices" class="ls-modal-actions"></div>

        <div id="ls-reauth-totp" style="display:none;">
          <div class="field" style="margin-top:12px;">
            <label>${LS.esc(STR.authenticator_code)}</label>
            <input inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" id="ls-reauth-code">
          </div>
          <button class="btn btn-primary" type="button" id="ls-reauth-submit">${LS.esc(STR.confirm)}</button>
          <button class="btn btn-ghost" type="button" id="ls-reauth-back" style="margin-top:10px;width:100%;">${LS.esc(STR.back)}</button>
        </div>

        <div id="ls-reauth-wait" style="display:none;margin-top:12px;font-size:12px;color:var(--muted);letter-spacing:.4px;">
          <span class="spin light"></span> ${LS.esc(STR.waiting)}
        </div>
      </div>
    `;
    document.body.appendChild(el);

    return el;
  }

  function trapFocus(modal, onEsc){
    const focusables = modal.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    function onKey(e){
      if(e.key === 'Escape') {
        e.preventDefault();
        if(typeof onEsc === 'function') onEsc();
        return;
      }
      if(e.key !== 'Tab') return;
      if(!focusables.length) return;

      if(e.shiftKey && document.activeElement === first){
        e.preventDefault();
        last.focus();
      } else if(!e.shiftKey && document.activeElement === last){
        e.preventDefault();
        first.focus();
      }
    }

    modal.addEventListener('keydown', onKey);
    return ()=>modal.removeEventListener('keydown', onKey);
  }

  function showReauthModal(methods){
    const overlay = getReauthEl();
    const modal = overlay.querySelector('.ls-modal');

    const err = overlay.querySelector('#ls-reauth-err');
    const choices = overlay.querySelector('#ls-reauth-choices');
    const totpWrap = overlay.querySelector('#ls-reauth-totp');
    const wait = overlay.querySelector('#ls-reauth-wait');
    const closeBtn = overlay.querySelector('.ls-modal-x');

    err.classList.remove('show');
    err.textContent = '';

    totpWrap.style.display = 'none';
    wait.style.display = 'none';

    choices.innerHTML = '';

    const btns = [];

    if(methods && methods.passkey && window.PublicKeyCredential){
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-primary';
      b.textContent = STR.use_passkey;
      btns.push({el:b, method:'passkey'});
      choices.appendChild(b);
    }

    if(methods && methods.totp){
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-ghost';
      b.textContent = STR.use_auth_code;
      b.style.width = '100%';
      b.style.marginTop = '10px';
      btns.push({el:b, method:'totp'});
      choices.appendChild(b);
    }

    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'btn btn-ghost';
    cancel.textContent = STR.cancel;
    cancel.style.width = '100%';
    cancel.style.marginTop = '10px';
    choices.appendChild(cancel);

    overlay.classList.add('show');

    const prevFocus = document.activeElement;

    let resolved = false;
    let resolve;
    const p = new Promise(r => resolve = r);

    let releaseTrap = null;

    function cleanup(){
      overlay.classList.remove('show');
      if(releaseTrap) releaseTrap();
      overlay.removeEventListener('click', onClickOut);
      closeBtn.removeEventListener('click', onCancel);
      cancel.removeEventListener('click', onCancel);
      if(prevFocus && prevFocus.focus) setTimeout(()=>prevFocus.focus(), 0);
    }

    function onCancel(){
      if(resolved) return;
      cleanup();
      resolve({ok:false});
    }

    function onClickOut(e){
      if(e.target === overlay) onCancel();
    }

    releaseTrap = trapFocus(modal, onCancel);

    overlay.addEventListener('click', onClickOut);
    closeBtn.addEventListener('click', onCancel);
    cancel.addEventListener('click', onCancel);

    setTimeout(()=>{
      const firstChoice = choices.querySelector('button');
      if(firstChoice) firstChoice.focus();
    }, 10);

    btns.forEach(({el, method})=>{
      el.addEventListener('click', ()=>{
        resolved = true;
        if(method === 'totp'){
          choices.style.display = 'none';
          totpWrap.style.display = 'block';
          const codeEl = overlay.querySelector('#ls-reauth-code');
          codeEl.value = '';
          setTimeout(()=>codeEl.focus(), 0);
          resolve({ok:true, method:'totp', overlay, cleanup});
        } else {
          choices.style.display = 'none';
          wait.style.display = 'block';
          resolve({ok:true, method:'passkey', overlay, cleanup});
        }
      });
    });

    return p;
  }

  LS.reauth = async function(methods, opts){
    const post = opts && typeof opts.post === 'function' ? opts.post : null;
    if(!post){
      LS.toast(STR.internal_error_missing_auth, 'err');
      return false;
    }

    if(!methods || (!methods.passkey && !methods.totp)){
      LS.toast(STR.enable_totp_or_passkey, 'warn');
      const go = await LS.confirm(LS.t('js.reauth.go_to_security_setup_confirm') || 'Go to Security setup now?', {
        title: STR.enable_totp_or_passkey,
        confirmText: STR.open,
        cancelText: STR.cancel,
      });
      if(go){
        window.location.href = 'security.php';
      }
      return false;
    }

    const modalState = await showReauthModal(methods);
    if(!modalState.ok) return false;

    const overlay = modalState.overlay;
    const cleanup = modalState.cleanup;

    const err = overlay.querySelector('#ls-reauth-err');
    const choices = overlay.querySelector('#ls-reauth-choices');
    const totpWrap = overlay.querySelector('#ls-reauth-totp');
    const wait = overlay.querySelector('#ls-reauth-wait');

    function showErr(message){
      err.textContent = message;
      err.classList.add('show');
      wait.style.display = 'none';
      totpWrap.style.display = 'none';
      choices.style.display = 'block';
    }

    try{
      if(modalState.method === 'passkey'){
        const begin = await post('api/webauthn.php', {action:'reauth_begin'});
        if(!begin || !begin.success) { showErr(begin && begin.error ? begin.error : STR.passkey_reauth_failed); return false; }

        const pk = begin.publicKey || {};
        const allow = (pk.allowCredentials||[]).map(c => ({type:c.type, id: LS.b64uToBuf(c.id)}));

        const cred = await navigator.credentials.get({publicKey:{
          challenge: LS.b64uToBuf(pk.challenge),
          rpId: pk.rpId,
          timeout: pk.timeout||60000,
          userVerification: pk.userVerification||'required',
          allowCredentials: allow,
        }});

        const a = cred.response;
        const fin = await post('api/webauthn.php', {
          action:'reauth_finish',
          rawId: LS.bufToB64u(cred.rawId),
          response:{
            clientDataJSON: LS.bufToB64u(a.clientDataJSON),
            authenticatorData: LS.bufToB64u(a.authenticatorData),
            signature: LS.bufToB64u(a.signature),
            userHandle: a.userHandle ? LS.bufToB64u(a.userHandle) : null,
          }
        });

        if(!fin || !fin.success) { showErr(fin && fin.error ? fin.error : STR.passkey_reauth_failed); return false; }

        cleanup();
        return true;
      }

      if(modalState.method === 'totp'){
        const submit = overlay.querySelector('#ls-reauth-submit');
        const back = overlay.querySelector('#ls-reauth-back');
        const codeEl = overlay.querySelector('#ls-reauth-code');

        const r = await new Promise(resolve => {
          function done(val){
            submit.removeEventListener('click', onSubmit);
            back.removeEventListener('click', onBack);
            codeEl.removeEventListener('keydown', onKey);
            resolve(val);
          }

          async function onSubmit(){
            err.classList.remove('show');
            err.textContent = '';

            const code = (codeEl.value || '').trim();
            if(!/^\d{6}$/.test(code)){
              err.textContent = STR.enter_6_digit_code;
              err.classList.add('show');
              return;
            }

            submit.disabled = true;
            submit.innerHTML = '<span class="spin"></span>';

            const res = await post('api/totp.php', {action:'reauth', code});

            submit.disabled = false;
            submit.textContent = STR.confirm;

            if(res && res.success){
              done(true);
            }else{
              err.textContent = (res && res.error) ? res.error : STR.invalid_code;
              err.classList.add('show');
            }
          }

          function onBack(){
            done(false);
          }

          function onKey(e){
            if(e.key === 'Enter') onSubmit();
          }

          submit.addEventListener('click', onSubmit);
          back.addEventListener('click', onBack);
          codeEl.addEventListener('keydown', onKey);
        });

        if(!r) { showErr(STR.cancelled); return false; }

        cleanup();
        return true;
      }

      showErr(STR.unsupported_reauth);
      return false;

    }catch(e){
      showErr(e && e.message ? e.message : STR.reauth_failed);
      return false;
    }
  };

  LS.copySensitive = async function(text, opts){
    const clearAfterMs = (opts && Number.isFinite(opts.clearAfterMs)) ? opts.clearAfterMs : 30000;

    const ok = await LS.confirm(STR.copy_confirm, {
      title: STR.confirm,
      confirmText: STR.copy,
      cancelText: STR.cancel,
    });
    if(!ok) return false;

    await navigator.clipboard.writeText(String(text||''));

    if(clearAfterMs > 0){
      setTimeout(async ()=>{
        try{ await navigator.clipboard.writeText(''); }catch{}
      }, clearAfterMs);
    }

    return true;
  };

  function setNavDropdownsOpen(nav, open){
    if(!nav) return;
    try{
      nav.querySelectorAll('details.nav-dd').forEach(d => {
        if(open){
          if(!d.hasAttribute('data-prev-open')) d.setAttribute('data-prev-open', d.open ? '1' : '0');
          d.open = true;
        }else{
          const prev = d.getAttribute('data-prev-open');
          if(prev !== null){
            d.open = (prev === '1');
            d.removeAttribute('data-prev-open');
          }else{
            d.open = false;
          }
        }
      });
    }catch{}
  }

  function initNavGroups(){
    const nav = document.querySelector('.topbar .topbar-r');
    if(!nav) return;
    if(nav.getAttribute('data-nav-enhanced') === '1') return;

    const user = nav.querySelector('.user-pill');
    if(!user) return;

    const children = Array.from(nav.children).filter(el => el !== user);

    const isLangLink = (el) => el.tagName === 'A' && /set_language\.php\?/.test(el.getAttribute('href') || '');
    const isThemeBtn = (el) => el.tagName === 'BUTTON' && el.hasAttribute('data-theme-toggle');

    const prefs = children.filter(el => isLangLink(el) || isThemeBtn(el));
    const rest = children.filter(el => !prefs.includes(el));

    const primaryHrefs = new Set([
      'dashboard.php',
      'create_code.php',
      'my_codes.php',
      'rooms.php',
      'notifications.php',
    ]);

    const isPrimary = (el) => {
      if(el.tagName !== 'A') return false;
      const href = (el.getAttribute('href') || '').trim();
      return primaryHrefs.has(href);
    };

    const primary = rest.filter(isPrimary);
    const secondary = rest.filter(el => !primary.includes(el));

    // Enforce a consistent primary nav order across pages.
    const primaryOrder = ['dashboard.php','create_code.php','my_codes.php','rooms.php','notifications.php'];
    primary.sort((a, b) => {
      const ha = String(a.getAttribute('href') || '').trim();
      const hb = String(b.getAttribute('href') || '').trim();
      const ia = primaryOrder.indexOf(ha);
      const ib = primaryOrder.indexOf(hb);
      if(ia === -1 && ib === -1) return 0;
      if(ia === -1) return 1;
      if(ib === -1) return -1;
      return ia - ib;
    });

    function decorateNavBtn(el, icon, label){
      if(!el) return;

      const lbl = (label == null ? '' : String(label)).trim();

      if(el.tagName === 'A' && el.getAttribute('href')){
        el.setAttribute('aria-label', lbl);
      }

      el.classList.add('nav-btn');
      el.innerHTML = `<span class="nav-ico" aria-hidden="true">${LS.esc(icon)}</span><span class="nav-lbl">${LS.esc(lbl)}</span>`;
    }

    function iconForHref(href){
      const h = String(href||'').trim();
      if(h === 'dashboard.php') return '⌂';
      if(h === 'create_code.php') return '✚';
      if(h === 'my_codes.php') return '⧉';
      if(h === 'rooms.php') return '◻';
      if(h === 'notifications.php') return '✉';
      if(h === 'backup.php') return '⤓';
      if(h === 'vault_settings.php') return '⌁';
      if(h === 'security.php') return '🔐';
      if(h === 'setup.php') return '✓';
      if(h === 'account.php') return '◎';
      if(h === 'admin.php') return '⚑';
      if(h === 'logout.php') return '⎋';
      return '•';
    }

    function mkDropdown(icon, label){
      const d = document.createElement('details');
      d.className = 'nav-dd';

      const s = document.createElement('summary');
      s.className = 'btn btn-ghost btn-sm';
      decorateNavBtn(s, icon, label);

      const panel = document.createElement('div');
      panel.className = 'nav-dd-panel';

      d.appendChild(s);
      d.appendChild(panel);

      // Close other dropdowns when one opens.
      d.addEventListener('toggle', () => {
        if(!d.open) return;
        nav.querySelectorAll('details.nav-dd[open]').forEach(x => { if(x !== d) x.open = false; });
      });

      // Close when a link inside is clicked.
      panel.addEventListener('click', (e) => {
        const a = e.target && e.target.closest ? e.target.closest('a') : null;
        if(a) d.open = false;
      });

      return {d, panel};
    }

    nav.innerHTML = '';
    if(user) nav.appendChild(user);

    primary.forEach(el => {
      if(el.tagName === 'A') decorateNavBtn(el, iconForHref(el.getAttribute('href')), el.textContent);
      nav.appendChild(el);
    });

    function groupKeyForHref(href){
      const h = String(href||'').trim();
      const base = h.split('#')[0];
      if(base === 'vault_settings.php' || base === 'backup.php') return 'vault';
      if(base === 'rooms.php' || base === 'notifications.php') return 'community';
      if(base === 'security.php' || base === 'account.php' || base === 'setup.php') return 'security';
      if(base === 'admin.php') return 'admin';
      if(base === 'logout.php') return 'session';
      if(h.indexOf('index.php#faq') === 0) return 'help';
      return 'other';
    }

    function groupTitle(key){
      if(key === 'vault') return LS.t('nav.vault') || 'Vault';
      if(key === 'community') return LS.t('nav.rooms') || 'Community';
      if(key === 'security') return LS.t('dashboard.security') || 'Security';
      if(key === 'admin') return LS.t('nav.admin') || 'Admin';
      if(key === 'help') return LS.t('common.help') || 'Help';
      if(key === 'session') return LS.t('common.session') || 'Session';
      return LS.t('common.other') || 'Other';
    }

    function appendGroup(panel, key, els){
      if(!els || !els.length) return;
      const title = document.createElement('div');
      title.className = 'nav-group-title';
      title.textContent = groupTitle(key);
      panel.appendChild(title);

      els.forEach(el => {
        if(el.tagName === 'A') decorateNavBtn(el, iconForHref(el.getAttribute('href')), el.getAttribute('data-label') || el.textContent);
        if(el.tagName === 'A' && (el.getAttribute('href')||'').trim().split('#')[0] === 'logout.php'){
          el.classList.remove('btn-ghost');
          el.classList.add('btn-red');
        }
        panel.appendChild(el);
      });
    }

    if(secondary.length){
      const more = mkDropdown('⋯', LS.t('common.more') || 'More');

      const byGroup = {vault:[], community:[], security:[], admin:[], help:[], session:[], other:[]};
      secondary.forEach(el => {
        const href = el.tagName === 'A' ? (el.getAttribute('href') || '') : '';
        const key = groupKeyForHref(href);
        if(!el.getAttribute('data-label')) el.setAttribute('data-label', (el.textContent || '').trim());
        (byGroup[key] || byGroup.other).push(el);
      });

      const groupOrder = {
        vault: ['vault_settings.php', 'backup.php'],
        security: ['security.php', 'account.php', 'setup.php'],
        admin: ['admin.php'],
        help: ['index.php#faq'],
        session: ['logout.php'],
      };

      function sortGroup(key){
        const ord = groupOrder[key];
        if(!ord) return;
        byGroup[key].sort((a, b) => {
          const ha = String(a.getAttribute('href') || '').trim();
          const hb = String(b.getAttribute('href') || '').trim();
          const ia = ord.indexOf(ha);
          const ib = ord.indexOf(hb);
          if(ia === -1 && ib === -1) return 0;
          if(ia === -1) return 1;
          if(ib === -1) return -1;
          return ia - ib;
        });
      }

      Object.keys(groupOrder).forEach(sortGroup);

      appendGroup(more.panel, 'vault', byGroup.vault);
      appendGroup(more.panel, 'community', byGroup.community);
      appendGroup(more.panel, 'security', byGroup.security);
      appendGroup(more.panel, 'admin', byGroup.admin);
      appendGroup(more.panel, 'help', byGroup.help);
      appendGroup(more.panel, 'session', byGroup.session);
      appendGroup(more.panel, 'other', byGroup.other);

      nav.appendChild(more.d);
    }

    if(prefs.length){
      const prefsDd = mkDropdown('⚙', LS.t('common.settings') || 'Settings');

      const title = document.createElement('div');
      title.className = 'nav-group-title';
      title.textContent = LS.t('common.preferences') || 'Preferences';
      prefsDd.panel.appendChild(title);

      // Theme first, then language.
      prefs.sort((a, b) => {
        const at = isThemeBtn(a) ? 0 : 1;
        const bt = isThemeBtn(b) ? 0 : 1;
        return at - bt;
      }).forEach(el => {
        if(isLangLink(el)){
          decorateNavBtn(el, '🌐', el.getAttribute('data-label') || el.textContent);
          el.classList.add('nav-chip');
        }
        prefsDd.panel.appendChild(el);
      });
      nav.appendChild(prefsDd.d);
    }

    // Close dropdowns when clicking outside.
    document.addEventListener('click', (e) => {
      try{
        const navOv = document.getElementById('ls-nav-overlay');
        if(navOv && navOv.classList.contains('show')) return;
      }catch{}

      try{
        if(nav.closest && nav.closest('#ls-sidebar')) return;
      }catch{}

      if(!nav.contains(e.target)){
        nav.querySelectorAll('details.nav-dd[open]').forEach(x => x.open = false);
      }
    });

    // Highlight current page in nav.
    try{
      const p = window.location && window.location.pathname ? window.location.pathname : '';
      const parts = p.split('/');
      const cur = parts[parts.length - 1] || '';
      const mapped = (cur === 'room.php') ? 'rooms.php' : ((cur && cur.indexOf('security_') === 0) ? 'security.php' : ((cur === 'admin_legacy.php' || (cur && cur.indexOf('admin_') === 0)) ? 'admin.php' : cur));

      nav.querySelectorAll('a[href]').forEach(a => {
        const href = String(a.getAttribute('href')||'');
        if(href === mapped) a.classList.add('active');
      });
    }catch{}

    nav.setAttribute('data-nav-enhanced', '1');
  }

  function initMobileNav(){
    // If a CSS-only drawer exists (server-rendered), enhance it with keyboard handling
    // (Escape to close, focus management, scroll lock) and skip building the JS drawer.
    const cssToggle = document.getElementById('ls-mobile-nav-toggle');
    if(cssToggle){
      try{
        const topbar = document.querySelector('.topbar');
        const btn = topbar ? topbar.querySelector('label.topbar-menu-btn[for="ls-mobile-nav-toggle"]') : null;
        const panel = document.getElementById('ls-mobile-nav-panel') || document.querySelector('.ls-mobile-nav-panel');

        let prevFocus = null;

        function sync(){
          const open = !!cssToggle.checked;
          if(btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
          document.body.style.overflow = open ? 'hidden' : '';

          if(open){
            prevFocus = document.activeElement;
            setTimeout(()=>{
              const first = panel ? panel.querySelector('a,button,[tabindex]:not([tabindex="-1"])') : null;
              if(first && first.focus) first.focus();
            }, 10);
          } else {
            const f = prevFocus || btn;
            if(f && f.focus) f.focus();
            prevFocus = null;
          }
        }

        if(btn && !btn.hasAttribute('aria-expanded')) btn.setAttribute('aria-expanded', cssToggle.checked ? 'true' : 'false');
        cssToggle.addEventListener('change', sync);
        sync();

        // Close on Escape.
        document.addEventListener('keydown', (e)=>{
          if(e.key !== 'Escape') return;
          if(!cssToggle.checked) return;
          cssToggle.checked = false;
          sync();
        });

        // If user taps a link in the drawer, close it.
        if(panel){
          panel.addEventListener('click', (e)=>{
            const a = e.target && e.target.closest ? e.target.closest('a') : null;
            if(a && a.getAttribute('href')){
              cssToggle.checked = false;
              sync();
            }
          });
        }
      }catch{}
      return;
    }

    const topbar = document.querySelector('.topbar');
    const nav = topbar ? topbar.querySelector('.topbar-r') : null;
    if(!topbar || !nav) return;
    if(!nav.querySelector('.user-pill')) return;

    // Create menu button once.
    let btn = topbar.querySelector('.topbar-menu-btn');
    if(!btn){
      btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-ghost btn-sm topbar-menu-btn nav-btn';
      btn.setAttribute('aria-label', LS.t('common.menu') || 'Menu');
      btn.innerHTML = `<span class="nav-ico" aria-hidden="true">☰</span><span class="nav-lbl">${LS.esc(LS.t('common.menu') || 'Menu')}</span>`;
      topbar.appendChild(btn);
    }

    btn.setAttribute('aria-haspopup', 'dialog');
    if(!btn.hasAttribute('aria-expanded')) btn.setAttribute('aria-expanded', 'false');

    function getOverlay(){
      let ov = document.getElementById('ls-nav-overlay');
      if(ov) return ov;

      ov = document.createElement('div');
      ov.id = 'ls-nav-overlay';
      ov.innerHTML = `
        <div id="ls-nav-panel" role="dialog" aria-modal="true" aria-labelledby="ls-nav-title">
          <div id="ls-nav-head">
            <div id="ls-nav-title">${LS.esc(LS.t('common.menu') || 'Menu')}</div>
            <button type="button" id="ls-nav-close" aria-label="${LS.esc(STR.close)}">×</button>
          </div>
          <div id="ls-nav-body"></div>
        </div>
      `;
      document.body.appendChild(ov);
      return ov;
    }

    function isMobile(){
      return window.matchMedia && window.matchMedia('(max-width: 980px) and (hover:none) and (pointer:coarse)').matches;
    }

    let releaseTrap = null;
    let prevFocus = null;

    function open(){
      if(!isMobile()) return;
      const ov = getOverlay();
      const body = ov.querySelector('#ls-nav-body');
      if(!body) return;

      // Move the real nav into the drawer so existing event handlers keep working.
      if(nav.parentNode !== body) body.appendChild(nav);

      // In the mobile drawer we want a full, categorized menu without extra taps.
      setNavDropdownsOpen(nav, true);

      prevFocus = document.activeElement;

      ov.classList.add('show');
      btn.setAttribute('aria-expanded', 'true');
      document.body.style.overflow = 'hidden';

      try{
        const panel = ov.querySelector('#ls-nav-panel');
        if(releaseTrap) releaseTrap();
        if(panel) releaseTrap = trapFocus(panel, close);
      }catch{}

      setTimeout(()=>{
        const first = nav.querySelector('a,button');
        if(first && first.focus) first.focus();
      }, 10);
    }

    function close(){
      const ov = document.getElementById('ls-nav-overlay');
      if(!ov) return;

      // Restore the dropdown state before we move the nav back.
      setNavDropdownsOpen(nav, false);

      // Restore nav to topbar.
      if(nav.parentNode !== topbar) topbar.insertBefore(nav, btn);

      ov.classList.remove('show');
      btn.setAttribute('aria-expanded', 'false');

      if(releaseTrap){
        releaseTrap();
        releaseTrap = null;
      }

      document.body.style.overflow = '';

      const f = prevFocus || btn;
      if(f && f.focus) f.focus();
      prevFocus = null;
    }

    btn.addEventListener('click', open);

    document.addEventListener('keydown', (e)=>{
      const ov = document.getElementById('ls-nav-overlay');
      if(!ov || !ov.classList.contains('show')) return;
      if(e.key === 'Escape') close();
    });

    document.addEventListener('click', (e)=>{
      const ov = document.getElementById('ls-nav-overlay');
      if(!ov || !ov.classList.contains('show')) return;
      if(e.target === ov) close();
    });

    // Delegate close button.
    document.addEventListener('click', (e)=>{
      const t = e.target;
      if(t && t.id === 'ls-nav-close') close();
    });

    // On resize to desktop, ensure nav is restored.
    window.addEventListener('resize', ()=>{
      if(!isMobile()) close();
    });

    // If user taps a link in the drawer, close it.
    nav.addEventListener('click', (e)=>{
      const a = e.target && e.target.closest ? e.target.closest('a') : null;
      if(a && a.getAttribute('href')) close();
    });
  }

  function initBottomNav(){
    const app = document.getElementById('app');
    if(!app) return;
    const topbar = app.querySelector('.topbar');
    if(!topbar) return;
    try{
      const navWrap = topbar.querySelector('.topbar-r');
      if(!navWrap || !navWrap.querySelector('.user-pill')) return;
      // Only show bottom navigation for verified sessions (dashboard link exists in the authenticated nav).
      if(!navWrap.querySelector('a[href="dashboard.php"]')) return;
    }catch{ return; }

    if(document.querySelector('.bottom-nav')) return;

    const nav = document.createElement('nav');
    nav.className = 'bottom-nav';
    nav.setAttribute('aria-label', LS.t('common.menu') || 'Menu');

    const p = window.location && window.location.pathname ? window.location.pathname : '';
    const parts = p.split('/');
    const base = parts[parts.length - 1] || '';
    const hash = (window.location && window.location.hash) ? window.location.hash : '';
    const curFull = base + hash;

    const cur = (base === 'room.php')
      ? 'rooms.php'
      : ((base && base.indexOf('security_') === 0)
        ? 'security.php'
        : ((base === 'admin_legacy.php' || (base && base.indexOf('admin_') === 0))
          ? 'admin.php'
          : base));

    function iconForHref(href){
      const h = String(href||'').trim();
      if(h === 'dashboard.php') return '⌂';
      if(h === 'create_code.php') return '✚';
      if(h === 'my_codes.php') return '⧉';
      if(h === 'rooms.php') return '◻';
      if(h === 'notifications.php') return '✉';
      return '•';
    }

    const items = [
      {href:'dashboard.php', label: LS.t('nav.dashboard') || 'Dashboard'},
      {href:'create_code.php', label: LS.t('nav.create_code') || 'Create'},
      {href:'my_codes.php', label: LS.t('nav.my_codes') || 'Codes'},
      {href:'rooms.php', label: LS.t('nav.rooms') || 'Rooms'},
      {href:'notifications.php', label: LS.t('nav.notifications') || 'Inbox'},
    ];

    const overflowItems = [
      {href:'vault_settings.php', label: LS.t('nav.vault') || 'Vault', ico:'⌁', group:'vault'},
      {href:'backup.php', label: LS.t('nav.backups') || 'Backups', ico:'⛁', group:'vault'},
      {href:'security.php', label: LS.t('nav.security') || 'Security', ico:'🔐', group:'security'},
      {href:'account.php', label: LS.t('nav.account') || 'Account', ico:'👤', group:'security'},
      {href:'setup.php', label: LS.t('nav.setup') || 'Setup', ico:'⚙', group:'security'},
      {href:'index.php#faq', label: LS.t('common.faq') || 'FAQ', ico:'?', group:'help'},
      {href:'logout.php', label: LS.t('common.logout') || 'Logout', ico:'⎋', group:'session', danger:true},
    ];
    try{
      if(document.querySelector('a[href="admin.php"]')){
        overflowItems.push({href:'admin.php', label: LS.t('nav.admin') || 'Admin', ico:'⬡', group:'admin'});
      }
    }catch{}

    const isOverflowActive = overflowItems.some(it => it.href === cur || it.href === curFull);

    let releaseOverflowTrap = null;
    let overflowPrevFocus = null;

    function closeOverflow(){
      const ov = document.getElementById('ls-overflow-overlay');
      if(!ov) return;

      ov.classList.remove('show');

      const mb = document.getElementById('ls-bottom-more');
      if(mb) mb.setAttribute('aria-expanded', 'false');

      if(releaseOverflowTrap){
        releaseOverflowTrap();
        releaseOverflowTrap = null;
      }

      document.body.style.overflow = '';

      const f = overflowPrevFocus || mb;
      if(f && f.focus) f.focus();
      overflowPrevFocus = null;
    }

    items.forEach(it => {
      const a = document.createElement('a');
      a.href = it.href;

      const b = document.createElement('span');
      b.className = 'btn bn-btn nav-btn btn-ghost btn-sm';
      if(cur === it.href){
        b.classList.add('active');
        a.setAttribute('aria-current', 'page');
      }

      b.innerHTML = `<span class="nav-ico" aria-hidden="true">${LS.esc(iconForHref(it.href))}</span><span class="nav-lbl">${LS.esc(it.label)}</span>`;
      a.setAttribute('aria-label', it.label);
      a.appendChild(b);

      nav.appendChild(a);
    });

    function ensureOverflowOverlay(){
      let ov = document.getElementById('ls-overflow-overlay');
      if(ov) return ov;

      ov = document.createElement('div');
      ov.id = 'ls-overflow-overlay';
      ov.innerHTML = `
        <div id="ls-overflow-sheet" role="dialog" aria-modal="true" aria-labelledby="ls-overflow-title">
          <div class="ls-overflow-head">
            <div class="ls-overflow-title" id="ls-overflow-title">${LS.esc(LS.t('common.more') || 'More')}</div>
            <button class="btn btn-ghost btn-sm" type="button" id="ls-overflow-close" aria-label="${LS.esc(LS.t('common.close') || 'Close')}">×</button>
          </div>
          <div class="ls-overflow-links"></div>
        </div>
      `;

      function groupTitle(key){
        if(key === 'vault') return LS.t('nav.vault') || 'Vault';
        if(key === 'security') return LS.t('dashboard.security') || 'Security';
        if(key === 'admin') return LS.t('nav.admin') || 'Admin';
        if(key === 'help') return LS.t('common.help') || 'Help';
        if(key === 'session') return LS.t('common.session') || 'Session';
        return LS.t('common.other') || 'Other';
      }

      const links = ov.querySelector('.ls-overflow-links');
      if(links){
        const order = ['vault','security','admin','help','session','other'];

        const by = {vault:[], security:[], admin:[], help:[], session:[], other:[]};
        overflowItems.forEach(it => {
          const g = it.group && by[it.group] ? it.group : 'other';
          by[g].push(it);
        });

        order.forEach(g => {
          const list = by[g] || [];
          if(!list.length) return;

          const title = document.createElement('div');
          title.className = 'nav-group-title';
          title.textContent = groupTitle(g);
          links.appendChild(title);

          list.forEach(it => {
            const a = document.createElement('a');
            a.href = it.href;
            a.className = 'btn btn-ghost nav-chip';
            if(it.danger){
              a.classList.remove('btn-ghost');
              a.classList.add('btn-red');
            }
            if(cur === it.href){
              a.classList.add('active');
              a.setAttribute('aria-current', 'page');
            }
            a.innerHTML = `<span class="nav-ico" aria-hidden="true">${LS.esc(it.ico || '•')}</span><span class="nav-lbl">${LS.esc(it.label)}</span>`;
            links.appendChild(a);
          });
        });
      }

      ov.addEventListener('click', (e)=>{
        if(e.target === ov) closeOverflow();
        const a = e.target && e.target.closest ? e.target.closest('a') : null;
        if(a && a.getAttribute('href')) closeOverflow();
      });

      const cbtn = ov.querySelector('#ls-overflow-close');
      if(cbtn) cbtn.addEventListener('click', closeOverflow);

      document.body.appendChild(ov);
      return ov;
    }

    const moreBtn = document.createElement('button');
    moreBtn.type = 'button';
    moreBtn.id = 'ls-bottom-more';
    moreBtn.className = 'btn bn-btn nav-btn btn-ghost btn-sm';
    if(isOverflowActive) moreBtn.classList.add('active');
    moreBtn.setAttribute('aria-label', LS.t('common.more') || 'More');
    moreBtn.setAttribute('aria-haspopup', 'dialog');
    moreBtn.setAttribute('aria-expanded', 'false');
    moreBtn.innerHTML = `<span class="nav-ico" aria-hidden="true">⋯</span><span class="nav-lbl">${LS.esc(LS.t('common.more') || 'More')}</span>`;
    moreBtn.addEventListener('click', ()=>{
      try{ nav.removeAttribute('data-hidden'); }catch{}

      overflowPrevFocus = document.activeElement;

      moreBtn.setAttribute('aria-expanded', 'true');
      const ov = ensureOverflowOverlay();
      ov.classList.add('show');
      document.body.style.overflow = 'hidden';

      try{
        const sheet = ov.querySelector('#ls-overflow-sheet');
        if(releaseOverflowTrap) releaseOverflowTrap();
        if(sheet) releaseOverflowTrap = trapFocus(sheet, closeOverflow);
      }catch{}

      setTimeout(()=>{
        const first = ov.querySelector('a,button');
        if(first && first.focus) first.focus();
      }, 10);
    });

    nav.appendChild(moreBtn);

    try{ app.classList.add('has-bottom-nav'); }catch{}
    document.body.appendChild(nav);

    // Optional: hide the dock while scrolling down (mobile only).
    try{
      const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const mq = window.matchMedia ? window.matchMedia('(max-width: 980px) and (hover:none) and (pointer:coarse)') : null;
      const isMobile = () => mq ? mq.matches : false;
      if(!reduce){
        let lastY = window.scrollY || 0;
        let hidden = false;
        let ticking = false;

        function show(){
          if(hidden){ nav.removeAttribute('data-hidden'); hidden = false; }
        }
        function hide(){
          if(!hidden){ nav.setAttribute('data-hidden','1'); hidden = true; }
        }

        function onScroll(){
          if(!isMobile()) return;
          try{
            const ov = document.getElementById('ls-overflow-overlay');
            if(ov && ov.classList.contains('show')) return;
          }catch{}
          const y = window.scrollY || 0;
          const dy = y - lastY;
          if(Math.abs(dy) < 12) return;
          if(dy > 0 && y > 80) hide();
          else show();
          lastY = y;
        }

        window.addEventListener('scroll', ()=>{
          if(ticking) return;
          ticking = true;
          requestAnimationFrame(()=>{ onScroll(); ticking = false; });
        }, {passive:true});

        document.addEventListener('focusin', show);
        if(mq){
          try{ mq.addEventListener('change', ()=>show()); }
          catch{ mq.addListener(()=>show()); }
        }
      }
    }catch{}
  }

  function initDesktopSidebar(){
    const app = document.getElementById('app');
    if(!app) return;

    const topbar = app.querySelector('.topbar');
    const nav = topbar ? topbar.querySelector('.topbar-r') : null;
    if(!topbar || !nav) return;
    if(!nav.querySelector('.user-pill')) return;

    const mq = window.matchMedia ? window.matchMedia('(min-width: 981px)') : null;
    const isDesktop = () => mq ? mq.matches : false;

    // Wrap all app children in a shell so the sidebar can sit as a sibling.
    let shell = document.getElementById('app-shell');
    if(!shell){
      shell = document.createElement('div');
      shell.id = 'app-shell';
      while(app.firstChild){
        shell.appendChild(app.firstChild);
      }
      app.appendChild(shell);
    }

    let side = document.getElementById('ls-sidebar');
    if(!side){
      side = document.createElement('aside');
      side.id = 'ls-sidebar';
      side.innerHTML = `
        <div class="ls-side-head">
          <button class="btn btn-ghost btn-sm btn-theme" type="button" id="ls-side-toggle" aria-label="${LS.esc(LS.t('common.toggle') || 'Toggle')}">⟷</button>
        </div>
        <div class="ls-side-body" id="ls-side-body"></div>
      `;
      app.insertBefore(side, shell);

      const stored = localStorage.getItem('ls_sidebar_collapsed');
      if(stored === '1') side.setAttribute('data-collapsed','1');

      const toggle = side.querySelector('#ls-side-toggle');
      if(toggle){
        toggle.addEventListener('click', ()=>{
          const next = side.getAttribute('data-collapsed') === '1' ? '0' : '1';
          if(next === '1') side.setAttribute('data-collapsed','1');
          else side.removeAttribute('data-collapsed');
          localStorage.setItem('ls_sidebar_collapsed', next === '1' ? '1' : '0');
        });
      }
    }

    function mount(){
      if(!isDesktop()) return;
      const body = document.getElementById('ls-side-body');
      if(!body) return;
      if(nav.parentNode !== body) body.appendChild(nav);

      // In the desktop sidebar, keep groups expanded for scanability.
      setNavDropdownsOpen(nav, true);
    }

    function unmount(){
      if(isDesktop()) return;

      // Restore the dropdown state before we move the nav back.
      setNavDropdownsOpen(nav, false);

      // Restore the nav to its original spot in the topbar.
      const menuBtn = topbar.querySelector('.topbar-menu-btn');
      if(nav.parentNode !== topbar){
        if(menuBtn) topbar.insertBefore(nav, menuBtn);
        else topbar.appendChild(nav);
      }
    }

    mount();

    if(mq){
      try{ mq.addEventListener('change', ()=>{ mount(); unmount(); }); }
      catch{ mq.addListener(()=>{ mount(); unmount(); }); }
    }
  }

  function initRipples(){
    // Lightweight click ripple for buttons.
    try{
      if(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    }catch{}

    document.addEventListener('pointerdown', (e)=>{
      const btn = e.target && e.target.closest ? e.target.closest('.btn') : null;
      if(!btn) return;
      if(btn.disabled) return;

      const r = btn.getBoundingClientRect();
      const x = e.clientX - r.left;
      const y = e.clientY - r.top;

      const s = document.createElement('span');
      s.className = 'ls-ripple';
      s.style.left = x + 'px';
      s.style.top = y + 'px';
      btn.appendChild(s);
      setTimeout(()=>s.remove(), 700);
    }, {passive:true});
  }

  function initRevealOnScroll(){
    if(!window.IntersectionObserver) return;

    const sel = '.card, .step, .item, .room, .lock-card';

    const io = new IntersectionObserver((entries)=>{
      entries.forEach(ent => {
        if(ent.isIntersecting){
          ent.target.classList.add('is-in');
          io.unobserve(ent.target);
        }
      });
    }, {rootMargin:'0px 0px -10% 0px', threshold:0.06});

    const seen = new WeakSet();
    function track(el){
      if(!el || seen.has(el)) return;
      seen.add(el);
      el.classList.add('ls-reveal');
      io.observe(el);
    }

    document.querySelectorAll(sel).forEach(track);

    // Observe dynamically-inserted content (rooms, notifications, etc.).
    try{
      const mo = new MutationObserver((muts)=>{
        muts.forEach(m => {
          (m.addedNodes||[]).forEach(n => {
            if(!(n instanceof Element)) return;
            if(n.matches && n.matches(sel)) track(n);
            if(n.querySelectorAll) n.querySelectorAll(sel).forEach(track);
          });
        });
      });
      mo.observe(document.body, {childList:true, subtree:true});
    }catch{}
  }

  function initA11y(){
    try{
      document.querySelectorAll('button[data-theme-toggle]').forEach(b => {
        if(!b.getAttribute('aria-label')) b.setAttribute('aria-label', LS.t('common.theme') || 'Theme');
      });

      document.querySelectorAll('button:not([aria-label])').forEach(b => {
        const txt = (b.textContent || '').trim();
        if(txt === '×' || txt === '✕') b.setAttribute('aria-label', STR.close);
      });
    }catch{}
  }

  function initPwa(){
    try{
      const head = document.head;
      if(head && !head.querySelector('link[rel="manifest"]')){
        const l = document.createElement('link');
        l.rel = 'manifest';
        l.href = 'manifest.php';
        head.appendChild(l);
      }

      if(head && !head.querySelector('meta[name="theme-color"]')){
        const m = document.createElement('meta');
        m.name = 'theme-color';
        m.content = '#0b0d12';
        head.appendChild(m);
      }
    }catch{}

    try{
      if(!('serviceWorker' in navigator)) return;
      const isLocal = (location.hostname === 'localhost' || location.hostname === '127.0.0.1');
      if(location.protocol !== 'https:' && !isLocal) return;

      navigator.serviceWorker.register('sw.js').catch(()=>{});

      let deferred = null;
      window.addEventListener('beforeinstallprompt', (e)=>{
        try{ e.preventDefault(); }catch{}
        deferred = e;

        try{
          if(sessionStorage.getItem('ls_pwa_prompted') === '1') return;
          sessionStorage.setItem('ls_pwa_prompted', '1');
        }catch{}

        setTimeout(async ()=>{
          if(!deferred) return;
          const ok = await LS.confirm(LS.t('js.pwa_install_confirm') || 'Install this app?', {
            title: STR.confirm,
            confirmText: STR.install,
            cancelText: STR.cancel,
          });
          if(!ok) return;
          deferred.prompt();
          try{ await deferred.userChoice; }catch{}
          deferred = null;
        }, 1200);
      });

    }catch{}
  }

  document.addEventListener('DOMContentLoaded', ()=>{
    initA11y();
    initPwa();
    initNavGroups();
    initDesktopSidebar();
    initMobileNav();
    initBottomNav();
    initRipples();
    initRevealOnScroll();
  });

  window.LS = LS;
})();
