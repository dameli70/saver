(function(){
  'use strict';

  const LS = {};

  LS.esc = function(s){
    return String(s||'')
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  };

  LS.toast = function(msg, type='ok', ms=3200){
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = String(msg||'');
    document.body.appendChild(t);
    setTimeout(()=>t.remove(), ms);
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
    return d.toLocaleString('en-US', {year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  };

  LS.fmtUtc = function(d){
    if(!(d instanceof Date) || isNaN(d.getTime())) return '';
    return new Intl.DateTimeFormat('en-US', {
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
        <button class="ls-modal-x" type="button" aria-label="Close">×</button>
        <div class="ls-modal-title" id="ls-reauth-title">Re-authentication required</div>
        <div class="ls-modal-sub">Confirm it’s you to continue. Choose a method below.</div>

        <div class="msg msg-err" id="ls-reauth-err"></div>

        <div id="ls-reauth-choices" class="ls-modal-actions"></div>

        <div id="ls-reauth-totp" style="display:none;">
          <div class="field" style="margin-top:12px;">
            <label>Authenticator code</label>
            <input inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" id="ls-reauth-code">
          </div>
          <button class="btn btn-primary" type="button" id="ls-reauth-submit">Confirm</button>
          <button class="btn btn-ghost" type="button" id="ls-reauth-back" style="margin-top:10px;width:100%;">Back</button>
        </div>

        <div id="ls-reauth-wait" style="display:none;margin-top:12px;font-size:12px;color:var(--muted);letter-spacing:.4px;">
          <span class="spin light"></span> Waiting for confirmation…
        </div>
      </div>
    `;
    document.body.appendChild(el);

    return el;
  }

  function trapFocus(modal){
    const focusables = modal.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    function onKey(e){
      if(e.key === 'Escape') {
        e.preventDefault();
        modal.dispatchEvent(new CustomEvent('ls-modal-esc'));
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
      b.textContent = 'Use passkey';
      btns.push({el:b, method:'passkey'});
      choices.appendChild(b);
    }

    if(methods && methods.totp){
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-ghost';
      b.textContent = 'Use authenticator code';
      b.style.width = '100%';
      b.style.marginTop = '10px';
      btns.push({el:b, method:'totp'});
      choices.appendChild(b);
    }

    const cancel = document.createElement('button');
    cancel.type = 'button';
    cancel.className = 'btn btn-ghost';
    cancel.textContent = 'Cancel';
    cancel.style.width = '100%';
    cancel.style.marginTop = '10px';
    choices.appendChild(cancel);

    overlay.classList.add('show');

    const releaseTrap = trapFocus(modal);
    const prevFocus = document.activeElement;

    setTimeout(()=>{
      const firstChoice = choices.querySelector('button');
      if(firstChoice) firstChoice.focus();
    }, 10);

    function cleanup(){
      overlay.classList.remove('show');
      releaseTrap();
      if(prevFocus && prevFocus.focus) setTimeout(()=>prevFocus.focus(), 0);
      modal.removeEventListener('ls-modal-esc', onEsc);
      overlay.removeEventListener('click', onClickOut);
      closeBtn.removeEventListener('click', onCancel);
      cancel.removeEventListener('click', onCancel);
    }

    function onCancel(){
      cleanup();
      resolve({ok:false});
    }

    function onEsc(){
      onCancel();
    }

    function onClickOut(e){
      if(e.target === overlay) onCancel();
    }

    let resolve;
    const p = new Promise(r => resolve = r);

    modal.addEventListener('ls-modal-esc', onEsc);
    overlay.addEventListener('click', onClickOut);
    closeBtn.addEventListener('click', onCancel);
    cancel.addEventListener('click', onCancel);

    btns.forEach(({el, method})=>{
      el.addEventListener('click', ()=>{
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
      LS.toast('Internal error: missing auth handler', 'err');
      return false;
    }

    if(!methods || (!methods.passkey && !methods.totp)){
      LS.toast('Enable TOTP or add a passkey in Account', 'warn');
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
        if(!begin || !begin.success) { showErr(begin && begin.error ? begin.error : 'Passkey re-auth failed'); return false; }

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

        if(!fin || !fin.success) { showErr(fin && fin.error ? fin.error : 'Passkey re-auth failed'); return false; }

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
              err.textContent = 'Enter a 6-digit code';
              err.classList.add('show');
              return;
            }

            submit.disabled = true;
            submit.innerHTML = '<span class="spin"></span>';

            const res = await post('api/totp.php', {action:'reauth', code});

            submit.disabled = false;
            submit.textContent = 'Confirm';

            if(res && res.success){
              done(true);
            }else{
              err.textContent = (res && res.error) ? res.error : 'Invalid code';
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

        if(!r) { showErr('Cancelled'); return false; }

        cleanup();
        return true;
      }

      showErr('Unsupported re-auth method');
      return false;

    }catch(e){
      showErr(e && e.message ? e.message : 'Re-auth failed');
      return false;
    }
  };

  LS.copySensitive = async function(text, opts){
    const clearAfterMs = (opts && Number.isFinite(opts.clearAfterMs)) ? opts.clearAfterMs : 30000;

    const ok = confirm('Copy to clipboard? Clipboard contents may be readable by other apps until overwritten.');
    if(!ok) return false;

    await navigator.clipboard.writeText(String(text||''));

    if(clearAfterMs > 0){
      setTimeout(async ()=>{
        try{ await navigator.clipboard.writeText(''); }catch{}
      }, clearAfterMs);
    }

    return true;
  };

  window.LS = LS;
})();
