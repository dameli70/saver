(function(){
  'use strict';

  // Shared helpers for admin pages. Expects global CSRF constant (set inline by admin.php pages).
  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (Object.prototype.hasOwnProperty.call(I18N, key) ? I18N[key] : null) || fallback || key;
  }

  function apiUrl(url){
    const u = String(url || '');
    return u.startsWith('/') ? u.slice(1) : u;
  }

  async function rawGet(url){
    const r = await fetch(apiUrl(url), { credentials: 'same-origin' });
    return r.json();
  }

  async function rawPostCsrf(url, body){
    const r = await fetch(apiUrl(url), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (typeof CSRF === 'string' ? CSRF : '') },
      body: JSON.stringify(body || {}),
    });
    return r.json();
  }

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
    if(window.LS && typeof window.LS.reauth === 'function'){
      return window.LS.reauth(methods||{}, {post: rawPostCsrf});
    }

    if(methods && methods.passkey && window.PublicKeyCredential){
      try{
        const begin = await rawPostCsrf('api/webauthn.php', {action:'reauth_begin'});
        if(begin && begin.success){
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
          const fin = await rawPostCsrf('api/webauthn.php', {
            action:'reauth_finish',
            rawId: bufToB64u(cred.rawId),
            response:{
              clientDataJSON: bufToB64u(a.clientDataJSON),
              authenticatorData: bufToB64u(a.authenticatorData),
              signature: bufToB64u(a.signature),
              userHandle: a.userHandle ? bufToB64u(a.userHandle) : null,
            }
          });
          if(fin && fin.success) return true;
        }
      }catch(e){
        // ignore
      }
    }

    if(methods && methods.totp){
      const code = prompt(tr('login.enter_totp', 'Enter your 6-digit authenticator code'));
      if(!code) return false;
      const r = await rawPostCsrf('api/totp.php', {action:'reauth', code});
      return !!(r && r.success);
    }

    return false;
  }

  async function get(url){
    let j = await rawGet(url);
    if(j && !j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
      const ok = await ensureReauth(j.methods||{});
      if(!ok) return j;
      j = await rawGet(url);
    }
    return j;
  }

  async function postCsrf(url, body){
    let j = await rawPostCsrf(url, body);
    if(j && !j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
      const ok = await ensureReauth(j.methods||{});
      if(!ok) return j;
      j = await rawPostCsrf(url, body);
    }
    return j;
  }

  function esc(s){
    if(window.LS && typeof window.LS.esc === 'function') return window.LS.esc(s);
    return String(s||'')
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  function parseUtcDate(ts){
    if(window.LS && typeof window.LS.parseUtc === 'function') return window.LS.parseUtc(ts);

    const s = String(ts||'').trim();
    if(!s) return null;

    // API timestamps are stored in UTC as "YYYY-MM-DD HH:MM:SS".
    if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
      return new Date(s.replace(' ', 'T') + 'Z');
    }

    return new Date(s);
  }

  function fmt(ts){
    const d = parseUtcDate(ts);
    if(!d || isNaN(d.getTime())) return '';
    if(window.LS && typeof window.LS.fmtLocal === 'function') return window.LS.fmtLocal(d);
    return d.toLocaleString();
  }

  function setMsg(id, text, ok){
    const el = document.getElementById(id);
    if(!el) return;
    el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
    el.textContent = String(text||'');
  }

  // Export globals expected by existing admin.php inline scripts.
  window.apiUrl = window.apiUrl || apiUrl;
  window.rawGet = window.rawGet || rawGet;
  window.rawPostCsrf = window.rawPostCsrf || rawPostCsrf;
  window.ensureReauth = window.ensureReauth || ensureReauth;
  window.get = window.get || get;
  window.postCsrf = window.postCsrf || postCsrf;
  window.esc = window.esc || esc;
  window.parseUtcDate = window.parseUtcDate || parseUtcDate;
  window.fmt = window.fmt || fmt;
  window.setMsg = window.setMsg || setMsg;
})();
