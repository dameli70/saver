(function(){
  'use strict';

  function csrfToken(){
    try{
      return (window.LS_SECURITY && typeof window.LS_SECURITY.csrf === 'string') ? window.LS_SECURITY.csrf : '';
    }catch(e){
      return '';
    }
  }

  async function postCsrf(url, body){
    const r = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken(),
      },
      body: JSON.stringify(body || {}),
    });
    return r.json();
  }

  async function postCsrfWithReauth(url, body){
    let j = await postCsrf(url, body);

    if(!j || j.success) return j;

    if(j.error_code === 'reauth_required' || j.error_code === 'security_setup_required'){
      if(window.LS && typeof window.LS.reauth === 'function'){
        const ok = await window.LS.reauth(j.methods || {}, {post: postCsrf});
        if(ok){
          j = await postCsrf(url, body);
        }
      }
    }

    return j;
  }

  function showMsg(el, message){
    if(!el) return;
    el.textContent = String(message || '');
    el.classList.add('show');
  }

  function clearMsg(el){
    if(!el) return;
    el.textContent = '';
    el.classList.remove('show');
  }

  window.LS_SECURITY_API = {
    postCsrf,
    postCsrfWithReauth,
    showMsg,
    clearMsg,
  };
})();
