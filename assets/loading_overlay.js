(function(){
  'use strict';

  // Idempotency guard (this file may be included multiple times).
  if(window.__LS_LOADING_OVERLAY_LOADED) return;
  window.__LS_LOADING_OVERLAY_LOADED = true;

  const W = window;
  W.LS = W.LS || {};
  const LS = W.LS;

  function i18nString(key, fallback){
    try{
      if(LS && typeof LS.t === 'function'){
        const v = LS.t(key);
        if(v && v !== key) return String(v);
      }
    }catch{}

    try{
      const src = (W.LS_I18N && W.LS_I18N.strings && typeof W.LS_I18N.strings === 'object') ? W.LS_I18N.strings : null;
      if(src && typeof src[key] === 'string') return String(src[key]);
    }catch{}

    return String(fallback == null ? '' : fallback);
  }

  const STR = {
    loading: i18nString('common.loading', 'Loading…'),
    pleaseWait: i18nString('common.please_wait', 'Please wait…'),
  };

  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/\"/g,'&quot;');
  }

  function clampPct(v){
    const n = Number(v);
    if(!Number.isFinite(n)) return null;
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  function ensureOverlay(){
    let ov = document.getElementById('ls-loading-overlay');
    if(ov) return ov;

    ov = document.createElement('div');
    ov.id = 'ls-loading-overlay';
    ov.className = 'ls-loading-overlay';
    ov.setAttribute('hidden', '');
    ov.setAttribute('aria-hidden', 'true');

    const title = STR.loading || 'Loading…';
    const desc = STR.pleaseWait || 'Please wait…';

    ov.innerHTML = `
      <div class="ls-loading-card" role="dialog" aria-modal="true" aria-labelledby="ls-loading-title" aria-describedby="ls-loading-desc" tabindex="-1">
        <div class="ls-loading-spinner" aria-hidden="true"></div>
        <div class="ls-loading-body">
          <div class="ls-loading-title" id="ls-loading-title">${esc(title)}</div>
          <div class="ls-loading-desc" id="ls-loading-desc" role="status" aria-live="polite" aria-atomic="true">${esc(desc)}</div>

          <div class="ls-loading-progress" id="ls-loading-progress" role="progressbar" aria-label="${esc(title)}" aria-valuemin="0" aria-valuemax="100" aria-hidden="true">
            <div class="ls-loading-bar" aria-hidden="true"><span class="ls-loading-bar-fill" id="ls-loading-bar-fill"></span></div>
            <div class="ls-loading-pct" id="ls-loading-pct" aria-hidden="true"></div>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(ov);
    return ov;
  }

  let shown = false;
  let prevFocus = null;
  let scrollY = 0;
  let bodyRestore = null;
  let releaseKeyTrap = null;

  function lockScroll(){
    if(bodyRestore) return;

    bodyRestore = {
      overflow: document.body.style.overflow,
      position: document.body.style.position,
      top: document.body.style.top,
      left: document.body.style.left,
      right: document.body.style.right,
      width: document.body.style.width,
    };

    scrollY = window.scrollY || 0;

    document.body.classList.add('ls-loading');
    document.body.style.overflow = 'hidden';

    // iOS: force scroll lock.
    document.body.style.position = 'fixed';
    document.body.style.top = (-scrollY) + 'px';
    document.body.style.left = '0';
    document.body.style.right = '0';
    document.body.style.width = '100%';
  }

  function unlockScroll(){
    if(!bodyRestore) return;

    document.body.classList.remove('ls-loading');

    document.body.style.overflow = bodyRestore.overflow;
    document.body.style.position = bodyRestore.position;
    document.body.style.top = bodyRestore.top;
    document.body.style.left = bodyRestore.left;
    document.body.style.right = bodyRestore.right;
    document.body.style.width = bodyRestore.width;

    const y = scrollY;
    bodyRestore = null;
    scrollY = 0;

    try{ window.scrollTo(0, y); }catch{}
  }

  function setBusy(isBusy){
    const app = document.getElementById('app');
    if(!app) return;

    if(isBusy) app.setAttribute('aria-busy', 'true');
    else app.removeAttribute('aria-busy');

    try{
      if('inert' in app) app.inert = !!isBusy;
    }catch{}
  }

  function trapKeys(overlay){
    function onKey(e){
      // Keep focus on the overlay while loading.
      if(e.key === 'Tab'){
        e.preventDefault();
        try{
          const card = overlay.querySelector('.ls-loading-card');
          if(card && card.focus) card.focus();
        }catch{}
      }
    }

    document.addEventListener('keydown', onKey, true);
    return ()=>document.removeEventListener('keydown', onKey, true);
  }

  function setText(text, opts){
    const o = (opts && typeof opts === 'object') ? opts : {};
    const ov = ensureOverlay();

    const titleEl = ov.querySelector('#ls-loading-title');
    const descEl = ov.querySelector('#ls-loading-desc');

    const title = (o.title != null) ? String(o.title) : null;
    const desc = (text != null) ? String(text) : '';

    if(titleEl){
      titleEl.textContent = title ? title : (STR.loading || 'Loading…');
    }

    if(descEl){
      descEl.textContent = desc || (STR.pleaseWait || 'Please wait…');
    }
  }

  function setProgress(pct, opts){
    const o = (opts && typeof opts === 'object') ? opts : {};
    const ov = ensureOverlay();

    const wrap = ov.querySelector('#ls-loading-progress');
    const fill = ov.querySelector('#ls-loading-bar-fill');
    const pctEl = ov.querySelector('#ls-loading-pct');

    if(!wrap) return;

    const v = (pct == null) ? null : clampPct(pct);

    if(v == null){
      wrap.classList.add('is-indeterminate');
      wrap.setAttribute('aria-hidden', 'false');
      wrap.removeAttribute('aria-valuenow');
      if(pctEl) pctEl.textContent = '';
      if(fill) fill.style.width = '100%';
      if(o.label != null) wrap.setAttribute('aria-label', String(o.label));
      return;
    }

    wrap.classList.remove('is-indeterminate');
    wrap.setAttribute('aria-hidden', 'false');
    wrap.setAttribute('aria-valuenow', String(v));

    if(fill) fill.style.width = v + '%';
    if(pctEl) pctEl.textContent = v + '%';

    if(o.label != null) wrap.setAttribute('aria-label', String(o.label));
  }

  function show(opts){
    const o = (opts && typeof opts === 'object') ? opts : {};
    const ov = ensureOverlay();

    if(shown){
      if(o.text != null || o.title != null) setText(o.text, {title: o.title});
      if(Object.prototype.hasOwnProperty.call(o, 'progress')) setProgress(o.progress, {label: o.progressLabel});
      return;
    }

    shown = true;
    prevFocus = document.activeElement;

    if(o.text != null || o.title != null) setText(o.text, {title: o.title});
    else setText('', {});

    if(Object.prototype.hasOwnProperty.call(o, 'progress')) setProgress(o.progress, {label: o.progressLabel});
    else{
      const wrap = ov.querySelector('#ls-loading-progress');
      if(wrap) wrap.setAttribute('aria-hidden', 'true');
    }

    ov.removeAttribute('hidden');
    ov.setAttribute('aria-hidden', 'false');

    lockScroll();
    setBusy(true);

    if(releaseKeyTrap) releaseKeyTrap();
    releaseKeyTrap = trapKeys(ov);

    requestAnimationFrame(()=>{
      ov.classList.add('show');
      try{
        const card = ov.querySelector('.ls-loading-card');
        if(card && card.focus) card.focus();
      }catch{}
    });
  }

  function hide(){
    const ov = document.getElementById('ls-loading-overlay');

    if(releaseKeyTrap){
      releaseKeyTrap();
      releaseKeyTrap = null;
    }

    if(!shown){
      if(ov){
        ov.classList.remove('show');
        ov.setAttribute('aria-hidden', 'true');
        ov.setAttribute('hidden', '');
      }
      unlockScroll();
      setBusy(false);
      return;
    }

    shown = false;

    if(ov){
      ov.classList.remove('show');
      ov.setAttribute('aria-hidden', 'true');
      setTimeout(()=>{
        try{
          if(!shown && ov) ov.setAttribute('hidden', '');
        }catch{}
      }, 180);
    }

    unlockScroll();
    setBusy(false);

    const f = prevFocus;
    prevFocus = null;
    if(f && f.focus){
      setTimeout(()=>{ try{ f.focus(); }catch{} }, 0);
    }
  }

  // Public API
  LS.loading = LS.loading || {};
  LS.loading.show = show;
  LS.loading.hide = hide;
  LS.loading.setText = setText;
  LS.loading.setProgress = setProgress;
  LS.loading.isActive = function(){ return !!shown; };

  // Optional: shorter alias for pages not using LS.
  W.LSLoader = LS.loading;

  // ────────────────────────────────────────────────────────────
  // Auto binding
  //  - Shows overlay for same-origin navigations (links, native form submits)
  //  - Shows overlay for user-initiated fetch/XHR calls (to prevent over-click)
  // ────────────────────────────────────────────────────────────

  (function initAutoLoading(){
    if(!W || !W.document) return;

    const GET_SHOW_DELAY_MS = 240;
    const ACTION_SHOW_DELAY_MS = 0;
    const MIN_VISIBLE_MS = 360;
    const USER_GESTURE_WINDOW_MS = 1400;

    let lastGestureAt = 0;
    function noteGesture(){ lastGestureAt = Date.now(); }

    try{ document.addEventListener('pointerdown', noteGesture, {capture:true, passive:true}); }
    catch{ document.addEventListener('pointerdown', noteGesture, true); }

    document.addEventListener('keydown', (e)=>{
      const k = e && e.key ? e.key : '';
      if(k === 'Enter' || k === ' ' || k === 'Spacebar') noteGesture();
    }, true);

    function looksUserInitiated(){
      return (Date.now() - lastGestureAt) <= USER_GESTURE_WINDOW_MS;
    }

    function hasOtherModalOpen(){
      try{ return !!document.querySelector('.ls-modal-overlay.show'); }
      catch{ return false; }
    }

    function sameOriginUrl(raw){
      try{
        const u = new URL(String(raw || ''), window.location.href);
        return u.origin === window.location.origin;
      }catch{
        return true; // treat relative/unknown as same-origin
      }
    }

    function headerValue(headers, keyLower){
      if(!headers) return null;

      // Headers instance
      try{
        if(typeof headers.get === 'function'){
          const v = headers.get(keyLower) || headers.get(keyLower.toUpperCase());
          if(v != null) return String(v);
        }
      }catch{}

      // Plain object
      try{
        const k = Object.keys(headers).find(k => String(k).toLowerCase() === keyLower);
        if(k) return String(headers[k]);
      }catch{}

      return null;
    }

    function methodOfFetch(input, init){
      const m = (init && init.method != null)
        ? String(init.method)
        : (input && typeof input === 'object' && input.method ? String(input.method) : 'GET');
      return m.toUpperCase();
    }

    function urlOfFetch(input){
      if(typeof input === 'string') return input;
      if(input && typeof input === 'object' && input.url) return input.url;
      return '';
    }

    let inFlight = 0;
    let autoShown = false;
    let autoShownAt = 0;
    let showTimer = null;

    function resetAutoState(){
      inFlight = 0;
      autoShown = false;
      autoShownAt = 0;
      if(showTimer){
        clearTimeout(showTimer);
        showTimer = null;
      }
    }

    function scheduleShow(delayMs){
      if(showTimer || autoShown) return;
      if(hasOtherModalOpen()) return;

      showTimer = setTimeout(()=>{
        showTimer = null;
        if(inFlight <= 0) return;
        if(autoShown) return;
        if(hasOtherModalOpen()) return;

        if(LS.loading && typeof LS.loading.show === 'function'){
          LS.loading.show({});
          autoShown = true;
          autoShownAt = Date.now();
        }
      }, Math.max(0, Number(delayMs)||0));
    }

    function begin(delayMs){
      inFlight++;
      scheduleShow(delayMs);
    }

    function end(){
      if(inFlight > 0) inFlight--;
      if(inFlight > 0) return;

      if(showTimer){
        clearTimeout(showTimer);
        showTimer = null;
      }

      if(autoShown && LS.loading && typeof LS.loading.hide === 'function'){
        const dt = Date.now() - autoShownAt;
        const wait = Math.max(0, MIN_VISIBLE_MS - dt);
        setTimeout(()=>{
          if(inFlight !== 0) return;
          if(!autoShown) return;
          autoShown = false;
          autoShownAt = 0;
          LS.loading.hide();
        }, wait);
      }
    }

    function shouldTrackFetch(input, init){
      if(init && init.ls_no_loading) return false;

      const url = urlOfFetch(input);
      if(url && !sameOriginUrl(url)) return false;

      // Skip requests explicitly marked as background.
      const hv = headerValue(init && init.headers ? init.headers : null, 'x-ls-background');
      if(hv === '1' || hv === 'true') return false;

      // Only show overlay for user-initiated work (prevents background polling flicker).
      if(!looksUserInitiated()) return false;

      return true;
    }

    if(typeof W.fetch === 'function' && !W.fetch.__ls_loading_patched){
      const origFetch = W.fetch;

      const patched = function(input, init){
        const track = shouldTrackFetch(input, init);
        if(track){
          const method = methodOfFetch(input, init);
          begin((method === 'GET' || method === 'HEAD') ? GET_SHOW_DELAY_MS : ACTION_SHOW_DELAY_MS);
        }

        const p = origFetch.apply(this, arguments);
        if(!track) return p;
        return Promise.resolve(p).finally(end);
      };

      try{ patched.__ls_loading_patched = true; }catch{}
      W.fetch = patched;
    }

    if(typeof W.XMLHttpRequest === 'function' && !W.XMLHttpRequest.__ls_loading_patched){
      const X = W.XMLHttpRequest;
      const open = X.prototype.open;
      const send = X.prototype.send;

      X.prototype.open = function(method, url){
        try{
          this.__ls_method = String(method || '').toUpperCase();
          this.__ls_url = String(url || '');
        }catch{}
        return open.apply(this, arguments);
      };

      X.prototype.send = function(){
        let track = false;
        try{
          const method = String(this.__ls_method || 'GET');
          const url = String(this.__ls_url || '');
          if(method !== 'GET' && method !== 'HEAD' && looksUserInitiated() && (!url || sameOriginUrl(url))){
            track = true;
          }
        }catch{}

        if(track){
          begin(ACTION_SHOW_DELAY_MS);
          const done = ()=>{ this.removeEventListener('loadend', done); end(); };
          this.addEventListener('loadend', done);
        }

        return send.apply(this, arguments);
      };

      try{ W.XMLHttpRequest.__ls_loading_patched = true; }catch{}
    }

    function queueAfterEvent(fn){
      if(typeof queueMicrotask === 'function') queueMicrotask(fn);
      else Promise.resolve().then(fn);
    }

    function isModifiedClick(e){
      return !!(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0);
    }

    // Ensure the overlay never gets "stuck" when the page is restored from
    // the back-forward cache (bfcache). This can happen if a navigation starts
    // while the overlay is visible or a tracked request is in-flight.
    window.addEventListener('pagehide', ()=>{
      resetAutoState();
      try{
        if(LS.loading && typeof LS.loading.hide === 'function') LS.loading.hide();
      }catch{}
    }, true);

    window.addEventListener('pageshow', ()=>{
      resetAutoState();
      try{
        if(LS.loading && typeof LS.loading.hide === 'function') LS.loading.hide();
      }catch{}
    }, true);

    // Same-origin navigation links: show overlay.
    document.addEventListener('click', (e)=>{
      if(!e || e.defaultPrevented) return;
      if(isModifiedClick(e)) return;

      const a = e.target && e.target.closest ? e.target.closest('a') : null;
      if(!a) return;
      if(a.hasAttribute('data-ls-no-loading')) return;
      if(a.hasAttribute('download')) return;

      const href = (a.getAttribute('href') || '').trim();
      if(!href || href[0] === '#') return;
      if(/^javascript:/i.test(href)) return;

      const target = (a.getAttribute('target') || '').trim();
      if(target && target !== '_self') return;

      let url;
      try{ url = new URL(href, window.location.href); }
      catch{ return; }

      if(url.origin !== window.location.origin) return;

      queueAfterEvent(()=>{
        if(e.defaultPrevented) return;
        if(LS.loading && typeof LS.loading.show === 'function') LS.loading.show({});
      });

    }, true);

    function willNavigateInPlace(form, submitter){
      if(!form) return true;
      const ft = submitter && submitter.getAttribute ? submitter.getAttribute('formtarget') : null;
      const t = (ft != null ? String(ft) : String(form.getAttribute('target') || '')).trim();
      if(!t) return true;
      return t === '_self';
    }

    // Native form submits: show overlay.
    document.addEventListener('submit', (e)=>{
      const form = e.target;
      if(!(form instanceof HTMLFormElement)) return;
      if(form.hasAttribute('data-ls-no-loading')) return;

      const submitter = e.submitter || null;

      queueAfterEvent(()=>{
        if(e.defaultPrevented) return;
        if(!willNavigateInPlace(form, submitter)) return;
        if(LS.loading && typeof LS.loading.show === 'function') LS.loading.show({});
      });

    }, true);

    // Programmatic form.submit() bypasses submit event.
    try{
      const proto = HTMLFormElement && HTMLFormElement.prototype;
      if(proto && typeof proto.submit === 'function' && !proto.submit.__ls_loading_patched){
        const origSubmit = proto.submit;
        const patchedSubmit = function(){
          try{
            if(this && this.hasAttribute && !this.hasAttribute('data-ls-no-loading')){
              const t = String(this.getAttribute('target') || '').trim();
              if(!t || t === '_self'){
                if(LS.loading && typeof LS.loading.show === 'function') LS.loading.show({});
              }
            }
          }catch{}
          return origSubmit.apply(this, arguments);
        };
        try{ patchedSubmit.__ls_loading_patched = true; }catch{}
        proto.submit = patchedSubmit;
      }
    }catch{}

  })();

})();
