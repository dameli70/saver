(function(){
  'use strict';

  // Idempotency guard: this file can be included via <script> AND loaded on-demand.
  // Prevent double-initialization (which could otherwise reset the modal queue).
  if(window.__LS_UI_MODAL_LOADED) return;
  window.__LS_UI_MODAL_LOADED = true;

  function t(key, fallback){
    try{
      if(window.LS && typeof window.LS.t === 'function'){
        const v = window.LS.t(key);
        if(v && v !== key) return v;
      }
    }catch{}
    return fallback;
  }

  const STR = {
    ok: t('common.confirm', 'OK'),
    confirm: t('common.confirm', 'Confirm'),
    cancel: t('common.cancel', 'Cancel'),
    close: t('common.close', 'Close'),
    invalid: t('js.invalid_input', 'Invalid input'),
  };

  function esc(s){
    return String(s == null ? '' : s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  function trapFocus(modal, onEsc){
    function focusables(){
      return modal.querySelectorAll('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])');
    }

    function onKey(e){
      if(e.key === 'Escape'){
        e.preventDefault();
        if(typeof onEsc === 'function') onEsc();
        return;
      }
      if(e.key !== 'Tab') return;

      const els = focusables();
      if(!els.length) return;
      const first = els[0];
      const last = els[els.length - 1];

      if(e.shiftKey && document.activeElement === first){
        e.preventDefault();
        last.focus();
      }else if(!e.shiftKey && document.activeElement === last){
        e.preventDefault();
        first.focus();
      }
    }

    modal.addEventListener('keydown', onKey);
    return ()=>modal.removeEventListener('keydown', onKey);
  }

  function ensureOverlay(){
    let overlay = document.getElementById('ui-modal-overlay');
    if(overlay) return overlay;

    overlay = document.createElement('div');
    overlay.id = 'ui-modal-overlay';
    overlay.className = 'ls-modal-overlay';
    overlay.innerHTML = `
      <div class="ls-modal" role="dialog" aria-modal="true" aria-labelledby="ui-modal-title" aria-describedby="ui-modal-msg">
        <button class="ls-modal-x" type="button" aria-label="${esc(STR.close)}">×</button>
        <div class="ls-modal-title" id="ui-modal-title"></div>
        <div class="ls-modal-sub" id="ui-modal-msg" style="white-space:pre-wrap;"></div>
        <div class="msg msg-err" id="ui-modal-err" aria-live="polite"></div>
        <div id="ui-modal-body"></div>
        <div class="ls-modal-actions" id="ui-modal-actions" style="display:flex;flex-direction:column;gap:10px;margin-top:18px;"></div>
      </div>
    `;
    document.body.appendChild(overlay);

    return overlay;
  }

  let queue = Promise.resolve();
  function enqueue(task){
    const run = queue.then(task, task);
    queue = run.catch(()=>{});
    return run;
  }

  function openModal(opts){
    const overlay = ensureOverlay();
    const modal = overlay.querySelector('.ls-modal');

    const titleEl = overlay.querySelector('#ui-modal-title');
    const msgEl = overlay.querySelector('#ui-modal-msg');
    const errEl = overlay.querySelector('#ui-modal-err');
    const bodyEl = overlay.querySelector('#ui-modal-body');
    const actionsEl = overlay.querySelector('#ui-modal-actions');
    const xBtn = overlay.querySelector('.ls-modal-x');

    const title = opts && opts.title != null ? String(opts.title) : '';
    const message = opts && opts.message != null ? String(opts.message) : '';

    if(titleEl) titleEl.textContent = title;
    if(msgEl) msgEl.textContent = message;

    if(errEl){
      errEl.textContent = '';
      errEl.classList.remove('show');
    }

    if(bodyEl) bodyEl.innerHTML = '';
    if(actionsEl) actionsEl.innerHTML = '';

    overlay.classList.add('show');

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const prevFocus = document.activeElement;

    let releaseTrap = null;
    let resolved = false;

    function cleanup(){
      overlay.classList.remove('show');
      document.body.style.overflow = prevOverflow;

      if(releaseTrap) releaseTrap();
      releaseTrap = null;

      overlay.removeEventListener('click', onClickOut);
      if(xBtn) xBtn.removeEventListener('click', onCancel);

      if(prevFocus && prevFocus.focus) setTimeout(()=>prevFocus.focus(), 0);
    }

    function showError(message){
      if(!errEl) return;
      errEl.textContent = String(message || '');
      if(errEl.textContent) errEl.classList.add('show');
      else errEl.classList.remove('show');
    }

    function onCancel(){
      if(resolved) return;
      resolved = true;
      cleanup();
      if(typeof opts.onCancel === 'function') opts.onCancel();
    }

    function onClickOut(e){
      if(e.target === overlay) onCancel();
    }

    overlay.addEventListener('click', onClickOut);
    if(xBtn) xBtn.addEventListener('click', onCancel);

    try{ if(modal) releaseTrap = trapFocus(modal, onCancel); }catch{}

    return {
      overlay,
      modal,
      titleEl,
      msgEl,
      errEl,
      bodyEl,
      actionsEl,
      showError,
      close: onCancel,
      finish: (cb)=>{
        if(resolved) return;
        resolved = true;
        cleanup();
        cb();
      }
    };
  }

  function uiConfirmImpl(o){
    const opts = (o && typeof o === 'object') ? o : {};

    return new Promise((resolve)=>{
      const state = openModal({
        title: opts.title != null ? opts.title : STR.confirm,
        message: opts.message != null ? opts.message : '',
        onCancel: ()=>resolve(false),
      });

      const okText = opts.okText != null ? String(opts.okText)
        : (opts.confirmText != null ? String(opts.confirmText) : STR.confirm);
      const cancelText = opts.cancelText != null ? String(opts.cancelText) : STR.cancel;

      const okBtn = document.createElement('button');
      okBtn.type = 'button';
      okBtn.className = (opts.danger ? 'btn btn-red' : 'btn btn-primary');
      okBtn.textContent = okText;
      okBtn.style.width = '100%';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn btn-ghost';
      cancelBtn.textContent = cancelText;
      cancelBtn.style.width = '100%';

      function cleanup(){
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
      }

      function onCancel(){
        cleanup();
        state.finish(()=>resolve(false));
      }

      function onOk(){
        cleanup();
        state.finish(()=>resolve(true));
      }

      cancelBtn.addEventListener('click', onCancel);
      okBtn.addEventListener('click', onOk);

      if(state.actionsEl){
        state.actionsEl.appendChild(okBtn);
        state.actionsEl.appendChild(cancelBtn);
      }

      setTimeout(()=>{ okBtn.focus(); }, 10);
    });
  }

  function uiPromptImpl(o){
    const opts = (o && typeof o === 'object') ? o : {};

    return new Promise((resolve)=>{
      const state = openModal({
        title: opts.title != null ? opts.title : '',
        message: opts.message != null ? opts.message : '',
        onCancel: ()=>resolve(null),
      });

      const placeholder = opts.placeholder != null ? String(opts.placeholder) : '';
      const initialValue = opts.initialValue != null ? String(opts.initialValue) : '';
      const validate = (typeof opts.validate === 'function') ? opts.validate : null;

      const form = document.createElement('form');
      form.autocomplete = 'off';

      const field = document.createElement('div');
      field.className = 'field';
      field.style.marginTop = '12px';

      const label = document.createElement('label');
      label.setAttribute('for', 'ui-modal-input');
      label.textContent = placeholder ? placeholder : 'Value';

      const input = document.createElement('input');
      input.id = 'ui-modal-input';
      input.type = (opts.inputType != null ? String(opts.inputType) : 'text');
      input.placeholder = placeholder;
      input.value = initialValue;
      input.autocomplete = 'off';
      if(opts.inputMode != null) input.setAttribute('inputmode', String(opts.inputMode));
      if(!label.textContent) input.setAttribute('aria-label', state.titleEl ? (state.titleEl.textContent || 'Input') : 'Input');

      field.appendChild(label);
      field.appendChild(input);

      form.appendChild(field);

      const okText = opts.okText != null ? String(opts.okText) : STR.ok;
      const cancelText = opts.cancelText != null ? String(opts.cancelText) : STR.cancel;

      const okBtn = document.createElement('button');
      okBtn.type = 'submit';
      okBtn.className = 'btn btn-primary';
      okBtn.textContent = okText;
      okBtn.style.width = '100%';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn btn-ghost';
      cancelBtn.textContent = cancelText;
      cancelBtn.style.width = '100%';

      function cleanup(){
        cancelBtn.removeEventListener('click', onCancel);
        form.removeEventListener('submit', onSubmit);
        input.removeEventListener('input', onInput);
      }

      function onCancel(){
        cleanup();
        state.finish(()=>resolve(null));
      }

      async function onSubmit(e){
        if(e && e.preventDefault) e.preventDefault();

        const v = String(input.value || '');

        if(validate){
          state.showError('');

          okBtn.disabled = true;
          try{
            const res = await validate(v);

            if(res === false){
              state.showError(STR.invalid);
              okBtn.disabled = false;
              input.focus();
              input.select();
              return;
            }

            if(typeof res === 'string' && res.trim()){
              state.showError(res.trim());
              okBtn.disabled = false;
              input.focus();
              input.select();
              return;
            }

          }catch(err){
            const msg = err && err.message ? err.message : STR.invalid;
            state.showError(msg);
            okBtn.disabled = false;
            input.focus();
            input.select();
            return;
          }
          okBtn.disabled = false;
        }

        cleanup();
        state.finish(()=>resolve(v));
      }

      function onInput(){
        state.showError('');
      }

      cancelBtn.addEventListener('click', onCancel);
      form.addEventListener('submit', onSubmit);
      input.addEventListener('input', onInput);

      if(state.bodyEl) state.bodyEl.appendChild(form);
      if(state.actionsEl){
        state.actionsEl.appendChild(okBtn);
        state.actionsEl.appendChild(cancelBtn);
      }

      setTimeout(()=>{
        input.focus();
        try{ input.select(); }catch{}
      }, 10);
    });
  }

  window.uiConfirm = function(opts){
    return enqueue(()=>uiConfirmImpl(opts));
  };

  window.uiPrompt = function(opts){
    return enqueue(()=>uiPromptImpl(opts));
  };
})();
