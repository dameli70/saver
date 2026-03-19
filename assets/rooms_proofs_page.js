(function(){
  'use strict';

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (I18N && typeof I18N[key] === 'string') ? I18N[key] : fallback;
  }

  function esc(s){
    if(window.LS && typeof window.LS.esc === 'function') return window.LS.esc(s);
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function apiUrl(url){
    const u = String(url || '');
    return u.startsWith('/') ? u.slice(1) : u;
  }

  function parseUtcDate(ts){
    if(window.LS && typeof window.LS.parseUtc === 'function') return window.LS.parseUtc(ts);

    const s = String(ts||'').trim();
    if(!s) return null;

    if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
      return new Date(s.replace(' ', 'T') + 'Z');
    }

    return new Date(s);
  }

  function fmt(ts){
    const d = parseUtcDate(ts);
    if(!d || isNaN(d.getTime())) return String(ts||'');
    if(window.LS && typeof window.LS.fmtLocal === 'function') return window.LS.fmtLocal(d);
    return d.toLocaleString();
  }

  function setMsg(id, text, ok){
    const el = document.getElementById(id);
    if(!el) return;
    el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
    el.textContent = String(text||'');
  }

  async function getJson(url){
    const r = await fetch(apiUrl(url), { credentials: 'same-origin' });
    const txt = await r.text();
    if(!txt) return null;
    try{
      return JSON.parse(txt);
    }catch(e){
      try{ console.error('Non-JSON response from API:', txt); }catch(_){}
      throw new Error('Server returned an invalid response.');
    }
  }

  function proofUrl(proofId){
    return '/api/room_proof.php?id=' + encodeURIComponent(String(proofId||''));
  }

  const STR = {
    failed: tr('common.failed', 'Failed'),
    upload: tr('rooms.proofs.upload_btn', 'Upload'),
    uploading: tr('rooms.proofs.uploading', 'Uploading…'),
    view: tr('rooms.proofs.view', 'View'),
    open_room: tr('rooms.proofs.open_room', 'Open room'),
    cycle_fmt: tr('rooms.proofs.cycle_fmt', 'Cycle #{n}'),
    turn_fmt: tr('rooms.proofs.turn_fmt', 'Turn #{n}'),
    prompt_reference: tr('rooms.proofs.prompt_reference', 'Optional reference / note (leave blank if none):'),
    file_required: tr('rooms.proofs.file_required', 'Select a proof image.'),
    file_too_large: tr('rooms.proofs.file_too_large', 'File too large (max 5MB).'),
  };

  function cycleOrTurnLabel(row){
    const idx = (row && typeof row.cycle_index !== 'undefined') ? String(row.cycle_index) : '';
    if(!idx) return '—';
    if(String(row.saving_type||'') === 'B') return STR.turn_fmt.replace('{n}', idx);
    return STR.cycle_fmt.replace('{n}', idx);
  }

  function roomLinkHtml(row){
    const href = 'room.php?id=' + encodeURIComponent(String(row.room_id||''));
    const goal = row.goal_text ? String(row.goal_text) : (tr('page.room', 'Room') + ' ' + String(row.room_id||''));
    return '<div class="proofs-room"><a href="' + esc(href) + '">' + esc(goal) + '</a></div><div class="small"><a href="' + esc(href) + '">' + esc(STR.open_room) + '</a></div>';
  }

  function clearTable(tbodySel){
    const tbody = document.querySelector(tbodySel);
    if(tbody) tbody.innerHTML = '';
  }

  function renderTaskRows(kind, rows){
    const wrap = document.getElementById(kind + '-table-wrap');
    const empty = document.getElementById(kind + '-empty');
    const tbody = document.querySelector('#' + kind + '-table tbody');
    if(!tbody) return;

    tbody.innerHTML = '';

    if(rows && rows.length){
      if(wrap) wrap.style.display = 'block';
      if(empty) empty.style.display = 'none';

      rows.forEach((r, i) => {
        const trEl = document.createElement('tr');

        const dueTxt = r.due_at ? fmt(r.due_at) : '—';
        const amount = (r.amount != null && String(r.amount) !== '') ? String(r.amount) : '—';
        const turn = cycleOrTurnLabel(r);

        const fileId = kind + '-file-' + i;

        trEl.innerHTML =
          '<td>' + roomLinkHtml(r) + '</td>' +
          '<td>' + esc(turn) + '</td>' +
          '<td>' + esc(dueTxt) + '</td>' +
          '<td>' + esc(amount) + '</td>' +
          '<td>' +
            '<div class="proofs-action">' +
              '<input type="file" id="' + esc(fileId) + '" style="display:none;" accept="image/png,image/jpeg,image/webp">' +
              '<button class="btn btn-blue btn-sm" type="button" data-upload-btn="1">' + esc(STR.upload) + '</button>' +
            '</div>' +
          '</td>';

        tbody.appendChild(trEl);

        const fileInput = document.getElementById(fileId);
        const btn = trEl.querySelector('button[data-upload-btn]');
        if(btn && fileInput){
          btn.addEventListener('click', () => fileInput.click());

          fileInput.addEventListener('change', async () => {
            const file = fileInput.files && fileInput.files[0] ? fileInput.files[0] : null;
            if(!file){
              setMsg('tasks-msg', STR.file_required, false);
              return;
            }
            if(file.size > 5000000){
              setMsg('tasks-msg', STR.file_too_large, false);
              fileInput.value = '';
              return;
            }

            btn.disabled = true;
            const oldTxt = btn.textContent;
            btn.textContent = STR.uploading;

            try{
              const ref = (window.LS && typeof window.LS.prompt === 'function')
                ? await window.LS.prompt({
                    title: tr('room.contribution.reference_optional', 'Reference (optional)'),
                    message: STR.prompt_reference,
                    placeholder: tr('room.contribution.reference_placeholder', 'e.g. bank tx id'),
                  })
                : null;

              const reference = (ref === null || typeof ref === 'undefined') ? '' : String(ref||'');

              const fd = new FormData();
              fd.append('csrf_token', (typeof CSRF === 'string' ? CSRF : ''));
              fd.append('room_id', String(r.room_id||''));
              fd.append('cycle_id', String(r.cycle_id||''));
              fd.append('amount', String(r.amount||''));
              fd.append('reference', reference);
              fd.append('proof', file);

              const resp = await fetch('/api/rooms.php?action=confirm_contribution_with_proof', {
                method: 'POST',
                credentials: 'same-origin',
                body: fd,
              });
              const res = await resp.json().catch(()=>null);
              if(!res || !res.success) throw new Error((res && res.error) ? res.error : STR.failed);

              setMsg('tasks-msg', tr('rooms.proofs.upload_ok', 'Uploaded.'), true);
              await reloadAll();

            }catch(e){
              setMsg('tasks-msg', (e && e.message) ? e.message : STR.failed, false);
            }finally{
              fileInput.value = '';
              btn.textContent = oldTxt;
              btn.disabled = false;
            }
          });
        }
      });

    } else {
      if(wrap) wrap.style.display = 'none';
      if(empty) empty.style.display = 'block';
    }
  }

  function renderMissedRows(rows){
    const wrap = document.getElementById('missed-table-wrap');
    const empty = document.getElementById('missed-empty');
    const tbody = document.querySelector('#missed-table tbody');
    if(!tbody) return;

    tbody.innerHTML = '';

    if(rows && rows.length){
      if(wrap) wrap.style.display = 'block';
      if(empty) empty.style.display = 'none';

      rows.forEach(r => {
        const trEl = document.createElement('tr');
        const dueTxt = r.due_at ? fmt(r.due_at) : '—';
        const amount = (r.amount != null && String(r.amount) !== '') ? String(r.amount) : '—';
        const turn = cycleOrTurnLabel(r);
        const st = r.contribution_status ? String(r.contribution_status) : '—';

        trEl.innerHTML =
          '<td>' + roomLinkHtml(r) + '</td>' +
          '<td>' + esc(turn) + '</td>' +
          '<td>' + esc(dueTxt) + '</td>' +
          '<td>' + esc(amount) + '</td>' +
          '<td>' + esc(st) + '</td>';

        tbody.appendChild(trEl);
      });

    } else {
      if(wrap) wrap.style.display = 'none';
      if(empty) empty.style.display = 'block';
    }
  }

  let uploadsNextBeforeId = null;
  let uploadsLoading = false;

  function addUploadRows(rows){
    const wrap = document.getElementById('uploads-table-wrap');
    const empty = document.getElementById('uploads-empty');
    const tbody = document.querySelector('#uploads-table tbody');
    if(!tbody) return;

    if(rows && rows.length){
      if(wrap) wrap.style.display = 'block';
      if(empty) empty.style.display = 'none';

      rows.forEach(p => {
        const trEl = document.createElement('tr');
        const amount = (p.amount != null && String(p.amount) !== '') ? String(p.amount) : '—';
        const confirmed = p.confirmed_at ? fmt(p.confirmed_at) : '—';
        const uploaded = p.proof_created_at ? fmt(p.proof_created_at) : '—';
        const turn = cycleOrTurnLabel(p);
        const url = proofUrl(p.proof_id);

        const proofCell =
          '<a class="proof-link" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' +
            '<img class="proof-thumb" loading="lazy" src="' + esc(url) + '" alt="proof">' +
            '<span class="small">' + esc(STR.view) + '</span>' +
          '</a>';

        trEl.innerHTML =
          '<td>' + roomLinkHtml(p) + '</td>' +
          '<td>' + esc(turn) + '<div class="small">' + esc(p.due_at ? fmt(p.due_at) : '') + '</div></td>' +
          '<td>' + esc(amount) + '</td>' +
          '<td>' + esc(confirmed) + '</td>' +
          '<td>' + esc(uploaded) + '</td>' +
          '<td>' + proofCell + '</td>';

        tbody.appendChild(trEl);
      });

    } else {
      const hasAny = tbody.children && tbody.children.length;
      if(!hasAny){
        if(wrap) wrap.style.display = 'none';
        if(empty) empty.style.display = 'block';
      }
    }
  }

  async function loadTasks(){
    document.getElementById('tasks-msg').className = 'msg';

    const roomParam = (typeof FILTER_ROOM_ID === 'string' && FILTER_ROOM_ID) ? ('&room_id=' + encodeURIComponent(FILTER_ROOM_ID)) : '';
    const res = await getJson('/api/rooms.php?action=my_proof_tasks' + roomParam);
    if(!res || !res.success) throw new Error((res && res.error) ? res.error : STR.failed);

    renderTaskRows('upcoming', res.upcoming || []);
    renderTaskRows('overdue', res.overdue || []);
    renderMissedRows(res.missed || []);
  }

  async function loadMoreUploads(reset){
    if(uploadsLoading) return;
    uploadsLoading = true;

    const btn = document.getElementById('uploads-load-more');
    if(btn) btn.disabled = true;

    if(reset){
      uploadsNextBeforeId = null;
      clearTable('#uploads-table tbody');
      document.getElementById('uploads-msg').className = 'msg';
    }

    try{
      const roomParam = (typeof FILTER_ROOM_ID === 'string' && FILTER_ROOM_ID) ? ('&room_id=' + encodeURIComponent(FILTER_ROOM_ID)) : '';
      const beforeParam = uploadsNextBeforeId ? ('&before_id=' + encodeURIComponent(String(uploadsNextBeforeId))) : '';
      const url = '/api/rooms.php?action=my_proofs&limit=50' + roomParam + beforeParam;

      const res = await getJson(url);
      if(!res || !res.success) throw new Error((res && res.error) ? res.error : STR.failed);

      addUploadRows(res.proofs || []);

      uploadsNextBeforeId = res.next_before_id || null;
      if(btn) btn.style.display = uploadsNextBeforeId ? 'inline-flex' : 'none';

    }catch(e){
      setMsg('uploads-msg', (e && e.message) ? e.message : STR.failed, false);
    }finally{
      if(btn) btn.disabled = false;
      uploadsLoading = false;
    }
  }

  async function reloadAll(){
    await loadTasks();
    await loadMoreUploads(true);
  }

  window.loadMoreUploads = function(){
    return loadMoreUploads(false);
  };

  // initial load
  (async function init(){
    try{
      await reloadAll();
    }catch(e){
      setMsg('tasks-msg', (e && e.message) ? e.message : STR.failed, false);
      // still try uploads for partial visibility
      try{ await loadMoreUploads(true); }catch(_e){}
    }
  })();

})();
