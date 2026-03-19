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

  const STR = {
    failed: tr('common.failed', 'Failed'),
    loading: tr('common.loading', 'Loading…'),
    proof_open: tr('room.proofs_open', 'Open'),
    proof_view: tr('room.proofs_view', 'View'),
    cycle_fmt: tr('room.proofs_cycle_fmt', 'Cycle #{n}'),
  };

  let nextBeforeId = null;
  let loading = false;

  function proofUrl(proofId){
    return '/api/room_proof.php?id=' + encodeURIComponent(String(proofId||''));
  }

  function addRows(rows){
    const tableWrap = document.getElementById('proofs-table-wrap');
    const empty = document.getElementById('proofs-empty');
    const tbody = document.querySelector('#proofs-table tbody');
    if(!tbody) return;

    if(rows && rows.length){
      if(tableWrap) tableWrap.style.display = 'block';
      if(empty) empty.style.display = 'none';

      rows.forEach(p => {
        const trEl = document.createElement('tr');

        const cycleIndex = (p && typeof p.cycle_index !== 'undefined') ? String(p.cycle_index) : '';
        const cycleTxt = cycleIndex ? STR.cycle_fmt.replace('{n}', cycleIndex) : '—';

        const who = p.display_name || ('User #' + p.user_id);
        const amt = (p.amount != null && String(p.amount) !== '') ? String(p.amount) : '—';
        const st = p.status ? String(p.status) : '—';
        const confirmed = p.confirmed_at ? fmt(p.confirmed_at) : '—';

        const url = proofUrl(p.proof_id);

        const proofCell = `
          <a class="proof-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">
            <img class="proof-thumb" loading="lazy" src="${esc(url)}" alt="proof">
            <span class="small">${esc(STR.proof_view)}</span>
          </a>`;

        trEl.innerHTML = `
          <td>${esc(cycleTxt)}<div class="small">${esc(p.due_at ? fmt(p.due_at) : '')}</div></td>
          <td>${esc(who)}</td>
          <td>${esc(amt)}</td>
          <td>${esc(st)}</td>
          <td>${esc(confirmed)}</td>
          <td>${proofCell}</td>
        `;

        tbody.appendChild(trEl);
      });
    } else {
      const hasAny = tbody.children && tbody.children.length;
      if(!hasAny){
        if(tableWrap) tableWrap.style.display = 'none';
        if(empty) empty.style.display = 'block';
      }
    }
  }

  async function loadMore(){
    if(loading) return;
    loading = true;

    const btn = document.getElementById('proofs-load-more');
    if(btn) btn.disabled = true;

    document.getElementById('proofs-msg').className = 'msg';

    try{
      const url = '/api/rooms.php?action=contribution_proofs&room_id=' + encodeURIComponent(ROOM_ID) + '&limit=80' + (nextBeforeId ? ('&before_id=' + encodeURIComponent(String(nextBeforeId))) : '');
      const res = await getJson(url);
      if(!res || !res.success) throw new Error((res && res.error) ? res.error : STR.failed);

      const rows = res.proofs || [];
      addRows(rows);

      nextBeforeId = res.next_before_id || null;

      if(btn) btn.style.display = nextBeforeId ? 'inline-flex' : 'none';

    }catch(e){
      setMsg('proofs-msg', e.message||STR.failed, false);
    }finally{
      if(btn) btn.disabled = false;
      loading = false;
    }
  }

  window.loadMoreProofs = loadMore;

  // initial
  const btn = document.getElementById('proofs-load-more');
  if(btn) btn.style.display = 'none';

  loadMore();

})();
