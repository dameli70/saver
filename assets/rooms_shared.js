(function(){
  'use strict';

  // Shared helpers for rooms pages. Expects global CSRF constant (set inline by each rooms*.php page).

  const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
  function tr(key, fallback){
    return (I18N && typeof I18N[key] === 'string') ? I18N[key] : fallback;
  }

  function fmt(s, vars){
    return String(s||'').replace(/\{(\w+)\}/g, (m, k) => (vars && Object.prototype.hasOwnProperty.call(vars, k)) ? String(vars[k]) : m);
  }

  function tf(key, vars, fallback){
    return fmt(tr(key, fallback), vars);
  }

  const STR = {
    failed: tr('common.failed', 'Failed'),
    open: tr('common.open', 'Open'),

    cat_all: tr('rooms.cat.all', 'All'),
    cat_education: tr('rooms.cat.education', 'Education'),
    cat_travel: tr('rooms.cat.travel', 'Travel'),
    cat_business: tr('rooms.cat.business', 'Business'),
    cat_emergency: tr('rooms.cat.emergency', 'Emergency'),
    cat_community: tr('rooms.cat.community', 'Community'),
    cat_other: tr('rooms.cat.other', 'Other'),

    prompt_auth_code: tr('js.enter_6_digit_code', 'Enter a 6-digit code'),

    eligibility_level: tr('rooms.eligibility.level', 'Your room access level: Level {level}'),
    eligibility_cooldown_until: tr('rooms.eligibility.cooldown_until', 'Cooldown until {local} {utc} (you can’t join new rooms yet)'),
    stored_enforced_utc: tr('rooms.utc_title', 'Stored/enforced in UTC'),

    badge_level_type: tr('rooms.badge.level_type', 'LEVEL {level} · TYPE {type}'),
    badge_status_type: tr('rooms.badge.status_type', '{status} · TYPE {type}'),

    meta_amount: tr('rooms.meta.amount', 'Amount'),
    meta_period: tr('rooms.meta.period', 'Period'),
    meta_spots_remaining: tr('rooms.meta.spots_remaining', 'Spots remaining'),
    meta_starts: tr('rooms.meta.starts', 'Starts'),
    meta_state: tr('rooms.meta.state', 'State'),

    periodicity_weekly: tr('rooms.periodicity.weekly', 'Weekly'),
    periodicity_biweekly: tr('rooms.periodicity.biweekly', 'Bi-weekly'),
    periodicity_monthly: tr('rooms.periodicity.monthly', 'Monthly'),

    join_request: tr('rooms.action.request_join', 'Request to join'),
    restricted: tr('rooms.action.restricted', 'Restricted'),
    restricted_title: tr('rooms.action.restricted_title', 'You cannot join new rooms until {ts}'),
    requested: tr('rooms.action.requested', 'Requested'),
    in_your_rooms: tr('rooms.action.in_your_rooms', 'In your rooms'),
    already_in_room_title: tr('rooms.action.already_in_room_title', 'You already have a status in this room ({status}).'),
    join_request_sent: tr('rooms.msg.join_request_sent', 'Join request sent.'),

    err_goal_required: tr('rooms.err.goal_required', 'Goal is required.'),
    err_dates_required: tr('rooms.err.dates_required', 'Start date and reveal date are required.'),
    err_max_lt_min: tr('rooms.err.max_lt_min', 'Max participants must be >= min participants.'),
    err_reveal_after_start: tr('rooms.err.reveal_after_start', 'Reveal date must be after start date.'),

    no_rooms_yet: tr('rooms.msg.no_rooms_yet', 'No rooms yet.'),
    failed_to_load: tr('rooms.msg.failed_to_load', 'Failed to load.'),
    no_eligible_rooms: tr('rooms.msg.no_eligible_rooms', 'No eligible rooms found for this category.'),
    trust_level_extra: tr('rooms.msg.trust_level_extra', 'Your trust level is Level {level}.'),
    failed_to_load_rooms: tr('rooms.msg.failed_to_load_rooms', 'Failed to load rooms.'),

    room_created: tr('rooms.msg.room_created', 'Room created.'),
  };

  function periodicityLabel(k){
    if(k === 'weekly') return STR.periodicity_weekly;
    if(k === 'biweekly') return STR.periodicity_biweekly;
    if(k === 'monthly') return STR.periodicity_monthly;
    return String(k||'');
  }

  function apiUrl(url){
    const u = String(url || '');
    return u.startsWith('/') ? u.slice(1) : u;
  }

  async function get(url){
    const r = await fetch(apiUrl(url), { credentials: 'same-origin' });
    return r.json();
  }

  async function postCsrf(url, body){
    const r = await fetch(apiUrl(url), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (typeof CSRF === 'string' ? CSRF : '') },
      body: JSON.stringify(body || {}),
    });

    const j = await r.json().catch(() => null);
    if(j && j.error_code==='package_limit' && j.redirect_url){
      window.location.href = apiUrl(String(j.redirect_url));
      return j;
    }
    return j;
  }

  function esc(s){
    if(window.LS && typeof window.LS.esc === 'function') return window.LS.esc(s);
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function setMsg(id, text, ok){
    const el = document.getElementById(id);
    if(!el) return;
    el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
    el.textContent = String(text||'');
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

  function fmtLocal(ts){
    const d = parseUtcDate(ts);
    if(!d || isNaN(d.getTime())) return String(ts||'');
    if(window.LS && typeof window.LS.fmtLocal === 'function') return window.LS.fmtLocal(d);
    return d.toLocaleString();
  }

  function fmtUtc(ts){
    const d = parseUtcDate(ts);
    if(!d || isNaN(d.getTime())) return '';
    if(window.LS && typeof window.LS.fmtUtc === 'function') return window.LS.fmtUtc(d);
    return d.toUTCString();
  }

  function renderRoomSkeletons(n){
    let s='';
    for(let i=0;i<(n||4);i++) s += '<div class="room skel" style="height:132px;"></div>';
    return s;
  }

  let myRoomStatusById = Object.create(null);

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
      return window.LS.reauth(methods||{}, {post: postCsrf});
    }

    if(methods && methods.passkey && window.PublicKeyCredential){
      try{
        const begin = await postCsrf('api/webauthn.php', {action:'reauth_begin'});
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
          const fin = await postCsrf('api/webauthn.php', {
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
      const code = prompt(STR.prompt_auth_code);
      if(!code) return false;
      const r = await postCsrf('api/totp.php', {action:'reauth', code});
      return !!(r && r.success);
    }

    return false;
  }

  async function postStrong(url, body){
    let j = await postCsrf(url, body);
    if(j && !j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
      const ok = await ensureReauth(j.methods||{});
      if(!ok) return j;
      j = await postCsrf(url, body);
    }
    return j;
  }

  let currentCategory = '';
  let myTrustLevel = null;
  let myRestrictedUntil = '';

  function renderCategories(){
    const row = document.getElementById('cat-row');
    if(!row) return;

    const cats = [
      {k:'', t: STR.cat_all},
      {k:'education', t: STR.cat_education},
      {k:'travel', t: STR.cat_travel},
      {k:'business', t: STR.cat_business},
      {k:'emergency', t: STR.cat_emergency},
      {k:'community', t: STR.cat_community},
      {k:'other', t: STR.cat_other},
    ];

    row.innerHTML='';
    cats.forEach(c => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'btn btn-ghost btn-sm cat-btn' + ((c.k===currentCategory) ? ' sel' : '');
      b.textContent = c.t;
      b.onclick = () => {
        currentCategory = c.k;
        renderCategories();
        loadRooms();
      };
      row.appendChild(b);
    });
  }

  function updateEligibility(){
    const el = document.getElementById('eligibility');
    if(!el) return;

    const bits = [];
    if(myTrustLevel !== null){
      bits.push(tf('rooms.eligibility.level', {level: myTrustLevel}, `Your room access level: Level ${esc(myTrustLevel)}`));
    }
    if(myRestrictedUntil){
      const local = '<b>' + esc(fmtLocal(myRestrictedUntil)) + '</b>';
      const utc = '<span class="utc-pill" title="' + esc(STR.stored_enforced_utc) + '">' + esc(fmtUtc(myRestrictedUntil)) + '</span>';
      bits.push(tf('rooms.eligibility.cooldown_until', {local, utc}, `Cooldown until ${local} ${utc} (you can’t join new rooms yet)`));
    }

    el.innerHTML = bits.join(' · ');
  }

  function buildRoomCard(r){
    const el = document.createElement('div');
    el.className = 'room';

    const top = document.createElement('div');
    top.className = 'room-top';

    const goal = document.createElement('div');
    goal.className = 'room-goal';
    goal.textContent = r.goal || '';

    const badge = document.createElement('div');
    badge.className = 'badge';
    badge.textContent = tf('rooms.badge.level_type', {level: r.required_level, type: r.saving_type}, `LEVEL ${r.required_level} · TYPE ${r.saving_type}`);

    top.appendChild(goal);
    top.appendChild(badge);

    const startLocal = fmtLocal(r.start_at);
    const startUtc = fmtUtc(r.start_at);

    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.innerHTML = `${esc(STR.meta_amount)}: <b>${esc(r.participation_amount)}</b><br>${esc(STR.meta_period)}: <b>${esc(periodicityLabel(r.periodicity))}</b><br>${esc(STR.meta_spots_remaining)}: <b>${esc(r.spots_remaining)}</b><br>${esc(STR.meta_starts)}: <b>${esc(startLocal)}</b> <span class="utc-pill" title="${esc(STR.stored_enforced_utc)}">${esc(startUtc)}</span>`;

    const actions = document.createElement('div');
    actions.className = 'actions';

    const open = document.createElement('a');
    open.className = 'btn btn-ghost btn-sm';
    open.href = 'room.php?id=' + encodeURIComponent(r.id);
    open.textContent = STR.open;

    const join = document.createElement('button');
    join.className = 'btn btn-primary btn-sm';
    join.type = 'button';
    join.textContent = STR.join_request;

    const myStatus = myRoomStatusById[String(r.id)] || '';
    if(myStatus && myStatus !== 'declined'){
      join.className = 'btn btn-ghost btn-sm';
      join.disabled = true;
      join.textContent = (myStatus === 'pending') ? STR.requested : STR.in_your_rooms;
      join.title = tf('rooms.action.already_in_room_title', {status: myStatus}, STR.already_in_room_title.replace('{status}', myStatus));
    } else if(myRestrictedUntil){
      join.className = 'btn btn-ghost btn-sm';
      join.disabled = true;
      join.textContent = STR.restricted;
      join.title = tf('rooms.action.restricted_title', {ts: fmtLocal(myRestrictedUntil)}, `You cannot join new rooms until ${fmtLocal(myRestrictedUntil)}`);
    } else {
      join.onclick = async () => {
        join.disabled = true;
        try{
          const res = await postStrong('/api/rooms.php', {action:'request_join', room_id: r.id});
          if(!res || !res.success) throw new Error((res && res.error) ? res.error : STR.failed);
          myRoomStatusById[String(r.id)] = 'pending';
          join.className = 'btn btn-ghost btn-sm';
          join.textContent = STR.requested;
          setMsg('rooms-msg', STR.join_request_sent, true);
          await loadMyRooms();
        }catch(e){
          setMsg('rooms-msg', e && e.message ? e.message : STR.failed, false);
        }finally{
          join.disabled = false;
        }
      };
    }

    actions.appendChild(open);
    actions.appendChild(join);

    el.appendChild(top);
    el.appendChild(meta);
    el.appendChild(actions);
    return el;
  }

  function buildMyRoomCard(r){
    const el = document.createElement('div');
    el.className = 'room';

    const top = document.createElement('div');
    top.className = 'room-top';

    const goal = document.createElement('div');
    goal.className = 'room-goal';
    goal.textContent = r.goal || '';

    const badge = document.createElement('div');
    badge.className = 'badge';
    badge.textContent = tf('rooms.badge.status_type', {status: String((r.my_status||'').toUpperCase()), type: r.saving_type}, `${String((r.my_status||'').toUpperCase())} · TYPE ${r.saving_type}`);

    top.appendChild(goal);
    top.appendChild(badge);

    const startLocal = fmtLocal(r.start_at);
    const startUtc = fmtUtc(r.start_at);

    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.innerHTML = `${esc(STR.meta_amount)}: <b>${esc(r.participation_amount)}</b><br>${esc(STR.meta_period)}: <b>${esc(periodicityLabel(r.periodicity))}</b><br>${esc(STR.meta_state)}: <b>${esc(r.room_state)} / ${esc(r.lobby_state)}</b><br>${esc(STR.meta_starts)}: <b>${esc(startLocal)}</b> <span class="utc-pill" title="${esc(STR.stored_enforced_utc)}">${esc(startUtc)}</span>`;

    const actions = document.createElement('div');
    actions.className = 'actions';

    const open = document.createElement('a');
    open.className = 'btn btn-ghost btn-sm';
    open.href = 'room.php?id=' + encodeURIComponent(r.id);
    open.textContent = STR.open;

    actions.appendChild(open);

    el.appendChild(top);
    el.appendChild(meta);
    el.appendChild(actions);
    return el;
  }

  async function loadMyRooms(){
    const wrap = document.getElementById('myrooms-wrap');
    const msgEl = document.getElementById('myrooms-msg');

    if(wrap) wrap.innerHTML = renderRoomSkeletons(3);
    if(msgEl) msgEl.className = 'msg';

    try{
      const r = await get('/api/rooms.php?action=my_rooms');
      if(!r || !r.success) throw new Error((r && r.error) ? r.error : STR.failed);

      const rooms = r.rooms || [];
      myRoomStatusById = Object.create(null);
      rooms.forEach(x => {
        myRoomStatusById[String(x.id)] = String(x.my_status||'');
      });

      if(!wrap) return rooms;

      if(!rooms.length){
        wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">' + esc(STR.no_rooms_yet) + '</div>';
        return rooms;
      }

      wrap.innerHTML = '';
      rooms.forEach(x => wrap.appendChild(buildMyRoomCard(x)));

      return rooms;

    }catch(e){
      myRoomStatusById = Object.create(null);
      if(wrap){
        wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">' + esc(STR.failed_to_load) + '</div>';
      }
      setMsg('myrooms-msg', e && e.message ? e.message : STR.failed, false);
      return [];
    }
  }

  async function loadRooms(){
    const wrap = document.getElementById('rooms-wrap');
    if(!wrap) return;

    wrap.innerHTML = renderRoomSkeletons(4);

    const msgEl = document.getElementById('rooms-msg');
    if(msgEl) msgEl.className = 'msg';

    try{
      const qs = new URLSearchParams({action:'discover'});
      if(currentCategory) qs.set('category', currentCategory);
      const r = await get('/api/rooms.php?' + qs.toString());
      if(!r || !r.success) throw new Error((r && r.error) ? r.error : STR.failed);

      if(typeof r.your_trust_level !== 'undefined' && r.your_trust_level !== null){
        const lvl = parseInt(String(r.your_trust_level), 10);
        myTrustLevel = (lvl && lvl > 0) ? lvl : 1;
      }
      myRestrictedUntil = r.restricted_until ? String(r.restricted_until) : '';
      updateEligibility();

      const rooms = r.rooms || [];
      if(!rooms.length){
        const extra = myTrustLevel !== null ? (' ' + tf('rooms.msg.trust_level_extra', {level: myTrustLevel}, `Your trust level is Level ${String(myTrustLevel)}.`)) : '';
        wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">' + esc(STR.no_eligible_rooms) + esc(extra) + '</div>';
        return;
      }

      wrap.innerHTML = '';
      rooms.forEach(x => wrap.appendChild(buildRoomCard(x)));

    }catch(e){
      wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;">' + esc(STR.failed_to_load_rooms) + '</div>';
      setMsg('rooms-msg', e && e.message ? e.message : STR.failed, false);
    }
  }

  function toServerDateTimeLocal(v){
    // datetime-local gives local time. Convert to an unambiguous UTC instant.
    // Avoid Date("YYYY-MM-DDTHH:MM") parsing inconsistencies across browsers.
    const s = String(v||'').trim();
    if(!s) return '';

    const m = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
    if(!m) return '';

    const y = parseInt(m[1], 10);
    const mo = parseInt(m[2], 10) - 1;
    const d0 = parseInt(m[3], 10);
    const h = parseInt(m[4], 10);
    const mi = parseInt(m[5], 10);
    const sec = parseInt(m[6] || '0', 10);

    const d = new Date(y, mo, d0, h, mi, sec, 0);
    if(isNaN(d.getTime())) return '';
    return d.toISOString();
  }

  async function createRoom(){
    const msgEl = document.getElementById('cr-msg');
    if(msgEl) msgEl.className = 'msg';

    const goalEl = document.getElementById('cr-goal');
    if(!goalEl) return;

    const goal = goalEl.value.trim();
    const purpose_category = (document.getElementById('cr-purpose') || {}).value;
    const saving_type = (document.getElementById('cr-type') || {}).value;
    const visibility = (document.getElementById('cr-vis') || {}).value;
    const required_trust_level = parseInt(((document.getElementById('cr-level') || {}).value)||'1',10);
    const min_participants = parseInt(((document.getElementById('cr-min') || {}).value)||'2',10);
    const max_participants = parseInt(((document.getElementById('cr-max') || {}).value)||'0',10);
    const participation_amount = String(((document.getElementById('cr-amt') || {}).value)||'').trim();
    const periodicity = (document.getElementById('cr-per') || {}).value;
    const start_at = toServerDateTimeLocal(((document.getElementById('cr-start') || {}).value)||'');
    const reveal_at = toServerDateTimeLocal(((document.getElementById('cr-reveal') || {}).value)||'');
    const privacy_mode = (document.getElementById('cr-privacy') || {}).checked ? 1 : 0;
    const escrow_policy = (document.getElementById('cr-escrow') || {}).value;

    const destination_account_type = (document.getElementById('cr-dest-type') || {}).value;
    const destination_account_id = parseInt(((document.getElementById('cr-dest-account') || {}).value)||'0',10);

    if(!goal){
      setMsg('cr-msg', STR.err_goal_required, false);
      return;
    }
    if(!start_at || !reveal_at){
      setMsg('cr-msg', STR.err_dates_required, false);
      return;
    }
    if(max_participants < min_participants){
      setMsg('cr-msg', STR.err_max_lt_min, false);
      return;
    }

    const startTs = Date.parse(start_at);
    const revealTs = Date.parse(reveal_at);
    if(startTs && revealTs && revealTs <= startTs){
      setMsg('cr-msg', STR.err_reveal_after_start, false);
      return;
    }

    try{
      const payload = {
        action:'create_room',
        goal_text: goal,
        purpose_category,
        saving_type,
        visibility,
        required_trust_level,
        min_participants,
        max_participants,
        participation_amount,
        periodicity,
        start_at,
        reveal_at,
        privacy_mode,
        escrow_policy,
      };

      if(destination_account_type){
        payload.destination_account_type = destination_account_type;
      }
      if(destination_account_id > 0){
        payload.destination_account_id = destination_account_id;
      }

      const r = await postStrong('/api/rooms.php', payload);

      if(!r || !r.success) throw new Error((r && r.error) ? r.error : STR.failed);

      setMsg('cr-msg', STR.room_created, true);
      window.location.href = 'room.php?id=' + encodeURIComponent(r.room_id);

    }catch(e){
      setMsg('cr-msg', e && e.message ? e.message : STR.failed, false);
    }
  }

  async function initDiscover(){
    renderCategories();
    await loadMyRooms();
    await loadRooms();
  }

  async function initMyRooms(){
    await loadMyRooms();
  }

  let createDestAccounts = [];
  let createDestInitDone = false;

  function maskTail(s, n){
    const str = String(s||'').trim();
    if(!str) return '';
    const keep = Math.max(2, Math.min(10, (n||4)));
    const tail = str.slice(-keep);
    return '••••' + tail;
  }

  function buildCreateDestOptions(){
    const typeSel = document.getElementById('cr-dest-type');
    const acctSel = document.getElementById('cr-dest-account');
    if(!typeSel || !acctSel) return;

    const firstOpt = acctSel.querySelector('option');
    const autoText = firstOpt ? String(firstOpt.textContent||'Auto select') : 'Auto select';

    const t = String(typeSel.value||'');

    acctSel.innerHTML = '';

    const opt0 = document.createElement('option');
    opt0.value = '';
    opt0.textContent = autoText;
    acctSel.appendChild(opt0);

    (createDestAccounts||[]).forEach(a => {
      if(!a) return;
      if(t && String(a.account_type||'') !== t) return;
      const opt = document.createElement('option');
      opt.value = String(a.id||'');
      opt.textContent = a.summary || a.display_label || (String(a.account_type||'') + ' #' + String(a.id||''));
      acctSel.appendChild(opt);
    });
  }

  async function initCreateDestAccounts(){
    const typeSel = document.getElementById('cr-dest-type');
    const acctSel = document.getElementById('cr-dest-account');
    if(!typeSel || !acctSel || createDestInitDone) return;
    createDestInitDone = true;

    typeSel.addEventListener('change', buildCreateDestOptions);

    try{
      const r = await get('/api/rooms.php?action=destination_accounts');
      if(r && r.success){
        createDestAccounts = Array.isArray(r.accounts) ? r.accounts : [];

        // Back-compat: if the server did not return a summary, build a minimal one.
        createDestAccounts = createDestAccounts.map(a => {
          if(a && !a.summary){
            if(a.account_type === 'mobile_money' && a.mobile_money_number){
              a.summary = (a.display_label ? (a.display_label + ' — ') : '') + 'Mobile money ' + maskTail(a.mobile_money_number, 4);
            } else if(a.account_type === 'bank' && (a.bank_name || a.bank_account_number)){
              a.summary = (a.display_label ? (a.display_label + ' — ') : '') + (a.bank_name ? (a.bank_name + ' ') : 'Bank ') + maskTail(a.bank_account_number, 4);
            } else if(a.account_type === 'crypto_wallet' && (a.crypto_address || a.crypto_wallet_address)){
              const addr = a.crypto_address || a.crypto_wallet_address;
              const net = a.crypto_network || a.crypto_wallet_network;
              const head = String(addr||'').slice(0, 6);
              const tail = String(addr||'').slice(-4);
              a.summary = (a.display_label ? (a.display_label + ' — ') : '') + (net ? (net + ' ') : '') + head + '…' + tail;
            }
          }
          return a;
        });
      }
    }catch(e){
      // best effort
    }

    buildCreateDestOptions();
  }

  function initCreate(){
    initCreateDestAccounts();
  }

  window.Rooms = window.Rooms || {};
  window.Rooms.initDiscover = window.Rooms.initDiscover || initDiscover;
  window.Rooms.initMyRooms = window.Rooms.initMyRooms || initMyRooms;
  window.Rooms.initCreate = window.Rooms.initCreate || initCreate;
  window.Rooms.loadRooms = window.Rooms.loadRooms || loadRooms;
  window.Rooms.loadMyRooms = window.Rooms.loadMyRooms || loadMyRooms;
  window.Rooms.createRoom = window.Rooms.createRoom || createRoom;

  window.createRoom = window.createRoom || createRoom;
})();
