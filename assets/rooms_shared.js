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
    meta_next: tr('rooms.meta.next', 'Next'),

    next_awaiting_approval: tr('rooms.next.awaiting_approval', 'Awaiting approval'),
    next_up_to_date: tr('rooms.next.up_to_date', 'Up to date'),
    next_proof_due_fmt: tr('rooms.next.proof_due_fmt', 'Proof due {ts}'),
    next_proof_grace_due_fmt: tr('rooms.next.proof_grace_due_fmt', 'Proof due (grace) {ts}'),
    next_proof_missed_fmt: tr('rooms.next.proof_missed_fmt', 'Proof missed {ts}'),

    periodicity_weekly: tr('rooms.periodicity.weekly', 'Weekly'),
    periodicity_biweekly: tr('rooms.periodicity.biweekly', 'Bi-weekly'),
    periodicity_monthly: tr('rooms.periodicity.monthly', 'Monthly'),

    join_request: tr('rooms.action.request_join', 'Request to join'),
    restricted: tr('rooms.action.restricted', 'Restricted'),
    restricted_title: tr('rooms.action.restricted_title', 'You cannot join new rooms until {ts}'),
    requested: tr('rooms.action.requested', 'Requested'),
    in_your_rooms: tr('rooms.action.in_your_rooms', 'In your rooms'),
    already_in_room_title: tr('rooms.action.already_in_room_title', 'You already have a status in this room ({status}).'),
    locked: tr('rooms.action.locked', 'Locked'),
    locked_title: tr('rooms.action.locked_title', 'Join requests are closed (lobby locked).'),
    full: tr('rooms.action.full', 'Full'),
    full_title: tr('rooms.action.full_title', 'No spots remaining.'),
    join_request_sent: tr('rooms.msg.join_request_sent', 'Join request sent.'),

    err_goal_required: tr('rooms.err.goal_required', 'Goal is required.'),
    err_start_required: tr('rooms.err.start_required', 'Start date is required.'),
    err_reveal_required: tr('rooms.err.reveal_required', 'Reveal date is required.'),
    err_destination_required: tr('rooms.err.destination_required', 'Destination account is required.'),
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

  async function readJson(r){
    const txt = await r.text();
    if(!txt) return null;
    try{
      return JSON.parse(txt);
    }catch(e){
      // Surface the actual HTML/PHP error in console for debugging.
      try{ console.error('Non-JSON response from API:', txt); }catch(_){}
      throw new Error('Server returned an invalid response.');
    }
  }

  async function get(url){
    const r = await fetch(apiUrl(url), { credentials: 'same-origin' });
    return readJson(r);
  }

  async function postCsrf(url, body){
    const r = await fetch(apiUrl(url), {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': (typeof CSRF === 'string' ? CSRF : '') },
      body: JSON.stringify(body || {}),
    });

    const j = await readJson(r).catch(() => null);
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
      const msg = STR.prompt_auth_code;
      let code = null;

      if(window.LS && typeof window.LS.prompt === 'function'){
        code = await window.LS.prompt({
          title: tr('common.confirm', 'Confirm'),
          message: msg,
          placeholder: '123456',
          inputMode: 'numeric',
          validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
        });
      } else if (typeof window.uiPrompt === 'function'){
        code = await window.uiPrompt({
          title: tr('common.confirm', 'Confirm'),
          message: msg,
          placeholder: '123456',
          inputMode: 'numeric',
          validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
        });
      }

      const c = String(code||'').trim();
      if(!c) return false;
      const r = await postCsrf('api/totp.php', {action:'reauth', code: c});
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

  function roomStartMs(r){
    const d = parseUtcDate(r && r.start_at);
    const ms = d && !isNaN(d.getTime()) ? d.getTime() : 0;
    return ms || 0;
  }

  function stableSort(arr, cmp){
    return (arr || []).map((v, i) => ({v, i}))
      .sort((a, b) => {
        const c = cmp(a.v, b.v);
        return c || (a.i - b.i);
      })
      .map(x => x.v);
  }

  function discoverRoomRank(r){
    const st = myRoomStatusById[String((r && r.id) || '')] || '';
    const spots = parseInt(String((r && r.spots_remaining) || ''), 10);
    const hasSpots = isNaN(spots) ? true : (spots > 0);

    const lobby = String((r && r.lobby_state) || 'open');
    const lobbyOpen = (lobby === 'open');

    // Discover hierarchy (rooms.php):
    //  0) Rooms you're already in (approved/active/etc)
    //  1) Rooms you've requested (pending)
    //  2) Joinable rooms (spots available + lobby open)
    //  3) Lobby locked (viewable, but join disabled)
    //  4) Joinable but you're globally restricted
    //  5) Full rooms
    if(st && st !== 'declined') return (st === 'pending') ? 1 : 0;
    if(!hasSpots) return 5;
    if(!lobbyOpen) return 3;
    if(myRestrictedUntil) return 4;
    return 2;
  }

  function sortDiscoverRooms(rooms){
    return stableSort(rooms, (a, b) => {
      const ra = discoverRoomRank(a);
      const rb = discoverRoomRank(b);
      if(ra !== rb) return ra - rb;

      const sa = roomStartMs(a);
      const sb = roomStartMs(b);
      if(sa !== sb) return sa - sb;

      const la = parseInt(String((a && a.required_level) || '0'), 10) || 0;
      const lb = parseInt(String((b && b.required_level) || '0'), 10) || 0;
      if(la !== lb) return la - lb;

      const pa = parseInt(String((a && a.spots_remaining) || '0'), 10) || 0;
      const pb = parseInt(String((b && b.spots_remaining) || '0'), 10) || 0;
      if(pa !== pb) return pb - pa;

      const ga = String((a && a.goal) || '');
      const gb = String((b && b.goal) || '');
      return ga.localeCompare(gb);
    });
  }

  function myRoomRank(r){
    const st = String((r && r.my_status) || '');
    if(st === 'active') return 0;
    if(st === 'approved') return 1;
    if(st === 'pending') return 2;
    if(st === 'completed') return 3;
    if(st === 'exited_poststart' || st === 'exited_prestart' || st === 'removed') return 4;
    return 5;
  }

  function sortMyRooms(rooms){
    return stableSort(rooms, (a, b) => {
      const ra = myRoomRank(a);
      const rb = myRoomRank(b);
      if(ra !== rb) return ra - rb;

      const ma = (a && a.is_maker) ? 0 : 1;
      const mb = (b && b.is_maker) ? 0 : 1;
      if(ma !== mb) return ma - mb;

      const sa = roomStartMs(a);
      const sb = roomStartMs(b);
      const dir = (ra <= 2) ? 1 : -1;
      if(sa !== sb) return (sa - sb) * dir;

      const ga = String((a && a.goal) || '');
      const gb = String((b && b.goal) || '');
      return ga.localeCompare(gb);
    });
  }

  function buildRoomCard(r){
    const el = document.createElement('div');
    el.className = 'room room-card';
    el.dataset.roomId = String(r.id || '');

    // ── Header (primary hierarchy)
    const head = document.createElement('div');
    head.className = 'room-head';

    const title = document.createElement('div');
    title.className = 'room-title';

    const goal = document.createElement('div');
    goal.className = 'room-goal';
    goal.textContent = r.goal || '';

    title.appendChild(goal);

    const badges = document.createElement('div');
    badges.className = 'room-badges';

    const badge = document.createElement('div');
    badge.className = 'badge';
    badge.textContent = tf('rooms.badge.level_type', {level: r.required_level, type: r.saving_type}, `LEVEL ${r.required_level} · TYPE ${r.saving_type}`);

    badges.appendChild(badge);

    head.appendChild(title);
    head.appendChild(badges);

    // ── Meta (secondary hierarchy)
    const startLocal = fmtLocal(r.start_at);
    const startUtc = fmtUtc(r.start_at);

    const meta = document.createElement('div');
    meta.className = 'room-meta meta';

    const grid = document.createElement('div');
    grid.className = 'meta-grid';

    function addMetaItem(label, valueHtml){
      const item = document.createElement('div');
      item.className = 'meta-item';

      const k = document.createElement('div');
      k.className = 'meta-k';
      k.textContent = String(label || '');

      const v = document.createElement('div');
      v.className = 'meta-v';
      v.innerHTML = valueHtml;

      item.appendChild(k);
      item.appendChild(v);
      grid.appendChild(item);
    }

    // Meta order by hierarchy: contribution info + schedule first.
    addMetaItem(STR.meta_amount, esc(r.participation_amount));
    addMetaItem(STR.meta_period, esc(periodicityLabel(r.periodicity)));
    addMetaItem(STR.meta_starts, esc(startLocal) + ' <span class="utc-pill" title="' + esc(STR.stored_enforced_utc) + '">' + esc(startUtc) + '</span>');
    addMetaItem(STR.meta_spots_remaining, esc(r.spots_remaining));

    meta.appendChild(grid);

    // ── Actions
    const actions = document.createElement('div');
    actions.className = 'room-actions actions';

    const open = document.createElement('a');
    open.className = 'btn btn-ghost btn-sm';
    open.href = 'room.php?id=' + encodeURIComponent(r.id);
    open.textContent = STR.open;

    const join = document.createElement('button');
    join.className = 'btn btn-primary btn-sm';
    join.type = 'button';
    join.textContent = STR.join_request;

    const myStatus = myRoomStatusById[String(r.id)] || '';
    const spots = parseInt(String(r.spots_remaining||''), 10);
    const hasSpots = isNaN(spots) ? true : (spots > 0);
    const lobby = String(r.lobby_state||'open');

    if(myStatus && myStatus !== 'declined'){
      join.className = 'btn btn-ghost btn-sm';
      join.disabled = true;
      join.textContent = (myStatus === 'pending') ? STR.requested : STR.in_your_rooms;
      join.title = tf('rooms.action.already_in_room_title', {status: myStatus}, STR.already_in_room_title.replace('{status}', myStatus));
    } else if(!hasSpots){
      join.className = 'btn btn-ghost btn-sm';
      join.disabled = true;
      join.textContent = STR.full;
      join.title = STR.full_title;
    } else if(lobby !== 'open'){
      join.className = 'btn btn-ghost btn-sm';
      join.disabled = true;
      join.textContent = STR.locked;
      join.title = STR.locked_title;
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

    el.appendChild(head);
    el.appendChild(meta);
    el.appendChild(actions);
    return el;
  }

  function prettyRoomStateCombo(r){
    const roomState = String((r && r.room_state) || '');
    const lobbyState = String((r && r.lobby_state) || '');

    if(roomState === 'active') return tr('room.state.active', 'Active');
    if(roomState === 'swap_window') return tr('room.state.swap_window', 'Swap window');
    if(roomState === 'closed') return tr('room.state.closed', 'Closed');
    if(roomState === 'cancelled') return tr('room.state.cancelled', 'Cancelled');

    if(lobbyState === 'locked') return tr('room.state.lobby_locked', 'Lobby (locked)');
    if(lobbyState === 'open') return tr('room.state.lobby_open', 'Lobby (open)');

    const bits = [];
    if(roomState) bits.push(roomState);
    if(lobbyState) bits.push(lobbyState);
    return bits.join(' / ') || '—';
  }

  function buildMyRoomCard(r){
    const el = document.createElement('div');
    el.className = 'room';

    // ── Header
    const head = document.createElement('div');
    head.className = 'room-head';

    const title = document.createElement('div');
    title.className = 'room-title';
    title.textContent = String(r.goal || '');

    const badges = document.createElement('div');
    badges.className = 'room-badges';

    badges.innerHTML = '';
    badges.appendChild(makeStatusBadge(r));
    badges.appendChild(makeTypeBadge(r));

    if(r.visibility && r.visibility !== 'public'){
      badges.appendChild(makeBadge(prettyVisibility(r.visibility)));
    }

    if(r.is_maker){
      badges.appendChild(makeBadge('maker'));
    }

    head.appendChild(title);
    head.appendChild(badges);

    // ── Meta
    const meta = document.createElement('div');
    meta.className = 'room-meta';

    const grid = document.createElement('div');
    grid.className = 'meta-grid';

    function addMetaItem(label, valueHtml){
      const item = document.createElement('div');
      item.className = 'meta-item';

      const k = document.createElement('div');
      k.className = 'meta-k';
      k.textContent = String(label || '');

      const v = document.createElement('div');
      v.className = 'meta-v';
      v.innerHTML = valueHtml;

      item.appendChild(k);
      item.appendChild(v);
      grid.appendChild(item);
    }

    function nextHint(){
      const myStatus = String(r.my_status||'');
      const roomState = String(r.room_state||'');

      if(myStatus === 'pending') return STR.next_awaiting_approval;

      if(roomState === 'active' && myStatus === 'active' && r.active_cycle_due_at){
        const cycStatus = String(r.active_cycle_status||'');
        const due = fmtLocal(r.active_cycle_due_at);
        const grace = r.active_cycle_grace_ends_at ? fmtLocal(r.active_cycle_grace_ends_at) : '';
        const deadline = (cycStatus === 'grace' && grace) ? grace : due;

        const st = String(r.my_active_cycle_contribution_status||'');
        if(!st || st === 'unpaid'){
          return (cycStatus === 'grace')
            ? tf('rooms.next.proof_grace_due_fmt', {ts: deadline}, 'Proof due (grace) ' + deadline)
            : tf('rooms.next.proof_due_fmt', {ts: deadline}, 'Proof due ' + deadline);
        }
        if(st === 'missed'){
          return tf('rooms.next.proof_missed_fmt', {ts: deadline}, 'Proof missed ' + deadline);
        }
        return STR.next_up_to_date;
      }

      return '';
    }

    const nextTxt = nextHint();

    // Meta order by hierarchy: current room state + next required action first.
    addMetaItem(STR.meta_state, esc(prettyRoomStateCombo(r)));
    if(nextTxt) addMetaItem(STR.meta_next, esc(nextTxt));
    addMetaItem(STR.meta_starts, esc(startLocal) + ' <span class="utc-pill" title="' + esc(STR.stored_enforced_utc) + '">' + esc(startUtc) + '</span>');
    addMetaItem(STR.meta_amount, esc(r.participation_amount));
    addMetaItem(STR.meta_period, esc(periodicityLabel(r.periodicity)));

    meta.appendChild(grid);

    // ── Actions
    const actions = document.createElement('div');
    actions.className = 'room-actions actions';

    const open = document.createElement('a');
    open.className = 'btn btn-ghost btn-sm';
    open.href = 'room.php?id=' + encodeURIComponent(r.id);
    open.textContent = STR.open;

    actions.appendChild(open);

    el.appendChild(head);
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

      const sorted = sortMyRooms(rooms);

      if(!wrap) return sorted;

      if(!sorted.length){
        wrap.innerHTML = '<div style="color:var(--muted);font-size:12px;line-height:1.6;">' + esc(STR.no_rooms_yet) + '</div>';
        return sorted;
      }

      wrap.innerHTML = '';
      sorted.forEach(x => wrap.appendChild(buildMyRoomCard(x)));

      return sorted;

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

      const sorted = sortDiscoverRooms(rooms);

      wrap.innerHTML = '';
      sorted.forEach(x => wrap.appendChild(buildRoomCard(x)));

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

    // Type B rooms use server time as the "created at"/start marker; we still send a value for API compatibility.
    const start_at = (saving_type === 'A')
      ? toServerDateTimeLocal(((document.getElementById('cr-start') || {}).value)||'')
      : (new Date()).toISOString();

    const reveal_at = (saving_type === 'A')
      ? toServerDateTimeLocal(((document.getElementById('cr-reveal') || {}).value)||'')
      : '';

    const privacy_mode = (document.getElementById('cr-privacy') || {}).checked ? 1 : 0;

    const escrowEl = document.getElementById('cr-escrow');
    const escrow_policy = escrowEl ? String(escrowEl.value||'') : '';

    const destination_account_type = (document.getElementById('cr-dest-type') || {}).value;
    const destination_account_id = parseInt(((document.getElementById('cr-dest-account') || {}).value)||'0',10);

    if(!goal){
      setMsg('cr-msg', STR.err_goal_required, false);
      return;
    }
    if(saving_type === 'A' && !start_at){
      setMsg('cr-msg', STR.err_start_required, false);
      return;
    }
    if(saving_type === 'A' && !reveal_at){
      setMsg('cr-msg', STR.err_reveal_required, false);
      return;
    }
    if(destination_account_id <= 0){
      setMsg('cr-msg', STR.err_destination_required, false);
      return;
    }
    if(max_participants < min_participants){
      setMsg('cr-msg', STR.err_max_lt_min, false);
      return;
    }

    if(saving_type === 'A'){
      const startTs = Date.parse(start_at);
      const revealTs = Date.parse(reveal_at);
      if(startTs && revealTs && revealTs <= startTs){
        setMsg('cr-msg', STR.err_reveal_after_start, false);
        return;
      }
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
        privacy_mode,
        destination_account_id,
      };

      if(saving_type === 'A'){
        payload.reveal_at = reveal_at;
      }

      if(destination_account_type){
        payload.destination_account_type = destination_account_type;
      }

      if(escrow_policy){
        payload.escrow_policy = escrow_policy;
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

  function destAccountSummary(a){
    if(!a) return '';

    const type = String(a.account_type||'');
    const label = a.display_label ? String(a.display_label) : '';

    let core = '';

    if(type === 'mobile_money'){
      const masked = a.mobile_money_masked ? String(a.mobile_money_masked) : '';
      core = masked ? tf('rooms.destination_account.summary.mobile_money', {masked}, `Mobile money ${masked}`)
                    : tr('rooms.destination_account.summary.mobile_money_short', 'Mobile money');

    }else if(type === 'bank'){
      const bankName = a.bank_name ? String(a.bank_name) : '';
      const masked = a.bank_account_masked ? String(a.bank_account_masked) : '';

      if(bankName && masked){
        core = tf('rooms.destination_account.summary.bank_named', {bank: bankName, masked}, `${bankName} ${masked}`);
      }else if(masked){
        core = tf('rooms.destination_account.summary.bank', {masked}, `Bank ${masked}`);
      }else if(bankName){
        core = bankName;
      }else{
        core = tr('rooms.destination_account.summary.bank_short', 'Bank');
      }

    }else if(type === 'crypto_wallet'){
      const net = a.crypto_network ? String(a.crypto_network) : '';
      const addr = a.crypto_address_masked ? String(a.crypto_address_masked) : '';

      if(net && addr){
        core = tf('rooms.destination_account.summary.crypto_wallet_with_network', {network: net, addr}, `Crypto wallet (${net}) ${addr}`);
      }else if(net){
        core = tf('rooms.destination_account.summary.crypto_wallet_with_network_no_addr', {network: net}, `Crypto wallet (${net})`);
      }else if(addr){
        core = tf('rooms.destination_account.summary.crypto_wallet', {addr}, `Crypto wallet ${addr}`);
      }else{
        core = tr('rooms.destination_account.summary.crypto_wallet_no_addr', 'Crypto wallet');
      }

    }else{
      core = type ? type.toUpperCase() : '';
    }

    if(label) return label + ' — ' + core;
    return core;
  }

  function buildCreateDestOptions(){
    const typeSel = document.getElementById('cr-dest-type');
    const acctSel = document.getElementById('cr-dest-account');
    if(!typeSel || !acctSel) return;

    const curVal = String(acctSel.value||'');

    const firstOpt = acctSel.querySelector('option');
    const placeholderText = firstOpt ? String(firstOpt.textContent||'Select an account') : 'Select an account';

    const t = String(typeSel.value||'');

    acctSel.innerHTML = '';

    const opt0 = document.createElement('option');
    opt0.value = '';
    opt0.textContent = placeholderText;
    opt0.disabled = true;
    acctSel.appendChild(opt0);

    (createDestAccounts||[]).forEach(a => {
      if(!a) return;
      if(t && String(a.account_type||'') !== t) return;
      const opt = document.createElement('option');
      opt.value = String(a.id||'');
      opt.textContent = destAccountSummary(a) || a.display_label || (String(a.account_type||'') + ' #' + String(a.id||''));
      acctSel.appendChild(opt);
    });

    // Restore selection if still available.
    let ok = false;
    if(curVal){
      Array.from(acctSel.options||[]).forEach(o => {
        if(String(o.value||'') === curVal) ok = true;
      });
    }
    acctSel.value = ok ? curVal : '';
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
      }
    }catch(e){
      // best effort
    }

    buildCreateDestOptions();
  }

  function pad2(n){
    const x = parseInt(String(n||'0'), 10) || 0;
    return (x < 10 ? '0' : '') + String(x);
  }

  function toDatetimeLocalValue(d){
    if(!d || isNaN(d.getTime())) return '';
    return d.getFullYear() + '-' + pad2(d.getMonth()+1) + '-' + pad2(d.getDate()) + 'T' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }

  function computeTypeBExampleFirstTurnDate(now, periodicity){
    const d = new Date(now.getTime());

    // Swap window is mandatory and lasts at least 24 hours.
    d.setHours(d.getHours() + 24);

    // First turn opens one full period after swap closes.
    if(periodicity === 'biweekly'){
      d.setDate(d.getDate() + 14);
    }else if(periodicity === 'monthly'){
      d.setMonth(d.getMonth() + 1);
    }else{
      d.setDate(d.getDate() + 7);
    }

    return d;
  }

  function updateCreateRevealMode(){
    const typeSel = document.getElementById('cr-type');
    const perSel = document.getElementById('cr-per');
    const startEl = document.getElementById('cr-start');
    const startLabelEl = document.getElementById('cr-start-label');
    const startFieldEl = document.getElementById('cr-start-field');
    const revealEl = document.getElementById('cr-reveal');
    const revealFieldEl = document.getElementById('cr-reveal-field');
    const hintEl = document.getElementById('cr-reveal-hint');
    const scheduleHintEl = document.getElementById('cr-typeb-schedule-hint');
    if(!typeSel || !perSel || !startEl) return;

    const t = String(typeSel.value||'');

    if(startLabelEl && !startLabelEl.dataset.origText){
      startLabelEl.dataset.origText = String(startLabelEl.textContent||'');
    }

    if(t === 'B'){
      // Type B starts "now" conceptually; the real activation happens after min participants is reached
      // and after the mandatory 24h swap window.
      if(startLabelEl){
        startLabelEl.textContent = tr('rooms.field.created_at', 'Created at');
      }

      const now = new Date();
      startEl.value = toDatetimeLocalValue(now);
      startEl.readOnly = true;
      startEl.disabled = true;

      if(revealFieldEl) revealFieldEl.style.display = 'none';
      if(hintEl) hintEl.style.display = 'none';

      if(scheduleHintEl){
        const ex = computeTypeBExampleFirstTurnDate(now, String(perSel.value||''));
        const exTxt = ex ? ex.toLocaleString() : '';
        scheduleHintEl.style.display = 'block';
        scheduleHintEl.textContent = tf(
          'rooms.typeb.schedule_hint',
          {example: exTxt},
          exTxt
            ? ('Type B flow: when the room reaches the minimum participants, a 24-hour swap window starts. The first turn opens one period after the swap closes (example if minimum is reached now: ' + exTxt + ').')
            : 'Type B flow: when the room reaches the minimum participants, a 24-hour swap window starts. The first turn opens one period after the swap closes.'
        );
      }

    }else{
      if(startLabelEl && startLabelEl.dataset.origText){
        startLabelEl.textContent = startLabelEl.dataset.origText;
      }

      startEl.readOnly = false;
      startEl.disabled = false;

      if(revealFieldEl) revealFieldEl.style.display = '';

      if(scheduleHintEl) scheduleHintEl.style.display = 'none';

      if(revealEl){
        const wasAuto = !!revealEl.disabled;
        revealEl.readOnly = false;
        revealEl.disabled = false;
        if(wasAuto) revealEl.value = '';
      }
      if(hintEl) hintEl.style.display = 'none';
    }
  }

  function initCreateTypeControls(){
    const typeSel = document.getElementById('cr-type');
    const perSel = document.getElementById('cr-per');
    const startEl = document.getElementById('cr-start');
    if(typeSel) typeSel.addEventListener('change', updateCreateRevealMode);
    if(perSel) perSel.addEventListener('change', updateCreateRevealMode);
    if(startEl) startEl.addEventListener('change', updateCreateRevealMode);
    if(startEl) startEl.addEventListener('keyup', updateCreateRevealMode);
    updateCreateRevealMode();
  }

  function initCreate(){
    initCreateDestAccounts();
    initCreateTypeControls();
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
