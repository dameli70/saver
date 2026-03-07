async function loadRoom(){
  document.getElementById('room-msg').className='msg';
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID));
Location: login.php');
    exit;
}
if (!isEmailVerified()) {
    header('Location: account.php');
    exit;
}

$roomId = (string)($_GET['id'] ?? '');
if ($roomId === '' || strlen($roomId) !== 36) {
    header('Location: rooms.php');
    exit;
}

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Room — LOCKSMITH</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Unbounded:wght@400;700;900&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06070a;--s1:#0d0f14;--s2:#13161d;--s3:#1a1d27;
  --b1:rgba(255,255,255,.07);--b2:rgba(255,255,255,.13);
  --accent:#e8ff47;--red:#ff4757;--blue:#47b8ff;--green:#47ffb0;--orange:#ffaa00;
  --text:#dde1ec;--muted:#525970;
  --mono:'DM Mono',monospace;--display:'Unbounded',sans-serif;
  --sat:env(safe-area-inset-top,0px);--sab:env(safe-area-inset-bottom,0px);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden;-webkit-font-smoothing:antialiased;}
.orb{position:fixed;border-radius:50%;filter:blur(120px);pointer-events:none;z-index:0;}
.orb1{width:520px;height:520px;background:rgba(232,255,71,.035);top:-170px;right:-120px;}
.orb2{width:360px;height:360px;background:rgba(71,184,255,.03);bottom:40px;left:-90px;}

.nav{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;
  padding:max(16px,var(--sat)) 20px 16px;border-bottom:1px solid var(--b1);background:rgba(6,7,10,.92);backdrop-filter:blur(14px);}
.logo{font-family:var(--display);font-weight:900;letter-spacing:-1px;font-size:18px;text-decoration:none;color:inherit;}
.logo span{color:var(--accent);} 
.nav-r{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end;}
.pill{font-size:10px;color:var(--muted);letter-spacing:1px;border:1px solid rgba(255,255,255,.13);padding:6px 10px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:none;}
@media(min-width:560px){.pill{display:block;}}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 18px;font-family:var(--mono);font-size:11px;letter-spacing:2px;
  text-transform:uppercase;cursor:pointer;border:none;transition:all .15s;border-radius:0;
  -webkit-appearance:none;min-height:42px;text-decoration:none;}
.btn-primary{background:var(--accent);color:#000;font-weight:600;}
.btn-ghost{background:transparent;border:1px solid var(--b2);color:var(--text);} 
.btn-ghost:hover{border-color:var(--text);} 
.btn-blue{background:rgba(71,184,255,.12);border:1px solid rgba(71,184,255,.25);color:var(--blue);} 
.btn-red{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:var(--red);} 
.btn-sm{padding:10px 14px;min-height:38px;font-size:10px;}

.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:26px 18px 60px;}
.h{font-family:var(--display);font-weight:900;font-size:18px;letter-spacing:1px;margin-bottom:8px;}
.p{color:var(--muted);font-size:12px;line-height:1.7;margin-bottom:16px;}
.grid{display:grid;grid-template-columns:1fr;gap:14px;}
@media(min-width:980px){.grid{grid-template-columns:1fr 1fr;}}
.card{background:rgba(13,15,20,.9);border:1px solid var(--b1);padding:18px;}
.card-title{font-family:var(--display);font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:14px;}

.msg{display:none;margin-top:12px;padding:12px 14px;font-size:12px;line-height:1.6;letter-spacing:.4px;}
.msg.show{display:block;}
.msg-err{background:rgba(255,71,87,.08);border:1px solid rgba(255,71,87,.2);color:var(--red);} 
.msg-ok{background:rgba(71,255,176,.08);border:1px solid rgba(71,255,176,.2);color:var(--green);} 

.k{color:var(--muted);} 

.table-wrap{overflow:auto;border:1px solid var(--b1);background:rgba(0,0,0,.2);}
.table{width:100%;border-collapse:collapse;min-width:760px;}
.table th,.table td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;font-size:12px;white-space:nowrap;}
.table th{color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;background:rgba(0,0,0,.25);} 

.feed{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.2);padding:12px;max-height:420px;overflow:auto;}
.feed-item{padding:10px 10px;border-bottom:1px solid rgba(255,255,255,.06);font-size:12px;line-height:1.6;}
.feed-item:last-child{border-bottom:none;}
.feed-meta{font-size:10px;color:var(--muted);letter-spacing:1px;margin-top:4px;}

</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div class="nav">
  <a class="logo" href="index.php">LOCK<span>SMITH</span></a>
  <div class="nav-r">
    <span class="pill"><?= htmlspecialchars($userEmail) ?></span>
    <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php">Admin</a><?php endif; ?>
    <a class="btn btn-ghost btn-sm" href="rooms.php">Rooms</a>
    <a class="btn btn-ghost btn-sm" href="dashboard.php">Dashboard</a>
    <a class="btn btn-ghost btn-sm" href="logout.php">Logout</a>
  </div>
</div>

<div class="wrap">
  <div class="h" id="room-title">Room</div>
  <div class="p" id="room-sub">Loading…</div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Overview</div>
      <div id="room-overview" class="k">Loading…</div>

      <div id="contrib-block" style="display:none; margin-top:12px;">
        <div class="hr" style="border-top:1px solid var(--b1);margin:16px 0;"></div>
        <div class="card-title" style="margin-bottom:10px;">Contribution</div>
        <div class="p" style="margin-bottom:10px;">Confirm your contribution for the active cycle. (Deposit verification / escrow processing is enforced by the worker milestone.)</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k">Cycle</div>
            <div class="v" id="contrib-cycle">—</div>
          </div>
          <div>
            <div class="k">Due</div>
            <div class="v" id="contrib-due">—</div>
          </div>
        </div>

        <div style="margin-top:12px;display:grid;grid-template-columns:1fr;gap:10px;">
          <div>
            <div class="k">Amount</div>
            <input id="contrib-amt" style="margin-top:6px;width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);font-size:14px;padding:12px;outline:none;" placeholder="e.g. 50.00">
          </div>
          <div>
            <div class="k">Reference (optional)</div>
            <input id="contrib-ref" style="margin-top:6px;width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);font-size:14px;padding:12px;outline:none;" placeholder="e.g. bank tx id">
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-primary btn-sm" onclick="confirmContribution()">Confirm contribution</button>
        </div>
        <div id="contrib-msg" class="msg"></div>
      </div>

      <div id="unlock-block" style="display:none; margin-top:12px;">
        <div class="hr" style="border-top:1px solid var(--b1);margin:16px 0;"></div>
        <div class="card-title" style="margin-bottom:10px;">Unlock (Type A)</div>
        <div class="p" style="margin-bottom:10px;">Requires 100% approval after the reveal date. When revealed, the unlock code is valid for 72 hours.</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k">Consensus</div>
            <div class="v" id="unlock-consensus">—</div>
          </div>
          <div>
            <div class="k">Window</div>
            <div class="v" id="unlock-window">—</div>
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-blue btn-sm" onclick="unlockVote('approve')">Approve unlock</button>
          <button class="btn btn-red btn-sm" onclick="unlockVote('reject')">Reject</button>
          <button class="btn btn-primary btn-sm" id="unlock-reveal-btn" onclick="unlockReveal()" style="display:none;">Reveal code</button>
        </div>

        <div id="unlock-code-wrap" style="display:none;margin-top:12px;">
          <div class="k">Unlock code (auto-clears)</div>
          <input id="unlock-code" readonly style="margin-top:6px;width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);font-size:14px;padding:12px;outline:none;">
          <div class="small" id="unlock-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="unlock-msg" class="msg"></div>
      </div>

      <div id="typeb-block" style="display:none; margin-top:12px;">
        <div class="hr" style="border-top:1px solid var(--b1);margin:16px 0;"></div>
        <div class="card-title" style="margin-bottom:10px;">Rotation (Type B)</div>
        <div class="p" style="margin-bottom:10px;">Each turn requires maker approval + 50% participant approval. If approved, only the current turn user can reveal the unlock code for 72 hours.</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k">Current turn</div>
            <div class="v" id="typeb-turn">—</div>
          </div>
          <div>
            <div class="k">Consensus</div>
            <div class="v" id="typeb-consensus">—</div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;">
          <div>
            <div class="k">Window</div>
            <div class="v" id="typeb-window">—</div>
          </div>
          <div>
            <div class="k">Maker vote</div>
            <div class="v" id="typeb-maker">—</div>
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-blue btn-sm" onclick="typeBVote('approve')">Approve</button>
          <button class="btn btn-red btn-sm" onclick="typeBVote('reject')">Reject</button>
          <button class="btn btn-primary btn-sm" id="typeb-reveal-btn" onclick="typeBReveal()" style="display:none;">Reveal code</button>
        </div>

        <div id="typeb-code-wrap" style="display:none;margin-top:12px;">
          <div class="k">Unlock code (auto-clears)</div>
          <input id="typeb-code" readonly style="margin-top:6px;width:100%;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--mono);font-size:14px;padding:12px;outline:none;">
          <div class="small" id="typeb-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="typeb-msg" class="msg"></div>
      </div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-primary btn-sm" id="join-btn" onclick="requestJoin()" style="display:none;">Request to join</button>
        <a class="btn btn-ghost btn-sm" href="rooms.php">Back to discovery</a>
      </div>
      <div id="room-msg" class="msg"></div>
    </div>

    <div class="card">
      <div class="card-title">Activity</div>
      <div class="feed" id="feed"></div>
      <div id="feed-msg" class="msg"></div>
    </div>

    <div class="card" id="underfill-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Underfilled room — action required</div>
      <div class="p">This room has not reached its minimum participant count 72 hours before start. If no action is taken within 24 hours, it auto-cancels.</div>

      <div id="underfill-meta" class="small"></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-blue btn-sm" onclick="underfillExtend()">Extend start date</button>
        <button class="btn btn-blue btn-sm" onclick="underfillLowerMin()">Lower minimum</button>
        <button class="btn btn-red btn-sm" onclick="underfillCancel()">Cancel room</button>
      </div>
      <div id="underfill-msg" class="msg"></div>
    </div>

    <div class="card" id="escrow-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Escrow settlements (maker)</div>
      <div class="p">Accounting entries recorded when participants are removed after two missed contributions.</div>

      <div id="escrow-empty" class="k" style="display:none;">No escrow settlements.</div>

      <div class="table-wrap" id="escrow-table-wrap" style="display:none;">
        <table class="table" id="escrow-table">
          <thead>
            <tr>
              <th>Removed user</th>
              <th>Policy</th>
              <th>Total contributed</th>
              <th>Fee</th>
              <th>Refund</th>
              <th>Status</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="escrow-msg" class="msg"></div>
    </div>

    <div class="card" id="maker-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Join requests (maker)</div>
      <div class="p">Review pending requests. You can see the applicant’s trust level and strikes summary.</div>
      <div class="table-wrap">
        <table class="table" id="req-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Snapshot</th>
              <th>Current</th>
              <th>Requested</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="maker-msg" class="msg"></div>
    </div>

  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const ROOM_ID = <?= json_encode($roomId) ?>;

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  return r.json();
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function setMsg(id, text, ok){
  const el=document.getElementById(id);
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}
function fmt(ts){
  try{return new Date(ts).toLocaleString();}catch{return String(ts||'');}
}
function destSummary(a){
  if(!a) return '—';
  if(a.account_type === 'mobile_money'){
    const carrier = a.carrier_id ? ('carrier ' + a.carrier_id) : 'mobile money';
    return carrier + ' · ' + (a.mobile_money_number||'');
  }
  if(a.account_type === 'bank'){
    return (a.bank_name||'Bank') + ' · ' + (a.bank_account_number||'');
  }
  return a.account_type || '—';
}

let roomCache = null;
let lastEventId = 0;
let unlockClearTimer = null;

function renderRoom(){
  const r = roomCache;
  if(!r) return;

  document.getElementById('room-title').textContent = r.goal_text || 'Room';
  document.getElementById('room-sub').textContent = `Type ${r.saving_type} · Level ${r.required_trust_level} · ${r.periodicity} · Starts ${fmt(r.start_at)}`;

  const ov = document.getElementById('room-overview');
  ov.innerHTML = `
    <div style="font-size:12px;line-height:1.7;">
      <div><span class="k">Purpose:</span> ${esc(r.purpose_category)}</div>
      <div><span class="k">Visibility:</span> ${esc(r.visibility)}</div>
      <div><span class="k">Participation amount:</span> ${esc(r.participation_amount)}</div>
      <div><span class="k">Destination:</span> ${esc(destSummary(r.destination_account))}</div>
      <div><span class="k">Participants:</span> ${esc(r.approved_count)} / ${esc(r.max_participants)} (min ${esc(r.min_participants)})</div>
      <div><span class="k">Lobby:</span> ${esc(r.lobby_state)} · <span class="k">State:</span> ${esc(r.room_state)}</div>
      <div><span class="k">Reveal date:</span> ${esc(fmt(r.reveal_at))}</div>
      <div><span class="k">Your status:</span> ${esc(r.my_status||'none')}</div>
    </div>
  `;

  const joinBtn = document.getElementById('join-btn');
  const canJoin = (!r.my_status || r.my_status === 'declined') && r.room_state === 'lobby' && r.lobby_state === 'open' && r.visibility !== 'private';
  joinBtn.style.display = canJoin ? 'inline-flex' : 'none';

  const contrib = document.getElementById('contrib-block');
  if(contrib){
    const canContrib = (r.room_state === 'active' && r.my_status === 'active' && r.active_cycle);
    contrib.style.display = canContrib ? 'block' : 'none';

    if(canContrib){
      document.getElementById('contrib-cycle').textContent = `#${r.active_cycle.cycle_index} (${r.active_cycle.status})`;
      document.getElementById('contrib-due').textContent = fmt(r.active_cycle.due_at);
      const amt = document.getElementById('contrib-amt');
      if(amt && !amt.value){
        amt.value = String(r.participation_amount||'');
      }
    }
  }

  const unlock = document.getElementById('unlock-block');
  if(unlock){
    const isTypeA = (r.saving_type === 'A');
    const canSee = isTypeA && r.my_status && (r.my_status === 'active' || r.my_status === 'approved');
    unlock.style.display = canSee ? 'block' : 'none';

    if(canSee){
      const approvals = (r.unlock && r.unlock.votes) ? (r.unlock.votes.approvals||0) : 0;
      const eligible = (r.unlock && r.unlock.votes) ? (r.unlock.votes.eligible||0) : 0;
      const myVote = (r.unlock && r.unlock.my_vote) ? r.unlock.my_vote : 'none';

      document.getElementById('unlock-consensus').textContent = `${approvals}/${eligible} (you: ${myVote})`;

      const ev = r.unlock ? r.unlock.event : null;
      if(ev && ev.status === 'revealed'){
        document.getElementById('unlock-window').textContent = `Revealed · expires ${fmt(ev.expires_at)}`;
      } else if(ev && ev.status === 'expired'){
        document.getElementById('unlock-window').textContent = 'Expired';
      } else {
        document.getElementById('unlock-window').textContent = 'Pending';
      }

      const canReveal = (r.room_state === 'active' && approvals === eligible && eligible > 0 && (new Date(r.reveal_at).getTime() <= Date.now()) && (!ev || ev.status !== 'expired'));
      document.getElementById('unlock-reveal-btn').style.display = canReveal ? 'inline-flex' : 'none';
    }
  }

  const typeb = document.getElementById('typeb-block');
  if(typeb){
    const isTypeB = (r.saving_type === 'B');
    const canSeeB = isTypeB && r.my_status && (r.my_status === 'active' || r.my_status === 'approved');
    typeb.style.display = canSeeB ? 'block' : 'none';

    if(canSeeB){
      const cur = r.rotation ? r.rotation.current : null;
      const approvals = (r.rotation && r.rotation.votes) ? (r.rotation.votes.approvals||0) : 0;
      const required = (r.rotation && r.rotation.votes) ? (r.rotation.votes.required||0) : 0;
      const eligible = (r.rotation && r.rotation.votes) ? (r.rotation.votes.eligible||0) : 0;
      const myVote = (r.rotation && r.rotation.my_vote) ? r.rotation.my_vote : 'none';
      const makerVote = (r.rotation && r.rotation.maker_vote) ? r.rotation.maker_vote : 'none';

      if(cur){
        document.getElementById('typeb-turn').textContent = `#${cur.rotation_index} · ${cur.turn_user_email || 'user'}`;
        document.getElementById('typeb-consensus').textContent = `${approvals}/${required} required (you: ${myVote} · eligible ${eligible})`;

        if(cur.status === 'revealed'){
          document.getElementById('typeb-window').textContent = `Revealed · expires ${fmt(cur.expires_at)}`;
        } else if(cur.status === 'blocked_dispute'){
          document.getElementById('typeb-window').textContent = 'Blocked (dispute)';
        } else {
          document.getElementById('typeb-window').textContent = 'Pending votes';
        }

        document.getElementById('typeb-maker').textContent = makerVote;

        const canRevealB = (r.room_state === 'active' && r.my_status === 'active' && cur.status === 'revealed' && (cur.is_turn_user === 1));
        document.getElementById('typeb-reveal-btn').style.display = canRevealB ? 'inline-flex' : 'none';

      } else {
        document.getElementById('typeb-turn').textContent = '—';
        document.getElementById('typeb-consensus').textContent = '—';
        document.getElementById('typeb-window').textContent = '—';
        document.getElementById('typeb-maker').textContent = '—';
        document.getElementById('typeb-reveal-btn').style.display = 'none';
      }
    }
  }

  if(r.is_maker){
    document.getElementById('maker-card').style.display='block';
    document.getElementById('escrow-card').style.display='block';
    loadJoinRequests();
    loadUnderfillDecision();
    renderEscrowSettlements(r.escrow_settlements||[]);
  } else {
    document.getElementById('maker-card').style.display='none';
    document.getElementById('escrow-card').style.display='none';
  }
}

async function loadRoom(){
  document.getElementById('room-msg').className='msg';
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');
    roomCache = res.room;
    roomCache.escrow_settlements = res.escrow_settlements || [];
    renderRoom();
  }catch(e){
    setMsg('room-msg', e.message||'Failed', false);
  }
}


async function pollFeed(){
  const msg = document.getElementById('feed-msg');
  msg.className='msg';

  try{
    const r = await get('/api/rooms.php?action=activity&room_id=' + encodeURIComponent(ROOM_ID) + '&since_id=' + encodeURIComponent(lastEventId) + '&limit=100');
    if(!r.success) throw new Error(r.error||'Failed');

    const events = r.events || [];
    events.forEach(addFeedItem);
    if(events.length){
      lastEventId = events[events.length-1].id;
    }

  }catch(e){
    setMsg('feed-msg', e.message||'Failed to load activity', false);
  }
}

function addFeedItem(ev){
  const feed = document.getElementById('feed');
  const el = document.createElement('div');
  el.className = 'feed-item';

  const payload = ev.payload || {};

  let line = '';
  if(ev.event_type === 'room_created') line = 'Room created';
  else if(ev.event_type === 'join_requested') line = 'New join request';
  else if(ev.event_type === 'join_approved') line = 'Join request approved';
  else if(ev.event_type === 'join_declined') line = 'Join request declined';
  else if(ev.event_type === 'lobby_locked') line = 'Lobby locked';
  else if(ev.event_type === 'room_started') line = 'Room started';
  else if(ev.event_type === 'grace_window_started') line = 'Contribution grace window started';
  else if(ev.event_type === 'contribution_confirmed') line = '✓ Contributed';
  else if(ev.event_type === 'strike_logged') line = 'Strike logged';
  else if(ev.event_type === 'participant_removed') line = 'Participant removed';
  else if(ev.event_type === 'escrow_settlement_recorded') line = 'Escrow settlement recorded';
  else if(ev.event_type === 'unlock_vote_updated') line = 'Unlock vote updated';
  else if(ev.event_type === 'unlock_revealed') line = 'Unlock revealed';
  else if(ev.event_type === 'unlock_expired') line = 'Unlock expired';
  else if(ev.event_type === 'rotation_queue_created') line = 'Rotation queue created';
  else if(ev.event_type === 'rotation_vote_updated') line = 'Rotation vote updated';
  else if(ev.event_type === 'typeB_turn_revealed') line = 'Type B turn revealed';
  else if(ev.event_type === 'typeB_turn_expired') line = 'Type B turn expired';
  else if(ev.event_type === 'typeB_turn_advanced') line = 'Type B turn advanced';
  else if(ev.event_type === 'rotation_blocked_dispute') line = 'Rotation blocked (dispute)';
  else if(ev.event_type === 'room_closed') line = 'Room closed';
  else if(ev.event_type === 'underfilled_alerted') line = 'Underfilled alert sent';
  else if(ev.event_type === 'underfilled_resolved') line = 'Underfilled resolved';
  else if(ev.event_type === 'room_auto_cancelled_underfilled') line = 'Room auto-cancelled (underfilled)';
  else if(ev.event_type === 'room_cancelled_by_maker') line = 'Room cancelled by maker';
  else line = ev.event_type;

  const extra = payload && Object.keys(payload).length ? ' — ' + esc(JSON.stringify(payload)) : '';
  el.innerHTML = `<div>${esc(line)}${extra}</div><div class="feed-meta">${esc(fmt(ev.created_at))}</div>`;

  feed.appendChild(el);
  feed.scrollTop = feed.scrollHeight;
}

async function requestJoin(){
  document.getElementById('room-msg').className='msg';
  const btn = document.getElementById('join-btn');
  btn.disabled=true;

  try{
    const res = await postCsrf('/api/rooms.php', {action:'request_join', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('room-msg','Join request sent.', true);
    await loadRoom();
  }catch(e){
    setMsg('room-msg', e.message||'Failed', false);
  }finally{
    btn.disabled=false;
  }
}

async function confirmContribution(){
  const r = roomCache;
  if(!r || !r.active_cycle){
    setMsg('contrib-msg','No active cycle.', false);
    return;
  }

  const amount = (document.getElementById('contrib-amt')||{}).value || '';
  const reference = (document.getElementById('contrib-ref')||{}).value || '';

  try{
    const res = await postCsrf('/api/rooms.php', {action:'confirm_contribution', room_id: ROOM_ID, cycle_id: r.active_cycle.id, amount, reference});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('contrib-msg','Contribution confirmed.', true);
    await pollFeed();
  }catch(e){
    setMsg('contrib-msg', e.message||'Failed', false);
  }
}

async function unlockVote(vote){
  try{
    const res = await postCsrf('/api/rooms.php', {action:'typeA_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('unlock-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('unlock-msg', e.message||'Failed', false);
  }
}

async function unlockReveal(){
  try{
    const res = await postCsrf('/api/rooms.php', {action:'typeA_reveal', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');

    const wrap = document.getElementById('unlock-code-wrap');
    const input = document.getElementById('unlock-code');
    const exp = document.getElementById('unlock-code-exp');

    wrap.style.display='block';
    input.value = String(res.code||'');
    exp.textContent = `Expires at ${fmt(res.expires_at)}`;

    if (unlockClearTimer) clearTimeout(unlockClearTimer);
    unlockClearTimer = setTimeout(()=>{
      input.value='';
      wrap.style.display='none';
    }, 30000);

    setMsg('unlock-msg','Code revealed. It will auto-clear in 30 seconds.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('unlock-msg', e.message||'Failed', false);
  }
}

async function typeBVote(vote){
  try{
    const res = await postCsrf('/api/rooms.php', {action:'typeB_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('typeb-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('typeb-msg', e.message||'Failed', false);
  }
}

async function typeBReveal(){
  try{
    const res = await postCsrf('/api/rooms.php', {action:'typeB_reveal', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');

    const wrap = document.getElementById('typeb-code-wrap');
    const input = document.getElementById('typeb-code');
    const exp = document.getElementById('typeb-code-exp');

    wrap.style.display='block';
    input.value = String(res.code||'');
    exp.textContent = `Expires at ${fmt(res.expires_at)}`;

    if (unlockClearTimer) clearTimeout(unlockClearTimer);
    unlockClearTimer = setTimeout(()=>{
      input.value='';
      wrap.style.display='none';
    }, 30000);

    setMsg('typeb-msg','Code revealed. It will auto-clear in 30 seconds.', true);
    await pollFeed();

  }catch(e){
    setMsg('typeb-msg', e.message||'Failed', false);
  }
}

function renderEscrowSettlements(rows){
  const empty = document.getElementById('escrow-empty');
  const wrap = document.getElementById('escrow-table-wrap');
  const tbody = document.querySelector('#escrow-table tbody');

  if(!tbody || !empty || !wrap) return;

  rows = rows || [];

  if(!rows.length){
    empty.style.display='block';
    wrap.style.display='none';
    tbody.innerHTML='';
    return;
  }

  empty.style.display='none';
  wrap.style.display='block';
  tbody.innerHTML='';

  rows.forEach(r => {
    const tr=document.createElement('tr');

    const fee = (r.platform_fee_amount || '0.00');
    const refund = (r.policy === 'refund_minus_fee') ? (r.refund_amount || '0.00') : '—';

    tr.innerHTML = `
      <td>${esc(r.email||('User ' + r.removed_user_id))}</td>
      <td>${esc(r.policy)}</td>
      <td>${esc(r.total_contributed||'0.00')}</td>
      <td>${esc(fee)}</td>
      <td>${esc(refund)}</td>
      <td>${esc(r.status||'')}</td>
      <td>${esc(fmt(r.created_at))}</td>
    `;
    tbody.appendChild(tr);
  });
}

function loadUnderfillDecision(){
  const r = roomCache;
  const card = document.getElementById('underfill-card');
  if(!card || !r) return;

  if(!r.is_maker || !r.underfill || r.underfill.status !== 'open'){
    card.style.display='none';
    return;
  }

  card.style.display='block';
  document.getElementById('underfill-meta').textContent = `Decision deadline: ${fmt(r.underfill.decision_deadline_at)}`;
}

async function underfillExtend(){
  const msg = document.getElementById('underfill-msg');
  msg.className='msg';

  const newStartAt = prompt('Enter new start date/time (YYYY-MM-DD HH:MM:SS)');
  if(!newStartAt) return;
  const newRevealAt = prompt('Enter new reveal date/time (YYYY-MM-DD HH:MM:SS)');
  if(!newRevealAt) return;

  try{
    const res = await postCsrf('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'extend_start', new_start_at:newStartAt, new_reveal_at:newRevealAt});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('underfill-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||'Failed', false);
  }
}

async function underfillLowerMin(){
  const msg = document.getElementById('underfill-msg');
  msg.className='msg';

  const newMinStr = prompt('Enter new minimum participants');
  if(!newMinStr) return;
  const newMin = parseInt(newMinStr, 10);
  if(!newMin || newMin < 2){
    setMsg('underfill-msg','Minimum must be at least 2', false);
    return;
  }

  try{
    const res = await postCsrf('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'lower_min', new_min_participants:newMin});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('underfill-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||'Failed', false);
  }
}

async function underfillCancel(){
  const ok = confirm('Cancel this room?');
  if(!ok) return;

  try{
    const res = await postCsrf('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'cancel'});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('underfill-msg','Room cancelled.', true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||'Failed', false);
  }
}

async function loadJoinRequests(){
  document.getElementById('maker-msg').className='msg';

  const tbody = document.querySelector('#req-table tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="k">Loading…</td></tr>';

  try{
    const res = await get('/api/rooms.php?action=maker_join_requests&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');

    const rows = res.requests || [];
    if(!rows.length){
      tbody.innerHTML = '<tr><td colspan="5" class="k">No pending requests.</td></tr>';
      return;
    }

    tbody.innerHTML='';
    rows.forEach(r => {
      const tr=document.createElement('tr');
      const snap = `L${r.snapshot_level} · strikes ${r.snapshot_strikes_6m}` + (r.snapshot_restricted_until ? ' · restricted' : '');
      const cur = `L${r.current_level||'?'} · strikes ${r.current_strikes_6m||0}` + (r.current_restricted_until ? ' · restricted' : '');

      tr.innerHTML = `
        <td>${esc(r.email)}</td>
        <td>${esc(snap)}</td>
        <td>${esc(cur)}</td>
        <td>${esc(fmt(r.created_at))}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="reviewJoin(${r.id}, 'approve')">Approve</button>
          <button class="btn btn-red btn-sm" onclick="reviewJoin(${r.id}, 'decline')">Decline</button>
        </td>
      `;

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = '<tr><td colspan="5" class="k">Failed to load requests.</td></tr>';
    setMsg('maker-msg', e.message||'Failed', false);
  }
}

async function reviewJoin(requestId, decision){
  document.getElementById('maker-msg').className='msg';

  const ok = confirm((decision==='approve') ? 'Approve this user?' : 'Decline this user?');
  if(!ok) return;

  try{
    const res = await postCsrf('/api/rooms.php', {action:'review_join', request_id: requestId, decision});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg('maker-msg', 'Saved.', true);
    await loadJoinRequests();
    await loadRoom();

  }catch(e){
    setMsg('maker-msg', e.message||'Failed', false);
  }
}

let feedPollTimer = null;
let feedEs = null;

function startPollingFeed(){
  if(feedEs){
    try{feedEs.close();}catch{}
    feedEs = null;
  }
  if(feedPollTimer) clearInterval(feedPollTimer);
  pollFeed();
  feedPollTimer = setInterval(pollFeed, 4000);
}

function startSseFeed(){
  if(!window.EventSource){
    startPollingFeed();
    return;
  }

  if(feedPollTimer){
    clearInterval(feedPollTimer);
    feedPollTimer = null;
  }

  const url = apiUrl('/api/rooms_stream.php?room_id=' + encodeURIComponent(ROOM_ID) + '&since_id=' + encodeURIComponent(lastEventId));
  feedEs = new EventSource(url);

  feedEs.addEventListener('activity', (ev) => {
    try{
      const data = JSON.parse(ev.data);
      addFeedItem(data);
      lastEventId = data.id;
    }catch{
      // ignore parse errors
    }
  });

  feedEs.onerror = () => {
    // If SSE is blocked/unavailable, fall back to polling.
    try{feedEs.close();}catch{}
    feedEs = null;
    startPollingFeed();
  };
}

loadRoom().then(async ()=>{
  await pollFeed();
  startSseFeed();
});
</script>
</body>
</html>
