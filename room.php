<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    header('Location: login.php');
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

$inviteToken = trim((string)($_GET['invite'] ?? ''));
if (strlen($inviteToken) > 200) $inviteToken = '';

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!doctype html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.room')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/room_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <div class="topbar">
    <div class="topbar-logo"><?= htmlspecialchars(APP_NAME) ?></div>
    <div class="topbar-r">
      <span class="user-pill"><?= htmlspecialchars($userEmail) ?></span>
      <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
      <?php $curLang = currentLang(); ?>
      <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
      <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>
      <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php"><?php e('nav.my_codes'); ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?php e('nav.backups'); ?></a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      <a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($isAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
    </div>
  </div>

  <div class="app-body wide">
    <div class="h" id="room-title"><?php e('page.room'); ?></div>
    <div class="p" id="room-sub">Loading…</div>

  <div class="grid">
    <div class="card">
      <div class="card-title">Overview</div>
      <div id="room-overview" class="k">Loading…</div>

      <div id="contrib-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
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
            <input id="contrib-amt" class="ls-input" style="margin-top:6px;" placeholder="e.g. 50.00">
          </div>
          <div>
            <div class="k">Reference (optional)</div>
            <input id="contrib-ref" class="ls-input" style="margin-top:6px;" placeholder="e.g. bank tx id">
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-primary btn-sm" onclick="confirmContribution()">Confirm contribution</button>
        </div>
        <div id="contrib-msg" class="msg"></div>
      </div>

      <div id="unlock-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;">Unlock (Type A)</div>
        <div class="p" style="margin-bottom:10px;">Requires 100% approval after the reveal date. When revealed, the unlock code is valid for 72 hours.</div>

        <div class="two-col">
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
          <input id="unlock-code" class="ls-input" readonly style="margin-top:6px;">
          <div class="small" id="unlock-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="unlock-msg" class="msg"></div>
      </div>

      <div id="typeb-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
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

        <div class="two-col" style="margin-top:12px;">
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
          <input id="typeb-code" class="ls-input" readonly style="margin-top:6px;">
          <div class="small" id="typeb-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="typeb-dispute-wrap" style="display:none;margin-top:12px;">
          <div class="hr"></div>
          <div class="k">Dispute (Type B)</div>
          <div class="v" id="typeb-dispute-meta">—</div>

          <div id="typeb-dispute-form" style="display:none;margin-top:10px;">
            <div class="k">Reason (optional)</div>
            <input id="typeb-dispute-reason" class="ls-input" placeholder="e.g. I believe the turn user is not eligible / suspicious activity" style="margin-top:6px;">
            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
              <button class="btn btn-red btn-sm" onclick="typeBRaiseDispute()">Raise dispute</button>
            </div>
          </div>

          <div id="typeb-dispute-actions" style="display:none;margin-top:10px;">
            <button class="btn btn-blue btn-sm" id="typeb-dispute-ack-btn" onclick="typeBAckDispute()">Acknowledge dispute</button>
          </div>

          <div id="typeb-dispute-msg" class="msg"></div>
        </div>

        <div id="typeb-msg" class="msg"></div>
      </div>

      <div id="exit-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;">Exit request (Type B)</div>
        <div class="p" style="margin-bottom:10px;">After the room starts, exiting requires maker approval + 60% participant approval. A settlement entry is recorded as a refund minus a 20% platform fee.</div>

        <div class="v" id="exit-meta">—</div>

        <div id="exit-actions-request" style="display:none;margin-top:10px;">
          <button class="btn btn-red btn-sm" onclick="createExitRequest()">Request to exit</button>
        </div>

        <div id="exit-actions-vote" style="display:none;margin-top:10px;">
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button class="btn btn-blue btn-sm" onclick="voteExit('approve')">Approve exit</button>
            <button class="btn btn-red btn-sm" onclick="voteExit('reject')">Reject</button>
          </div>
        </div>

        <div id="exit-actions-cancel" style="display:none;margin-top:10px;">
          <button class="btn btn-ghost btn-sm" onclick="cancelExitRequest()">Cancel request</button>
        </div>

        <div id="exit-msg" class="msg"></div>
      </div>

      <div id="invite-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;">Invitation</div>
        <div class="p" style="margin-bottom:10px;">You were invited to this private room. Accepting will add you as an approved participant.</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-blue btn-sm" onclick="respondInvite('accept')">Accept invite</button>
          <button class="btn btn-red btn-sm" onclick="respondInvite('decline')">Decline</button>
        </div>
        <div id="invite-msg" class="msg"></div>
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

    <div class="card" id="unlisted-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Unlisted invite link (maker)</div>
      <div class="p">Unlisted rooms are not shown on discovery. Share a link to allow others to view and request to join (until the start date).</div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-blue btn-sm" onclick="generateUnlistedLink()">Generate new link</button>
        <button class="btn btn-red btn-sm" onclick="revokeUnlistedLink()">Revoke link</button>
      </div>

      <div id="unlisted-link-wrap" style="display:none;margin-top:12px;">
        <div class="k">Shareable link (shown once)</div>
        <input id="unlisted-link" class="ls-input" readonly style="margin-top:6px;">
      </div>

      <div class="small" id="unlisted-meta" style="margin-top:10px;"></div>
      <div id="unlisted-msg" class="msg"></div>
    </div>

    <div class="card" id="invites-card" style="display:none;grid-column:1/-1;">
      <div class="card-title">Invites (maker)</div>
      <div class="p">Private rooms require invites. Invite by email; invited users can accept from the room page.</div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;align-items:center;">
        <input id="invite-email" class="ls-input" placeholder="user@example.com" style="flex:1;min-width:220px;">
        <button class="btn btn-blue btn-sm" onclick="sendInvite()">Send invite</button>
      </div>

      <div class="table-wrap" id="invites-table-wrap" style="margin-top:12px;display:none;">
        <table class="table" id="invites-table">
          <thead>
            <tr>
              <th>Email</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="invites-empty" class="k" style="display:none;margin-top:10px;">No invites.</div>
      <div id="invites-msg" class="msg"></div>
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
const INVITE_TOKEN = <?= json_encode($inviteToken) ?>;
function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
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
  if(window.LS && LS.reauth){
    return LS.reauth(methods||{}, {post: postCsrf});
  }

  if(methods && methods.passkey && window.PublicKeyCredential){
    try{
      const begin = await postCsrf('api/webauthn.php', {action:'reauth_begin'});
      if(begin.success){
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
        if(fin.success) return true;
      }
    }catch{}
  }

  if(methods && methods.totp){
    const code = prompt('Enter your 6-digit authenticator code');
    if(!code) return false;
    const r = await postCsrf('api/totp.php', {action:'reauth', code});
    return !!r.success;
  }

  return false;
}

async function postStrong(url, body){
  let j = await postCsrf(url, body);
  if(!j.success && (j.error_code==='reauth_required' || j.error_code==='security_setup_required')){
    const ok = await ensureReauth(j.methods||{});
    if(!ok) return j;
    j = await postCsrf(url, body);
  }
  return j;
}

function esc(s){
  if(window.LS && LS.esc) return LS.esc(s);
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setMsg(id, text, ok){
  const el=document.getElementById(id);
  if(!el) return;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err') + ' show';
  el.textContent = text;
}
function parseUtcDate(ts){
  if(window.LS && LS.parseUtc) return LS.parseUtc(ts);

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
  if(!d || isNaN(d.getTime())) return String(ts||'');
  if(window.LS && LS.fmtLocal) return LS.fmtLocal(d);
  return d.toLocaleString();
}

function fmtUtc(ts){
  const d = parseUtcDate(ts);
  if(!d || isNaN(d.getTime())) return '';
  if(window.LS && LS.fmtUtc) return LS.fmtUtc(d);
  return d.toUTCString();
}
function prettyVisibility(v){
  if(v === 'public') return 'Public';
  if(v === 'unlisted') return 'Unlisted';
  if(v === 'private') return 'Private';
  return v ? String(v) : '';
}
function prettySavingType(t){
  if(t === 'A') return 'Type A';
  if(t === 'B') return 'Type B';
  return t ? String(t) : '';
}
function formatActivityExtra(eventType, payload){
  if(!payload) return '';

  if(eventType === 'room_created'){
    const bits = [];
    if(payload.visibility) bits.push(prettyVisibility(payload.visibility));
    if(payload.saving_type) bits.push(prettySavingType(payload.saving_type));
    return bits.join(' · ');
  }

  if(eventType === 'lobby_locked'){
    if(payload.reason === 'capacity_reached') return 'Room full';
    if(payload.reason === 'start_date_reached') return 'Start date reached';
    if(payload.reason) return 'Reason: ' + String(payload.reason);
    return '';
  }

  if(eventType === 'invite_created' || eventType === 'invite_revoked'){
    if(payload.mode === 'private_user') return 'Private invite';
    if(payload.mode === 'unlisted_link') return 'Unlisted link';
    if(payload.mode) return String(payload.mode);
    return '';
  }

  if(eventType === 'unlock_vote_updated'){
    const a = payload.approvals;
    const e = payload.eligible;
    if(typeof a === 'number' && typeof e === 'number') return `Approvals ${a}/${e}`;
    return '';
  }

  if(eventType === 'unlock_revealed' || eventType === 'unlock_expired'){
    if(payload.expires_at) return 'Expires ' + fmt(payload.expires_at);
    return '';
  }

  if(eventType === 'rotation_queue_created'){
    if(payload.rotation_index) return 'Turn #' + String(payload.rotation_index);
    return '';
  }

  if(eventType === 'rotation_vote_updated'){
    const bits = [];
    if(payload.rotation_index) bits.push('Turn #' + String(payload.rotation_index));
    if(typeof payload.approvals === 'number' && typeof payload.required === 'number') bits.push(`Approvals ${payload.approvals}/${payload.required}`);
    if(payload.maker_vote) bits.push('Maker ' + String(payload.maker_vote));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_turn_revealed'){
    const bits = [];
    if(payload.rotation_index) bits.push('Turn #' + String(payload.rotation_index));
    if(payload.expires_at) bits.push('Expires ' + fmt(payload.expires_at));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_turn_expired' || eventType === 'typeB_turn_advanced' || eventType === 'rotation_blocked_dispute' || eventType === 'rotation_blocked_debt' || eventType === 'rotation_unblocked_debt'){
    if(payload.rotation_index) return 'Turn #' + String(payload.rotation_index);
    return '';
  }

  if(eventType === 'grace_window_started'){
    if(payload.cycle_index) return 'Cycle #' + String(payload.cycle_index);
    if(payload.cycle_id) return 'Cycle ' + String(payload.cycle_id);
    return '';
  }

  if(eventType === 'contribution_confirmed'){
    const bits = [];
    if(payload.cycle_id) bits.push('Cycle ' + String(payload.cycle_id));
    if(payload.amount) bits.push('Amount ' + String(payload.amount));
    return bits.join(' · ');
  }

  if(eventType === 'strike_logged'){
    if(payload.cycle_id) return 'Cycle ' + String(payload.cycle_id);
    return '';
  }

  if(eventType === 'participant_removed'){
    if(payload.reason === 'two_missed_contributions') return 'Two missed contributions';
    if(payload.reason) return 'Reason: ' + String(payload.reason);
    return '';
  }

  if(eventType === 'escrow_settlement_recorded'){
    if(payload.policy) return 'Policy: ' + String(payload.policy);
    return '';
  }

  if(eventType === 'underfilled_alerted'){
    const bits = [];
    if(typeof payload.approved_count !== 'undefined' && typeof payload.min_participants !== 'undefined'){
      bits.push(`Approved ${payload.approved_count}/${payload.min_participants}`);
    }
    if(payload.decision_deadline_at) bits.push('Decision by ' + fmt(payload.decision_deadline_at));
    return bits.join(' · ');
  }

  if(eventType === 'underfilled_resolved'){
    if(payload.action === 'extend_start') return 'Start date extended';
    if(payload.action === 'lower_min'){
      if(payload.new_min_participants) return 'Minimum lowered to ' + String(payload.new_min_participants);
      return 'Minimum lowered';
    }
    if(payload.action) return String(payload.action);
    return '';
  }

  if(eventType === 'room_auto_cancelled_underfilled' || eventType === 'room_cancelled_by_maker' || eventType === 'room_closed'){
    if(payload.reason) return 'Reason: ' + String(payload.reason);
    return '';
  }

  if(eventType === 'exit_requested' || eventType === 'exit_vote_updated' || eventType === 'exit_approved' || eventType === 'exit_cancelled'){
    const bits = [];
    if(payload.exit_request_id) bits.push('Request #' + String(payload.exit_request_id));
    if(typeof payload.approvals === 'number' && typeof payload.required === 'number') bits.push(`Approvals ${payload.approvals}/${payload.required}`);
    if(payload.maker_vote) bits.push('Maker ' + String(payload.maker_vote));
    return bits.join(' · ');
  }

  if(eventType === 'dispute_raised' || eventType === 'dispute_ack_updated'){
    const bits = [];
    if(payload.rotation_index) bits.push('Turn #' + String(payload.rotation_index));
    if(typeof payload.ack_count === 'number' && typeof payload.required === 'number') bits.push(`Ack ${payload.ack_count}/${payload.required}`);
    return bits.join(' · ');
  }

  // Fallback: show primitive key/value pairs (avoid dumping raw JSON).
  const bits = [];
  Object.keys(payload).forEach(k => {
    const v = payload[k];
    if(v === null || typeof v === 'undefined') return;
    if(typeof v === 'object') return;
    bits.push(k.replace(/_/g,' ') + ': ' + String(v));
  });
  return bits.join(' · ');
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
let roomTicker = null;

function roomCountdownText(r){
  if(!r) return '';

  const now = Date.now();
  const start = parseUtcDate(r.start_at);
  const reveal = parseUtcDate(r.reveal_at);

  function fmtDelta(ms){
    const s = Math.max(0, Math.floor(ms/1000));
    if(window.LS && LS.fmtCountdown) return LS.fmtCountdown(s);
    return String(s) + 's';
  }

  if(start && !isNaN(start.getTime()) && now < start.getTime()){
    return 'Starts in ' + fmtDelta(start.getTime() - now);
  }

  if(reveal && !isNaN(reveal.getTime()) && now < reveal.getTime()){
    return 'Reveals in ' + fmtDelta(reveal.getTime() - now);
  }

  return 'Reveal eligible (server-enforced)';
}

function updateRoomCountdown(){
  const r = roomCache;
  const el = document.getElementById('room-countdown');
  if(!el || !r) return;
  el.textContent = roomCountdownText(r);
}

function startRoomCountdown(){
  if(roomTicker) clearInterval(roomTicker);
  roomTicker = setInterval(updateRoomCountdown, 1000);
}

function renderRoom(){
  const r = roomCache;
  if(!r) return;

  const startLocal = fmt(r.start_at);
  const startUtc = fmtUtc(r.start_at);
  const revealLocal = fmt(r.reveal_at);
  const revealUtc = fmtUtc(r.reveal_at);

  document.getElementById('room-title').textContent = r.goal_text || 'Room';
  document.getElementById('room-sub').innerHTML = `Type ${esc(r.saving_type)} · Level ${esc(r.required_trust_level)} · ${esc(r.periodicity)} · Starts <b>${esc(startLocal)}</b> <span class="utc-pill" title="Stored/enforced in UTC">${esc(startUtc)}</span>`;

  const ov = document.getElementById('room-overview');
  ov.innerHTML = `
    <div style="font-size:12px;line-height:1.7;">
      <div><span class="k">Purpose:</span> ${esc(r.purpose_category)}</div>
      <div><span class="k">Visibility:</span> ${esc(r.visibility)}</div>
      <div><span class="k">Participation amount:</span> ${esc(r.participation_amount)}</div>
      <div><span class="k">Destination:</span> ${esc(destSummary(r.destination_account))}</div>
      <div><span class="k">Participants:</span> ${esc(r.approved_count)} / ${esc(r.max_participants)} (min ${esc(r.min_participants)})</div>
      <div><span class="k">Lobby:</span> ${esc(r.lobby_state)} · <span class="k">State:</span> ${esc(r.room_state)}</div>
      <div><span class="k">Start date:</span> ${esc(startLocal)} <span class="utc-pill" title="Stored/enforced in UTC">${esc(startUtc)}</span></div>
      <div><span class="k">Reveal date:</span> ${esc(revealLocal)} <span class="utc-pill" title="Stored/enforced in UTC">${esc(revealUtc)}</span></div>
      <div><span class="k">Countdown:</span> <span id="room-countdown"></span></div>
      <div><span class="k">Your status:</span> ${esc(r.my_status||'none')}</div>
    </div>
  `;

  updateRoomCountdown();
  startRoomCountdown();

  const joinBtn = document.getElementById('join-btn');
  const canJoin = (!r.my_status || r.my_status === 'declined') && r.room_state === 'lobby' && r.lobby_state === 'open' && r.visibility !== 'private';
  joinBtn.style.display = canJoin ? 'inline-flex' : 'none';

  const inv = document.getElementById('invite-block');
  if(inv){
    const showInvite = (!r.my_status && r.my_invite && r.visibility === 'private' && r.room_state === 'lobby' && r.lobby_state === 'open');
    inv.style.display = showInvite ? 'block' : 'none';
  }

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

      const ra = parseUtcDate(r.reveal_at);
      const revealOk = (ra && !isNaN(ra.getTime()) && ra.getTime() <= Date.now());
      const canReveal = (r.room_state === 'active' && approvals === eligible && eligible > 0 && revealOk && (!ev || ev.status !== 'expired'));
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
        } else if(cur.status === 'blocked_debt'){
          document.getElementById('typeb-window').textContent = 'Blocked (unpaid contribution)';
        } else {
          document.getElementById('typeb-window').textContent = 'Pending votes';
        }

        document.getElementById('typeb-maker').textContent = makerVote;

        const canRevealB = (r.room_state === 'active' && r.my_status === 'active' && cur.status === 'revealed' && (cur.is_turn_user === 1));
        document.getElementById('typeb-reveal-btn').style.display = canRevealB ? 'inline-flex' : 'none';

        const dispWrap = document.getElementById('typeb-dispute-wrap');
        if(dispWrap){
          const meta = document.getElementById('typeb-dispute-meta');
          const form = document.getElementById('typeb-dispute-form');
          const actions = document.getElementById('typeb-dispute-actions');
          const ackBtn = document.getElementById('typeb-dispute-ack-btn');

          const endsD = cur.dispute_window_ends_at ? parseUtcDate(cur.dispute_window_ends_at) : null;
          const endsAt = (endsD && !isNaN(endsD.getTime())) ? endsD.getTime() : 0;
          const within = endsAt && Date.now() < endsAt;
          const dispute = (r.rotation && r.rotation.dispute) ? r.rotation.dispute : null;

          const showDispute = (cur.status === 'revealed' || cur.status === 'blocked_dispute');
          dispWrap.style.display = showDispute ? 'block' : 'none';

          if(showDispute){
            if(dispute){
              const who = dispute.raised_by_email || 'participant';
              const windowTxt = within ? ('window ends ' + fmt(cur.dispute_window_ends_at)) : ('window ended ' + fmt(cur.dispute_window_ends_at));
              meta.textContent = `${dispute.status} · ${dispute.ack_count}/${dispute.threshold_required} acknowledgements · raised by ${who} · ${windowTxt}`;

              form.style.display = 'none';

              const canAck = within && (r.my_status === 'active') && !dispute.my_ack && (dispute.status !== 'validated' && dispute.status !== 'dismissed');
              actions.style.display = canAck ? 'block' : 'none';

              if(ackBtn){
                ackBtn.disabled = !canAck;
              }
            } else {
              meta.textContent = within ? ('No dispute · window ends ' + fmt(cur.dispute_window_ends_at)) : ('No dispute · window ended ' + fmt(cur.dispute_window_ends_at));
              actions.style.display = 'none';
              form.style.display = (within && r.my_status === 'active') ? 'block' : 'none';
            }
          }
        }

      } else {
        document.getElementById('typeb-turn').textContent = '—';
        document.getElementById('typeb-consensus').textContent = '—';
        document.getElementById('typeb-window').textContent = '—';
        document.getElementById('typeb-maker').textContent = '—';
        document.getElementById('typeb-reveal-btn').style.display = 'none';
        const dispWrap = document.getElementById('typeb-dispute-wrap');
        if(dispWrap) dispWrap.style.display = 'none';
      }
    }
  }

  const exitBlock = document.getElementById('exit-block');
  if(exitBlock){
    const canUseExit = (r.saving_type === 'B' && r.room_state === 'active' && r.my_status === 'active');
    exitBlock.style.display = canUseExit ? 'block' : 'none';

    if(canUseExit){
      const meta = document.getElementById('exit-meta');
      const actReq = document.getElementById('exit-actions-request');
      const actVote = document.getElementById('exit-actions-vote');
      const actCancel = document.getElementById('exit-actions-cancel');

      const er = r.exit_request;

      if(!er){
        if(meta) meta.textContent = 'No open exit request.';
        if(actReq) actReq.style.display = 'block';
        if(actVote) actVote.style.display = 'none';
        if(actCancel) actCancel.style.display = 'none';
      } else {
        const makerVote = (er.votes && er.votes.maker_vote) ? er.votes.maker_vote : '—';
        const approvals = (er.votes && typeof er.votes.approvals !== 'undefined') ? er.votes.approvals : 0;
        const required = (er.votes && typeof er.votes.required !== 'undefined') ? er.votes.required : 0;
        const myVote = er.my_vote ? er.my_vote : '—';

        if(meta) meta.textContent = `Open · requested by ${er.requested_by_email} · approvals ${approvals}/${required} · maker ${makerVote} · your vote ${myVote}`;

        if(actReq) actReq.style.display = 'none';

        const isRequester = !!er.is_requester;
        if(actVote) actVote.style.display = isRequester ? 'none' : 'block';
        if(actCancel) actCancel.style.display = isRequester ? 'block' : 'none';
      }
    }
  }

  if(r.is_maker){
    document.getElementById('maker-card').style.display='block';
    document.getElementById('escrow-card').style.display='block';

    const invitesCard = document.getElementById('invites-card');
    if(invitesCard){
      invitesCard.style.display = (r.visibility === 'private') ? 'block' : 'none';
      if(r.visibility === 'private') loadInvites();
    }

    const unlistedCard = document.getElementById('unlisted-card');
    if(unlistedCard){
      unlistedCard.style.display = (r.visibility === 'unlisted') ? 'block' : 'none';
      if(r.visibility === 'unlisted') loadUnlistedInviteInfo();
    }

    loadJoinRequests();
    loadUnderfillDecision();
    renderEscrowSettlements(r.escrow_settlements||[]);
  } else {
    document.getElementById('maker-card').style.display='none';
    document.getElementById('escrow-card').style.display='none';
    const invitesCard = document.getElementById('invites-card');
    if(invitesCard) invitesCard.style.display='none';
    const unlistedCard = document.getElementById('unlisted-card');
    if(unlistedCard) unlistedCard.style.display='none';
  }
}

function inviteParam(){return INVITE_TOKEN ? ('&invite=' + encodeURIComponent(INVITE_TOKEN)) : '';}

async function loadRoom(){
  document.getElementById('room-msg').className='msg';
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID) + inviteParam());
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
    const r = await get('/api/rooms.php?action=activity&room_id=' + encodeURIComponent(ROOM_ID) + inviteParam() + '&since_id=' + encodeURIComponent(lastEventId) + '&limit=100');
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
  const shouldScroll = (feed.scrollTop + feed.clientHeight) >= (feed.scrollHeight - 24);

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
  else if(ev.event_type === 'escrow_settlement_processed') line = 'Escrow settlement processed';
  else if(ev.event_type === 'invite_created') line = 'Invite created';
  else if(ev.event_type === 'invite_accepted') line = 'Invite accepted';
  else if(ev.event_type === 'invite_declined') line = 'Invite declined';
  else if(ev.event_type === 'invite_revoked') line = 'Invite revoked';
  else if(ev.event_type === 'unlock_vote_updated') line = 'Unlock vote updated';
  else if(ev.event_type === 'unlock_revealed') line = 'Unlock revealed';
  else if(ev.event_type === 'unlock_expired') line = 'Unlock expired';
  else if(ev.event_type === 'rotation_queue_created') line = 'Rotation queue created';
  else if(ev.event_type === 'rotation_vote_updated') line = 'Rotation vote updated';
  else if(ev.event_type === 'typeB_turn_revealed') line = 'Type B turn revealed';
  else if(ev.event_type === 'typeB_turn_expired') line = 'Type B turn expired';
  else if(ev.event_type === 'typeB_turn_advanced') line = 'Type B turn advanced';
  else if(ev.event_type === 'rotation_blocked_dispute') line = 'Rotation blocked (dispute)';
  else if(ev.event_type === 'rotation_blocked_debt') line = 'Rotation blocked (unpaid contribution)';
  else if(ev.event_type === 'rotation_unblocked_debt') line = 'Rotation unblocked (debt cleared)';
  else if(ev.event_type === 'dispute_raised') line = 'Dispute raised';
  else if(ev.event_type === 'dispute_ack_updated') line = 'Dispute acknowledgment updated';
  else if(ev.event_type === 'dispute_validated') line = 'Dispute validated';
  else if(ev.event_type === 'dispute_dismissed') line = 'Dispute dismissed';
  else if(ev.event_type === 'rotation_unblocked') line = 'Rotation unblocked';
  else if(ev.event_type === 'underfilled_alerted') line = 'Underfilled alert sent';
  else if(ev.event_type === 'underfilled_resolved') line = 'Underfilled room resolved';
  else if(ev.event_type === 'room_auto_cancelled_underfilled') line = 'Room auto-cancelled (underfilled)';
  else if(ev.event_type === 'room_cancelled_by_maker') line = 'Room cancelled by maker';
  else if(ev.event_type === 'exit_requested') line = 'Exit request opened';
  else if(ev.event_type === 'exit_vote_updated') line = 'Exit request vote updated';
  else if(ev.event_type === 'exit_approved') line = 'Exit request approved';
  else if(ev.event_type === 'exit_cancelled') line = 'Exit request cancelled';
  else if(ev.event_type === 'room_closed') line = 'Room closed';
  else line = ev.event_type;

  const extraTxt = formatActivityExtra(ev.event_type, payload);
  const extra = extraTxt ? ' — ' + esc(extraTxt) : '';
  el.innerHTML = `<div>${esc(line)}${extra}</div><div class="feed-meta">${esc(fmt(ev.created_at))}</div>`;

  feed.appendChild(el);
  if(shouldScroll) feed.scrollTop = feed.scrollHeight;
}

async function requestJoin(){
  document.getElementById('room-msg').className='msg';
  const btn = document.getElementById('join-btn');
  btn.disabled=true;

  try{
    const payload = {action:'request_join', room_id: ROOM_ID};
    if(roomCache && roomCache.visibility === 'unlisted') payload.invite_token = INVITE_TOKEN;

    const res = await postStrong('/api/rooms.php', payload);

    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('room-msg','Join request sent.', true);
    await loadRoom();
  }catch(e){
    setMsg('room-msg', e.message||'Failed', false);
  }finally{
    btn.disabled=false;
  }
}

async function respondInvite(decision){
  const r = roomCache;
  if(!r || !r.my_invite){
    setMsg('invite-msg','No active invite.', false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'respond_invite', invite_id: r.my_invite.id, decision});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('invite-msg', decision === 'accept' ? 'Invite accepted.' : 'Invite declined.', true);
    await loadRoom();
  }catch(e){
    setMsg('invite-msg', e.message||'Failed', false);
  }
}

let unlistedLoadedAt = 0;
async function loadUnlistedInviteInfo(force=false){
  const now = Date.now();
  if(!force && (now - unlistedLoadedAt) < 1500) return;
  unlistedLoadedAt = now;

  const meta = document.getElementById('unlisted-meta');
  if(meta) meta.textContent='';

  try{
    const res = await get('/api/rooms.php?action=unlisted_invite_info&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');

    const inv = res.invite;
    if(!inv){
      if(meta) meta.textContent = 'No link generated.';
      return;
    }

    const activeTxt = inv.is_active ? 'active' : 'inactive';
    const exp = inv.expires_at ? fmt(inv.expires_at) : '—';
    if(meta) meta.textContent = `Link status: ${activeTxt} · expires ${exp}`;

  }catch(e){
    setMsg('unlisted-msg', e.message||'Failed', false);
  }
}

async function generateUnlistedLink(){
  document.getElementById('unlisted-msg').className='msg';

  const wrap = document.getElementById('unlisted-link-wrap');
  const input = document.getElementById('unlisted-link');
  if(wrap) wrap.style.display='none';
  if(input) input.value='';

  try{
    const res = await postStrong('/api/rooms.php', {action:'unlisted_invite_create', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');

    if(input) input.value = res.link || '';
    if(wrap) wrap.style.display='block';
    if(input) input.select();

    setMsg('unlisted-msg', 'Link generated. Copy it now; it will not be shown again.', true);
    await loadUnlistedInviteInfo(true);

  }catch(e){
    setMsg('unlisted-msg', e.message||'Failed', false);
  }
}

async function revokeUnlistedLink(){
  document.getElementById('unlisted-msg').className='msg';
  const ok = confirm('Revoke the current unlisted link?');
  if(!ok) return;

  const wrap = document.getElementById('unlisted-link-wrap');
  const input = document.getElementById('unlisted-link');
  if(wrap) wrap.style.display='none';
  if(input) input.value='';

  try{
    const res = await postStrong('/api/rooms.php', {action:'unlisted_invite_revoke', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('unlisted-msg','Link revoked.', true);
    await loadUnlistedInviteInfo(true);
  }catch(e){
    setMsg('unlisted-msg', e.message||'Failed', false);
  }
}

let invitesLoadedAt = 0;
async function loadInvites(force=false){
  const now = Date.now();
  if(!force && (now - invitesLoadedAt) < 1500) return;
  invitesLoadedAt = now;

  const wrap = document.getElementById('invites-table-wrap');
  const empty = document.getElementById('invites-empty');
  const tbody = document.querySelector('#invites-table tbody');

  if(wrap) wrap.style.display='none';
  if(empty) empty.style.display='none';
  if(tbody) tbody.innerHTML='';

  try{
    const res = await get('/api/rooms.php?action=maker_invites&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||'Failed');

    const rows = res.invites || [];
    if(!rows.length){
      if(empty) empty.style.display='block';
      return;
    }

    if(wrap) wrap.style.display='block';

    rows.forEach(x => {
      const tr=document.createElement('tr');
      const revokeBtn = (x.status === 'active') ? `<button class="btn btn-red btn-sm" onclick="revokeInvite(${x.id})">Revoke</button>` : '';
      tr.innerHTML = `
        <td>${esc(x.email)}</td>
        <td>${esc(x.status)}</td>
        <td>${x.expires_at ? esc(fmt(x.expires_at)) : '—'}</td>
        <td>${esc(fmt(x.created_at))}</td>
        <td>${revokeBtn}</td>
      `;
      tbody.appendChild(tr);
    });

  }catch(e){
    setMsg('invites-msg', e.message||'Failed', false);
  }
}

async function sendInvite(){
  const input = document.getElementById('invite-email');
  const email = (input ? input.value : '').trim();
  if(!email){
    setMsg('invites-msg','Email required.', false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'invite_user', room_id: ROOM_ID, email});
    if(!res.success) throw new Error(res.error||'Failed');
    if(input) input.value='';
    setMsg('invites-msg','Invite sent.', true);
    await loadInvites(true);
  }catch(e){
    setMsg('invites-msg', e.message||'Failed', false);
  }
}

async function revokeInvite(inviteId){
  const ok = confirm('Revoke this invite?');
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'revoke_invite', invite_id: inviteId});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('invites-msg','Invite revoked.', true);
    await loadInvites(true);
  }catch(e){
    setMsg('invites-msg', e.message||'Failed', false);
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
    const res = await postStrong('/api/rooms.php', {action:'confirm_contribution', room_id: ROOM_ID, cycle_id: r.active_cycle.id, amount, reference});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('contrib-msg','Contribution confirmed.', true);
    await pollFeed();
  }catch(e){
    setMsg('contrib-msg', e.message||'Failed', false);
  }
}

async function unlockVote(vote){
  try{
    const res = await postStrong('/api/rooms.php', {action:'typeA_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('unlock-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('unlock-msg', e.message||'Failed', false);
  }
}

async function unlockReveal(){
  try{
    const res = await postStrong('/api/rooms.php', {action:'typeA_reveal', room_id: ROOM_ID});
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
    const res = await postStrong('/api/rooms.php', {action:'typeB_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||'Failed');
    setMsg('typeb-msg','Saved.', true);
    await loadRoom();
  }catch(e){
    setMsg('typeb-msg', e.message||'Failed', false);
  }
}

async function typeBReveal(){
  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_reveal', room_id: ROOM_ID});
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

async function typeBRaiseDispute(){
  const msgId = 'typeb-dispute-msg';
  document.getElementById(msgId).className='msg';

  const reason = (document.getElementById('typeb-dispute-reason')||{}).value || '';

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_raise_dispute', room_id: ROOM_ID, reason});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg(msgId,'Dispute raised.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||'Failed', false);
  }
}

async function typeBAckDispute(){
  const msgId = 'typeb-dispute-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const dispute = (r && r.rotation) ? r.rotation.dispute : null;
  if(!dispute){
    setMsg(msgId,'No dispute to acknowledge.', false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_ack_dispute', room_id: ROOM_ID, dispute_id: dispute.id});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg(msgId,'Acknowledged.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||'Failed', false);
  }
}

async function createExitRequest(){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const ok = confirm('Request to exit this room? This requires approvals and will record a refund-minus-fee settlement.');
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_create', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg(msgId,'Exit request submitted.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||'Failed', false);
  }
}

async function voteExit(vote){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const er = r ? r.exit_request : null;
  if(!er){
    setMsg(msgId,'No open exit request.', false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_vote', room_id: ROOM_ID, exit_request_id: er.id, vote});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg(msgId, res.approved ? 'Exit approved.' : 'Vote saved.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||'Failed', false);
  }
}

async function cancelExitRequest(){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const er = r ? r.exit_request : null;
  if(!er){
    setMsg(msgId,'No open exit request.', false);
    return;
  }

  const ok = confirm('Cancel your exit request?');
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_cancel', room_id: ROOM_ID, exit_request_id: er.id});
    if(!res.success) throw new Error(res.error||'Failed');

    setMsg(msgId,'Exit request cancelled.', true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||'Failed', false);
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

  const rawStart = prompt('Enter new start date/time (YYYY-MM-DDTHH:MM)');
  if(!rawStart) return;
  const rawReveal = prompt('Enter new reveal date/time (YYYY-MM-DDTHH:MM)');
  if(!rawReveal) return;

  const startIso = (function(){
    const s = String(rawStart||'').trim().replace(' ', 'T');
    const d = new Date(s);
    if(isNaN(d.getTime())) return '';
    return d.toISOString();
  })();

  const revealIso = (function(){
    const s = String(rawReveal||'').trim().replace(' ', 'T');
    const d = new Date(s);
    if(isNaN(d.getTime())) return '';
    return d.toISOString();
  })();

  if(!startIso || !revealIso){
    setMsg('underfill-msg','Invalid date/time format.', false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'extend_start', new_start_at:startIso, new_reveal_at:revealIso});
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
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'lower_min', new_min_participants:newMin});
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
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'cancel'});
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
    const res = await postStrong('/api/rooms.php', {action:'review_join', request_id: requestId, decision});
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

  const url = apiUrl('/api/rooms_stream.php?room_id=' + encodeURIComponent(ROOM_ID) + inviteParam() + '&since_id=' + encodeURIComponent(lastEventId));
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
</div>
</body>
</html> 
