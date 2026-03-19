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
$currentUserId = (int)(getCurrentUserId() ?? 0);
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
?>
<!DOCTYPE html>
<html <?= htmlLangAttr() ?>>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.room')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
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
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title" id="room-title"><?php e('page.room'); ?></div>
        <div class="page-sub" id="room-sub"><?php e('common.loading'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="room_proofs.php?id=<?= htmlspecialchars($roomId, ENT_QUOTES, 'UTF-8') ?>"><?php e('room.nav.proofs'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      </div>
    </div>

  <div class="grid">
    <div class="card">
      <div class="card-title"><?php e('room.overview_title'); ?></div>
      <div id="room-overview" class="room-ov"><?php e('common.loading'); ?></div>

      <div id="timeline-wrap" style="margin-top:12px;display:none;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.timeline_title'); ?></div>
        <div id="room-timeline" class="room-timeline"></div>
      </div>

      <div id="next-wrap" style="margin-top:12px;display:none;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.next_title'); ?></div>
        <div id="next-panel" class="next-panel"></div>
        <div id="next-actions" class="next-actions"></div>
      </div>

      <?php if ($isAdmin): ?>
      <details id="admin-panel" style="margin-top:12px;">
        <summary style="cursor:pointer;user-select:none;"><?php e('nav.admin'); ?></summary>
        <div id="admin-panel-body" style="margin-top:10px;"></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
          <a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a>
        </div>
      </details>
      <?php endif; ?>

      <div id="contrib-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.contribution_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.contribution_sub'); ?></div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k"><?php e('room.contribution.cycle'); ?></div>
            <div class="v" id="contrib-cycle">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.contribution.due'); ?></div>
            <div class="v" id="contrib-due">—</div>
          </div>
        </div>

        <div style="margin-top:12px;display:grid;grid-template-columns:1fr;gap:10px;">
          <div>
            <div class="k"><?php e('room.contribution.amount'); ?></div>
            <div class="v" id="contrib-amount">—</div>
          </div>
        </div>

        <div class="p" style="margin-top:10px;"><?php e('room.contribution.proofs_redirect_note'); ?></div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <a class="btn btn-primary btn-sm" id="contrib-open-proofs" href="rooms_proofs.php?room_id=<?= htmlspecialchars($roomId, ENT_QUOTES, 'UTF-8') ?>"><?php e('room.contribution.open_proofs_btn'); ?></a>
        </div>
        <div id="contrib-msg" class="msg"></div>
      </div>

      <div id="unlock-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.unlock_type_a_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.unlock_type_a_sub'); ?></div>

        <div class="two-col">
          <div>
            <div class="k"><?php e('room.unlock.consensus'); ?></div>
            <div class="v" id="unlock-consensus">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.unlock.window'); ?></div>
            <div class="v" id="unlock-window">—</div>
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-blue btn-sm" id="unlock-vote-approve" onclick="unlockVote('approve')"><?php e('room.unlock.btn_approve'); ?></button>
          <button class="btn btn-red btn-sm" id="unlock-vote-reject" onclick="unlockVote('reject')"><?php e('room.unlock.btn_reject'); ?></button>
          <button class="btn btn-primary btn-sm" id="unlock-reveal-btn" onclick="unlockReveal()" style="display:none;"><?php e('room.unlock.btn_reveal_code'); ?></button>
        </div>

        <div id="unlock-code-wrap" style="display:none;margin-top:12px;">
          <div class="k"><?php e('room.unlock.code_label'); ?></div>
          <input id="unlock-code" class="ls-input" readonly style="margin-top:6px;">
          <div class="small" id="unlock-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="unlock-msg" class="msg"></div>
      </div>

      <div id="typeb-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.rotation_type_b_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.rotation_type_b_sub'); ?></div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k"><?php e('room.rotation.current_turn'); ?></div>
            <div class="v" id="typeb-turn">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.rotation.consensus'); ?></div>
            <div class="v" id="typeb-consensus">—</div>
          </div>
        </div>

        <div class="two-col" style="margin-top:12px;">
          <div>
            <div class="k"><?php e('room.rotation.room_balance'); ?></div>
            <div class="v" id="typeb-balance">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.rotation.required_amount'); ?></div>
            <div class="v" id="typeb-required">—</div>
          </div>
        </div>

        <div class="two-col" style="margin-top:12px;">
          <div>
            <div class="k"><?php e('room.rotation.window'); ?></div>
            <div class="v" id="typeb-window">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.rotation.maker_vote'); ?></div>
            <div class="v" id="typeb-maker">—</div>
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <button class="btn btn-blue btn-sm" id="typeb-vote-approve" onclick="typeBVote('approve')"><?php e('room.rotation.btn_approve'); ?></button>
          <button class="btn btn-red btn-sm" id="typeb-vote-reject" onclick="typeBVote('reject')"><?php e('room.rotation.btn_reject'); ?></button>
          <button class="btn btn-primary btn-sm" id="typeb-reveal-btn" onclick="typeBReveal()" style="display:none;"><?php e('room.rotation.btn_reveal_code'); ?></button>
        </div>

        <div id="typeb-code-wrap" style="display:none;margin-top:12px;">
          <div class="k"><?php e('room.rotation.code_label'); ?></div>
          <input id="typeb-code" class="ls-input" readonly style="margin-top:6px;">
          <div class="small" id="typeb-code-exp" style="margin-top:6px;"></div>
        </div>

        <div id="typeb-delegate-wrap" style="display:none;margin-top:12px;">
          <div class="hr"></div>
          <div class="k"><?php e('room.rotation.delegate_title'); ?></div>
          <div class="v" id="typeb-delegate-meta">—</div>

          <div id="typeb-delegate-form" style="display:none;margin-top:10px;">
            <div class="k"><?php e('room.rotation.delegate_select'); ?></div>
            <select id="typeb-delegate-user" class="ls-input" style="margin-top:6px;"></select>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
              <button class="btn btn-blue btn-sm" onclick="typeBSetDelegate()"><?php e('room.rotation.delegate_set_btn'); ?></button>
              <button class="btn btn-ghost btn-sm" onclick="typeBClearDelegate()"><?php e('room.rotation.delegate_clear_btn'); ?></button>
            </div>
          </div>

          <div id="typeb-delegate-msg" class="msg"></div>
        </div>

        <div id="typeb-withdraw-wrap" style="display:none;margin-top:12px;">
          <div class="hr"></div>
          <div class="k"><?php e('room.rotation.withdrawal_title'); ?></div>
          <div class="v" id="typeb-withdraw-meta">—</div>

          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
            <button class="btn btn-primary btn-sm" id="typeb-confirm-btn" onclick="typeBConfirmWithdrawal()" style="display:none;"><?php e('room.rotation.withdrawal_confirm_btn'); ?></button>
          </div>

          <div id="typeb-withdraw-msg" class="msg"></div>
        </div>

        <div id="typeb-history-wrap" style="display:none;margin-top:12px;">
          <div class="hr"></div>
          <div class="k"><?php e('room.rotation.history_title'); ?></div>
          <div class="table-wrap" id="typeb-history-table-wrap" style="margin-top:10px;display:none;">
            <table class="table" id="typeb-history-table">
              <thead>
                <tr>
                  <th><?php e('room.rotation.history_th_turn'); ?></th>
                  <th><?php e('room.rotation.history_th_turn_user'); ?></th>
                  <th><?php e('room.rotation.history_th_code'); ?></th>
                  <th><?php e('room.rotation.history_th_collected'); ?></th>
                  <th><?php e('room.rotation.history_th_withdrawal'); ?></th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
          <div id="typeb-history-empty" class="k" style="display:none;"><?php e('room.rotation.history_empty'); ?></div>
        </div>

        <div id="typeb-dispute-wrap" style="display:none;margin-top:12px;">
          <div class="hr"></div>
          <div class="k"><?php e('room.dispute_title'); ?></div>
          <div class="v" id="typeb-dispute-meta">—</div>

          <div id="typeb-dispute-form" style="display:none;margin-top:10px;">
            <div class="k"><?php e('room.dispute_reason_optional'); ?></div>
            <input id="typeb-dispute-reason" class="ls-input" placeholder="<?= htmlspecialchars(t('room.dispute_reason_placeholder'), ENT_QUOTES, 'UTF-8') ?>" style="margin-top:6px;">
            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
              <button class="btn btn-red btn-sm" onclick="typeBRaiseDispute()"><?php e('room.dispute_raise_btn'); ?></button>
            </div>
          </div>

          <div id="typeb-dispute-actions" style="display:none;margin-top:10px;">
            <button class="btn btn-blue btn-sm" id="typeb-dispute-ack-btn" onclick="typeBAckDispute()"><?php e('room.dispute_ack_btn'); ?></button>
          </div>

          <div id="typeb-dispute-msg" class="msg"></div>
        </div>

        <div id="typeb-msg" class="msg"></div>
      </div>

      <div id="swap-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.swap.title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.swap.sub'); ?></div>
        <div id="swap-admin-hint" class="small" style="display:none;margin-top:-6px;margin-bottom:10px;">
          <?php e('nav.admin'); ?>: you can review slots and swap requests, but swap actions are disabled unless you are a participant.
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
          <div>
            <div class="k"><?php e('room.swap.status'); ?></div>
            <div class="v" id="swap-status">—</div>
          </div>
          <div>
            <div class="k"><?php e('room.swap.closes'); ?></div>
            <div class="v" id="swap-closes">—</div>
          </div>
        </div>

        <div id="swap-slots" style="margin-top:12px;">
          <div class="k"><?php e('room.swap.slots_title'); ?></div>
          <div class="table-wrap" id="swap-slots-table-wrap" style="margin-top:10px;display:none;">
            <table class="table" id="swap-slots-table">
              <thead>
                <tr>
                  <th><?php e('room.swap.slots_th_pos'); ?></th>
                  <th><?php e('room.swap.slots_th_participant'); ?></th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
          <div id="swap-slots-empty" class="k" style="display:none;margin-top:10px;"><?php e('room.swap.slots_empty'); ?></div>
        </div>

        <div id="swap-request-form" style="margin-top:12px;display:none;">
          <div class="k"><?php e('room.swap.request_to'); ?></div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:6px;">
            <select id="swap-to-user" class="ls-input" style="flex:1;min-width:220px;"></select>
            <button class="btn btn-blue btn-sm" id="swap-request-btn" onclick="requestSwap()"><?php e('room.swap.btn_request'); ?></button>
          </div>
        </div>

        <div id="swap-requests" style="margin-top:12px;">
          <div class="k"><?php e('room.swap.requests_title'); ?></div>
          <div class="table-wrap" id="swap-requests-table-wrap" style="margin-top:10px;display:none;">
            <table class="table" id="swap-requests-table">
              <thead>
                <tr>
                  <th><?php e('room.swap.requests_th_from'); ?></th>
                  <th><?php e('room.swap.requests_th_to'); ?></th>
                  <th><?php e('room.swap.requests_th_status'); ?></th>
                  <th><?php e('room.swap.requests_th_created'); ?></th>
                  <th><?php e('room.swap.requests_th_actions'); ?></th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
          <div id="swap-requests-empty" class="k" style="display:none;margin-top:10px;"><?php e('room.swap.requests_empty'); ?></div>
        </div>

        <div id="swap-msg" class="msg"></div>
      </div>

      <div id="exit-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.exit_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.exit_sub'); ?></div>

        <div class="v" id="exit-meta">—</div>

        <div id="exit-actions-request" style="display:none;margin-top:10px;">
          <button class="btn btn-red btn-sm" onclick="createExitRequest()"><?php e('room.exit_request_btn'); ?></button>
        </div>

        <div id="exit-actions-vote" style="display:none;margin-top:10px;">
          <div style="display:flex;gap:10px;flex-wrap:wrap;">
            <button class="btn btn-blue btn-sm" onclick="voteExit('approve')"><?php e('room.exit_approve_btn'); ?></button>
            <button class="btn btn-red btn-sm" onclick="voteExit('reject')"><?php e('room.exit_reject_btn'); ?></button>
          </div>
        </div>

        <div id="exit-actions-cancel" style="display:none;margin-top:10px;">
          <button class="btn btn-ghost btn-sm" onclick="cancelExitRequest()"><?php e('room.exit_cancel_btn'); ?></button>
        </div>

        <div id="exit-msg" class="msg"></div>
      </div>

      <div id="invite-block" style="display:none; margin-top:12px;">
        <div class="hr"></div>
        <div class="card-title" style="margin-bottom:10px;"><?php e('room.invitation_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('room.invitation_sub'); ?></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="btn btn-blue btn-sm" onclick="respondInvite('accept')"><?php e('room.invitation.accept'); ?></button>
          <button class="btn btn-red btn-sm" onclick="respondInvite('decline')"><?php e('room.invitation.decline'); ?></button>
        </div>
        <div id="invite-msg" class="msg"></div>
      </div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-primary btn-sm" id="join-btn" onclick="requestJoin()" style="display:none;"><?php e('room.action.request_join'); ?></button>
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('room.back_to_discovery'); ?></a>
      </div>
      <div id="room-msg" class="msg"></div>
    </div>

    <div class="card">
      <div class="card-title"><?php e('room.activity_title'); ?></div>
      <div class="feed" id="feed"></div>
      <div id="feed-msg" class="msg"></div>
    </div>

    <div class="card" id="underfill-card" style="display:none;grid-column:1/-1;">
      <div class="card-title"><?php e('room.underfilled_title'); ?></div>
      <div class="p"><?php e('room.underfilled_sub'); ?></div>

      <div id="underfill-meta" class="small"></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-blue btn-sm" onclick="underfillExtend()"><?php e('room.underfilled.extend'); ?></button>
        <button class="btn btn-blue btn-sm" onclick="underfillLowerMin()"><?php e('room.underfilled.lower_min'); ?></button>
        <button class="btn btn-red btn-sm" onclick="underfillCancel()"><?php e('room.underfilled.cancel'); ?></button>
      </div>
      <div id="underfill-msg" class="msg"></div>
    </div>

    <div class="card" id="escrow-card" style="display:none;grid-column:1/-1;">
      <div class="card-title"><?php e('room.escrow_title'); ?></div>
      <div class="p"><?php e('room.escrow_sub'); ?></div>

      <div id="escrow-empty" class="k" style="display:none;"><?php e('room.escrow_empty'); ?></div>

      <div class="table-wrap" id="escrow-table-wrap" style="display:none;">
        <table class="table" id="escrow-table">
          <thead>
            <tr>
              <th><?php e('room.escrow_th_removed_user'); ?></th>
              <th><?php e('room.escrow_th_policy'); ?></th>
              <th><?php e('room.escrow_th_total_contributed'); ?></th>
              <th><?php e('room.escrow_th_fee'); ?></th>
              <th><?php e('room.escrow_th_refund'); ?></th>
              <th><?php e('room.escrow_th_status'); ?></th>
              <th><?php e('room.escrow_th_created'); ?></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="escrow-msg" class="msg"></div>
    </div>

    <div class="card" id="unlisted-card" style="display:none;grid-column:1/-1;">
      <div class="card-title"><?php e('room.unlisted_title'); ?></div>
      <div class="p"><?php e('room.unlisted_sub'); ?></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
        <button class="btn btn-blue btn-sm" onclick="generateUnlistedLink()"><?php e('room.unlisted_generate_btn'); ?></button>
        <button class="btn btn-red btn-sm" onclick="revokeUnlistedLink()"><?php e('room.unlisted_revoke_btn'); ?></button>
      </div>

      <div id="unlisted-link-wrap" style="display:none;margin-top:12px;">
        <div class="k"><?php e('room.unlisted_link_label'); ?></div>
        <input id="unlisted-link" class="ls-input" readonly style="margin-top:6px;">
      </div>

      <div class="small" id="unlisted-meta" style="margin-top:10px;"></div>
      <div id="unlisted-msg" class="msg"></div>
    </div>

    <div class="card" id="invites-card" style="display:none;grid-column:1/-1;">
      <div class="card-title"><?php e('room.invites_title'); ?></div>
      <div class="p"><?php e('room.invites_sub'); ?></div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;align-items:center;">
        <input id="invite-email" class="ls-input" placeholder="<?= htmlspecialchars(t('room.invites_email_placeholder'), ENT_QUOTES, 'UTF-8') ?>" style="flex:1;min-width:220px;">
        <button class="btn btn-blue btn-sm" onclick="sendInvite()"><?php e('room.invites_send_btn'); ?></button>
      </div>

      <div class="table-wrap" id="invites-table-wrap" style="margin-top:12px;display:none;">
        <table class="table" id="invites-table">
          <thead>
            <tr>
              <th><?php e('room.invites_th_email'); ?></th>
              <th><?php e('room.invites_th_status'); ?></th>
              <th><?php e('room.invites_th_expires'); ?></th>
              <th><?php e('room.invites_th_created'); ?></th>
              <th><?php e('room.invites_th_actions'); ?></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="invites-empty" class="k" style="display:none;margin-top:10px;"><?php e('room.invites_empty'); ?></div>
      <div id="invites-msg" class="msg"></div>
    </div>

    <div class="card" id="maker-card" style="display:none;grid-column:1/-1;">
      <div class="card-title"><?php e('room.requests_title'); ?></div>
      <div class="p"><?php e('room.requests_sub'); ?></div>
      <div class="table-wrap">
        <table class="table" id="req-table">
          <thead>
            <tr>
              <th><?php e('room.requests_th_user'); ?></th>
              <th><?php e('room.requests_th_snapshot'); ?></th>
              <th><?php e('room.requests_th_current'); ?></th>
              <th><?php e('room.requests_th_requested'); ?></th>
              <th><?php e('room.requests_th_actions'); ?></th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      <div id="maker-msg" class="msg"></div>
    </div>

  </div>
  </div>
</div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const ROOM_ID = <?= json_encode($roomId) ?>;
const INVITE_TOKEN = <?= json_encode($inviteToken) ?>;
const IS_ADMIN = <?= json_encode($isAdmin ? 1 : 0) ?>;
const CURRENT_USER_ID = <?= json_encode($currentUserId) ?>;

const I18N = (window.LS_I18N && window.LS_I18N.strings) ? window.LS_I18N.strings : {};
function tr(key, vars, fallback){
  let s = (I18N && typeof I18N[key] === 'string') ? I18N[key] : fallback;
  s = String(s == null ? '' : s);
  if(vars){
    Object.keys(vars).forEach(k => {
      s = s.split('{' + k + '}').join(String(vars[k]));
    });
  }
  return s;
}

const STR = {
  failed: tr('common.failed', null, 'Failed'),
  saved: tr('common.saved', null, 'Saved.'),
  vote_saved: tr('room.vote_saved', null, 'Vote saved.'),
  loading: tr('common.loading', null, 'Loading…'),
  confirm: tr('common.confirm', null, 'Confirm'),
  cancel: tr('common.cancel', null, 'Cancel'),
  enter_totp: tr('login.enter_totp', null, 'Enter your 6-digit authenticator code'),
  email_required: tr('common.email_required', null, 'Email required'),

  join_request_sent: tr('rooms.msg.join_request_sent', null, 'Join request sent.'),

  invite_no_active: tr('room.invitation.no_active', null, 'No active invite.'),
  invite_accepted: tr('room.invitation.accepted', null, 'Invite accepted.'),
  invite_declined: tr('room.invitation.declined', null, 'Invite declined.'),

  invite_sent: tr('room.invites.sent', null, 'Invite sent.'),
  invite_revoked: tr('room.invites.revoked', null, 'Invite revoked.'),

  no_active_cycle: tr('room.contribution.no_active_cycle', null, 'No active cycle.'),
  contribution_confirmed: tr('room.contribution.confirmed', null, 'Contribution confirmed.'),
  proof_required: tr('room.contribution.proof_required', null, 'Proof screenshot required.'),

  feed_failed: tr('room.feed.failed_to_load_activity', null, 'Failed to load activity'),

  active: tr('common.active', null, 'active'),
  inactive: tr('common.inactive', null, 'inactive'),
  participant: tr('common.participant', null, 'participant'),
  revoke: tr('common.revoke', null, 'Revoke'),
  approve: tr('common.approve', null, 'Approve'),
  decline: tr('common.decline', null, 'Decline'),
  restricted: tr('common.restricted', null, 'restricted'),
  strikes: tr('common.strikes', null, 'strikes'),
};

const FEED_EVENT_LABELS = {
  room_created: tr('room.feed.room_created', null, 'Room created'),
  join_requested: tr('room.feed.join_requested', null, 'New join request'),
  join_approved: tr('room.feed.join_approved', null, 'Join request approved'),
  join_declined: tr('room.feed.join_declined', null, 'Join request declined'),
  lobby_locked: tr('room.feed.lobby_locked', null, 'Lobby locked'),
  room_started: tr('room.feed.room_started', null, 'Room started'),
  grace_window_started: tr('room.feed.grace_window_started', null, 'Contribution grace window started'),
  contribution_confirmed: tr('room.feed.contribution_confirmed', null, '✓ Contributed'),
  strike_logged: tr('room.feed.strike_logged', null, 'Strike logged'),
  participant_removed: tr('room.feed.participant_removed', null, 'Participant removed'),
  escrow_settlement_recorded: tr('room.feed.escrow_settlement_recorded', null, 'Escrow settlement recorded'),
  escrow_settlement_processed: tr('room.feed.escrow_settlement_processed', null, 'Escrow settlement processed'),
  invite_created: tr('room.feed.invite_created', null, 'Invite created'),
  invite_accepted: tr('room.feed.invite_accepted', null, 'Invite accepted'),
  invite_declined: tr('room.feed.invite_declined', null, 'Invite declined'),
  invite_revoked: tr('room.feed.invite_revoked', null, 'Invite revoked'),
  unlock_vote_updated: tr('room.feed.unlock_vote_updated', null, 'Unlock vote updated'),
  unlock_revealed: tr('room.feed.unlock_revealed', null, 'Unlock revealed'),
  unlock_expired: tr('room.feed.unlock_expired', null, 'Unlock expired'),
  rotation_queue_created: tr('room.feed.rotation_queue_created', null, 'Rotation queue created'),
  rotation_vote_updated: tr('room.feed.rotation_vote_updated', null, 'Rotation vote updated'),
  typeB_turn_revealed: tr('room.feed.typeB_turn_revealed', null, 'Type B turn revealed'),
  typeB_turn_expired: tr('room.feed.typeB_turn_expired', null, 'Type B turn expired'),
  typeB_turn_advanced: tr('room.feed.typeB_turn_advanced', null, 'Type B turn advanced'),
  typeB_code_accessed: tr('room.feed.typeB_code_accessed', null, 'Type B code accessed'),
  typeB_delegate_set: tr('room.feed.typeB_delegate_set', null, 'Type B delegate set'),
  typeB_withdrawal_confirmed: tr('room.feed.typeB_withdrawal_confirmed', null, 'Withdrawal confirmed'),
  typeB_turn_voided: tr('room.feed.typeB_turn_voided', null, 'Turn voided (no confirmation)'),
  rotation_blocked_dispute: tr('room.feed.rotation_blocked_dispute', null, 'Rotation blocked (dispute)'),
  rotation_blocked_debt: tr('room.feed.rotation_blocked_debt', null, 'Rotation blocked (unpaid contribution)'),
  rotation_unblocked_debt: tr('room.feed.rotation_unblocked_debt', null, 'Rotation unblocked (debt cleared)'),
  dispute_raised: tr('room.feed.dispute_raised', null, 'Dispute raised'),
  dispute_ack_updated: tr('room.feed.dispute_ack_updated', null, 'Dispute acknowledgment updated'),
  dispute_validated: tr('room.feed.dispute_validated', null, 'Dispute validated'),
  dispute_dismissed: tr('room.feed.dispute_dismissed', null, 'Dispute dismissed'),
  rotation_unblocked: tr('room.feed.rotation_unblocked', null, 'Rotation unblocked'),
  underfilled_alerted: tr('room.feed.underfilled_alerted', null, 'Underfilled alert sent'),
  underfilled_resolved: tr('room.feed.underfilled_resolved', null, 'Underfilled room resolved'),
  room_auto_cancelled_underfilled: tr('room.feed.room_auto_cancelled_underfilled', null, 'Room auto-cancelled (underfilled)'),
  room_cancelled_by_maker: tr('room.feed.room_cancelled_by_maker', null, 'Room cancelled by maker'),
  exit_requested: tr('room.feed.exit_requested', null, 'Exit request opened'),
  exit_vote_updated: tr('room.feed.exit_vote_updated', null, 'Exit request vote updated'),
  exit_approved: tr('room.feed.exit_approved', null, 'Exit request approved'),
  exit_cancelled: tr('room.feed.exit_cancelled', null, 'Exit request cancelled'),
  room_closed: tr('room.feed.room_closed', null, 'Room closed'),

  swap_window_started: tr('room.feed.swap_window_started', null, 'Swap window started'),
  swap_window_ended: tr('room.feed.swap_window_ended', null, 'Swap window ended'),
  slot_swap_requested: tr('room.feed.slot_swap_requested', null, 'Slot swap requested'),
  slot_swap_accepted: tr('room.feed.slot_swap_accepted', null, 'Slot swap accepted'),
  slot_swap_declined: tr('room.feed.slot_swap_declined', null, 'Slot swap declined'),
  slot_swap_cancelled: tr('room.feed.slot_swap_cancelled', null, 'Slot swap cancelled'),
};

function apiUrl(url){return url.startsWith('/') ? url.slice(1) : url;}
async function get(url){const r=await fetch(apiUrl(url),{credentials:'same-origin'});return r.json();}
async function postCsrf(url,body){
  const r=await fetch(apiUrl(url),{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body)});
  const j = await r.json().catch(()=>null);
  if(j && j.error_code==='package_limit' && j.redirect_url){
    window.location.href = apiUrl(String(j.redirect_url));
    return j;
  }
  return j;
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
    const msg = STR.enter_totp;
    let code = null;

    if(window.LS && typeof window.LS.prompt === 'function'){
      code = await window.LS.prompt({
        title: STR.confirm,
        message: msg,
        placeholder: '123456',
        inputMode: 'numeric',
        validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
      });
    } else if (typeof window.uiPrompt === 'function'){
      code = await window.uiPrompt({
        title: STR.confirm,
        message: msg,
        placeholder: '123456',
        inputMode: 'numeric',
        validate: (v)=> (/^\d{6}$/.test(String(v||'').trim()) ? true : msg),
      });
    }

    const c = String(code||'').trim();
    if(!c) return false;
    const r = await postCsrf('api/totp.php', {action:'reauth', code: c});
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

function setBtnDisabled(btn, reason){
  if(!btn) return;

  // Keep the element interactive so the browser can show the tooltip.
  // We enforce the disable in JS handlers using data-disabledReason.
  btn.disabled = false;

  const r = String(reason||'').trim();
  if(r){
    btn.classList.add('is-disabled');
    btn.setAttribute('aria-disabled','true');
    btn.title = r;
    btn.dataset.disabledReason = r;
  } else {
    btn.classList.remove('is-disabled');
    btn.removeAttribute('aria-disabled');
    btn.title = '';
    delete btn.dataset.disabledReason;
  }
}
function parseUtcDate(ts){
  if(window.LS && LS.parseUtc) return LS.parseUtc(ts);

  if(ts instanceof Date) return ts;

  const s = String(ts||'').trim();
  if(!s) return null;

  // API timestamps are stored in UTC as "YYYY-MM-DD HH:MM:SS".
  if(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s)){
    return new Date(s.replace(' ', 'T') + 'Z');
  }

  return new Date(s);
}

function addPeriod(dt, periodicity){
  if(!dt || isNaN(dt.getTime())) return null;
  const d = new Date(dt.getTime());

  if(periodicity === 'weekly'){
    d.setUTCDate(d.getUTCDate() + 7);
  } else if(periodicity === 'biweekly'){
    d.setUTCDate(d.getUTCDate() + 14);
  } else if(periodicity === 'monthly'){
    d.setUTCMonth(d.getUTCMonth() + 1);
  } else {
    d.setUTCDate(d.getUTCDate() + 7);
  }

  return d;
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
  if(v === 'public') return tr('rooms.visibility.public', null, 'Public');
  if(v === 'unlisted') return tr('rooms.visibility.unlisted', null, 'Unlisted');
  if(v === 'private') return tr('rooms.visibility.private', null, 'Private');
  return v ? String(v) : '';
}
function prettySavingType(t){
  if(t === 'A') return tr('rooms.saving_type.a', null, 'Type A');
  if(t === 'B') return tr('rooms.saving_type.b', null, 'Type B');
  return t ? String(t) : '';
}
function shortSavingType(t){
  const s = prettySavingType(t);
  // Keep badges short even if translations include descriptions (e.g. "Type A — …").
  return String(s).split('—')[0].trim() || String(s||'');
}
function prettyPeriodicity(p){
  if(p === 'weekly') return tr('rooms.periodicity.weekly', null, 'Weekly');
  if(p === 'biweekly') return tr('rooms.periodicity.biweekly', null, 'Bi-weekly');
  if(p === 'monthly') return tr('rooms.periodicity.monthly', null, 'Monthly');
  return p ? String(p) : '';
}
function prettyRoomState(r){
  if(!r) return '';
  const st = String(r.room_state||'');
  if(st === 'active') return tr('room.state.active', null, 'Active');
  if(st === 'swap_window') return tr('room.state.swap_window', null, 'Swap window');
  if(st === 'closed') return tr('room.state.closed', null, 'Closed');
  if(st === 'cancelled') return tr('room.state.cancelled', null, 'Cancelled');

  if(st === 'lobby'){
    const lobby = String(r.lobby_state||'');
    if(lobby === 'locked') return tr('room.state.lobby_locked', null, 'Lobby (locked)');
    return tr('room.state.lobby_open', null, 'Lobby (open)');
  }

  return st;
}
function roomStateBadgeClass(r){
  if(!r) return '';
  const st = String(r.room_state||'');
  if(st === 'active') return 'ok';
  if(st === 'swap_window') return 'wait';
  if(st === 'closed' || st === 'cancelled') return 'err';
  if(st === 'lobby' && String(r.lobby_state||'') === 'locked') return 'wait';
  if(st === 'lobby') return 'wait';
  return '';
}
function prettyMyStatus(st){
  const s = String(st||'');
  if(!s) return tr('room.status.none', null, 'Not a member');
  if(s === 'pending') return tr('room.status.pending', null, 'Pending');
  if(s === 'approved') return tr('room.status.approved', null, 'Approved');
  if(s === 'active') return tr('room.status.active', null, 'Active');
  if(s === 'declined') return tr('room.status.declined', null, 'Declined');
  if(s === 'removed') return tr('room.status.removed', null, 'Removed');
  if(s === 'completed') return tr('room.status.completed', null, 'Completed');
  if(s === 'exited_prestart') return tr('room.status.exited_prestart', null, 'Exited (pre-start)');
  if(s === 'exited_poststart') return tr('room.status.exited_poststart', null, 'Exited');
  return s;
}
function myStatusBadgeClass(st){
  const s = String(st||'');
  if(s === 'active' || s === 'approved') return 'ok';
  if(s === 'pending') return 'wait';
  if(s === 'removed' || s === 'declined' || s === 'exited_prestart' || s === 'exited_poststart') return 'err';
  if(s === 'completed') return 'ok';
  return '';
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
    if(payload.reason === 'capacity_reached') return tr('room.activity.room_full', null, 'Room full');
    if(payload.reason === 'start_date_reached') return tr('room.activity.start_date_reached', null, 'Start date reached');
    if(payload.reason) return tr('room.activity.reason', {reason: String(payload.reason)}, 'Reason: ' + String(payload.reason));
    return '';
  }

  if(eventType === 'invite_created' || eventType === 'invite_revoked'){
    if(payload.mode === 'private_user') return tr('room.activity.private_invite', null, 'Private invite');
    if(payload.mode === 'unlisted_link') return tr('room.activity.unlisted_link', null, 'Unlisted link');
    if(payload.mode) return String(payload.mode);
    return '';
  }

  if(eventType === 'unlock_vote_updated'){
    const a = payload.approvals;
    const e = payload.eligible;
    if(typeof a === 'number' && typeof e === 'number') return tr('room.activity.approvals', {a, b: e}, `Approvals ${a}/${e}`);
    return '';
  }

  if(eventType === 'unlock_revealed' || eventType === 'unlock_expired'){
    if(payload.expires_at) return tr('room.activity.expires', {ts: fmt(payload.expires_at)}, 'Expires ' + fmt(payload.expires_at));
    return '';
  }

  if(eventType === 'rotation_queue_created'){
    if(payload.rotation_index) return tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index));
    return '';
  }

  if(eventType === 'rotation_vote_updated'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(typeof payload.approvals === 'number' && typeof payload.required === 'number') bits.push(tr('room.activity.approvals', {a: payload.approvals, b: payload.required}, `Approvals ${payload.approvals}/${payload.required}`));
    if(payload.maker_vote) bits.push(tr('room.activity.maker', {vote: String(payload.maker_vote)}, 'Maker ' + String(payload.maker_vote)));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_turn_revealed'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(payload.expires_at) bits.push(tr('room.activity.expires', {ts: fmt(payload.expires_at)}, 'Expires ' + fmt(payload.expires_at)));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_turn_expired' || eventType === 'typeB_turn_advanced' || eventType === 'rotation_blocked_dispute' || eventType === 'rotation_blocked_debt' || eventType === 'rotation_unblocked_debt' || eventType === 'typeB_turn_voided'){
    if(payload.rotation_index) return tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index));
    return '';
  }

  if(eventType === 'typeB_code_accessed'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(payload.role) bits.push(tr('room.activity.role', {role: String(payload.role)}, 'role ' + String(payload.role)));
    if(payload.viewer_name) bits.push(String(payload.viewer_name));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_delegate_set'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(payload.delegate_name) bits.push(tr('room.activity.delegate_to', {name: String(payload.delegate_name)}, 'delegate ' + String(payload.delegate_name)));
    return bits.join(' · ');
  }

  if(eventType === 'typeB_withdrawal_confirmed'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(payload.turn_user_name) bits.push(tr('room.activity.collected_by_fmt', {name: String(payload.turn_user_name)}, 'Collected by ' + String(payload.turn_user_name)));
    if(payload.amount) bits.push(tr('room.activity.amount', {amount: String(payload.amount)}, 'Amount ' + String(payload.amount)));
    if(payload.balance_after) bits.push(tr('room.activity.room_balance_fmt', {bal: String(payload.balance_after)}, 'Balance ' + String(payload.balance_after)));
    if(payload.role) bits.push(tr('room.activity.role', {role: String(payload.role)}, 'role ' + String(payload.role)));
    return bits.join(' · ');
  }

  if(eventType === 'grace_window_started'){
    if(payload.cycle_index) return tr('room.activity.cycle_num', {n: String(payload.cycle_index)}, 'Cycle #' + String(payload.cycle_index));
    if(payload.cycle_id) return tr('room.activity.cycle_id', {id: String(payload.cycle_id)}, 'Cycle ' + String(payload.cycle_id));
    return '';
  }

  if(eventType === 'contribution_confirmed'){
    const bits = [];
    if(payload.cycle_id) bits.push(tr('room.activity.cycle_id', {id: String(payload.cycle_id)}, 'Cycle ' + String(payload.cycle_id)));
    if(payload.amount) bits.push(tr('room.activity.amount', {amount: String(payload.amount)}, 'Amount ' + String(payload.amount)));
    if(payload.room_balance) bits.push(tr('room.activity.room_balance_fmt', {bal: String(payload.room_balance)}, 'Balance ' + String(payload.room_balance)));
    return bits.join(' · ');
  }

  if(eventType === 'strike_logged'){
    if(payload.cycle_id) return tr('room.activity.cycle_id', {id: String(payload.cycle_id)}, 'Cycle ' + String(payload.cycle_id));
    return '';
  }

  if(eventType === 'participant_removed'){
    if(payload.reason === 'two_missed_contributions') return tr('room.activity.two_missed_contributions', null, 'Two missed contributions');
    if(payload.reason) return tr('room.activity.reason', {reason: String(payload.reason)}, 'Reason: ' + String(payload.reason));
    return '';
  }

  if(eventType === 'escrow_settlement_recorded'){
    const bits = [];

    if(payload.policy){
      let pol = String(payload.policy);
      if(pol === 'refund_minus_fee') pol = tr('rooms.escrow.refund_minus_fee', null, 'Return minus platform fee');
      else if(pol === 'redistribute') pol = tr('rooms.escrow.redistribute', null, 'Proportional redistribution');
      bits.push(tr('room.activity.policy', {policy: pol}, 'Policy: ' + pol));
    }

    const fr = parseFloat(String(payload.fee_rate||''));
    if(!isNaN(fr)){
      const pct = Math.round(fr * 100);
      bits.push(tr('room.activity.fee_rate_fmt', {pct}, 'Fee ' + pct + '%'));
    }

    if(payload.reason){
      const r = String(payload.reason);
      bits.push(tr('room.activity.reason', {reason: r}, 'Reason: ' + r));
    }

    return bits.join(' · ');
  }

  if(eventType === 'underfilled_alerted'){
    const bits = [];
    if(typeof payload.approved_count !== 'undefined' && typeof payload.min_participants !== 'undefined'){
      bits.push(tr('room.activity.approved', {a: payload.approved_count, b: payload.min_participants}, `Approved ${payload.approved_count}/${payload.min_participants}`));
    }
    if(payload.decision_deadline_at) bits.push(tr('room.activity.decision_by', {ts: fmt(payload.decision_deadline_at)}, 'Decision by ' + fmt(payload.decision_deadline_at)));
    return bits.join(' · ');
  }

  if(eventType === 'underfilled_resolved'){
    if(payload.action === 'extend_start') return tr('room.activity.start_date_extended', null, 'Start date extended');
    if(payload.action === 'lower_min'){
      if(payload.new_min_participants) return tr('room.activity.minimum_lowered_to', {n: String(payload.new_min_participants)}, 'Minimum lowered to ' + String(payload.new_min_participants));
      return tr('room.activity.minimum_lowered', null, 'Minimum lowered');
    }
    if(payload.action) return String(payload.action);
    return '';
  }

  if(eventType === 'room_auto_cancelled_underfilled' || eventType === 'room_cancelled_by_maker' || eventType === 'room_closed'){
    if(payload.reason) return tr('room.activity.reason', {reason: String(payload.reason)}, 'Reason: ' + String(payload.reason));
    return '';
  }

  if(eventType === 'exit_requested' || eventType === 'exit_vote_updated' || eventType === 'exit_approved' || eventType === 'exit_cancelled'){
    const bits = [];
    if(payload.exit_request_id) bits.push(tr('room.activity.request', {id: String(payload.exit_request_id)}, 'Request #' + String(payload.exit_request_id)));
    if(typeof payload.approvals === 'number' && typeof payload.required === 'number') bits.push(tr('room.activity.approvals', {a: payload.approvals, b: payload.required}, `Approvals ${payload.approvals}/${payload.required}`));
    if(payload.maker_vote) bits.push(tr('room.activity.maker', {vote: String(payload.maker_vote)}, 'Maker ' + String(payload.maker_vote)));
    return bits.join(' · ');
  }

  if(eventType === 'dispute_raised' || eventType === 'dispute_ack_updated'){
    const bits = [];
    if(payload.rotation_index) bits.push(tr('room.activity.turn', {n: String(payload.rotation_index)}, 'Turn #' + String(payload.rotation_index)));
    if(typeof payload.ack_count === 'number' && typeof payload.required === 'number') bits.push(tr('room.activity.ack', {a: payload.ack_count, b: payload.required}, `Ack ${payload.ack_count}/${payload.required}`));
    return bits.join(' · ');
  }

  if(eventType === 'swap_window_started'){
    const bits = [];
    if(payload.swap_window_ends_at) bits.push(tr('room.activity.ends', {ts: fmt(payload.swap_window_ends_at)}, 'Ends ' + fmt(payload.swap_window_ends_at)));
    return bits.join(' · ');
  }

  if(eventType === 'swap_window_ended'){
    const bits = [];
    if(typeof payload.expired_swap_requests === 'number') bits.push(tr('room.activity.expired_swap_requests', {n: payload.expired_swap_requests}, 'Expired swap requests ' + payload.expired_swap_requests));
    return bits.join(' · ');
  }

  if(eventType === 'slot_swap_requested' || eventType === 'slot_swap_accepted' || eventType === 'slot_swap_declined' || eventType === 'slot_swap_cancelled'){
    if(payload.swap_id) return tr('room.activity.swap_id', {id: String(payload.swap_id)}, 'Swap #' + String(payload.swap_id));
    return '';
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

  function alreadyMasked(s){
    s = String(s||'');
    return s.includes('•') || s.includes('…') || s.includes('*');
  }
  function maskTail(s, tail=4){
    s = String(s||'').trim();
    if(!s) return '';
    if(alreadyMasked(s)) return s;
    if(s.length <= tail) return s;
    return '••••' + s.slice(-tail);
  }
  function maskCrypto(addr){
    addr = String(addr||'').trim();
    if(!addr) return '';
    if(alreadyMasked(addr)) return addr;
    if(addr.length <= 12) return addr;
    return addr.slice(0, 6) + '…' + addr.slice(-4);
  }

  if(a.account_type === 'mobile_money'){
    const carrier = a.carrier_id ? tr('room.dest.carrier', {id: a.carrier_id}, 'carrier ' + a.carrier_id) : tr('room.dest.mobile_money', null, 'mobile money');
    return carrier + ' · ' + maskTail(a.mobile_money_number||'');
  }
  if(a.account_type === 'bank'){
    const name = a.bank_name || tr('room.dest.bank', null, 'Bank');
    return name + ' · ' + maskTail(a.bank_account_number||'');
  }
  if(a.account_type === 'crypto_wallet'){
    const net = String(a.crypto_network || a.network || '').trim();
    const addr = String(a.crypto_address || a.address || '').trim();
    const shown = addr ? ((net ? '(' + net + ') ' : '') + maskCrypto(addr)) : '';
    if(shown){
      return tr('rooms.destination_account.summary.crypto_wallet', {addr: shown}, 'Crypto wallet ' + shown);
    }
    return tr('rooms.destination_account.summary.crypto_wallet_no_addr', null, 'Crypto wallet');
  }

  return '—';
}

let roomCache = null;
let lastEventId = 0;
let unlockClearTimer = null;
let roomTicker = null;
let timelineStage = '';

function roomCountdownText(r){
  if(!r) return '';

  const now = Date.now();

  const swapClosesAt = (r && r.swap_window && r.swap_window.closes_at) ? parseUtcDate(r.swap_window.closes_at) : null;
  const effStartAt = (String(r.room_state||'') === 'swap_window' && swapClosesAt && !isNaN(swapClosesAt.getTime()))
    ? swapClosesAt
    : parseUtcDate(r.start_at);

  const start = effStartAt;
  const reveal = parseUtcDate(r.reveal_at);

  const nextTurn = (r && r.active_cycle && r.active_cycle.due_at)
    ? parseUtcDate(r.active_cycle.due_at)
    : (String(r.room_state||'') === 'swap_window' ? swapClosesAt : null);

  function fmtDelta(ms){
    const s = Math.max(0, Math.floor(ms/1000));
    if(window.LS && LS.fmtCountdown) return LS.fmtCountdown(s);
    return String(s) + 's';
  }

  if(String(r.room_state||'') === 'swap_window' && nextTurn && !isNaN(nextTurn.getTime()) && now < nextTurn.getTime()){
    const delta = fmtDelta(nextTurn.getTime() - now);
    return tr('room.countdown.swap_closes_in', {delta}, 'Swap closes in ' + delta);
  }

  if(String(r.saving_type||'') === 'B'){
    const rs = String(r.room_state||'');

    if(rs === 'lobby'){
      const cnt = (r.approved_count != null) ? (r.approved_count|0) : 0;
      const min = (r.min_participants != null) ? (r.min_participants|0) : 0;
      if(min > 0){
        return tr('room.countdown.waiting_min_fmt', {n: cnt, min}, `Waiting for minimum participants (${cnt}/${min})`);
      }
      return tr('room.countdown.waiting_min', null, 'Waiting for minimum participants');
    }

    if(rs === 'swap_window'){
      return tr('room.state.swap_window', null, 'Swap window');
    }

    if(nextTurn && !isNaN(nextTurn.getTime()) && now < nextTurn.getTime()){
      const delta = fmtDelta(nextTurn.getTime() - now);
      return tr('room.countdown.next_turn_in', {delta}, 'Next turn in ' + delta);
    }

    if(rs === 'active'){
      return tr('room.state.active', null, 'Active');
    }

    return '';
  }

  if(start && !isNaN(start.getTime()) && now < start.getTime()){
    const delta = fmtDelta(start.getTime() - now);
    return tr('room.countdown.starts_in', {delta}, 'Starts in ' + delta);
  }

  if(reveal && !isNaN(reveal.getTime()) && now < reveal.getTime()){
    const delta = fmtDelta(reveal.getTime() - now);
    return tr('room.countdown.reveals_in', {delta}, 'Reveals in ' + delta);
  }

  return tr('room.countdown.eligible', null, 'Reveal eligible (server-enforced)');
}

function currentTimelineStage(r){
  if(!r) return '';

  const t = String(r.saving_type||'');
  const rs = String(r.room_state||'');

  if(rs === 'closed' || rs === 'cancelled') return 'done';
  if(rs === 'swap_window') return 'swap';
  if(rs === 'lobby') return 'lobby';

  if(t === 'A'){
    const ev = (r.unlock && r.unlock.event) ? r.unlock.event : null;
    if(ev && String(ev.status||'') === 'revealed') return 'unlock';

    const reveal = parseUtcDate(r.reveal_at);
    if(reveal && !isNaN(reveal.getTime()) && Date.now() >= reveal.getTime()) return 'unlock_vote';

    if(rs === 'active') return 'saving';
    return 'lobby';
  }

  if(t === 'B'){
    if(rs === 'active'){
      const cur = (r.rotation && r.rotation.current) ? r.rotation.current : null;
      const st = cur ? String(cur.status||'') : '';
      if(st === 'pending_votes') return 'turn_vote';
      if(st === 'revealed') return 'turn_withdraw';
      if(st === 'blocked_dispute' || st === 'blocked_debt') return 'blocked';
      return 'saving';
    }
    return rs;
  }

  return rs;
}

function timelineActiveStepId(r){
  const st = currentTimelineStage(r);
  if(st === 'swap') return 'swap';
  if(st === 'saving') return 'saving';
  if(st === 'unlock_vote' || st === 'unlock') return 'unlock';
  if(st === 'turn_vote' || st === 'turn_withdraw' || st === 'blocked') return 'turn';
  if(st === 'done') return 'done';
  return 'lobby';
}

function buildTimelineSteps(r){
  const steps = [];

  const t = String(r.saving_type||'');
  const rs = String(r.room_state||'');

  const hasSwap = !!(r.swap_window && r.swap_window.closes_at);
  const swapCloses = hasSwap ? String(r.swap_window.closes_at) : '';

  const effStartAt = (t === 'B' && swapCloses) ? swapCloses
    : ((rs === 'swap_window' && swapCloses) ? swapCloses : String(r.start_at||''));

  const activeDue = (r.active_cycle && r.active_cycle.due_at) ? String(r.active_cycle.due_at) : '';

  const lobbyMetaKey = (t === 'B' && rs === 'lobby' && !swapCloses)
    ? 'room.timeline.created_fmt'
    : 'room.timeline.starts_fmt';

  const lobbyMetaFallback = (t === 'B' && rs === 'lobby' && !swapCloses)
    ? `Created ${fmt(effStartAt)}`
    : `Starts ${fmt(effStartAt)}`;

  steps.push({
    id:'lobby',
    label: tr('room.timeline.lobby', null, 'Lobby'),
    meta: effStartAt ? tr(lobbyMetaKey, {ts: fmt(effStartAt)}, lobbyMetaFallback) : '',
    scroll: 'room-overview',
  });

  if(hasSwap){
    steps.push({
      id:'swap',
      label: tr('room.timeline.swap', null, 'Swap'),
      meta: tr('room.timeline.closes_fmt', {ts: fmt(swapCloses)}, `Closes ${fmt(swapCloses)}`),
      scroll: 'swap-block',
    });
  }

  steps.push({
    id:'saving',
    label: tr('room.timeline.saving', null, 'Saving'),
    meta: activeDue ? tr('room.timeline.due_fmt', {ts: fmt(activeDue)}, `Due ${fmt(activeDue)}`) : (effStartAt ? fmt(effStartAt) : ''),
    scroll: 'contrib-block',
  });

  if(t === 'A'){
    const revealAt = String(r.reveal_at||'');

    let unlockMeta = '';
    const ev = (r.unlock && r.unlock.event) ? r.unlock.event : null;
    if(ev && String(ev.status||'') === 'revealed' && ev.expires_at){
      unlockMeta = tr('room.timeline.expires_fmt', {ts: fmt(ev.expires_at)}, `Expires ${fmt(ev.expires_at)}`);
    } else if(revealAt){
      unlockMeta = tr('room.timeline.reveals_fmt', {ts: fmt(revealAt)}, `Reveals ${fmt(revealAt)}`);
    }

    steps.push({
      id:'unlock',
      label: tr('room.timeline.unlock', null, 'Unlock'),
      meta: unlockMeta,
      scroll: 'unlock-block',
    });

  } else if(t === 'B'){
    const cur = (r.rotation && r.rotation.current) ? r.rotation.current : null;
    const n = cur && cur.rotation_index ? String(cur.rotation_index) : '';

    let meta = '';
    if(cur){
      const st = String(cur.status||'');
      if(st === 'pending_votes' && cur.approve_due_at){
        meta = tr('room.timeline.vote_due_fmt', {ts: fmt(cur.approve_due_at)}, `Vote due ${fmt(cur.approve_due_at)}`);
      } else if(st === 'revealed' && cur.expires_at){
        meta = tr('room.timeline.expires_fmt', {ts: fmt(cur.expires_at)}, `Expires ${fmt(cur.expires_at)}`);
      } else if((st === 'blocked_dispute' || st === 'blocked_debt') && cur.dispute_window_ends_at){
        meta = tr('room.timeline.ends_fmt', {ts: fmt(cur.dispute_window_ends_at)}, `Ends ${fmt(cur.dispute_window_ends_at)}`);
      }
    }

    steps.push({
      id:'turn',
      label: n ? tr('room.timeline.turn_fmt', {n}, `Turn #${n}`) : tr('room.timeline.turn', null, 'Turn'),
      meta,
      scroll: 'typeb-block',
    });
  }

  steps.push({
    id:'done',
    label: tr('room.timeline.done', null, 'Done'),
    meta: (rs === 'cancelled') ? tr('room.state.cancelled', null, 'Cancelled') : ((rs === 'closed') ? tr('room.state.closed', null, 'Closed') : ''),
    scroll: '',
  });

  return steps;
}

function renderRoomTimeline(r){
  const wrap = document.getElementById('timeline-wrap');
  const el = document.getElementById('room-timeline');
  if(!wrap || !el || !r) return;

  wrap.style.display = 'block';

  const steps = buildTimelineSteps(r);
  const activeId = timelineActiveStepId(r);
  const activeIdx = Math.max(0, steps.findIndex(s => s.id === activeId));

  el.innerHTML = '';

  const head = document.createElement('div');
  head.className = 'room-tl-head';

  const cd = document.createElement('div');
  cd.id = 'room-tl-countdown';
  cd.className = 'room-tl-countdown';
  cd.textContent = roomCountdownText(r);

  const left = document.createElement('div');
  left.className = 'k';
  left.textContent = tr('room.timeline.next_deadline', null, 'Next deadline');

  head.appendChild(left);
  head.appendChild(cd);
  el.appendChild(head);

  const stepsWrap = document.createElement('div');
  stepsWrap.className = 'room-tl-steps';

  steps.forEach((s, idx) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'room-tl-step ' + (idx < activeIdx ? 'is-done' : (idx === activeIdx ? 'is-current' : 'is-upcoming'));
    b.dataset.scroll = s.scroll ? String(s.scroll) : '';

    b.innerHTML = '<span class="tl-dot"></span>'
      + '<div class="tl-title">' + esc(s.label) + '</div>'
      + (s.meta ? ('<div class="tl-meta">' + esc(s.meta) + '</div>') : '');

    b.addEventListener('click', () => {
      const target = String(b.dataset.scroll||'').trim();
      if(target) scrollToBlock(target);
    });

    stepsWrap.appendChild(b);
  });

  el.appendChild(stepsWrap);
}

function updateRoomCountdown(){
  const r = roomCache;
  if(!r) return;

  const txt = roomCountdownText(r);

  const el = document.getElementById('room-countdown');
  if(el) el.textContent = txt;

  const tl = document.getElementById('room-tl-countdown');
  if(tl) tl.textContent = txt;

  const st = currentTimelineStage(r);
  if(st && st !== timelineStage){
    timelineStage = st;
    renderRoomTimeline(r);
  }
}

function startRoomCountdown(){
  if(roomTicker) clearInterval(roomTicker);
  roomTicker = setInterval(updateRoomCountdown, 1000);
}

function renderAdminPanel(r){
  const wrap = document.getElementById('admin-panel');
  const body = document.getElementById('admin-panel-body');
  if(!wrap || !body) return;

  if(!IS_ADMIN){
    wrap.style.display='none';
    return;
  }

  const rows = [];
  rows.push(['Room ID', ROOM_ID]);
  rows.push(['room_state', r ? r.room_state : null]);
  rows.push(['saving_type', r ? r.saving_type : null]);
  rows.push(['visibility', r ? r.visibility : null]);
  rows.push(['lobby_state', r ? r.lobby_state : null]);
  rows.push(['my_status', r ? (r.my_status||'none') : null]);
  rows.push(['is_maker', (r && r.is_maker) ? '1' : '0']);

  if(r){
    rows.push(['approved_count', r.approved_count]);
    rows.push(['min_participants', r.min_participants]);
    rows.push(['max_participants', r.max_participants]);
    rows.push(['required_trust_level', r.required_trust_level]);
    rows.push(['periodicity', r.periodicity]);
    rows.push(['participation_amount', r.participation_amount]);
    rows.push(['start_at', r.start_at]);
    rows.push(['reveal_at', r.reveal_at]);

    if(r.swap_window){
      rows.push(['swap_window.is_open', r.swap_window.is_open]);
      rows.push(['swap_window.closes_at', r.swap_window.closes_at]);
    }

    const slots = Array.isArray(r.slots) ? r.slots : [];
    const swaps = Array.isArray(r.slot_swaps) ? r.slot_swaps : [];
    rows.push(['slots', String(slots.length)]);
    rows.push(['slot_swaps', String(swaps.length)]);
  }

  body.innerHTML = '<div style="font-size:12px;line-height:1.7;">' + rows.map(([k,v]) => {
    const vv = (v === null || typeof v === 'undefined' || v === '') ? '—' : String(v);
    return '<div><span class="k">' + esc(k) + ':</span> ' + esc(vv) + '</div>';
  }).join('') + '</div>';
}

function scrollToBlock(id){
  const el = document.getElementById(id);
  if(!el) return;
  try{
    el.scrollIntoView({behavior:'smooth', block:'start'});
  }catch(e){
    el.scrollIntoView(true);
  }
}

function computeNextStep(r){
  const now = Date.now();

  const step = {kind:'info', title:'', body:'', actions:[]};
  function set(kind, title, body){
    step.kind = kind;
    step.title = title;
    step.body = body;
    return step;
  }
  function addAction(a){ step.actions.push(a); }

  const myStatus = String(r.my_status||'');
  const roomState = String(r.room_state||'');
  const lobbyState = String(r.lobby_state||'');
  const savingType = String(r.saving_type||'');

  if(!myStatus && r.my_invite && roomState === 'lobby' && lobbyState === 'open'){
    set('warn',
      tr('room.next.invited_title', null, 'Invitation pending'),
      tr('room.next.invited_body', null, 'You have been invited to this room. Accept to join or decline if you’re not participating.')
    );
    addAction({text: tr('room.next.cta.review_invite', null, 'Review invitation'), type:'primary', scroll:'invite-block'});
    return step;
  }

  const canJoin = (!myStatus || myStatus === 'declined') && roomState === 'lobby' && lobbyState === 'open' && r.visibility !== 'private';
  if(canJoin){
    set('info',
      tr('room.next.join_title', null, 'Join this room'),
      tr('room.next.join_body', null, 'Send a join request. The maker will approve or decline.')
    );
    addAction({text: tr('room.action.request_join', null, 'Request to join'), type:'primary', onClick:'requestJoin'});
    return step;
  }

  if(myStatus === 'pending'){
    set('info',
      tr('room.next.pending_title', null, 'Waiting for approval'),
      tr('room.next.pending_body', null, 'Your join request is pending. You’ll be able to participate once approved.')
    );
    return step;
  }

  if(myStatus === 'approved' && roomState === 'lobby' && savingType === 'A'){
    set('info',
      tr('room.next.approved_prestart_title', null, 'Approved'),
      tr('room.next.approved_prestart_body_fmt', {ts: fmt(r.start_at)}, 'You are approved. The room will start at {ts}.')
    );
    return step;
  }

  if(savingType === 'B' && roomState === 'lobby' && myStatus){
    const cnt = (r.approved_count != null) ? (r.approved_count|0) : 0;
    const min = (r.min_participants != null) ? (r.min_participants|0) : 0;
    if(min > 0 && cnt < min){
      set('info',
        tr('room.next.waiting_min_title', null, 'Waiting for participants'),
        tr('room.next.waiting_min_body_fmt', {n: cnt, min}, `Waiting for minimum participants (${cnt}/${min}).`)
      );
      return step;
    }
  }

  if(roomState === 'swap_window'){
    const closes = (r.swap_window && r.swap_window.closes_at) ? fmt(r.swap_window.closes_at) : '—';
    set('warn',
      tr('room.next.swap_title', null, 'Swap window open'),
      tr('room.next.swap_body_fmt', {ts: closes}, 'Swap window is open until {ts}. You can request a position swap.')
    );
    if(myStatus === 'approved' || myStatus === 'active'){
      addAction({text: tr('room.next.cta.open_swap', null, 'Open swap'), type:'primary', scroll:'swap-block'});
    }
    return step;
  }

  if(roomState === 'active' && myStatus === 'active'){
    // Exit request vote is time-sensitive.
    if(savingType === 'B' && r.exit_request && String(r.exit_request.status||'') === 'open'){
      const er = r.exit_request;
      if(!er.is_requester && !er.my_vote){
        set('warn',
          tr('room.next.exit_vote_title', null, 'Exit vote pending'),
          tr('room.next.exit_vote_body_fmt', {name: String(er.requested_by_name||'')}, 'Vote on the exit request from {name}.')
        );
        addAction({text: tr('room.next.cta.open_exit', null, 'Open exit request'), type:'primary', scroll:'exit-block'});
        return step;
      }
    }

    // Dispute acknowledgement (Type B)
    if(savingType === 'B'){
      const cur = (r.rotation && r.rotation.current) ? r.rotation.current : null;
      const dispute = (r.rotation && r.rotation.dispute) ? r.rotation.dispute : null;
      if(cur && dispute && !dispute.my_ack && cur.dispute_window_ends_at){
        const ends = parseUtcDate(cur.dispute_window_ends_at);
        if(ends && !isNaN(ends.getTime()) && now < ends.getTime()){
          set('warn',
            tr('room.next.dispute_ack_title', null, 'Dispute open'),
            tr('room.next.dispute_ack_body_fmt', {ts: fmt(cur.dispute_window_ends_at)}, 'A dispute is open. Acknowledge before {ts}.')
          );
          addAction({text: tr('room.next.cta.open_dispute', null, 'Open dispute'), type:'primary', scroll:'typeb-dispute-wrap'});
          return step;
        }
      }
    }

    // Contribution (all types)
    if(r.active_cycle){
      const cyc = r.active_cycle;
      const contrib = r.my_active_cycle_contribution || null;
      const dueAt = fmt(cyc.due_at);
      const graceAt = cyc.grace_ends_at ? fmt(cyc.grace_ends_at) : '';
      const deadline = (String(cyc.status||'') === 'grace' && graceAt) ? graceAt : dueAt;

      const cycLabel = tr('room.next.cycle_fmt', {n: String(cyc.cycle_index)}, 'Cycle #' + String(cyc.cycle_index));

      if(!contrib || String(contrib.status||'') === 'unpaid'){
        set('warn',
          tr('room.next.contribution_due_title', null, 'Contribution due'),
          tr('room.next.contribution_due_body_fmt', {cycle: cycLabel, ts: deadline}, '{cycle} is due by {ts}. Upload your proof to confirm your contribution.')
        );
        addAction({text: tr('room.contribution.open_proofs_btn', null, 'Open My proofs'), type:'primary', href:'rooms_proofs.php?room_id=' + encodeURIComponent(ROOM_ID)});
        return step;
      }

      if(String(contrib.status||'') === 'paid' || String(contrib.status||'') === 'paid_in_grace'){
        set('ok',
          tr('room.next.contribution_done_title', null, 'Contribution recorded'),
          tr('room.next.contribution_done_body_fmt', {cycle: cycLabel, ts: dueAt}, '{cycle} is recorded. Next due date is {ts}.')
        );
        addAction({text: tr('room.contribution.open_proofs_btn', null, 'Open My proofs'), type:'ghost', href:'rooms_proofs.php?room_id=' + encodeURIComponent(ROOM_ID)});
        return step;
      }

      if(String(contrib.status||'') === 'missed'){
        const by = graceAt || dueAt;
        set('err',
          tr('room.next.contribution_missed_title', null, 'Contribution missed'),
          tr('room.next.contribution_missed_body_fmt', {cycle: cycLabel, ts: by}, '{cycle} was missed (grace ended {ts}). Contact the maker if you believe this is incorrect.')
        );
        addAction({text: tr('room.contribution.open_proofs_btn', null, 'Open My proofs'), type:'ghost', href:'rooms_proofs.php?room_id=' + encodeURIComponent(ROOM_ID)});
        return step;
      }
    }

    // Type A unlock vote/reveal
    if(savingType === 'A' && r.unlock){
      const approvals = (r.unlock.votes && typeof r.unlock.votes.approvals !== 'undefined') ? (r.unlock.votes.approvals|0) : 0;
      const eligible = (r.unlock.votes && typeof r.unlock.votes.eligible !== 'undefined') ? (r.unlock.votes.eligible|0) : 0;
      const myVote = r.unlock.my_vote ? String(r.unlock.my_vote) : 'none';
      const ev = r.unlock.event;

      if(eligible > 0 && approvals < eligible && myVote === 'none'){
        set('warn',
          tr('room.next.unlock_vote_title', null, 'Unlock vote needed'),
          tr('room.next.unlock_vote_body_fmt', {a: approvals, b: eligible}, 'Cast your vote to unlock ({a}/{b} approvals).')
        );
        addAction({text: tr('room.next.cta.open_unlock', null, 'Open unlock'), type:'primary', scroll:'unlock-block'});
        return step;
      }

      if(ev && ev.status === 'revealed'){
        set('info',
          tr('room.next.unlock_revealed_title', null, 'Unlock code available'),
          tr('room.next.unlock_revealed_body_fmt', {ts: fmt(ev.expires_at)}, 'The unlock code has been revealed. It expires at {ts}.')
        );
        addAction({text: tr('room.next.cta.open_unlock', null, 'Open unlock'), type:'primary', scroll:'unlock-block'});
        return step;
      }
    }

    // Type B vote/reveal/withdrawal
    if(savingType === 'B' && r.rotation && r.rotation.current){
      const cur = r.rotation.current;
      const votesMeta = r.rotation.votes || {};
      const myVote = r.rotation.my_vote ? String(r.rotation.my_vote) : 'none';
      const isTurnUser = (cur.turn_user_id|0) === (CURRENT_USER_ID|0);
      const isOpen = (votesMeta.is_open === 1);
      const isClosed = (votesMeta.is_closed === 1);
      const eligibleCount = (typeof votesMeta.eligible === 'number') ? (votesMeta.eligible|0) : 0;
      const requiredCount = (typeof votesMeta.required === 'number') ? (votesMeta.required|0) : 0;
      const voteCast = (myVote === 'approve' || myVote === 'reject');

      if(cur.status === 'pending_votes' && !isTurnUser && isOpen && !isClosed && !voteCast && eligibleCount > 0 && requiredCount > 0){
        set('warn',
          tr('room.next.turn_vote_title', null, 'Turn vote needed'),
          tr('room.next.turn_vote_body_fmt', {n: cur.rotation_index, name: String(cur.turn_user_name||'')}, 'Vote on turn #{n} for {name}.')
        );
        addAction({text: tr('room.next.cta.open_turn', null, 'Open turn'), type:'primary', scroll:'typeb-block'});
        return step;
      }

      if(cur.status === 'revealed' && cur.can_confirm_withdrawal === 1 && !cur.withdrawal_confirmed_at){
        set('warn',
          tr('room.next.withdraw_confirm_title', null, 'Confirm withdrawal'),
          tr('room.next.withdraw_confirm_body', null, 'After collecting the funds, confirm the withdrawal to advance the room.')
        );
        addAction({text: tr('room.next.cta.open_withdrawal', null, 'Open withdrawal'), type:'primary', scroll:'typeb-withdraw-wrap'});
        return step;
      }

      if(cur.status === 'revealed' && cur.can_reveal_code === 1){
        set('info',
          tr('room.next.reveal_code_title', null, 'Reveal code'),
          tr('room.next.reveal_code_body_fmt', {n: cur.rotation_index}, 'Reveal the destination code for turn #{n}.')
        );
        addAction({text: tr('room.next.cta.open_turn', null, 'Open turn'), type:'primary', scroll:'typeb-block'});
        return step;
      }
    }

    set('info',
      tr('room.next.active_title', null, 'No action needed'),
      tr('room.next.active_body', null, 'You are up to date. Keep an eye on the countdown and activity feed.')
    );
    return step;
  }

  if(roomState === 'closed' || roomState === 'cancelled'){
    set('info',
      tr('room.next.closed_title', null, 'Room finished'),
      tr('room.next.closed_body', null, 'This room is no longer active.')
    );
    return step;
  }

  set('info',
    tr('room.next.default_title', null, 'Next step'),
    tr('room.next.default_body', null, 'Review the room status and wait for the next window.')
  );
  return step;
}

function renderNextPanel(r){
  const wrap = document.getElementById('next-wrap');
  const panel = document.getElementById('next-panel');
  const actionsEl = document.getElementById('next-actions');
  if(!wrap || !panel || !actionsEl) return;

  wrap.style.display = 'block';

  const step = computeNextStep(r);
  const kind = String(step.kind||'info');

  panel.className = 'next-panel kind-' + kind;
  panel.innerHTML = '<div class="next-title">' + esc(step.title||'') + '</div>'
    + '<div>' + esc(step.body||'') + '</div>';

  actionsEl.innerHTML = '';
  (step.actions||[]).forEach(a => {
    const hasHref = !!a.href;
    const el = document.createElement(hasHref ? 'a' : 'button');

    const t = String(a.type||'ghost');
    el.className = 'btn btn-' + t + ' btn-sm';

    if(hasHref){
      el.href = String(a.href);
    } else {
      el.type = 'button';
    }

    el.textContent = String(a.text||'');

    el.addEventListener('click', (ev) => {
      if(a.scroll){
        ev.preventDefault();
        scrollToBlock(String(a.scroll));
        return;
      }

      if(a.onClick){
        ev.preventDefault();
        const fn = window[String(a.onClick)];
        if(typeof fn === 'function') fn();
      }
    });

    actionsEl.appendChild(el);
  });
}

function renderRoom(){
  const r = roomCache;
  if(!r) return;

  const swapClosesAt = (r.swap_window && r.swap_window.closes_at) ? String(r.swap_window.closes_at) : '';

  const effStartAt = (String(r.saving_type||'') === 'B' && swapClosesAt)
    ? swapClosesAt
    : ((String(r.room_state||'') === 'swap_window' && swapClosesAt) ? swapClosesAt : r.start_at);

  const startLocal = fmt(effStartAt);
  const startUtc = fmtUtc(effStartAt);
  const revealLocal = fmt(r.reveal_at);
  const revealUtc = fmtUtc(r.reveal_at);

  const utcTitle = tr('rooms.utc_title', null, 'Stored/enforced in UTC');

  document.getElementById('room-title').textContent = r.goal_text || tr('page.room', null, 'Room');

  const periodicityLabel = prettyPeriodicity(r.periodicity) || String(r.periodicity||'');
  const subtitleKey = (String(r.saving_type||'') === 'B' && String(r.room_state||'') === 'lobby' && !swapClosesAt)
    ? 'room.ov.subtitle_created_html'
    : 'room.ov.subtitle_html';

  document.getElementById('room-sub').innerHTML = tr(subtitleKey, {
    type: esc(r.saving_type),
    level: esc(r.required_trust_level),
    periodicity: esc(periodicityLabel),
    start_local: esc(startLocal),
    start_utc: esc(startUtc),
    utc_title: esc(utcTitle),
  }, `Type ${esc(r.saving_type)} · Level ${esc(r.required_trust_level)} · ${esc(periodicityLabel)} · Starts <b>${esc(startLocal)}</b> <span class="utc-pill" title="${esc(utcTitle)}">${esc(startUtc)}</span>`);

  const ov = document.getElementById('room-overview');

  const badges = [];
  badges.push(`<span class="badge">${esc(shortSavingType(r.saving_type))}</span>`);

  if(r.purpose_category && r.purpose_category !== 'other'){
    const p = tr('rooms.purpose.' + String(r.purpose_category), null, String(r.purpose_category));
    badges.push(`<span class="badge">${esc(p)}</span>`);
  }

  if(r.visibility && r.visibility !== 'public'){
    badges.push(`<span class="badge">${esc(prettyVisibility(r.visibility))}</span>`);
  }

  const rs = prettyRoomState(r);
  const rsCls = roomStateBadgeClass(r);
  badges.push(`<span class="badge ${rsCls}">${esc(rs)}</span>`);

  if(r.my_invite && !r.my_status){
    badges.push(`<span class="badge info">${esc(tr('room.status.invited', null, 'Invited'))}</span>`);
  }

  if(r.my_status){
    const ms = prettyMyStatus(r.my_status);
    const msCls = myStatusBadgeClass(r.my_status);
    badges.push(`<span class="badge ${msCls}">${esc(tr('room.status.you_fmt', {status: ms}, 'You: ' + ms))}</span>`);
  }

  const items = [];
  items.push({k: tr('room.ov.participation_amount', null, 'Participation amount'), v: esc(r.participation_amount||'—')});
  items.push({k: tr('room.ov.period', null, 'Period'), v: esc(prettyPeriodicity(r.periodicity)||'—')});
  items.push({k: tr('room.ov.start_date', null, 'Start date'), v: esc(startLocal||'—')});

  if(r.saving_type === 'B'){
    // Type B rooms do not use a user-facing "reveal date". Show next turn date + expected withdrawal instead.
    const nextTurn = (function(){
      if(r.room_state === 'active' && r.active_cycle && r.active_cycle.due_at) return fmt(r.active_cycle.due_at);

      if(r.room_state === 'swap_window' && r.swap_window && r.swap_window.closes_at){
        const closes = parseUtcDate(r.swap_window.closes_at);
        const firstTurn = addPeriod(closes, String(r.periodicity||'weekly'));
        return firstTurn ? fmt(firstTurn) : fmt(r.swap_window.closes_at);
      }

      return '—';
    })();

    items.push({k: tr('room.ov.next_turn_date', null, 'Next turn date'), v: esc(nextTurn||'—')});

    let expected = (r.required_withdrawal_amount != null && String(r.required_withdrawal_amount) !== '')
      ? String(r.required_withdrawal_amount)
      : '';

    if(!expected){
      const amt = parseFloat(String(r.participation_amount||''));
      const n = parseInt(String(r.approved_count||'0'), 10);
      if(!isNaN(amt) && !isNaN(n) && n > 0){
        expected = (amt * n).toFixed(2);
      }
    }

    items.push({k: tr('room.ov.expected_withdrawal_amount', null, 'Expected withdrawal'), v: esc(expected||'—')});

  } else {
    items.push({k: tr('room.ov.reveal_date', null, 'Reveal date'), v: esc(revealLocal||'—')});
  }

  items.push({k: tr('room.ov.participants', null, 'Participants'), v: esc(`${r.approved_count||0} / ${r.max_participants||0}`)});

  const canSeeDest = !!(r.is_maker || (r.my_status && r.my_status !== 'declined'));
  if(canSeeDest && r.destination_account){
    items.push({k: tr('room.ov.destination', null, 'Destination'), v: esc(destSummary(r.destination_account))});
  }

  ov.innerHTML = `
    <div class="room-ov-head">
      <div class="room-ov-badges">${badges.join('')}</div>
    </div>
    <div class="room-ov-grid">
      ${items.map(it => `<div class="room-ov-item"><div class="k">${esc(it.k)}</div><div class="v">${it.v}</div></div>`).join('')}
    </div>
    <div class="room-ov-foot">
      <div class="k">${esc(tr('room.ov.countdown', null, 'Countdown'))}</div>
      <div class="v" id="room-countdown"></div>
    </div>
  `;

  timelineStage = currentTimelineStage(r);
  renderRoomTimeline(r);

  renderNextPanel(r);
  renderAdminPanel(r);

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
      const amt = document.getElementById('contrib-amount');
      if(amt){
        amt.textContent = String(r.participation_amount||'—');
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

      document.getElementById('unlock-consensus').textContent = tr('room.unlock.consensus_you', {approvals, eligible, vote: myVote}, `${approvals}/${eligible} (you: ${myVote})`);

      const approveBtn = document.getElementById('unlock-vote-approve');
      const rejectBtn = document.getElementById('unlock-vote-reject');

      let voteDisabledReason = '';
      if(r.room_state !== 'lobby' && r.room_state !== 'active'){
        voteDisabledReason = tr('room.vote.disabled_unavailable', null, 'Voting is unavailable.');
      } else if(myVote !== 'none'){
        voteDisabledReason = tr('room.vote.disabled_already_voted_fmt', {vote: String(myVote)}, `Vote already cast (you: ${myVote}).`);
      }

      setBtnDisabled(approveBtn, voteDisabledReason);
      setBtnDisabled(rejectBtn, voteDisabledReason);

      const ev = r.unlock ? r.unlock.event : null;
      if(ev && ev.status === 'revealed'){
        document.getElementById('unlock-window').textContent = tr('room.unlock.window_revealed_expires', {ts: fmt(ev.expires_at)}, `Revealed · expires ${fmt(ev.expires_at)}`);
      } else if(ev && ev.status === 'expired'){
        document.getElementById('unlock-window').textContent = tr('room.unlock.window_expired', null, 'Expired');
      } else {
        document.getElementById('unlock-window').textContent = tr('room.unlock.window_pending', null, 'Pending');
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
        const turnUser = cur.turn_user_name || tr('common.user', null, 'user');
        const slots = Array.isArray(r.slots) ? r.slots : [];
        const slotRow = slots.find(x => x && ((x.user_id|0) === (cur.turn_user_id|0)));
        const posTxt = slotRow && slotRow.position
          ? (' · ' + tr('room.rotation.position_fmt', {n: String(slotRow.position)}, 'Position ' + String(slotRow.position)))
          : '';

        document.getElementById('typeb-turn').textContent = `#${cur.rotation_index} · ${turnUser}${posTxt}`;

        document.getElementById('typeb-consensus').textContent = tr('room.rotation.consensus_you_required', {
          approvals,
          required,
          vote: myVote,
          eligible,
        }, `${approvals}/${required} required (you: ${myVote} · eligible ${eligible})`);

        if(cur.status === 'revealed'){
          const expTs = fmt(cur.expires_at);
          const graceTs = cur.grace_ends_at ? fmt(cur.grace_ends_at) : '';
          if(graceTs){
            document.getElementById('typeb-window').textContent = tr('room.rotation.window_revealed_grace_expires_fmt', {grace: graceTs, ts: expTs}, `Revealed · grace until ${graceTs} · expires ${expTs}`);
          } else {
            document.getElementById('typeb-window').textContent = tr('room.unlock.window_revealed_expires', {ts: expTs}, `Revealed · expires ${expTs}`);
          }
        } else if(cur.status === 'blocked_dispute'){
          document.getElementById('typeb-window').textContent = tr('room.rotation.blocked_dispute', null, 'Blocked (dispute)');
        } else if(cur.status === 'blocked_debt'){
          document.getElementById('typeb-window').textContent = tr('room.rotation.blocked_debt', null, 'Blocked (unpaid contribution)');
        } else {
          document.getElementById('typeb-window').textContent = tr('room.rotation.pending_votes', null, 'Pending votes');
        }

        document.getElementById('typeb-maker').textContent = makerVote;

        // Room balance / required amount (updates as proofs are submitted and withdrawals are confirmed)
        const balEl = document.getElementById('typeb-balance');
        const reqEl = document.getElementById('typeb-required');
        if(balEl || reqEl){
          const hasBal = !(r.account_balance === null || typeof r.account_balance === 'undefined' || String(r.account_balance) === '');
          const bal = hasBal ? String(r.account_balance) : '—';
          const req = (r.required_withdrawal_amount != null && String(r.required_withdrawal_amount) !== '') ? String(r.required_withdrawal_amount) : '—';
          if(balEl) balEl.textContent = bal;
          if(reqEl) reqEl.textContent = req;
        }

        const approveBtn = document.getElementById('typeb-vote-approve');
        const rejectBtn = document.getElementById('typeb-vote-reject');

        const voteCast = (myVote === 'approve' || myVote === 'reject');
        const votesMeta = (r.rotation && r.rotation.votes) ? r.rotation.votes : {};
        const isOpen = (votesMeta.is_open === 1);
        const isClosed = (votesMeta.is_closed === 1);
        const isTurnUser = (cur.turn_user_id|0) === (CURRENT_USER_ID|0);
        const isMaker = (r.is_maker === 1);

        const canVoteRole = (!isTurnUser);
        const votingWindow = (r.room_state === 'active' && r.my_status === 'active' && cur.status === 'pending_votes');

        const eligibleCount = (votesMeta && typeof votesMeta.eligible === 'number') ? (votesMeta.eligible|0) : 0;
        const requiredCount = (votesMeta && typeof votesMeta.required === 'number') ? (votesMeta.required|0) : 0;

        // Hide vote buttons entirely unless the room is active and the approval window is open.
        // Maker vote is required even when participant votes are not.
        const showVoteButtons = (votingWindow && canVoteRole && isOpen && !isClosed && !voteCast && (isMaker || (eligibleCount > 0 && requiredCount > 0)));

        if(approveBtn) approveBtn.style.display = showVoteButtons ? 'inline-flex' : 'none';
        if(rejectBtn) rejectBtn.style.display = showVoteButtons ? 'inline-flex' : 'none';

        if(!showVoteButtons){
          setBtnDisabled(approveBtn, '');
          setBtnDisabled(rejectBtn, '');
        } else {
          let voteDisabledReason = '';

          if(voteCast){
            voteDisabledReason = tr('room.vote.disabled_already_voted_fmt', {vote: String(myVote)}, `Vote already cast (you: ${myVote}).`);
          } else if(!isOpen && votesMeta.opens_at){
            voteDisabledReason = tr('room.rotation.vote_disabled_opens_fmt', {ts: fmt(votesMeta.opens_at)}, 'Voting opens ' + fmt(votesMeta.opens_at));
          } else if(isClosed){
            voteDisabledReason = tr('room.rotation.vote_disabled_closed', null, 'Voting window is closed.');
          } else if(!isOpen){
            voteDisabledReason = tr('room.rotation.vote_disabled_unavailable', null, 'Voting is unavailable.');
          }

          const canVoteNow = (isOpen && !isClosed && !voteCast && !voteDisabledReason);
          setBtnDisabled(approveBtn, canVoteNow ? '' : voteDisabledReason);
          setBtnDisabled(rejectBtn, canVoteNow ? '' : voteDisabledReason);
        }

        // Approval window status text
        if(cur.status === 'pending_votes'){
          if(!isOpen && votesMeta.opens_at){
            document.getElementById('typeb-window').textContent = tr('room.rotation.approval_opens_fmt', {ts: fmt(votesMeta.opens_at)}, 'Approval opens ' + fmt(votesMeta.opens_at));
          } else if(isClosed && votesMeta.due_at){
            document.getElementById('typeb-window').textContent = tr('room.rotation.approval_closed_fmt', {ts: fmt(votesMeta.due_at)}, 'Approval window closed ' + fmt(votesMeta.due_at));
          } else if(votesMeta.due_at && typeof votesMeta.seconds_remaining === 'number'){
            const s = Math.max(0, votesMeta.seconds_remaining|0);
            const h = Math.floor(s/3600);
            const m = Math.floor((s%3600)/60);
            document.getElementById('typeb-window').textContent = tr('room.rotation.approval_due_in_fmt', {ts: fmt(votesMeta.due_at), h, m}, `Approval due ${fmt(votesMeta.due_at)} (in ${h}h ${m}m)`);
          } else {
            document.getElementById('typeb-window').textContent = tr('room.rotation.pending_votes', null, 'Pending votes');
          }
        }

        const canRevealB = (r.room_state === 'active' && (r.my_status === 'active' || IS_ADMIN) && cur.status === 'revealed' && (cur.can_reveal_code === 1));
        document.getElementById('typeb-reveal-btn').style.display = canRevealB ? 'inline-flex' : 'none';

        // Delegate UI
        const delWrap = document.getElementById('typeb-delegate-wrap');
        if(delWrap){
          const meta = document.getElementById('typeb-delegate-meta');
          const form = document.getElementById('typeb-delegate-form');
          const sel = document.getElementById('typeb-delegate-user');

          const canSee = (cur.status === 'revealed');
          delWrap.style.display = canSee ? 'block' : 'none';

          if(canSee){
            if(cur.delegate_name){
              meta.textContent = tr('room.rotation.delegate_current_fmt', {name: cur.delegate_name}, `Delegated to: ${cur.delegate_name}`);
            } else {
              meta.textContent = tr('room.rotation.delegate_none', null, 'No delegate set.');
            }

            const canSet = (cur.can_set_delegate === 1);
            form.style.display = canSet ? 'block' : 'none';

            if(canSet && sel){
              const rows = (roomCache && roomCache.participants) ? roomCache.participants : [];
              const opts = rows.filter(x => x && x.status === 'active' && x.user_id !== cur.turn_user_id);
              sel.innerHTML = '<option value="0">' + esc(tr('room.rotation.delegate_select_placeholder', null, 'Select a participant')) + '</option>';
              opts.forEach(x => {
                const o = document.createElement('option');
                o.value = String(x.user_id);
                o.textContent = String(x.display_name||('User #' + x.user_id));
                if(cur.delegate_user_id && x.user_id === cur.delegate_user_id) o.selected = true;
                sel.appendChild(o);
              });
            }
          }
        }

        // Withdrawal confirmation UI
        const wdWrap = document.getElementById('typeb-withdraw-wrap');
        if(wdWrap){
          const meta = document.getElementById('typeb-withdraw-meta');
          const btn = document.getElementById('typeb-confirm-btn');

          const canSee = (cur.status === 'revealed');
          wdWrap.style.display = canSee ? 'block' : 'none';

          if(canSee){
            const hasBal = !(r.account_balance === null || typeof r.account_balance === 'undefined' || String(r.account_balance) === '');
            const bal = hasBal ? String(r.account_balance) : '—';
            const req = (r.required_withdrawal_amount != null) ? String(r.required_withdrawal_amount) : '';

            const balNum = hasBal ? parseFloat(bal) : NaN;
            const reqNum = parseFloat(req);
            const hasReq = (!isNaN(reqNum) && reqNum > 0);
            const insufficient = (hasReq && hasBal && !isNaN(balNum) && balNum + 0.00001 < reqNum);

            if(cur.withdrawal_confirmed_at){
              const by = cur.withdrawal_confirmed_by_name ? (' · ' + String(cur.withdrawal_confirmed_by_name)) : '';
              const role = cur.withdrawal_confirmed_role ? (' · ' + String(cur.withdrawal_confirmed_role)) : '';
              const ref = cur.withdrawal_reference ? (' · ' + String(cur.withdrawal_reference)) : '';
              meta.textContent = tr('room.rotation.withdrawal_confirmed_fmt', {ts: fmt(cur.withdrawal_confirmed_at)}, `Confirmed ${fmt(cur.withdrawal_confirmed_at)}`) + role + by + ref;
            } else {
              const base = tr('room.rotation.withdrawal_not_confirmed', null, 'Not confirmed yet.');
              const balLine = hasReq
                ? tr('room.rotation.withdrawal_balance_fmt', {bal, req}, `Balance ${bal} / Required ${req}`)
                : tr('room.rotation.withdrawal_balance_only_fmt', {bal}, `Balance ${bal}`);
              const warn = insufficient ? (' · ' + tr('room.rotation.withdrawal_blocked_balance', null, 'Blocked (insufficient balance)')) : '';
              meta.textContent = base + ' · ' + balLine + warn;
            }

            const canConfirm = (cur.can_confirm_withdrawal === 1) && !insufficient && !cur.withdrawal_confirmed_at;
            if(btn) btn.style.display = canConfirm ? 'inline-flex' : 'none';
          }
        }

        // History
        const hWrap = document.getElementById('typeb-history-wrap');
        if(hWrap){
          const rows = r.rotation_history || [];
          const empty = document.getElementById('typeb-history-empty');
          const wrap = document.getElementById('typeb-history-table-wrap');
          const tbody = document.querySelector('#typeb-history-table tbody');

          const show = (rows && rows.length);
          hWrap.style.display = show ? 'block' : 'none';
          if(show){
            wrap.style.display = 'block';
            empty.style.display = 'none';
            tbody.innerHTML = '';

            rows.forEach(x => {
              const trEl = document.createElement('tr');
              const codeTxt = x.code_last_viewed_at
                ? (fmt(x.code_last_viewed_at) + (x.code_last_viewed_role ? (' · ' + x.code_last_viewed_role) : '') + (x.code_last_viewed_by_name ? (' · ' + x.code_last_viewed_by_name) : ''))
                : '—';

              let wdTxt = '—';
              if(x.withdrawal_confirmed_at){
                wdTxt = fmt(x.withdrawal_confirmed_at) + (x.withdrawal_confirmed_role ? (' · ' + x.withdrawal_confirmed_role) : '') + (x.withdrawal_confirmed_by_name ? (' · ' + x.withdrawal_confirmed_by_name) : '');
              } else if(x.status === 'expired') {
                wdTxt = tr('room.rotation.withdrawal_unconfirmed', null, 'Unconfirmed');
              }

              const collectedTxt = (x.collected_amount != null && String(x.collected_amount) !== '')
                ? String(x.collected_amount)
                : '—';

              trEl.innerHTML = `
                <td>#${esc(String(x.rotation_index||''))}</td>
                <td>${esc(String(x.turn_user_name||''))}${x.delegate_name ? ('<div class="small">' + esc(tr('room.rotation.delegate_short_fmt', {name: String(x.delegate_name)}, 'delegate: ' + String(x.delegate_name))) + '</div>') : ''}</td>
                <td>${esc(codeTxt)}</td>
                <td>${esc(collectedTxt)}</td>
                <td>${esc(wdTxt)}</td>
              `;
              tbody.appendChild(trEl);
            });
          } else {
            wrap.style.display = 'none';
            empty.style.display = 'block';
            tbody.innerHTML = '';
          }

        }

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
            const windowTs = fmt(cur.dispute_window_ends_at);
            const windowTxt = within
              ? tr('room.dispute.window_ends_fmt', {ts: windowTs}, 'window ends ' + windowTs)
              : tr('room.dispute.window_ended_fmt', {ts: windowTs}, 'window ended ' + windowTs);

            if(dispute){
              const who = dispute.raised_by_name || tr('common.participant', null, 'participant');
              meta.textContent = tr('room.dispute.meta_fmt', {
                status: String(dispute.status||''),
                ack_count: dispute.ack_count,
                required: dispute.threshold_required,
                who,
                window: windowTxt,
              }, `${dispute.status} · ${dispute.ack_count}/${dispute.threshold_required} acknowledgements · raised by ${who} · ${windowTxt}`);

              form.style.display = 'none';

              const canAck = within && (r.my_status === 'active') && !dispute.my_ack && (dispute.status !== 'validated' && dispute.status !== 'dismissed');
              actions.style.display = canAck ? 'block' : 'none';

              if(ackBtn){
                ackBtn.disabled = !canAck;
              }
            } else {
              meta.textContent = tr('room.dispute.meta_none_fmt', {window: windowTxt}, `No dispute · ${windowTxt}`);
              actions.style.display = 'none';
              form.style.display = (within && r.my_status === 'active') ? 'block' : 'none';
            }
          }
        }

      } else {
        document.getElementById('typeb-turn').textContent = '—';
        document.getElementById('typeb-consensus').textContent = '—';
        const balEl = document.getElementById('typeb-balance');
        const reqEl = document.getElementById('typeb-required');
        if(balEl) balEl.textContent = '—';
        if(reqEl) reqEl.textContent = '—';
        document.getElementById('typeb-window').textContent = '—';
        document.getElementById('typeb-maker').textContent = '—';
        const approveBtn = document.getElementById('typeb-vote-approve');
        const rejectBtn = document.getElementById('typeb-vote-reject');
        if(approveBtn) approveBtn.style.display = 'none';
        if(rejectBtn) rejectBtn.style.display = 'none';
        setBtnDisabled(approveBtn, '');
        setBtnDisabled(rejectBtn, '');

        document.getElementById('typeb-reveal-btn').style.display = 'none';
        const delWrap = document.getElementById('typeb-delegate-wrap');
        if(delWrap) delWrap.style.display = 'none';
        const wdWrap = document.getElementById('typeb-withdraw-wrap');
        if(wdWrap) wdWrap.style.display = 'none';
        const hWrap = document.getElementById('typeb-history-wrap');
        if(hWrap) hWrap.style.display = 'none';
        const dispWrap = document.getElementById('typeb-dispute-wrap');
        if(dispWrap) dispWrap.style.display = 'none';
      }
    }
  }

  renderSwapWindow(r);

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
        if(meta) meta.textContent = tr('room.exit.no_open_request', null, 'No open exit request.');
        if(actReq) actReq.style.display = 'block';
        if(actVote) actVote.style.display = 'none';
        if(actCancel) actCancel.style.display = 'none';
      } else {
        const makerVote = (er.votes && er.votes.maker_vote) ? er.votes.maker_vote : '—';
        const approvals = (er.votes && typeof er.votes.approvals !== 'undefined') ? er.votes.approvals : 0;
        const required = (er.votes && typeof er.votes.required !== 'undefined') ? er.votes.required : 0;
        const myVote = er.my_vote ? er.my_vote : '—';

        if(meta) meta.textContent = tr('room.exit.meta_open_fmt', {
          name: String(er.requested_by_name||''),
          approvals,
          required,
          maker: makerVote,
          vote: myVote,
        }, `Open · requested by ${er.requested_by_name} · approvals ${approvals}/${required} · maker ${makerVote} · your vote ${myVote}`);

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
    if(r.saving_type === 'A') loadUnderfillDecision();
    else {
      const underfillCard = document.getElementById('underfill-card');
      if(underfillCard) underfillCard.style.display = 'none';
    }
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

function swapStatusText(status){
  if(status === 'pending') return tr('room.swap.status_pending', null, 'pending');
  if(status === 'accepted') return tr('room.swap.status_accepted', null, 'accepted');
  if(status === 'declined') return tr('room.swap.status_declined', null, 'declined');
  if(status === 'cancelled') return tr('room.swap.status_cancelled', null, 'cancelled');
  return status ? String(status) : '';
}

function isSwapParticipant(r){
  return !!(r && (r.my_status === 'approved' || r.my_status === 'active'));
}



function renderSwapWindow(r){
  const block = document.getElementById('swap-block');
  if(!block) return;

  const inSwap = (r.room_state === 'swap_window');
  const participant = isSwapParticipant(r);

  // Admins can always review swap state + requests for Type B rooms during swap_window/active.
  const show = (r.saving_type === 'B' && (inSwap || r.room_state === 'active') && (participant || IS_ADMIN));
  block.style.display = show ? 'block' : 'none';
  if(!show) return;

  const adminHint = document.getElementById('swap-admin-hint');
  if(adminHint) adminHint.style.display = (IS_ADMIN && !participant) ? 'block' : 'none';

  const swapWindow = r.swap_window || {};
  const isOpen = inSwap && !!swapWindow.is_open;

  // Title/subtitle can change depending on whether swap window is active.
  const titleEl = block.querySelector('.card-title');
  const subEl = block.querySelector('.p');
  if(titleEl) titleEl.textContent = inSwap
    ? tr('room.swap.title', null, 'Swap window (Type B)')
    : tr('room.swap.final_positions_title', null, 'Final positions');
  if(subEl) subEl.textContent = inSwap
    ? tr('room.swap.sub', null, 'Request to swap your payout slot with another participant during this window.')
    : tr('room.swap.final_positions_sub', null, 'The payout order for this room.');

  const statusEl = document.getElementById('swap-status');
  const closesEl = document.getElementById('swap-closes');
  if(statusEl) statusEl.textContent = isOpen ? tr('room.swap.open', null, 'Open') : tr('room.swap.closed', null, 'Closed');
  if(closesEl) closesEl.textContent = swapWindow.closes_at ? fmt(swapWindow.closes_at) : '—';

  // Slots table
  const slots = Array.isArray(r.slots) ? r.slots : [];
  const slotsWrap = document.getElementById('swap-slots-table-wrap');
  const slotsEmpty = document.getElementById('swap-slots-empty');
  const slotsBody = document.querySelector('#swap-slots-table tbody');

  if(slotsBody) slotsBody.innerHTML = '';

  if(slots && slots.length && slotsBody && slotsWrap && slotsEmpty){
    slotsWrap.style.display = 'block';
    slotsEmpty.style.display = 'none';

    slots.forEach(s => {
      const trEl = document.createElement('tr');
      if((s.user_id|0) === (CURRENT_USER_ID|0)){
        trEl.style.background = 'var(--ls-surface-1)';
      }
      trEl.innerHTML = `<td>#${esc(String(s.position||''))}</td><td>${esc(String(s.display_name||('User #' + s.user_id)))}</td>`;
      slotsBody.appendChild(trEl);
    });
  } else {
    if(slotsWrap) slotsWrap.style.display = 'none';
    if(slotsEmpty) slotsEmpty.style.display = 'block';
  }

  // Request form (only if window is open + viewer is a participant)
  const form = document.getElementById('swap-request-form');
  const sel = document.getElementById('swap-to-user');
  const btn = document.getElementById('swap-request-btn');

  if(form) form.style.display = (isOpen && participant) ? 'block' : 'none';

  if(isOpen && participant && sel){
    const opts = slots.filter(x => x && (x.user_id|0) !== (CURRENT_USER_ID|0));
    sel.innerHTML = '<option value="0">' + esc(tr('room.swap.select_placeholder', null, 'Select a participant')) + '</option>';
    opts.forEach(x => {
      const o = document.createElement('option');
      o.value = String(x.user_id);
      o.textContent = String(x.display_name||('User #' + x.user_id));
      sel.appendChild(o);
    });

    if(btn) btn.disabled = (opts.length === 0);
  }

  // Swap requests
  const swaps = Array.isArray(r.slot_swaps) ? r.slot_swaps : [];
  const reqWrap = document.getElementById('swap-requests-table-wrap');
  const reqEmpty = document.getElementById('swap-requests-empty');
  const reqBody = document.querySelector('#swap-requests-table tbody');

  if(reqBody) reqBody.innerHTML='';

  if(swaps && swaps.length && reqBody && reqWrap && reqEmpty){
    reqWrap.style.display = 'block';
    reqEmpty.style.display = 'none';

    swaps.forEach(s => {
      const trEl = document.createElement('tr');
      const st = String(s.status||'');

      let actions = '';
      const canAct = (isOpen && participant);
      // Only allow swap actions while the swap window is open; backend also enforces this.
      if(canAct && st === 'pending' && (s.to_user_id|0) === (CURRENT_USER_ID|0)){
        actions = `
          <button class="btn btn-blue btn-sm" onclick="respondSwap(${s.id}, 'accept')">${esc(tr('room.swap.btn_accept', null, 'Accept'))}</button>
          <button class="btn btn-red btn-sm" onclick="respondSwap(${s.id}, 'decline')">${esc(tr('room.swap.btn_decline', null, 'Decline'))}</button>
        `;
      } else if(canAct && st === 'pending' && (s.from_user_id|0) === (CURRENT_USER_ID|0)){
        actions = `<button class="btn btn-ghost btn-sm" onclick="cancelSwap(${s.id})">${esc(STR.cancel)}</button>`;
      }

      trEl.innerHTML = `
        <td>${esc(String(s.from_name||('User #' + s.from_user_id)))}</td>
        <td>${esc(String(s.to_name||('User #' + s.to_user_id)))}</td>
        <td>${esc(swapStatusText(st))}</td>
        <td>${esc(fmt(s.created_at))}</td>
        <td>${actions}</td>
      `;
      reqBody.appendChild(trEl);
    });
  } else {
    if(reqWrap) reqWrap.style.display = 'none';
    if(reqEmpty) reqEmpty.style.display = 'block';
  }
}

function canUseSwapActions(){
  return isSwapParticipant(roomCache);
}

async function requestSwap(){
  document.getElementById('swap-msg').className='msg';

  const r = roomCache;
  if(!r) return;

  if(!canUseSwapActions()){
    const msg = IS_ADMIN
      ? 'Admin view only — swap actions are disabled unless you are a participant.'
      : 'Swap actions are available to participants only.';
    setMsg('swap-msg', msg, false);
    return;
  }

  const sel = document.getElementById('swap-to-user');
  const to_user_id = sel ? parseInt(sel.value||'0', 10) : 0;
  if(!to_user_id) {
    setMsg('swap-msg', tr('room.swap.select_required', null, 'Select a participant.'), false);
    return;
  }

  if(!(r.swap_window && r.swap_window.is_open)){
    setMsg('swap-msg', tr('room.swap.closed', null, 'Closed'), false);
    return;
  }

  const btn = document.getElementById('swap-request-btn');
  if(btn) btn.disabled = true;

  try{
    const res = await postStrong('/api/rooms.php', {action:'request_swap', room_id: ROOM_ID, to_user_id});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg('swap-msg', tr('room.swap.msg_requested', null, 'Swap request sent.'), true);
    if(sel) sel.value = '0';

    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('swap-msg', e.message||STR.failed, false);
  }finally{
    if(btn) btn.disabled = false;
  }
}

async function respondSwap(swapId, decision){
  document.getElementById('swap-msg').className='msg';

  if(!canUseSwapActions()){
    const msg = IS_ADMIN
      ? 'Admin view only — swap actions are disabled unless you are a participant.'
      : 'Swap actions are available to participants only.';
    setMsg('swap-msg', msg, false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'respond_swap', swap_id: swapId, decision});
    if(!res.success) throw new Error(res.error||STR.failed);

    const msg = (decision === 'accept')
      ? tr('room.swap.msg_accepted', null, 'Swap accepted. Slots updated.')
      : tr('room.swap.msg_declined', null, 'Swap declined.');

    setMsg('swap-msg', msg, true);

    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('swap-msg', e.message||STR.failed, false);
  }
}

async function cancelSwap(swapId){
  document.getElementById('swap-msg').className='msg';

  if(!canUseSwapActions()){
    const msg = IS_ADMIN
      ? 'Admin view only — swap actions are disabled unless you are a participant.'
      : 'Swap actions are available to participants only.';
    setMsg('swap-msg', msg, false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'cancel_swap', swap_id: swapId});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg('swap-msg', tr('room.swap.msg_cancelled', null, 'Swap request cancelled.'), true);

    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('swap-msg', e.message||STR.failed, false);
  }
}

function inviteParam(){return INVITE_TOKEN ? ('&invite=' + encodeURIComponent(INVITE_TOKEN)) : '';}

async function loadRoom(){
  document.getElementById('room-msg').className='msg';
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID) + inviteParam());
    if(!res.success) throw new Error(res.error||STR.failed);
    roomCache = res.room;
    roomCache.escrow_settlements = res.escrow_settlements || [];
    roomCache.participants = res.participants || [];
    renderRoom();
  }catch(e){
    setMsg('room-msg', e.message||STR.failed, false);
  }
}


async function pollFeed(){
  const msg = document.getElementById('feed-msg');
  msg.className='msg';

  try{
    const r = await get('/api/rooms.php?action=activity&room_id=' + encodeURIComponent(ROOM_ID) + inviteParam() + '&since_id=' + encodeURIComponent(lastEventId) + '&limit=100');
    if(!r.success) throw new Error(r.error||STR.failed);

    const events = r.events || [];
    events.forEach(ev => {
      addFeedItem(ev);
      maybeScheduleRoomRefreshForEvent(ev);
    });
    if(events.length){
      lastEventId = events[events.length-1].id;
    }

  }catch(e){
    setMsg('feed-msg', e.message||STR.feed_failed, false);
  }
}

function addFeedItem(ev){
  const feed = document.getElementById('feed');
  const shouldScroll = (feed.scrollTop + feed.clientHeight) >= (feed.scrollHeight - 24);

  const el = document.createElement('div');
  el.className = 'feed-item';

  const payload = ev.payload || {};

  const line = FEED_EVENT_LABELS[ev.event_type] || ev.event_type;

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

    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('room-msg', STR.join_request_sent, true);
    await loadRoom();
  }catch(e){
    setMsg('room-msg', e.message||STR.failed, false);
  }finally{
    btn.disabled=false;
  }
}

async function respondInvite(decision){
  const r = roomCache;
  if(!r || !r.my_invite){
    setMsg('invite-msg', STR.invite_no_active, false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'respond_invite', invite_id: r.my_invite.id, decision});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('invite-msg', decision === 'accept' ? STR.invite_accepted : STR.invite_declined, true);
    await loadRoom();
  }catch(e){
    setMsg('invite-msg', e.message||STR.failed, false);
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
    if(!res.success) throw new Error(res.error||STR.failed);

    const inv = res.invite;
    if(!inv){
      if(meta) meta.textContent = tr('room.unlisted.none', null, 'No link generated.');
      return;
    }

    const activeTxt = inv.is_active ? STR.active : STR.inactive;
    const exp = inv.expires_at ? fmt(inv.expires_at) : '—';
    if(meta) meta.textContent = tr('room.unlisted.link_status_fmt', {status: activeTxt, exp}, `Link status: ${activeTxt} · expires ${exp}`);

  }catch(e){
    setMsg('unlisted-msg', e.message||STR.failed, false);
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
    if(!res.success) throw new Error(res.error||STR.failed);

    if(input) input.value = res.link || '';
    if(wrap) wrap.style.display='block';
    if(input) input.select();

    setMsg('unlisted-msg', tr('room.unlisted.link_generated_once', null, 'Link generated. Copy it now; it will not be shown again.'), true);
    await loadUnlistedInviteInfo(true);

  }catch(e){
    setMsg('unlisted-msg', e.message||STR.failed, false);
  }
}

async function revokeUnlistedLink(){
  document.getElementById('unlisted-msg').className='msg';
  const msg = tr('room.confirm.unlisted_revoke', null, 'Revoke the current unlisted link?');
  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: true})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: true}) : false);
  if(!ok) return;

  const wrap = document.getElementById('unlisted-link-wrap');
  const input = document.getElementById('unlisted-link');
  if(wrap) wrap.style.display='none';
  if(input) input.value='';

  try{
    const res = await postStrong('/api/rooms.php', {action:'unlisted_invite_revoke', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('unlisted-msg', tr('room.unlisted.link_revoked', null, 'Link revoked.'), true);
    await loadUnlistedInviteInfo(true);
  }catch(e){
    setMsg('unlisted-msg', e.message||STR.failed, false);
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
    if(!res.success) throw new Error(res.error||STR.failed);

    const rows = res.invites || [];
    if(!rows.length){
      if(empty) empty.style.display='block';
      return;
    }

    if(wrap) wrap.style.display='block';

    rows.forEach(x => {
      const tr=document.createElement('tr');
      const revokeBtn = (x.status === 'active') ? `<button class="btn btn-red btn-sm" onclick="revokeInvite(${x.id})">${esc(STR.revoke)}</button>` : '';
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
    setMsg('invites-msg', e.message||STR.failed, false);
  }
}

async function sendInvite(){
  const input = document.getElementById('invite-email');
  const email = (input ? input.value : '').trim();
  if(!email){
    setMsg('invites-msg', STR.email_required, false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'invite_user', room_id: ROOM_ID, email});
    if(!res.success) throw new Error(res.error||STR.failed);
    if(input) input.value='';
    setMsg('invites-msg', STR.invite_sent, true);
    await loadInvites(true);
  }catch(e){
    setMsg('invites-msg', e.message||STR.failed, false);
  }
}

async function revokeInvite(inviteId){
  const msg = tr('room.confirm.invite_revoke', null, 'Revoke this invite?');
  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: true})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: true}) : false);
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'revoke_invite', invite_id: inviteId});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('invites-msg', STR.invite_revoked, true);
    await loadInvites(true);
  }catch(e){
    setMsg('invites-msg', e.message||STR.failed, false);
  }
}



async function unlockVote(vote){
  const btn = document.getElementById(vote === 'approve' ? 'unlock-vote-approve' : 'unlock-vote-reject');
  if(btn && btn.dataset && btn.dataset.disabledReason){
    setMsg('unlock-msg', btn.dataset.disabledReason, false);
    return;
  }

  if(btn) btn.disabled = true;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeA_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('unlock-msg', STR.saved, true);
    await loadRoom();
  }catch(e){
    setMsg('unlock-msg', e.message||STR.failed, false);
    await loadRoom();
  }finally{
    if(btn) btn.disabled = false;
  }
}

async function unlockReveal(){
  try{
    const res = await postStrong('/api/rooms.php', {action:'typeA_reveal', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||STR.failed);

    const wrap = document.getElementById('unlock-code-wrap');
    const input = document.getElementById('unlock-code');
    const exp = document.getElementById('unlock-code-exp');

    const ts = fmt(res.expires_at);

    wrap.style.display='block';
    input.value = String(res.code||'');
    exp.textContent = tr('room.code.expires_at_fmt', {ts}, 'Expires at ' + ts);

    if (unlockClearTimer) clearTimeout(unlockClearTimer);
    unlockClearTimer = setTimeout(()=>{
      input.value='';
      wrap.style.display='none';
    }, 30000);

    setMsg('unlock-msg', tr('room.code.revealed_autoclear_30s', null, 'Code revealed. It will auto-clear in 30 seconds.'), true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('unlock-msg', e.message||STR.failed, false);
  }
}

async function typeBVote(vote){
  const a = document.getElementById('typeb-vote-approve');
  const b = document.getElementById('typeb-vote-reject');
  const btn = (vote === 'approve') ? a : b;

  if(btn && btn.dataset && btn.dataset.disabledReason){
    setMsg('typeb-msg', btn.dataset.disabledReason, false);
    return;
  }

  if(a) a.disabled = true;
  if(b) b.disabled = true;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_vote', room_id: ROOM_ID, vote});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('typeb-msg', res.no_change ? STR.saved : STR.saved, true);
    await loadRoom();
  }catch(e){
    setMsg('typeb-msg', e.message||STR.failed, false);
    await loadRoom();
  }finally{
    if(a) a.disabled = false;
    if(b) b.disabled = false;
  }
}

async function typeBReveal(){
  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_reveal', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||STR.failed);

    const wrap = document.getElementById('typeb-code-wrap');
    const input = document.getElementById('typeb-code');
    const exp = document.getElementById('typeb-code-exp');

    const ts = fmt(res.expires_at);

    wrap.style.display='block';
    input.value = String(res.code||'');
    exp.textContent = tr('room.code.expires_at_fmt', {ts}, 'Expires at ' + ts);

    if (unlockClearTimer) clearTimeout(unlockClearTimer);
    unlockClearTimer = setTimeout(()=>{
      input.value='';
      wrap.style.display='none';
    }, 30000);

    const who = res.role ? (' (' + String(res.role) + ')') : '';
    setMsg('typeb-msg', tr('room.code.revealed_autoclear_30s', null, 'Code revealed. It will auto-clear in 30 seconds.') + who, true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg('typeb-msg', e.message||STR.failed, false);
  }
}

async function typeBSetDelegate(){
  const msgId = 'typeb-delegate-msg';
  document.getElementById(msgId).className='msg';

  try{
    const sel = document.getElementById('typeb-delegate-user');
    const delegate_user_id = sel ? parseInt(sel.value||'0', 10) : 0;
    if(!delegate_user_id) throw new Error(tr('room.rotation.delegate_select_required', null, 'Select a delegate.'));

    const res = await postStrong('/api/rooms.php', {action:'typeB_set_delegate', room_id: ROOM_ID, delegate_user_id});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, STR.saved, true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function typeBClearDelegate(){
  const msgId = 'typeb-delegate-msg';
  document.getElementById(msgId).className='msg';

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_set_delegate', room_id: ROOM_ID, delegate_user_id: 0});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, STR.saved, true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function typeBConfirmWithdrawal(){
  const msgId = 'typeb-withdraw-msg';
  document.getElementById(msgId).className='msg';

  try{
    const msg = tr('room.rotation.withdrawal_reference_prompt', null, 'Optional reference / note (leave blank if none):');

    let ref = null;
    if(window.LS && typeof window.LS.prompt === 'function'){
      ref = await window.LS.prompt({
        title: STR.confirm,
        message: msg,
        placeholder: '',
        initialValue: '',
      });
    } else if (typeof window.uiPrompt === 'function'){
      ref = await window.uiPrompt({
        title: STR.confirm,
        message: msg,
        placeholder: '',
        initialValue: '',
      });
    }

    if(ref === null) return;

    const res = await postStrong('/api/rooms.php', {action:'typeB_confirm_withdrawal', room_id: ROOM_ID, reference: String(ref||'')});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, STR.saved, true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function typeBRaiseDispute(){
  const msgId = 'typeb-dispute-msg';
  document.getElementById(msgId).className='msg';

  const reason = (document.getElementById('typeb-dispute-reason')||{}).value || '';

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_raise_dispute', room_id: ROOM_ID, reason});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, tr('room.dispute.raised', null, 'Dispute raised.'), true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function typeBAckDispute(){
  const msgId = 'typeb-dispute-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const dispute = (r && r.rotation) ? r.rotation.dispute : null;
  if(!dispute){
    setMsg(msgId, tr('room.dispute.none_to_ack', null, 'No dispute to acknowledge.'), false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_ack_dispute', room_id: ROOM_ID, dispute_id: dispute.id});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, tr('room.dispute.acknowledged', null, 'Acknowledged.'), true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function createExitRequest(){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const msg = tr('room.confirm.exit_request', null, 'Request to exit this room? This requires approvals and will record a refund-minus-fee settlement.');
  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: true})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: true}) : false);
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_create', room_id: ROOM_ID});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, tr('room.exit.request_submitted', null, 'Exit request submitted.'), true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function voteExit(vote){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const er = r ? r.exit_request : null;
  if(!er){
    setMsg(msgId, tr('room.exit.no_open_request', null, 'No open exit request.'), false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_vote', room_id: ROOM_ID, exit_request_id: er.id, vote});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, res.approved ? tr('room.exit.approved', null, 'Exit approved.') : STR.vote_saved, true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
  }
}

async function cancelExitRequest(){
  const msgId = 'exit-msg';
  document.getElementById(msgId).className='msg';

  const r = roomCache;
  const er = r ? r.exit_request : null;
  if(!er){
    setMsg(msgId, tr('room.exit.no_open_request', null, 'No open exit request.'), false);
    return;
  }

  const msg = tr('room.confirm.exit_cancel', null, 'Cancel your exit request?');
  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: true})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: true}) : false);
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'typeB_exit_request_cancel', room_id: ROOM_ID, exit_request_id: er.id});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg(msgId, tr('room.exit.request_cancelled', null, 'Exit request cancelled.'), true);
    await loadRoom();
    await pollFeed();

  }catch(e){
    setMsg(msgId, e.message||STR.failed, false);
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

    const policy = String(r.policy||'');
    const reason = String(r.reason||'');

    let policyLabel = policy;
    if(policy === 'refund_minus_fee') policyLabel = tr('rooms.escrow.refund_minus_fee', null, 'Return minus platform fee');
    else if(policy === 'redistribute') policyLabel = tr('rooms.escrow.redistribute', null, 'Proportional redistribution');

    let reasonLabel = '';
    if(reason === 'two_missed_contributions') reasonLabel = tr('room.escrow.reason.two_missed_contributions', null, 'Two missed contributions');
    else if(reason === 'exit_request') reasonLabel = tr('room.escrow.reason.exit_request', null, 'Exit request');
    else if(reason === 'room_cancelled_underfilled') reasonLabel = tr('room.escrow.reason.room_cancelled_underfilled', null, 'Room cancelled (underfilled)');
    else if(reason) reasonLabel = reason;

    const fee = (r.platform_fee_amount || '0.00');
    const refund = (policy === 'refund_minus_fee') ? (r.refund_amount || '0.00') : '—';

    const fr = parseFloat(String(r.fee_rate||''));
    const pct = (!isNaN(fr)) ? Math.round(fr * 100) : null;
    const feeLabel = fee + ((pct !== null) ? (' (' + pct + '%)') : '');

    tr.innerHTML = `
      <td>${esc(r.removed_user_name||('User #' + r.removed_user_id))}</td>
      <td title="${esc(reasonLabel)}">${esc(policyLabel)}${reasonLabel ? ('<div class="k" style="font-size:10px;">' + esc(reasonLabel) + '</div>') : ''}</td>
      <td>${esc(r.total_contributed||'0.00')}</td>
      <td title="${esc(reasonLabel)}">${esc(feeLabel)}</td>
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
  const ts = fmt(r.underfill.decision_deadline_at);
  document.getElementById('underfill-meta').textContent = tr('room.underfill.decision_deadline_fmt', {ts}, `Decision deadline: ${ts}`);
}

async function underfillExtend(){
  const msg = document.getElementById('underfill-msg');
  msg.className='msg';

  const msgStart = tr('room.underfill.prompt_new_start_dt', null, 'Enter new start date/time (YYYY-MM-DDTHH:MM)');
  const msgReveal = tr('room.underfill.prompt_new_reveal_dt', null, 'Enter new reveal date/time (YYYY-MM-DDTHH:MM)');

  let rawStart = null;
  if(window.LS && typeof window.LS.prompt === 'function'){
    rawStart = await window.LS.prompt({title: STR.confirm, message: msgStart, placeholder: 'YYYY-MM-DDTHH:MM'});
  } else if (typeof window.uiPrompt === 'function'){
    rawStart = await window.uiPrompt({title: STR.confirm, message: msgStart, placeholder: 'YYYY-MM-DDTHH:MM'});
  }
  if(!rawStart) return;

  let rawReveal = null;
  if(window.LS && typeof window.LS.prompt === 'function'){
    rawReveal = await window.LS.prompt({title: STR.confirm, message: msgReveal, placeholder: 'YYYY-MM-DDTHH:MM'});
  } else if (typeof window.uiPrompt === 'function'){
    rawReveal = await window.uiPrompt({title: STR.confirm, message: msgReveal, placeholder: 'YYYY-MM-DDTHH:MM'});
  }
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
    setMsg('underfill-msg', tr('room.underfill.invalid_datetime', null, 'Invalid date/time format.'), false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'extend_start', new_start_at:startIso, new_reveal_at:revealIso});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('underfill-msg', STR.saved, true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||STR.failed, false);
  }
}

async function underfillLowerMin(){
  const msg = document.getElementById('underfill-msg');
  msg.className='msg';

  const msgPrompt = tr('room.underfill.prompt_new_min_participants', null, 'Enter new minimum participants');

  let newMinStr = null;
  if(window.LS && typeof window.LS.prompt === 'function'){
    newMinStr = await window.LS.prompt({
      title: STR.confirm,
      message: msgPrompt,
      placeholder: '2',
      inputMode: 'numeric',
      validate: (v)=> {
        const n = parseInt(String(v||'').trim(), 10);
        if(!n || n < 2) return tr('room.underfill.min_at_least_2', null, 'Minimum must be at least 2');
        return true;
      },
    });
  } else if (typeof window.uiPrompt === 'function'){
    newMinStr = await window.uiPrompt({
      title: STR.confirm,
      message: msgPrompt,
      placeholder: '2',
      inputMode: 'numeric',
      validate: (v)=> {
        const n = parseInt(String(v||'').trim(), 10);
        if(!n || n < 2) return tr('room.underfill.min_at_least_2', null, 'Minimum must be at least 2');
        return true;
      },
    });
  }

  if(!newMinStr) return;
  const newMin = parseInt(newMinStr, 10);
  if(!newMin || newMin < 2){
    setMsg('underfill-msg', tr('room.underfill.min_at_least_2', null, 'Minimum must be at least 2'), false);
    return;
  }

  try{
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'lower_min', new_min_participants:newMin});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('underfill-msg', STR.saved, true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||STR.failed, false);
  }
}

async function underfillCancel(){
  const msg = tr('room.confirm.room_cancel', null, 'Cancel this room?');
  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: true})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: true}) : false);
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'underfill_decide', room_id: ROOM_ID, decision:'cancel'});
    if(!res.success) throw new Error(res.error||STR.failed);
    setMsg('underfill-msg', tr('room.underfill.room_cancelled', null, 'Room cancelled.'), true);
    await loadRoom();
  }catch(e){
    setMsg('underfill-msg', e.message||STR.failed, false);
  }
}

async function loadJoinRequests(){
  document.getElementById('maker-msg').className='msg';

  const tbody = document.querySelector('#req-table tbody');
  tbody.innerHTML = `<tr><td colspan="5" class="k">${esc(STR.loading)}</td></tr>`;

  try{
    const res = await get('/api/rooms.php?action=maker_join_requests&room_id=' + encodeURIComponent(ROOM_ID));
    if(!res.success) throw new Error(res.error||STR.failed);

    const rows = res.requests || [];
    if(!rows.length){
      tbody.innerHTML = `<tr><td colspan="5" class="k">${esc(tr('room.requests.none_pending', null, 'No pending requests.'))}</td></tr>`;
      return;
    }

    tbody.innerHTML='';
    rows.forEach(r => {
      const tr=document.createElement('tr');
      const snap = `L${r.snapshot_level} · ${STR.strikes} ${r.snapshot_strikes_6m}` + (r.snapshot_restricted_until ? (' · ' + STR.restricted) : '');
      const cur = `L${r.current_level||'?'} · ${STR.strikes} ${r.current_strikes_6m||0}` + (r.current_restricted_until ? (' · ' + STR.restricted) : '');

      tr.innerHTML = `
        <td>${esc(r.display_name || ('User #' + r.user_id))}</td>
        <td>${esc(snap)}</td>
        <td>${esc(cur)}</td>
        <td>${esc(fmt(r.created_at))}</td>
        <td>
          <button class="btn btn-blue btn-sm" onclick="reviewJoin(${r.id}, 'approve')">${esc(STR.approve)}</button>
          <button class="btn btn-red btn-sm" onclick="reviewJoin(${r.id}, 'decline')">${esc(STR.decline)}</button>
        </td>
      `;

      tbody.appendChild(tr);
    });

  }catch(e){
    tbody.innerHTML = `<tr><td colspan="5" class="k">${esc(tr('room.requests.failed_to_load', null, 'Failed to load requests.'))}</td></tr>`;
    setMsg('maker-msg', e.message||STR.failed, false);
  }
}

async function reviewJoin(requestId, decision){
  document.getElementById('maker-msg').className='msg';

  const msg = (decision === 'approve')
    ? tr('room.requests.confirm_approve_user', null, 'Approve this user?')
    : tr('room.requests.confirm_decline_user', null, 'Decline this user?');

  const ok = (window.LS && typeof window.LS.confirm === 'function')
    ? await window.LS.confirm(msg, {title: STR.confirm, danger: (decision !== 'approve')})
    : (typeof window.uiConfirm === 'function' ? await window.uiConfirm({title: STR.confirm, message: msg, danger: (decision !== 'approve')}) : false);
  if(!ok) return;

  try{
    const res = await postStrong('/api/rooms.php', {action:'review_join', request_id: requestId, decision});
    if(!res.success) throw new Error(res.error||STR.failed);

    setMsg('maker-msg', STR.saved, true);
    await loadJoinRequests();
    await loadRoom();

  }catch(e){
    setMsg('maker-msg', e.message||STR.failed, false);
  }
}

let roomRefreshTimer = null;

function maybeScheduleRoomRefreshForEvent(ev){
  const t = (ev && ev.event_type) ? String(ev.event_type) : '';
  if(!t) return;

  if(t === 'contribution_confirmed' ||
     t === 'typeB_withdrawal_confirmed' ||
     t === 'typeB_turn_revealed' ||
     t === 'typeB_turn_advanced' ||
     t === 'typeB_turn_expired' ||
     t === 'room_started' ||
     t === 'swap_window_started' ||
     t === 'swap_window_ended'){
    scheduleRoomRefresh();
  }
}

function scheduleRoomRefresh(){
  if(roomRefreshTimer) return;
  roomRefreshTimer = setTimeout(async ()=>{
    roomRefreshTimer = null;
    await refreshRoomSilent();
  }, 900);
}

async function refreshRoomSilent(){
  try{
    const res = await get('/api/rooms.php?action=room_detail&room_id=' + encodeURIComponent(ROOM_ID) + inviteParam());
    if(!res.success) return;
    roomCache = res.room;
    roomCache.escrow_settlements = res.escrow_settlements || [];
    roomCache.participants = res.participants || [];
    renderRoom();
  }catch{
    // ignore
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
      maybeScheduleRoomRefreshForEvent(data);
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
