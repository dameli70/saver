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

$userEmail = getCurrentUserEmail() ?? '';
$isAdmin   = isAdmin();
$csrf      = getCsrfToken();

require_once __DIR__ . '/includes/packages.php';
$userId = (int)getCurrentUserId();
$pkgLimits = packagesGetUserLimits($userId);
$pkgUsage  = packagesGetUserUsage($userId);

$roomsLimit = packagesLimitFor('rooms', $pkgLimits);
$roomsUsage = packagesUsageFor('rooms', $pkgUsage);
$roomsLimitReached = ($roomsLimit > 0 && $roomsUsage >= $roomsLimit);

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.rooms')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/rooms_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('rooms.create_title'); ?></div>
        <div class="page-sub"><?php e('rooms.create_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('rooms.discover_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms_my.php"><?php e('rooms.my_rooms_title'); ?></a>
      </div>
    </div>

    <div class="grid">

      <?php if ($roomsLimitReached): ?>
      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><div class="dot" style="background:var(--orange)"></div><?php e('package_limit.title'); ?></div>
        <div class="msg msg-warn show" style="display:block;">
          <div><?php e('package_limit.rooms_reached_fmt', ['cur' => (int)$roomsUsage, 'limit' => (int)$roomsLimit]); ?></div>
          <div style="margin-top:8px;"><?php e('package_limit.upgrade_note'); ?></div>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;">
          <a class="btn btn-primary" href="packages.php"><?php e('package_limit.upgrade_btn'); ?></a>
          <a class="btn btn-ghost" href="rooms.php"><?php e('common.back'); ?></a>
        </div>
      </div>
      <?php else: ?>

      <div class="card" id="create-room" style="grid-column:1/-1;">
        <div class="card-title"><?php e('rooms.create_title'); ?></div>

        <div class="field"><label><?php e('rooms.field.purpose'); ?></label>
          <select id="cr-purpose">
            <option value="education"><?php e('rooms.purpose.education'); ?></option>
            <option value="travel"><?php e('rooms.purpose.travel'); ?></option>
            <option value="business"><?php e('rooms.purpose.business'); ?></option>
            <option value="emergency"><?php e('rooms.purpose.emergency'); ?></option>
            <option value="community"><?php e('rooms.purpose.community'); ?></option>
            <option value="other" selected><?php e('rooms.purpose.other'); ?></option>
          </select>
        </div>

        <div class="field"><label><?php e('rooms.field.goal'); ?></label>
          <input id="cr-goal" maxlength="500" placeholder="<?= htmlspecialchars(t('rooms.goal_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <div class="field"><label><?php e('rooms.field.saving_type'); ?></label>
          <select id="cr-type">
            <option value="A"><?php e('rooms.saving_type.a'); ?></option>
            <option value="B"><?php e('rooms.saving_type.b'); ?></option>
          </select>
        </div>

        <div class="field"><label><?php e('rooms.field.visibility'); ?></label>
          <select id="cr-vis">
            <option value="public"><?php e('rooms.visibility.public'); ?></option>
            <option value="unlisted"><?php e('rooms.visibility.unlisted'); ?></option>
            <option value="private"><?php e('rooms.visibility.private'); ?></option>
          </select>
        </div>

        <div class="field"><label><?php e('rooms.field.required_trust'); ?></label>
          <select id="cr-level">
            <option value="1"><?php e('rooms.trust_level.1'); ?></option>
            <option value="2"><?php e('rooms.trust_level.2'); ?></option>
            <option value="3"><?php e('rooms.trust_level.3'); ?></option>
          </select>
        </div>

        <div class="field"><label><?php e('rooms.field.participants'); ?></label>
          <div class="two-col">
            <input id="cr-min" type="number" min="2" value="2">
            <input id="cr-max" type="number" min="2" value="6">
          </div>
        </div>

        <div class="field"><label><?php e('rooms.field.participation_amount'); ?></label>
          <input id="cr-amt" type="number" min="0" step="0.01" placeholder="<?= htmlspecialchars(t('rooms.amount_placeholder'), ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <div class="field"><label><?php e('rooms.field.periodicity'); ?></label>
          <select id="cr-per">
            <option value="weekly"><?php e('rooms.periodicity.weekly'); ?></option>
            <option value="biweekly"><?php e('rooms.periodicity.biweekly'); ?></option>
            <option value="monthly"><?php e('rooms.periodicity.monthly'); ?></option>
          </select>
        </div>

        <div class="field" id="cr-start-field"><label id="cr-start-label"><?php e('rooms.field.start_date'); ?></label>
          <input id="cr-start" type="datetime-local">
          <div class="k" id="cr-typeb-schedule-hint" style="margin-top:6px;font-size:11px;display:none;"></div>
        </div>

        <div class="field" id="cr-reveal-field"><label id="cr-reveal-label"><?php e('rooms.field.reveal_date'); ?></label>
          <input id="cr-reveal" type="datetime-local">
          <div class="k" id="cr-reveal-hint" style="margin-top:6px;font-size:11px;display:none;"></div>
        </div>

        <label style="display:flex;align-items:center;gap:10px;color:var(--muted);font-size:12px;line-height:1.4;margin:10px 0;">
          <input type="checkbox" id="cr-privacy" checked style="width:16px;height:16px;">
          <span><?php e('rooms.privacy_mode'); ?></span>
        </label>

        <?php if ($isAdmin): ?>
        <div class="field"><label><?php e('rooms.field.escrow_policy'); ?></label>
          <select id="cr-escrow">
            <option value="redistribute"><?php e('rooms.escrow.redistribute'); ?></option>
            <option value="refund_minus_fee"><?php e('rooms.escrow.refund_minus_fee'); ?></option>
          </select>
        </div>
        <?php endif; ?>

        <div class="field"><label><?php e('rooms.field.destination_account'); ?></label>
          <div class="two-col">
            <select id="cr-dest-type">
              <option value=""><?php e('rooms.destination_account.type_any'); ?></option>
              <option value="mobile_money"><?php e('rooms.destination_account.type_mobile_money'); ?></option>
              <option value="bank"><?php e('rooms.destination_account.type_bank'); ?></option>
              <option value="crypto_wallet"><?php e('rooms.destination_account.type_crypto'); ?></option>
            </select>
            <select id="cr-dest-account">
              <option value=""><?php e('rooms.destination_account.auto'); ?></option>
            </select>
          </div>
          <div class="k" style="margin-top:6px;font-size:11px;"><?php e('rooms.destination_account_hint'); ?></div>
        </div>

        <button class="btn btn-primary" onclick="createRoom()"><?php e('rooms.btn.create_room'); ?></button>
        <div id="cr-msg" class="msg"></div>
      </div>

      <?php endif; ?>
    </div>

  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
</script>
<script src="assets/rooms_shared.js"></script>
<script>
if(window.Rooms && typeof Rooms.initCreate === 'function') Rooms.initCreate();
</script>
</div>
</body>
</html>
