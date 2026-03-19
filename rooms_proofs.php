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

$filterRoomId = trim((string)($_GET['room_id'] ?? ''));
if ($filterRoomId !== '' && strlen($filterRoomId) !== 36) {
    $filterRoomId = '';
}

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.rooms_proofs')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/room_page.css">
<link rel="stylesheet" href="assets/room_proofs_page.css">
<link rel="stylesheet" href="assets/rooms_proofs_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('rooms.proofs_title'); ?></div>
        <div class="page-sub"><?php e('rooms.proofs_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms_my.php"><?php e('rooms.my_rooms_title'); ?></a>
      </div>
    </div>

    <div class="grid">
      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><?php e('rooms.proofs.todo_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('rooms.proofs.todo_sub'); ?></div>

        <div id="tasks-msg" class="msg"></div>

        <div class="proofs-section">
          <div class="k" style="margin-bottom:8px;"><?php e('rooms.proofs.upcoming_title'); ?></div>
          <div id="upcoming-empty" class="k" style="display:none;"><?php e('rooms.proofs.upcoming_empty'); ?></div>
          <div class="table-wrap" id="upcoming-table-wrap" style="display:none;">
            <table class="table" id="upcoming-table">
              <thead>
                <tr>
                  <th><?php e('rooms.proofs.th_room'); ?></th>
                  <th><?php e('rooms.proofs.th_turn'); ?></th>
                  <th><?php e('rooms.proofs.th_due'); ?></th>
                  <th><?php e('rooms.proofs.th_amount'); ?></th>
                  <th><?php e('rooms.proofs.th_action'); ?></th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>

        <div class="proofs-section">
          <div class="k" style="margin-bottom:8px;"><?php e('rooms.proofs.overdue_title'); ?></div>
          <div id="overdue-empty" class="k" style="display:none;"><?php e('rooms.proofs.overdue_empty'); ?></div>
          <div class="table-wrap" id="overdue-table-wrap" style="display:none;">
            <table class="table" id="overdue-table">
              <thead>
                <tr>
                  <th><?php e('rooms.proofs.th_room'); ?></th>
                  <th><?php e('rooms.proofs.th_turn'); ?></th>
                  <th><?php e('rooms.proofs.th_due'); ?></th>
                  <th><?php e('rooms.proofs.th_amount'); ?></th>
                  <th><?php e('rooms.proofs.th_action'); ?></th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><?php e('rooms.proofs.uploads_title'); ?></div>

        <div id="uploads-empty" class="k" style="display:none;"><?php e('rooms.proofs.uploads_empty'); ?></div>

        <div class="table-wrap" id="uploads-table-wrap" style="display:none;">
          <table class="table" id="uploads-table">
            <thead>
              <tr>
                <th><?php e('rooms.proofs.th_room'); ?></th>
                <th><?php e('rooms.proofs.th_turn'); ?></th>
                <th><?php e('rooms.proofs.th_amount'); ?></th>
                <th><?php e('rooms.proofs.th_confirmed'); ?></th>
                <th><?php e('rooms.proofs.th_uploaded'); ?></th>
                <th><?php e('rooms.proofs.th_proof'); ?></th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;align-items:center;">
          <button class="btn btn-blue btn-sm" id="uploads-load-more" onclick="loadMoreUploads()" style="display:none;"><?php e('common.load_more'); ?></button>
          <div id="uploads-msg" class="msg"></div>
        </div>
      </div>

      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><?php e('rooms.proofs.missed_title'); ?></div>
        <div class="p" style="margin-bottom:10px;"><?php e('rooms.proofs.missed_sub'); ?></div>

        <div id="missed-empty" class="k" style="display:none;"><?php e('rooms.proofs.missed_empty'); ?></div>

        <div class="table-wrap" id="missed-table-wrap" style="display:none;">
          <table class="table" id="missed-table">
            <thead>
              <tr>
                <th><?php e('rooms.proofs.th_room'); ?></th>
                <th><?php e('rooms.proofs.th_turn'); ?></th>
                <th><?php e('rooms.proofs.th_due'); ?></th>
                <th><?php e('rooms.proofs.th_amount'); ?></th>
                <th><?php e('rooms.proofs.th_status'); ?></th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>

        <div id="missed-msg" class="msg"></div>
      </div>
    </div>

  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const FILTER_ROOM_ID = <?= json_encode($filterRoomId) ?>;
</script>
<script src="assets/rooms_proofs_page.js"></script>
</div>
</body>
</html>
