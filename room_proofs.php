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

$isAdmin = isAdmin();

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
<title><?= htmlspecialchars(APP_NAME) ?> — <?= htmlspecialchars(t('page.room_proofs')) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700;800;900&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;600&display=swap" rel="stylesheet">
<?php emitI18nJsGlobals(); ?>
<script src="assets/theme.js"></script>
<script src="assets/app.js"></script>
<link rel="stylesheet" href="assets/base.css">
<link rel="stylesheet" href="assets/app.css">
<link rel="stylesheet" href="assets/room_page.css">
<link rel="stylesheet" href="assets/room_proofs_page.css">
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>

<div id="app">
  <?php include __DIR__ . '/includes/topbar.php'; ?>

  <div class="app-body wide">

    <div class="page-head">
      <div>
        <div class="page-title"><?php e('room.proofs_title'); ?></div>
        <div class="page-sub"><?php e('room.proofs_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="room.php?id=<?= htmlspecialchars($roomId, ENT_QUOTES, 'UTF-8') ?>"><?php e('room.proofs_back_to_room'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      </div>
    </div>

    <div class="grid">
      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><?php e('room.proofs_table_title'); ?></div>

        <div id="proofs-empty" class="k" style="display:none;"><?php e('room.proofs_empty'); ?></div>

        <div class="table-wrap" id="proofs-table-wrap" style="display:none;">
          <table class="table" id="proofs-table">
            <thead>
              <tr>
                <th><?php e('room.proofs_th_cycle'); ?></th>
                <th><?php e('room.proofs_th_participant'); ?></th>
                <th><?php e('room.proofs_th_amount'); ?></th>
                <th><?php e('room.proofs_th_status'); ?></th>
                <th><?php e('room.proofs_th_confirmed'); ?></th>
                <th><?php e('room.proofs_th_proof'); ?></th>
              </tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;align-items:center;">
          <button class="btn btn-blue btn-sm" id="proofs-load-more" onclick="loadMoreProofs()" style="display:none;"><?php e('common.load_more'); ?></button>
          <div id="proofs-msg" class="msg"></div>
        </div>
      </div>
    </div>

  </div>

<script>
const ROOM_ID = <?= json_encode($roomId) ?>;
const IS_ADMIN = <?= json_encode($isAdmin ? 1 : 0) ?>;
</script>
<script src="assets/room_proofs_page.js"></script>
</div>
</body>
</html>
