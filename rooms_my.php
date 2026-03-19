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
        <div class="page-title"><?php e('rooms.my_rooms_title'); ?></div>
        <div class="page-sub"><?php e('rooms.my_rooms_sub'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('rooms.discover_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms_proofs.php"><?php e('rooms.proofs_nav'); ?></a>
        <a class="btn btn-primary btn-sm" href="rooms_create.php"><?php e('common.create'); ?></a>
      </div>
    </div>

    <div class="grid">
      <div class="card" style="grid-column:1/-1;">
        <div class="card-title"><?php e('rooms.my_rooms_title'); ?></div>
        <div id="myrooms-msg" class="msg"></div>
        <div id="myrooms-wrap" class="rooms"></div>
      </div>
    </div>

  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
</script>
<script src="assets/rooms_shared.js"></script>
<script>
if(window.Rooms && typeof Rooms.initMyRooms === 'function') Rooms.initMyRooms();
</script>
</div>
</body>
</html>
