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
        <div class="page-title"><?php e('page.rooms'); ?></div>
        <div class="page-sub"><?php e('rooms.intro'); ?></div>
      </div>
      <div class="page-actions">
        <a class="btn btn-ghost btn-sm" href="rooms_my.php"><?php e('rooms.my_rooms_title'); ?></a>
        <a class="btn btn-ghost btn-sm" href="rooms_proofs.php"><?php e('rooms.proofs_nav'); ?></a>
        <a class="btn btn-primary btn-sm" href="rooms_create.php"><?php e('common.create'); ?></a>
      </div>
    </div>

    <div id="eligibility" style="color:var(--muted);font-size:12px;line-height:1.6;margin:-8px 0 18px 0;"></div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title"><?php e('rooms.filters.title'); ?></div>
    <div class="filters-grid">
      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.search'); ?></label>
        <input type="text" id="rooms-q" placeholder="<?= htmlspecialchars(t('rooms.filters.search_placeholder'), ENT_QUOTES, 'UTF-8') ?>" autocomplete="off" spellcheck="false">
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.saving_type'); ?></label>
        <select id="rooms-type">
          <option value=""><?php e('rooms.filters.any'); ?></option>
          <option value="A"><?php e('rooms.saving_type.a'); ?></option>
          <option value="B"><?php e('rooms.saving_type.b'); ?></option>
        </select>
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.periodicity'); ?></label>
        <select id="rooms-per">
          <option value=""><?php e('rooms.filters.any'); ?></option>
          <option value="weekly"><?php e('rooms.periodicity.weekly'); ?></option>
          <option value="biweekly"><?php e('rooms.periodicity.biweekly'); ?></option>
          <option value="monthly"><?php e('rooms.periodicity.monthly'); ?></option>
        </select>
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.min_amount'); ?></label>
        <input type="number" id="rooms-min" step="0.01" min="0" placeholder="0">
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.max_amount'); ?></label>
        <input type="number" id="rooms-max" step="0.01" min="0" placeholder="0">
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.start_after'); ?></label>
        <input type="date" id="rooms-start-after">
      </div>

      <div class="field" style="margin:0;">
        <label><?php e('rooms.filters.start_before'); ?></label>
        <input type="date" id="rooms-start-before">
      </div>

      <div class="filters-actions">
        <label class="check" style="margin:0;">
          <input type="checkbox" id="rooms-only-open">
          <span><?php e('rooms.filters.only_open'); ?></span>
        </label>

        <label class="check" style="margin:0;">
          <input type="checkbox" id="rooms-only-spots">
          <span><?php e('rooms.filters.only_spots'); ?></span>
        </label>

        <button class="btn btn-ghost btn-sm" type="button" id="rooms-clear"><?php e('rooms.filters.clear'); ?></button>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:14px;">
    <div class="card-title"><?php e('rooms.categories'); ?></div>
    <div class="cat-row" id="cat-row"></div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column:1/-1;">
      <div class="card-title"><?php e('rooms.discover_title'); ?></div>
      <div id="rooms-msg" class="msg"></div>
      <div id="rooms-wrap" class="rooms"></div>
    </div>
  </div>
  </div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
</script>
<script src="assets/rooms_shared.js"></script>
<script>
if(window.Rooms && typeof Rooms.initDiscover === 'function') Rooms.initDiscover();
</script>
</div>
</body>
</html>
 