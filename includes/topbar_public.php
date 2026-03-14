<?php
// Shared public navigation (landing + auth + share).
// Safe to include whether the viewer is logged in or not.

$publicLoggedIn = function_exists('isLoggedIn') ? isLoggedIn() : false;
$publicVerified = $publicLoggedIn && function_exists('isEmailVerified') ? isEmailVerified() : false;
$publicIsAdmin  = $publicLoggedIn && function_exists('isAdmin') ? isAdmin() : false;
$publicEmail    = $publicLoggedIn && function_exists('getCurrentUserEmail') ? (getCurrentUserEmail() ?? '') : '';

$curPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$curFile = $curPath ? basename($curPath) : '';
?>
<div class="topbar topbar-public">
  <a class="topbar-logo" href="index.php"><?= htmlspecialchars(APP_NAME) ?></a>
  <div class="topbar-r">
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>

    <?php $curLang = currentLang(); ?>
    <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_fr'); ?></a>
    <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_en'); ?></a>

    <a class="btn btn-ghost btn-sm" href="index.php#faq"><?php e('common.faq'); ?></a>

    <?php if ($publicLoggedIn): ?>
      <span class="user-pill"><?= htmlspecialchars($publicEmail) ?></span>
      <?php if ($publicVerified): ?>
        <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
        <?php if ($publicIsAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
      <?php else: ?>
        <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.verify_email'); ?></a>
      <?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
    <?php else: ?>
      <?php if ($curFile !== 'login.php'): ?>
        <a class="btn btn-ghost btn-sm" href="login.php"><?php e('common.login'); ?></a>
      <?php endif; ?>
      <?php if ($curFile !== 'signup.php'): ?>
        <a class="btn btn-primary btn-sm" href="signup.php"><?php e('common.create_account'); ?></a>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>
