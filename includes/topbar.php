<?php
// Shared authenticated navigation.
// Expects (optionally):
//   $userEmail (string)
//   $isAdmin (bool)
//   $verified (bool)

$topbarUserEmail = isset($userEmail) ? (string)$userEmail : (getCurrentUserEmail() ?? '');
$topbarIsAdmin   = isset($isAdmin) ? (bool)$isAdmin : isAdmin();

// Prefer a provided $verified flag (account.php computes it already).
if (isset($verified)) {
    $topbarVerified = (bool)$verified;
} else {
    $topbarVerified = isEmailVerified();
}

$topbarHomeHref = $topbarVerified ? 'dashboard.php' : 'index.php';
?>
<div class="topbar">
  <a class="topbar-logo" href="<?= htmlspecialchars($topbarHomeHref, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars(APP_NAME) ?></a>
  <div class="topbar-r">
    <?php if (isset($topbarBadgeText) && trim((string)$topbarBadgeText) !== ''): ?>
      <span class="topbar-badge"><?= htmlspecialchars((string)$topbarBadgeText) ?></span>
    <?php endif; ?>
    <span class="user-pill"><?= htmlspecialchars($topbarUserEmail) ?></span>
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
    <?php $curLang = currentLang(); ?>
    <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
    <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>
    <a class="btn btn-ghost btn-sm" href="index.php#faq"><?php e('common.faq'); ?></a>

    <?php if ($topbarVerified): ?>
      <a class="btn btn-ghost btn-sm" href="dashboard.php"><?php e('nav.dashboard'); ?></a>
      <a class="btn btn-ghost btn-sm" href="create_code.php"><?php e('nav.create_code'); ?></a>
      <a class="btn btn-ghost btn-sm" href="my_codes.php"><?php e('nav.my_codes'); ?></a>
      <a class="btn btn-ghost btn-sm" href="rooms.php"><?php e('nav.rooms'); ?></a>
      <a class="btn btn-ghost btn-sm" href="notifications.php"><?php e('nav.notifications'); ?></a>
      <a class="btn btn-ghost btn-sm" href="backup.php"><?php e('nav.backups'); ?></a>
      <a class="btn btn-ghost btn-sm" href="vault_settings.php"><?php e('nav.vault'); ?></a>
      <a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($topbarIsAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
    <?php else: ?>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.verify_email'); ?></a>
    <?php endif; ?>

    <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
  </div>
</div>
