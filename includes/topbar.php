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
$topbarLogoUrl = (defined('APP_LOGO_URL') ? trim((string)APP_LOGO_URL) : '');

$topbarShowSetup = true;
if ($topbarVerified) {
    $uid = (int)(getCurrentUserId() ?? 0);
    if ($uid && hasOnboardingColumns() && isOnboardingComplete($uid)) {
        $topbarShowSetup = false;
    }
}

$topbarCurPage = basename($_SERVER['PHP_SELF'] ?? '');
$topbarActive = function(string $href) use ($topbarCurPage): bool {
    $base = explode('#', $href, 2)[0];

    if ($base === 'security.php') {
        return $topbarCurPage === 'security.php' || str_starts_with($topbarCurPage, 'security_');
    }

    if ($base === 'admin.php') {
        return $topbarCurPage === 'admin.php' || str_starts_with($topbarCurPage, 'admin_');
    }

    return $base !== '' && $base === $topbarCurPage;
};
?>
<div class="topbar">
  <a class="topbar-logo" href="<?= htmlspecialchars($topbarHomeHref, ENT_QUOTES, 'UTF-8') ?>">
    <?php if ($topbarLogoUrl !== ''): ?>
      <img class="topbar-logo-img" src="<?= htmlspecialchars($topbarLogoUrl, ENT_QUOTES, 'UTF-8') ?>" alt="<?= htmlspecialchars(APP_NAME, ENT_QUOTES, 'UTF-8') ?>">
    <?php endif; ?>
    <span class="topbar-logo-text"><?= htmlspecialchars(APP_NAME, ENT_QUOTES, 'UTF-8') ?></span>
  </a>

  <!-- Mobile-only drawer (CSS-only fallback in case assets/app.js fails). -->
  <input class="ls-mobile-nav-toggle" type="checkbox" id="ls-mobile-nav-toggle">
  <label class="btn btn-ghost btn-sm topbar-menu-btn nav-btn" for="ls-mobile-nav-toggle" role="button" tabindex="0" aria-haspopup="dialog" aria-controls="ls-mobile-nav-panel" aria-expanded="false" aria-label="<?= htmlspecialchars(t('common.menu'), ENT_QUOTES, 'UTF-8') ?>" onkeydown="if(event.key==='Enter'||event.key===' '||event.key==='Spacebar'){event.preventDefault();this.click();}">
    <span class="nav-ico" aria-hidden="true">☰</span>
    <span class="nav-lbl"><?php e('common.menu'); ?></span>
  </label>
  <div class="ls-mobile-nav-overlay">
    <label class="ls-mobile-nav-backdrop" for="ls-mobile-nav-toggle" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>"></label>
    <div class="ls-mobile-nav-panel" id="ls-mobile-nav-panel" role="dialog" aria-modal="true" aria-labelledby="ls-mobile-nav-title">
      <div class="ls-mobile-nav-head">
        <div class="ls-mobile-nav-title" id="ls-mobile-nav-title"><?php e('common.menu'); ?></div>
        <label class="btn btn-ghost btn-sm" for="ls-mobile-nav-toggle" role="button" tabindex="0" aria-label="<?= htmlspecialchars(t('common.close'), ENT_QUOTES, 'UTF-8') ?>" onkeydown="if(event.key==='Enter'||event.key===' '||event.key==='Spacebar'){event.preventDefault();this.click();}">×</label>
      </div>

      <div class="ls-mobile-nav-links" style="display:flex;flex-direction:column;gap:10px;">
        <?php if (isset($topbarBadgeText) && trim((string)$topbarBadgeText) !== ''): ?>
          <span class="topbar-badge"><?= htmlspecialchars((string)$topbarBadgeText) ?></span>
        <?php endif; ?>
        <span class="user-pill"><?= htmlspecialchars($topbarUserEmail) ?></span>

        <div class="nav-group-title"><?php e('common.preferences'); ?></div>
        <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>
        <?php $curLang = currentLang(); ?>
        <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr')) ?>"><?php e('common.lang_fr'); ?></a>
        <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en')) ?>"><?php e('common.lang_en'); ?></a>

        <?php if ($topbarVerified): ?>
          <div class="nav-group-title"><?php e('common.menu'); ?></div>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('dashboard.php') ? 'active' : '' ?>" href="dashboard.php" <?= $topbarActive('dashboard.php') ? 'aria-current="page"' : '' ?>><?php e('nav.dashboard'); ?></a>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('create_code.php') ? 'active' : '' ?>" href="create_code.php" <?= $topbarActive('create_code.php') ? 'aria-current="page"' : '' ?>><?php e('nav.create_code'); ?></a>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('my_codes.php') ? 'active' : '' ?>" href="my_codes.php" <?= $topbarActive('my_codes.php') ? 'aria-current="page"' : '' ?>><?php e('nav.my_codes'); ?></a>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('rooms.php') || $topbarActive('room.php') ? 'active' : '' ?>" href="rooms.php" <?= ($topbarActive('rooms.php') || $topbarActive('room.php')) ? 'aria-current="page"' : '' ?>><?php e('nav.rooms'); ?></a>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('notifications.php') ? 'active' : '' ?>" href="notifications.php" <?= $topbarActive('notifications.php') ? 'aria-current="page"' : '' ?>><?php e('nav.notifications'); ?></a>

          <div class="nav-group-title"><?php e('nav.vault'); ?></div>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('vault_settings.php') ? 'active' : '' ?>" href="vault_settings.php" <?= $topbarActive('vault_settings.php') ? 'aria-current="page"' : '' ?>><?php e('nav.vault'); ?></a>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('backup.php') ? 'active' : '' ?>" href="backup.php" <?= $topbarActive('backup.php') ? 'aria-current="page"' : '' ?>><?php e('nav.backups'); ?></a>

          <div class="nav-group-title"><?php e('dashboard.security'); ?></div>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('security.php') ? 'active' : '' ?>" href="security.php" <?= $topbarActive('security.php') ? 'aria-current="page"' : '' ?>><?php e('nav.security'); ?></a>
          <?php if ($topbarShowSetup): ?><a class="btn btn-ghost btn-sm <?= $topbarActive('setup.php') ? 'active' : '' ?>" href="setup.php" <?= $topbarActive('setup.php') ? 'aria-current="page"' : '' ?>><?php e('nav.setup'); ?></a><?php endif; ?>
          <a class="btn btn-ghost btn-sm <?= $topbarActive('account.php') ? 'active' : '' ?>" href="account.php" <?= $topbarActive('account.php') ? 'aria-current="page"' : '' ?>><?php e('nav.account'); ?></a>
          <?php if ($topbarIsAdmin): ?><a class="btn btn-ghost btn-sm <?= $topbarActive('admin.php') ? 'active' : '' ?>" href="admin.php" <?= $topbarActive('admin.php') ? 'aria-current="page"' : '' ?>><?php e('nav.admin'); ?></a><?php endif; ?>

          <div class="nav-group-title"><?php e('common.help'); ?></div>
          <a class="btn btn-ghost btn-sm" href="index.php#faq"><?php e('common.faq'); ?></a>

          <div class="nav-group-title"><?php e('common.session'); ?></div>
          <a class="btn btn-red btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
        <?php else: ?>
          <div class="nav-group-title"><?php e('common.help'); ?></div>
          <a class="btn btn-ghost btn-sm" href="index.php#faq"><?php e('common.faq'); ?></a>

          <div class="nav-group-title"><?php e('common.session'); ?></div>
          <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.verify_email'); ?></a>
          <a class="btn btn-red btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- Desktop / JS-enhanced nav container. -->
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
      <a class="btn btn-ghost btn-sm" href="security.php"><?php e('nav.security'); ?></a>
      <?php if ($topbarShowSetup): ?><a class="btn btn-ghost btn-sm" href="setup.php"><?php e('nav.setup'); ?></a><?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.account'); ?></a>
      <?php if ($topbarIsAdmin): ?><a class="btn btn-ghost btn-sm" href="admin.php"><?php e('nav.admin'); ?></a><?php endif; ?>
    <?php else: ?>
      <a class="btn btn-ghost btn-sm" href="account.php"><?php e('nav.verify_email'); ?></a>
    <?php endif; ?>

    <a class="btn btn-ghost btn-sm" href="logout.php"><?php e('common.logout'); ?></a>
  </div>
</div>

<?php if ($topbarVerified): ?>
  <div class="bottom-nav" aria-label="<?= htmlspecialchars(t('common.menu'), ENT_QUOTES, 'UTF-8') ?>">
    <a href="dashboard.php" aria-label="<?= htmlspecialchars(t('nav.dashboard'), ENT_QUOTES, 'UTF-8') ?>" <?= $topbarActive('dashboard.php') ? 'aria-current="page"' : '' ?>><span class="btn bn-btn nav-btn btn-ghost btn-sm <?= $topbarActive('dashboard.php') ? 'active' : '' ?>"><span class="nav-ico" aria-hidden="true">⌂</span><span class="nav-lbl"><?php e('nav.dashboard'); ?></span></span></a>
    <a href="create_code.php" aria-label="<?= htmlspecialchars(t('nav.create_code'), ENT_QUOTES, 'UTF-8') ?>" <?= $topbarActive('create_code.php') ? 'aria-current="page"' : '' ?>><span class="btn bn-btn nav-btn btn-ghost btn-sm <?= $topbarActive('create_code.php') ? 'active' : '' ?>"><span class="nav-ico" aria-hidden="true">✚</span><span class="nav-lbl"><?php e('nav.create_code'); ?></span></span></a>
    <a href="my_codes.php" aria-label="<?= htmlspecialchars(t('nav.my_codes'), ENT_QUOTES, 'UTF-8') ?>" <?= $topbarActive('my_codes.php') ? 'aria-current="page"' : '' ?>><span class="btn bn-btn nav-btn btn-ghost btn-sm <?= $topbarActive('my_codes.php') ? 'active' : '' ?>"><span class="nav-ico" aria-hidden="true">⧉</span><span class="nav-lbl"><?php e('nav.my_codes'); ?></span></span></a>
    <a href="rooms.php" aria-label="<?= htmlspecialchars(t('nav.rooms'), ENT_QUOTES, 'UTF-8') ?>" <?= ($topbarActive('rooms.php') || $topbarActive('room.php')) ? 'aria-current="page"' : '' ?>><span class="btn bn-btn nav-btn btn-ghost btn-sm <?= ($topbarActive('rooms.php') || $topbarActive('room.php')) ? 'active' : '' ?>"><span class="nav-ico" aria-hidden="true">◻</span><span class="nav-lbl"><?php e('nav.rooms'); ?></span></span></a>
    <a href="notifications.php" aria-label="<?= htmlspecialchars(t('nav.notifications'), ENT_QUOTES, 'UTF-8') ?>" <?= $topbarActive('notifications.php') ? 'aria-current="page"' : '' ?>><span class="btn bn-btn nav-btn btn-ghost btn-sm <?= $topbarActive('notifications.php') ? 'active' : '' ?>"><span class="nav-ico" aria-hidden="true">✉</span><span class="nav-lbl"><?php e('nav.notifications'); ?></span></span></a>
  </div>
  <script>try{var a=document.getElementById('app');if(a)a.classList.add('has-bottom-nav');}catch(e){}</script>
<?php endif; ?>
