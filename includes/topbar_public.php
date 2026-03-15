<?php
// Shared public navigation (landing + auth + share + installer).
// Safe to include whether the viewer is logged in or not.

$topbarPrefix = $topbarPrefix ?? '';
$GLOBALS['topbarPrefix'] = $topbarPrefix;
$topbarShowFaq = $topbarShowFaq ?? true;
$topbarShowAuth = $topbarShowAuth ?? true;

$publicAppName = $topbarAppName ?? (defined('APP_NAME') ? APP_NAME : 'Controle');
$publicLogoUrl = (defined('APP_LOGO_URL') ? trim((string)APP_LOGO_URL) : '');

// Prefer uploaded logo (stored encrypted server-side) if available.
// IMPORTANT: the installer must be viewable even when default DB credentials are invalid.
// Only attempt DB-backed branding after the installer has successfully completed.
$canUseDbBranding = file_exists(__DIR__ . '/../config/installed.flag');
$isInstallPage = strpos($_SERVER['SCRIPT_NAME'] ?? '', '/install/') !== false;

if ($canUseDbBranding && !$isInstallPage && function_exists('getDB')) {
    require_once __DIR__ . '/app_settings.php';
    $uploaded = appUploadedLogoUrl($topbarPrefix);
    if ($uploaded !== '') {
        $publicLogoUrl = $uploaded;
    }
}

$publicLoggedIn = function_exists('isLoggedIn') ? isLoggedIn() : false;
$publicVerified = $publicLoggedIn && function_exists('isEmailVerified') ? isEmailVerified() : false;
$publicIsAdmin  = $publicLoggedIn && function_exists('isAdmin') ? isAdmin() : false;
$publicEmail    = $publicLoggedIn && function_exists('getCurrentUserEmail') ? (getCurrentUserEmail() ?? '') : '';

$curPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
$curFile = $curPath ? basename($curPath) : '';

if (!function_exists('topbarHref')) {
    function topbarHref(string $path): string {
        $pfx = $GLOBALS['topbarPrefix'] ?? '';
        return $pfx . $path;
    }
}
?>
<div class="topbar topbar-public">
  <a class="topbar-logo" href="<?= htmlspecialchars(topbarHref('index.php'), ENT_QUOTES, 'UTF-8') ?>">
    <?php if ($publicLogoUrl !== ''): ?>
      <img class="topbar-logo-img" src="<?= htmlspecialchars($publicLogoUrl, ENT_QUOTES, 'UTF-8') ?>" alt="<?= htmlspecialchars($publicAppName, ENT_QUOTES, 'UTF-8') ?>">
    <?php endif; ?>
    <span class="topbar-logo-text"><?= htmlspecialchars($publicAppName, ENT_QUOTES, 'UTF-8') ?></span>
  </a>
  <div class="topbar-r">
    <button class="btn btn-ghost btn-sm btn-theme" type="button" data-theme-toggle><?php e('common.theme'); ?></button>

    <?php $curLang = currentLang(); ?>
    <a class="<?= $curLang === 'fr' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('fr'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_fr'); ?></a>
    <a class="<?= $curLang === 'en' ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm' ?>" href="<?= htmlspecialchars(langSwitchUrl('en'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.lang_en'); ?></a>

    <?php if ($topbarShowFaq): ?>
      <a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('index.php#faq'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.faq'); ?></a>
    <?php endif; ?>

    <?php if ($topbarShowAuth && $publicLoggedIn): ?>
      <span class="user-pill"><?= htmlspecialchars($publicEmail) ?></span>
      <?php if ($publicVerified): ?>
        <a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('dashboard.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('nav.dashboard'); ?></a>
        <?php if ($publicIsAdmin): ?><a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('admin.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('nav.admin'); ?></a><?php endif; ?>
      <?php else: ?>
        <a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('account.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('nav.verify_email'); ?></a>
      <?php endif; ?>
      <a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('logout.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.logout'); ?></a>
    <?php elseif ($topbarShowAuth): ?>
      <?php if ($curFile !== 'login.php'): ?>
        <a class="btn btn-ghost btn-sm" href="<?= htmlspecialchars(topbarHref('login.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.login'); ?></a>
      <?php endif; ?>
      <?php if ($curFile !== 'signup.php'): ?>
        <a class="btn btn-primary btn-sm" href="<?= htmlspecialchars(topbarHref('signup.php'), ENT_QUOTES, 'UTF-8') ?>"><?php e('common.create_account'); ?></a>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>
