<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForPage();

require_once __DIR__ . '/includes/helpers.php';
startSecureSession();

require_once __DIR__ . '/includes/i18n.php';
// startSecureSession() bootstraps i18n via helpers.php, but keep explicit for safety.
i18nBootstrap();

$lang = (string)($_GET['lang'] ?? '');
$r = (string)($_GET['r'] ?? '/');
$r = str_replace(["\r", "\n"], '', $r);

// Only allow in-app relative paths.
if ($r === '' || $r[0] !== '/' || str_starts_with($r, '//')) $r = '/';

if (!in_array($lang, I18N_SUPPORTED_LANGS, true)) {
    $lang = I18N_DEFAULT_LANG;
}

i18nSetLang($lang);

$base = i18nAppBasePath();

// For subdirectory installs, normalize $r so we don't build /base/base/*.
if ($base !== '' && (
    $r === $base ||
    str_starts_with($r, $base . '/') ||
    str_starts_with($r, $base . '?')
)) {
    $r = substr($r, strlen($base));
    if ($r === '' || $r[0] !== '/') {
        $r = '/' . ltrim($r, '/');
    }
}

$target = ($base ? $base : '') . $r;

header('Location: ' . $target);
exit;
