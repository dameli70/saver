<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/includes/helpers.php';
require_once __DIR__ . '/includes/app_settings.php';

header('Content-Type: application/manifest+json; charset=utf-8');
header('Cache-Control: no-store');

$icons = [];

$uploadedLogo = appUploadedLogoUrl();
$logo = ($uploadedLogo !== '')
    ? $uploadedLogo
    : trim((string)(defined('APP_LOGO_URL') ? APP_LOGO_URL : ''));

$logoType = ($uploadedLogo !== '')
    ? appUploadedLogoContentType()
    : 'image/png';

if ($logo !== '') {
    // Historically the manifest used a single logo URL for multiple sizes.
    // We preserve that behavior for compatibility.
    $icons[] = ['src' => $logo, 'sizes' => '192x192', 'type' => $logoType, 'purpose' => 'any'];
    $icons[] = ['src' => $logo, 'sizes' => '512x512', 'type' => $logoType, 'purpose' => 'any'];
}

$out = [
    'name' => APP_NAME,
    'short_name' => APP_NAME,
    'start_url' => './dashboard.php',
    'scope' => './',
    'display' => 'standalone',
    'background_color' => '#07080c',
    'theme_color' => '#0b0d12',
    'icons' => $icons,
];

echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
