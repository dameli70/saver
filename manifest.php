<?php
require_once __DIR__ . '/includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/includes/helpers.php';

header('Content-Type: application/manifest+json; charset=utf-8');
header('Cache-Control: no-store');

$icons = [];
$logo = trim((string)(defined('APP_LOGO_URL') ? APP_LOGO_URL : ''));
if ($logo !== '') {
    $icons[] = ['src' => $logo, 'sizes' => '192x192', 'type' => 'image/png', 'purpose' => 'any'];
    $icons[] = ['src' => $logo, 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'any'];
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
