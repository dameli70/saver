<?php
require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');

$baseUrl = getAppBaseUrl();
$basePath = getAppBasePath();

jsonResponse([
    'success' => true,
    'app_name' => defined('APP_NAME') ? APP_NAME : 'LOCKSMITH',
    'base_url' => $baseUrl,
    'base_path' => $basePath,
    'api_base_url' => $baseUrl . '/api',
    'pwa' => [
        'manifest_url' => $baseUrl . '/manifest.webmanifest',
        'service_worker_url' => $baseUrl . '/sw.js',
    ],
]);
