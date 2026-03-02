<?php
// ============================================================
//  API: GET /api/csrf.php
//  Returns the current session CSRF token (mobile clients)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

jsonResponse([
    'success' => true,
    'csrf_token' => getCsrfToken(),
]);
