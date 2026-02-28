<?php
// ============================================================
//  API: POST /api/vault_verify.php (deprecated)
//
//  Strong security mode: the vault passphrase is never sent to the server.
//  Slot detection now happens purely client-side.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

jsonResponse([
    'error' => 'This endpoint is disabled. The vault passphrase is never sent to the server in strong security mode.',
    'error_code' => 'deprecated',
], 410);
