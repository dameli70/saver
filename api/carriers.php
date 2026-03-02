<?php
// ============================================================
//  API: GET /api/carriers.php
//  Lists active carriers + their USSD templates (non-secret)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

try {
    $db = getDB();

    $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
    if (!$has) {
        jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);
    }

    $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template FROM carriers WHERE is_active = 1 ORDER BY name ASC")->fetchAll();

    jsonResponse(['success' => true, 'carriers' => $rows]);
} catch (Throwable $e) {
    jsonResponse(['error' => 'Failed to load carriers'], 500);
}
