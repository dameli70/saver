<?php
// ============================================================
//  API: /api/packages.php
//  User-facing package endpoints (view plan + create purchase requests)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/packages.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireCsrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

$body = json_decode(file_get_contents('php://input'), true);
$action = (string)($body['action'] ?? '');

$userId = (int)getCurrentUserId();
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'info') {
    $info = packagesGetUserInfo($userId);
    jsonResponse(['success' => true] + $info);
}

if ($action === 'purchase') {
    if (!hasPackagesTables()) {
        jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
    }

    $packageId = (int)($body['package_id'] ?? 0);
    if ($packageId < 1) jsonResponse(['error' => 'package_id required'], 400);

    $db = getDB();
    packagesSeedDefaults($db);

    $p = $db->prepare('SELECT id, is_active FROM packages WHERE id = ?');
    $p->execute([$packageId]);
    $row = $p->fetch();
    if (!$row) jsonResponse(['error' => 'Package not found'], 404);
    if (empty($row['is_active'])) jsonResponse(['error' => 'Package is not available'], 409);

    // Avoid creating duplicates if a pending purchase exists.
    $q = $db->prepare("SELECT id FROM package_purchases WHERE user_id = ? AND package_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1");
    $q->execute([$userId, $packageId]);
    $existing = (int)($q->fetchColumn() ?: 0);

    if ($existing > 0) {
        jsonResponse(['success' => true, 'purchase_id' => $existing, 'already_pending' => 1]);
    }

    $db->prepare('INSERT INTO package_purchases (user_id, package_id, status) VALUES (?, ?, \'pending\')')
       ->execute([$userId, $packageId]);

    $purchaseId = (int)$db->lastInsertId();
    auditLog('package_purchase_request', null, $userId);

    jsonResponse(['success' => true, 'purchase_id' => $purchaseId]);
}

jsonResponse(['error' => 'Unknown action'], 400);
