<?php
// ============================================================
//  API: /api/onboarding.php
//  First-login setup page controls
//   - complete
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'complete') {
    if (!hasOnboardingColumns()) {
        jsonResponse(['success' => true, 'available' => false]);
    }

    markOnboardingComplete((int)$userId);
    jsonResponse(['success' => true, 'available' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
