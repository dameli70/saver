<?php
// ============================================================
//  API: POST /api/copied.php — Zero-Knowledge Edition
//  Simply marks the lock as "copied_at" for audit.
//  No password material involved — it was already in the browser.
//  The blind copy happens entirely client-side in zero-knowledge mode.
// ============================================================

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$lockId = trim($body['lock_id'] ?? '');
if (empty($lockId)) jsonResponse(['error' => 'lock_id required'], 400);

$userId = getCurrentUserId();
$db     = getDB();

$stmt = $db->prepare("SELECT id, copied_at FROM locks WHERE id = ? AND user_id = ? AND is_active = 1");
$stmt->execute([$lockId, $userId]);
$lock = $stmt->fetch();

if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);
if ($lock['copied_at']) jsonResponse(['success' => true, 'already_copied' => true]);

$db->prepare("UPDATE locks SET copied_at = NOW() WHERE id = ? AND user_id = ?")
   ->execute([$lockId, $userId]);

auditLog('copy', $lockId);
jsonResponse(['success' => true]);
