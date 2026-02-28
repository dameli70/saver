<?php
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
$stmt   = $db->prepare("UPDATE locks SET is_active = 0 WHERE id = ? AND user_id = ?");
$stmt->execute([$lockId, $userId]);
if ($stmt->rowCount() === 0) jsonResponse(['error' => 'Not found'], 404);

auditLog('delete', $lockId);
jsonResponse(['success' => true]);
