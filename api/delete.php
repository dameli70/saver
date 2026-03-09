<?php
require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

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

$stmt = $db->prepare("SELECT confirmation_status, revealed_at FROM locks WHERE id = ? AND user_id = ? AND is_active = 1 LIMIT 1");
$stmt->execute([$lockId, $userId]);
$row = $stmt->fetch();

if (!$row) jsonResponse(['error' => 'Not found'], 404);

// Only confirmed (time-locked) codes are protected from early deletion.
if (($row['confirmation_status'] ?? '') === 'confirmed') {
    if (empty($row['revealed_at'])) {
        jsonResponse([
            'error' => 'This code cannot be deleted until it has been revealed at least once.',
            'error_code' => 'delete_not_allowed',
        ], 403);
    }

    $revealedAt = new DateTimeImmutable((string)$row['revealed_at']);
    $earliest   = $revealedAt->modify('+1 month');
    $now        = new DateTimeImmutable('now', $revealedAt->getTimezone());

    if ($now < $earliest) {
        $diff = $now->diff($earliest);
        jsonResponse([
            'error' => 'This code can be deleted 1 month after it is revealed.',
            'error_code' => 'delete_too_soon',
            'earliest_delete_at' => $earliest->format('Y-m-d H:i:s'),
            'time_remaining' => sprintf('%dd %dh %dm', $diff->days, $diff->h, $diff->i),
        ], 403);
    }
}

$stmt = $db->prepare('UPDATE locks SET is_active = 0 WHERE id = ? AND user_id = ? AND is_active = 1');
$stmt->execute([$lockId, $userId]);
if ($stmt->rowCount() === 0) jsonResponse(['error' => 'Not found'], 404);

auditLog('delete', $lockId);
jsonResponse(['success' => true]);
