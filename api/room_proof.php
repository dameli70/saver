<?php
// ============================================================
//  API: /api/room_proof.php
//  Download/view a saving room contribution proof (decrypt server-side)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';

startSecureSession();

requireLogin();
requireVerifiedEmail();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Method not allowed";
    exit;
}

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) {
    http_response_code(401);
    exit;
}

$id = trim((string)($_GET['id'] ?? ''));
if ($id === '' || !preg_match('/^\d+$/', $id)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Bad request";
    exit;
}

try {
    $db = getDB();

    $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'saving_room_contribution_proofs' LIMIT 1")->fetchColumn();
    if (!$has) {
        http_response_code(404);
        exit;
    }

    $st = $db->prepare('SELECT id, room_id, user_id, original_filename, content_type, enc_cipher, iv, tag FROM saving_room_contribution_proofs WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();

    if (!$row) {
        http_response_code(404);
        exit;
    }

    $roomId = (string)($row['room_id'] ?? '');

    $allowed = false;
    if (isAdmin($userId)) {
        $allowed = true;
    } else {
        $makerStmt = $db->prepare('SELECT maker_user_id FROM saving_rooms WHERE id = ?');
        $makerStmt->execute([$roomId]);
        $makerId = (int)$makerStmt->fetchColumn();
        if ($makerId === $userId) {
            $allowed = true;
        } else {
            $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
            $myStmt->execute([$roomId, $userId]);
            $myStatus = (string)($myStmt->fetchColumn() ?: '');
            $allowed = in_array($myStatus, ['approved','active','completed'], true);
        }
    }

    if (!$allowed) {
        http_response_code(403);
        exit;
    }

    $contentType = (string)($row['content_type'] ?? 'application/octet-stream');
    if ($contentType === '') $contentType = 'application/octet-stream';

    $plain = mediaDecryptBytes((string)$row['enc_cipher'], (string)$row['iv'], (string)$row['tag']);

    header('Content-Type: ' . $contentType);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');

    echo $plain;
    exit;

} catch (Throwable) {
    http_response_code(404);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    exit;
}
