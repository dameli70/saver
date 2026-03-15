<?php
// ============================================================
//  API: /api/profile_image.php
//  Fetch the logged-in user's profile image (decrypt server-side)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';

startSecureSession();

requireLogin();

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
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

try {
    $db = getDB();
    $stmt = $db->prepare('SELECT content_type, enc_cipher, iv, tag FROM user_profile_images WHERE user_id = ?');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(404);
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        exit;
    }

    $contentType = (string)($row['content_type'] ?? '');
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
