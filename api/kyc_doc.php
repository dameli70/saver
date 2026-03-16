<?php
// ============================================================
//  API: /api/kyc_doc.php
//  Download a KYC document (decrypt server-side)
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
    $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'kyc_documents' LIMIT 1")->fetchColumn();
    if (!$has) {
        http_response_code(404);
        exit;
    }

    $st = $db->prepare('SELECT id, user_id, original_filename, content_type, enc_cipher, iv, tag FROM kyc_documents WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();

    if (!$row) {
        http_response_code(404);
        exit;
    }

    $docUserId = (int)($row['user_id'] ?? 0);
    $isAdmin = isAdmin($userId);
    if (!$isAdmin && $docUserId !== $userId) {
        http_response_code(403);
        exit;
    }

    $contentType = (string)($row['content_type'] ?? 'application/octet-stream');
    if ($contentType === '') $contentType = 'application/octet-stream';

    $plain = mediaDecryptBytes((string)$row['enc_cipher'], (string)$row['iv'], (string)$row['tag']);

    $fn = (string)($row['original_filename'] ?? 'document');
    $fn = str_replace(["\0", "\r", "\n"], '', $fn);
    $fn = preg_replace('#[\\\\/]+#', '_', $fn);
    $fn = trim((string)$fn);
    if ($fn === '') $fn = 'document';

    header('Content-Type: ' . $contentType);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');

    $safe = addcslashes($fn, "\\\"\\\\");
    header('Content-Disposition: attachment; filename="' . $safe . '"');

    echo $plain;
    exit;

} catch (Throwable) {
    http_response_code(404);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    exit;
}
