<?php
// ============================================================
//  API: /api/app_logo.php
//  Fetch the current app logo (public; decrypt server-side)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';
require_once __DIR__ . '/../includes/app_settings.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    http_response_code(405);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Method not allowed';
    exit;
}

if (!hasAppSettingsTable()) {
    http_response_code(404);
    header('Cache-Control: public, max-age=0, must-revalidate');
    exit;
}

try {
    $db = getDB();
    $stmt = $db->prepare('SELECT logo_content_type, logo_enc_cipher, logo_iv, logo_tag, logo_updated_at FROM app_settings WHERE id = 1 LIMIT 1');
    $stmt->execute();
    $row = $stmt->fetch();

    if (!$row || empty($row['logo_enc_cipher']) || empty($row['logo_iv']) || empty($row['logo_tag'])) {
        http_response_code(404);
        header('Cache-Control: public, max-age=0, must-revalidate');
        exit;
    }

    $contentType = (string)($row['logo_content_type'] ?? '');
    if ($contentType === '') $contentType = 'application/octet-stream';

    $cipher = (string)$row['logo_enc_cipher'];
    $iv = (string)$row['logo_iv'];
    $tag = (string)$row['logo_tag'];

    $etag = '"' . hash('sha256', $cipher . $iv . $tag) . '"';

    if (!empty($_SERVER['HTTP_IF_NONE_MATCH']) && trim((string)$_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
        http_response_code(304);
        header('ETag: ' . $etag);
        header('Cache-Control: public, max-age=0, must-revalidate');
        exit;
    }

    $lastMod = null;
    if (!empty($row['logo_updated_at'])) {
        $ts = strtotime((string)$row['logo_updated_at']);
        if ($ts) $lastMod = gmdate('D, d M Y H:i:s', $ts) . ' GMT';
    }

    if ($lastMod && !empty($_SERVER['HTTP_IF_MODIFIED_SINCE'])) {
        $ims = strtotime((string)$_SERVER['HTTP_IF_MODIFIED_SINCE']);
        $lm = strtotime($lastMod);
        if ($ims && $lm && $ims >= $lm) {
            http_response_code(304);
            header('ETag: ' . $etag);
            header('Last-Modified: ' . $lastMod);
            header('Cache-Control: public, max-age=0, must-revalidate');
            exit;
        }
    }

    $plain = mediaDecryptBytes($cipher, $iv, $tag);

    header('Content-Type: ' . $contentType);
    header('Cache-Control: public, max-age=0, must-revalidate');
    header('ETag: ' . $etag);
    if ($lastMod) header('Last-Modified: ' . $lastMod);
    header('X-Content-Type-Options: nosniff');

    echo $plain;
    exit;

} catch (Throwable) {
    http_response_code(404);
    header('Cache-Control: public, max-age=0, must-revalidate');
    exit;
}
