<?php
// ============================================================
//  API: /api/app_logo_upload.php
//  Upload/update the app logo (admin-only, multipart/form-data)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';
require_once __DIR__ . '/../includes/app_settings.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireAdmin();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

if (!hasAppSettingsTable()) {
    jsonResponse(['error' => 'App settings are unavailable on this server. Apply database migrations.'], 409);
}

if (empty($_FILES['logo']) || !is_array($_FILES['logo'])) {
    jsonResponse(['error' => 'Missing logo file'], 400);
}

$f = $_FILES['logo'];
$err = (int)($f['error'] ?? UPLOAD_ERR_NO_FILE);
if ($err !== UPLOAD_ERR_OK) {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$tmp = (string)($f['tmp_name'] ?? '');
if ($tmp === '' || !is_uploaded_file($tmp)) {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$maxBytes = 5 * 1024 * 1024;
$size = (int)($f['size'] ?? 0);
if ($size < 1 || $size > $maxBytes) {
    jsonResponse(['error' => 'Logo must be 5MB or less'], 400);
}

$fi = new finfo(FILEINFO_MIME_TYPE);
$mime = (string)($fi->file($tmp) ?: '');

$allowed = [
    'image/png' => true,
    'image/jpeg' => true,
    'image/webp' => true,
];

if (!isset($allowed[$mime])) {
    jsonResponse(['error' => 'Unsupported image type (PNG/JPG/WebP only)'], 415);
}

$imgInfo = @getimagesize($tmp);
if (!$imgInfo || empty($imgInfo[0]) || empty($imgInfo[1])) {
    jsonResponse(['error' => 'Invalid image'], 400);
}

$w = (int)$imgInfo[0];
$h = (int)$imgInfo[1];
if ($w < 64 || $h < 64 || $w > 4096 || $h > 4096) {
    jsonResponse(['error' => 'Image dimensions are invalid'], 400);
}

if ($w !== $h) {
    jsonResponse(['error' => 'Logo must be square (client-side crop required)'], 400);
}

$bytes = file_get_contents($tmp);
if ($bytes === false || $bytes === '') {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$enc = mediaEncryptBytes($bytes);

$db = getDB();
$db->prepare(
    'INSERT INTO app_settings (id, logo_content_type, logo_enc_cipher, logo_iv, logo_tag, logo_updated_at)
     VALUES (1, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE
       logo_content_type = VALUES(logo_content_type),
       logo_enc_cipher = VALUES(logo_enc_cipher),
       logo_iv = VALUES(logo_iv),
       logo_tag = VALUES(logo_tag),
       logo_updated_at = NOW()'
)->execute([
    $mime,
    $enc['cipher'],
    $enc['iv'],
    $enc['tag'],
]);

auditLog('app_logo_updated', null, getCurrentUserId());

jsonResponse(['success' => true]);
