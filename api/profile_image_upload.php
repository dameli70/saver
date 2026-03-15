<?php
// ============================================================
//  API: /api/profile_image_upload.php
//  Upload/update the logged-in user's profile image (multipart/form-data)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

function hasUserProfileImagesTable(): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $db = getDB();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'user_profile_images' LIMIT 1");
        $cached = (bool)$stmt->fetchColumn();
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

if (!hasUserProfileImagesTable()) {
    jsonResponse(['error' => 'Profile images are unavailable on this server. Apply database migrations.'], 409);
}

if (empty($_FILES['image']) || !is_array($_FILES['image'])) {
    jsonResponse(['error' => 'Missing image file'], 400);
}

$f = $_FILES['image'];
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
    jsonResponse(['error' => 'Image must be 5MB or less'], 400);
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
if ($w < 32 || $h < 32 || $w > 4096 || $h > 4096) {
    jsonResponse(['error' => 'Image dimensions are invalid'], 400);
}

$bytes = file_get_contents($tmp);
if ($bytes === false || $bytes === '') {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$enc = mediaEncryptBytes($bytes);

$db = getDB();
$db->prepare(
    'INSERT INTO user_profile_images (user_id, content_type, enc_cipher, iv, tag, updated_at)
     VALUES (?, ?, ?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE content_type = VALUES(content_type), enc_cipher = VALUES(enc_cipher), iv = VALUES(iv), tag = VALUES(tag), updated_at = NOW()'
)->execute([
    $userId,
    $mime,
    $enc['cipher'],
    $enc['iv'],
    $enc['tag'],
]);

auditLog('profile_image_updated', null, $userId);

jsonResponse(['success' => true]);
