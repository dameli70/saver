<?php
require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();

function hasProfilePhotoColumn(PDO $db): bool {
    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'profile_photo' LIMIT 1");
        return (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        return false;
    }
}

function profilePhotoUrl(?string $path): ?string {
    if (!$path) return null;
    $path = ltrim($path, '/');
    return rtrim(getAppBaseUrl(), '/') . '/' . $path;
}

$db = getDB();
$hasPhotoCol = hasProfilePhotoColumn($db);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $uid = (int)getCurrentUserId();

    $sel = 'email, email_verified_at' . ($hasPhotoCol ? ', profile_photo' : ", '' AS profile_photo");
    $stmt = $db->prepare("SELECT {$sel} FROM users WHERE id = ?");
    $stmt->execute([$uid]);
    $u = $stmt->fetch();
    if (!$u) jsonResponse(['error' => 'User not found'], 404);

    $photoPath = $hasPhotoCol ? (string)$u['profile_photo'] : '';

    jsonResponse([
        'success' => true,
        'email' => (string)$u['email'],
        'verified' => !empty($u['email_verified_at']),
        'profile_photo' => $photoPath !== '' ? $photoPath : null,
        'profile_photo_url' => $photoPath !== '' ? profilePhotoUrl($photoPath) : null,
        'profile_photo_available' => $hasPhotoCol,
    ]);
}

// POST
requireCsrf();

// Multipart upload
if (!empty($_FILES['photo'])) {
    if (!$hasPhotoCol) jsonResponse(['error' => 'Profile photo feature unavailable (missing migrations).'], 400);

    $uid = (int)getCurrentUserId();

    $f = $_FILES['photo'];
    if (!is_array($f) || ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        jsonResponse(['error' => 'Upload failed'], 400);
    }

    $size = (int)($f['size'] ?? 0);
    if ($size <= 0 || $size > 2_000_000) {
        jsonResponse(['error' => 'File must be <= 2MB'], 400);
    }

    $tmp = (string)($f['tmp_name'] ?? '');
    $info = @getimagesize($tmp);
    if (!$info || empty($info['mime'])) {
        jsonResponse(['error' => 'Invalid image'], 400);
    }

    $mime = (string)$info['mime'];
    $ext = match ($mime) {
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
        default => '',
    };

    if ($ext === '') {
        jsonResponse(['error' => 'Supported formats: JPG, PNG, WEBP'], 400);
    }

    $uploadsDir = realpath(__DIR__ . '/..') . '/uploads/avatars';
    if (!is_dir($uploadsDir)) {
        if (!mkdir($uploadsDir, 0755, true)) {
            jsonResponse(['error' => 'Server is not configured for uploads (mkdir failed).'], 500);
        }
    }

    if (!is_writable($uploadsDir)) {
        jsonResponse(['error' => 'Upload directory is not writable.'], 500);
    }

    $name = bin2hex(random_bytes(16)) . '.' . $ext;
    $destAbs = $uploadsDir . '/' . $name;

    if (!move_uploaded_file($tmp, $destAbs)) {
        jsonResponse(['error' => 'Failed to save file'], 500);
    }

    // Remove previous photo (best-effort)
    $stmtPrev = $db->prepare('SELECT profile_photo FROM users WHERE id = ?');
    $stmtPrev->execute([$uid]);
    $prevRow = $stmtPrev->fetch();
    $prevPath = $prevRow ? (string)($prevRow['profile_photo'] ?? '') : '';

    $newPath = 'uploads/avatars/' . $name;

    $stmt = $db->prepare('UPDATE users SET profile_photo = ? WHERE id = ?');
    $stmt->execute([$newPath, $uid]);

    if ($prevPath !== '' && str_starts_with($prevPath, 'uploads/avatars/')) {
        $prevAbs = realpath(__DIR__ . '/..') . '/' . $prevPath;
        if ($prevAbs && str_starts_with($prevAbs, $uploadsDir . '/')) {
            @unlink($prevAbs);
        }
    }

    jsonResponse([
        'success' => true,
        'profile_photo' => $newPath,
        'profile_photo_url' => profilePhotoUrl($newPath),
    ]);
}

$body = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

if ($action === 'delete_photo') {
    if (!$hasPhotoCol) jsonResponse(['error' => 'Profile photo feature unavailable (missing migrations).'], 400);

    $uid = (int)getCurrentUserId();

    $stmtPrev = $db->prepare('SELECT profile_photo FROM users WHERE id = ?');
    $stmtPrev->execute([$uid]);
    $prevRow = $stmtPrev->fetch();
    $prevPath = $prevRow ? (string)($prevRow['profile_photo'] ?? '') : '';

    $db->prepare('UPDATE users SET profile_photo = NULL WHERE id = ?')->execute([$uid]);

    if ($prevPath !== '' && str_starts_with($prevPath, 'uploads/avatars/')) {
        $uploadsDir = realpath(__DIR__ . '/..') . '/uploads/avatars';
        $prevAbs = realpath(__DIR__ . '/..') . '/' . $prevPath;
        if ($uploadsDir && $prevAbs && str_starts_with($prevAbs, $uploadsDir . '/')) {
            @unlink($prevAbs);
        }
    }

    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
