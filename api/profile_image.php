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

function outputDefaultAvatarSvg(int $userId): void {
    $initial = '?';

    try {
        $db = getDB();
        if (dbHasColumn('users', 'room_display_name')) {
            $st = $db->prepare('SELECT room_display_name FROM users WHERE id = ?');
        } else {
            $st = $db->prepare('SELECT email AS room_display_name FROM users WHERE id = ?');
        }
        $st->execute([$userId]);

        $name = trim((string)($st->fetchColumn() ?: ''));
        if ($name !== '') {
            if (function_exists('mb_substr')) {
                $initial = strtoupper((string)mb_substr($name, 0, 1, 'UTF-8'));
            } else {
                $initial = strtoupper(substr($name, 0, 1));
            }

            if (!preg_match('/^[A-Z0-9]$/', $initial)) {
                $initial = strtoupper(substr(preg_replace('/[^A-Za-z0-9]/', '', $name), 0, 1));
                if ($initial === '') $initial = '?';
            }
        }
    } catch (Throwable) {
        // Fall back to '?'
    }

    header('Content-Type: image/svg+xml; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');

    // Simple, neutral avatar that avoids 404 noise for users without an uploaded image.
    echo '<?xml version="1.0" encoding="UTF-8"?>'
        . '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128">'
        . '<rect width="128" height="128" rx="64" fill="#E9EEF5"/>'
        . '<circle cx="64" cy="52" r="22" fill="#B9C6D6"/>'
        . '<path d="M20 118c10-22 26-34 44-34s34 12 44 34" fill="#B9C6D6"/>'
        . '<text x="64" y="70" text-anchor="middle" font-family="system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif" font-size="28" font-weight="700" fill="#5B6B7F">'
        . htmlspecialchars($initial, ENT_QUOTES, 'UTF-8')
        . '</text>'
        . '</svg>';
    exit;
}

try {
    $db = getDB();
    $stmt = $db->prepare('SELECT content_type, enc_cipher, iv, tag FROM user_profile_images WHERE user_id = ?');
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    if (!$row) {
        outputDefaultAvatarSvg($userId);
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
    // Avoid persistent 404 spam for avatar URLs; return a neutral fallback instead.
    outputDefaultAvatarSvg($userId);
}
