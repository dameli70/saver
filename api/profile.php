<?php
// ============================================================
//  API: /api/profile.php
//  User profile settings (room display nickname, avatar URL, neighborhood, phone numbers)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

function ensureUserTrustRowProfile(int $userId): void {
    $db = getDB();
    $db->prepare('INSERT IGNORE INTO user_trust (user_id, trust_level, completed_reveals_count) VALUES (?, 1, 0)')
       ->execute([(int)$userId]);
}

function getUserTrustLevelProfile(int $userId): int {
    try {
        ensureUserTrustRowProfile($userId);
        $db = getDB();
        $stmt = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
        $stmt->execute([(int)$userId]);
        $lvl = (int)$stmt->fetchColumn();
        return $lvl > 0 ? $lvl : 1;
    } catch (Throwable) {
        return 1;
    }
}

function strLenU(string $s): int {
    return function_exists('mb_strlen') ? (int)mb_strlen($s, 'UTF-8') : strlen($s);
}

function loadProfileRow(int $userId): array {
    $db = getDB();

    $sel = [];

    if (hasRoomDisplayNameColumn()) $sel[] = 'room_display_name';
    else $sel[] = 'NULL AS room_display_name';

    if (hasProfileImageUrlColumn()) $sel[] = 'profile_image_url';
    else $sel[] = 'NULL AS profile_image_url';

    if (hasNeighborhoodColumn()) $sel[] = 'neighborhood';
    else $sel[] = 'NULL AS neighborhood';

    if (hasPhonePrimaryColumn()) $sel[] = 'phone_primary';
    else $sel[] = 'NULL AS phone_primary';

    if (hasPhoneSecondaryColumn()) $sel[] = 'phone_secondary';
    else $sel[] = 'NULL AS phone_secondary';

    $sql = 'SELECT ' . implode(', ', $sel) . ' FROM users WHERE id = ?';
    $stmt = $db->prepare($sql);
    $stmt->execute([(int)$userId]);
    $row = $stmt->fetch();

    return $row ?: [
        'room_display_name' => null,
        'profile_image_url' => null,
        'neighborhood' => null,
        'phone_primary' => null,
        'phone_secondary' => null,
    ];
}

function normalizeNullableText($v): ?string {
    if ($v === null) return null;
    $s = trim((string)$v);
    return ($s === '') ? null : $s;
}

function validatePhoneNullable($v): ?string {
    $s = normalizeNullableText($v);
    if ($s === null) return null;

    if (strLenU($s) > 30) jsonResponse(['error' => 'Phone number must be 30 characters or less'], 400);

    // Allow typical phone formats: digits, spaces, +, -, (), .
    if (!preg_match('/^[0-9+\-().\s]+$/', $s)) {
        jsonResponse(['error' => 'Invalid phone number format'], 400);
    }

    return $s;
}

$trustLevel = getUserTrustLevelProfile($userId);

if ($action === 'get_profile') {
    $row = loadProfileRow($userId);

    $nickname = normalizeNullableText($row['room_display_name'] ?? null);
    $imgUrl = normalizeNullableText($row['profile_image_url'] ?? null);
    $neighborhood = normalizeNullableText($row['neighborhood'] ?? null);
    $phonePrimary = normalizeNullableText($row['phone_primary'] ?? null);
    $phoneSecondary = normalizeNullableText($row['phone_secondary'] ?? null);

    $nicknameLocked = ($trustLevel === 1 && $nickname !== null);

    $profileAvailable = (hasRoomDisplayNameColumn() || hasProfileImageUrlColumn() || hasNeighborhoodColumn() || hasPhonePrimaryColumn() || hasPhoneSecondaryColumn()) ? 1 : 0;

    jsonResponse([
        'success' => true,
        'trust_level' => $trustLevel,
        'room_display_name' => $nickname,
        'profile_image_url' => $imgUrl,
        'neighborhood' => $neighborhood,
        'phone_primary' => $phonePrimary,
        'phone_secondary' => $phoneSecondary,
        'profile_fields_available' => $profileAvailable,
        'nickname_locked' => $nicknameLocked ? 1 : 0,
    ]);
}

if ($action === 'set_profile') {
    $canSetName = hasRoomDisplayNameColumn();
    $canSetImg  = hasProfileImageUrlColumn();
    $canSetNeighborhood = hasNeighborhoodColumn();
    $canSetPhonePrimary = hasPhonePrimaryColumn();
    $canSetPhoneSecondary = hasPhoneSecondaryColumn();

    if (!$canSetName && !$canSetImg && !$canSetNeighborhood && !$canSetPhonePrimary && !$canSetPhoneSecondary) {
        jsonResponse(['error' => 'Profile fields are unavailable on this server. Apply database migrations.'], 409);
    }

    $updates = [];
    $params = [];

    $wantName = array_key_exists('room_display_name', $body);
    $wantImg  = array_key_exists('profile_image_url', $body);
    $wantNeighborhood = array_key_exists('neighborhood', $body);
    $wantPhonePrimary = array_key_exists('phone_primary', $body);
    $wantPhoneSecondary = array_key_exists('phone_secondary', $body);

    $newName = null;
    if ($wantName) {
        if (!$canSetName) {
            jsonResponse(['error' => 'Room nickname is unavailable on this server. Apply database migrations.'], 409);
        }

        $newName = normalizeNullableText($body['room_display_name']);

        if ($newName !== null) {
            if (strLenU($newName) > 60) jsonResponse(['error' => 'Nickname must be 60 characters or less'], 400);
        }

        if ($trustLevel === 1) {
            $cur = loadProfileRow($userId);
            $curName = normalizeNullableText($cur['room_display_name'] ?? null);

            if ($curName !== null && $curName !== $newName) {
                jsonResponse(['error' => 'Nickname cannot be changed at trust level 1.'], 403);
            }
        }

        $updates[] = 'room_display_name = ?';
        $params[] = $newName;
    }

    $newUrl = null;
    if ($wantImg) {
        if (!$canSetImg) {
            jsonResponse(['error' => 'Profile image URL is unavailable on this server. Apply database migrations.'], 409);
        }

        $newUrl = normalizeNullableText($body['profile_image_url']);

        if ($newUrl !== null) {
            if (strLenU($newUrl) > 500) jsonResponse(['error' => 'Profile image URL must be 500 characters or less'], 400);

            if (!filter_var($newUrl, FILTER_VALIDATE_URL)) {
                jsonResponse(['error' => 'Invalid profile image URL'], 400);
            }

            $scheme = strtolower((string)parse_url($newUrl, PHP_URL_SCHEME));
            if (!in_array($scheme, ['http', 'https'], true)) {
                jsonResponse(['error' => 'Profile image URL must start with http:// or https://'], 400);
            }
        }

        $updates[] = 'profile_image_url = ?';
        $params[] = $newUrl;
    }

    $newNeighborhood = null;
    if ($wantNeighborhood) {
        if (!$canSetNeighborhood) {
            jsonResponse(['error' => 'Neighborhood is unavailable on this server. Apply database migrations.'], 409);
        }

        $newNeighborhood = normalizeNullableText($body['neighborhood']);
        if ($newNeighborhood !== null && strLenU($newNeighborhood) > 120) {
            jsonResponse(['error' => 'Neighborhood must be 120 characters or less'], 400);
        }

        $updates[] = 'neighborhood = ?';
        $params[] = $newNeighborhood;
    }

    $newPhonePrimary = null;
    if ($wantPhonePrimary) {
        if (!$canSetPhonePrimary) {
            jsonResponse(['error' => 'Phone number is unavailable on this server. Apply database migrations.'], 409);
        }

        $newPhonePrimary = validatePhoneNullable($body['phone_primary']);
        $updates[] = 'phone_primary = ?';
        $params[] = $newPhonePrimary;
    }

    $newPhoneSecondary = null;
    if ($wantPhoneSecondary) {
        if (!$canSetPhoneSecondary) {
            jsonResponse(['error' => 'Secondary phone number is unavailable on this server. Apply database migrations.'], 409);
        }

        $newPhoneSecondary = validatePhoneNullable($body['phone_secondary']);
        $updates[] = 'phone_secondary = ?';
        $params[] = $newPhoneSecondary;
    }

    if (!$updates) {
        jsonResponse(['error' => 'No fields to update'], 400);
    }

    $db = getDB();
    $sql = 'UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = ?';
    $params[] = $userId;

    $db->prepare($sql)->execute($params);

    auditLog('profile_updated', null, (int)$userId);

    $row = loadProfileRow($userId);

    $nickname = normalizeNullableText($row['room_display_name'] ?? null);
    $imgUrl = normalizeNullableText($row['profile_image_url'] ?? null);
    $neighborhood = normalizeNullableText($row['neighborhood'] ?? null);
    $phonePrimary = normalizeNullableText($row['phone_primary'] ?? null);
    $phoneSecondary = normalizeNullableText($row['phone_secondary'] ?? null);

    $nicknameLocked = ($trustLevel === 1 && $nickname !== null);
    $profileAvailable = (hasRoomDisplayNameColumn() || hasProfileImageUrlColumn() || hasNeighborhoodColumn() || hasPhonePrimaryColumn() || hasPhoneSecondaryColumn()) ? 1 : 0;

    jsonResponse([
        'success' => true,
        'trust_level' => $trustLevel,
        'room_display_name' => $nickname,
        'profile_image_url' => $imgUrl,
        'neighborhood' => $neighborhood,
        'phone_primary' => $phonePrimary,
        'phone_secondary' => $phoneSecondary,
        'profile_fields_available' => $profileAvailable,
        'nickname_locked' => $nicknameLocked ? 1 : 0,
    ]);
}

jsonResponse(['error' => 'Unknown action'], 400);
