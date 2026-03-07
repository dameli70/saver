<?php
require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
startSecureSession();

if (!isLoggedIn()) {
    http_response_code(401);
    exit;
}
if (!isEmailVerified()) {
    http_response_code(403);
    exit;
}

$userId = (int)getCurrentUserId();
$roomId = (string)($_GET['room_id'] ?? '');
if ($roomId === '' || strlen($roomId) !== 36) {
    http_response_code(400);
    exit;
}

$sinceId = (int)($_GET['since_id'] ?? 0);
$lastEventIdHeader = (int)($_SERVER['HTTP_LAST_EVENT_ID'] ?? 0);
$lastId = max($sinceId, $lastEventIdHeader);

$db = getDB();

$roomStmt = $db->prepare('SELECT id, visibility, required_trust_level, maker_user_id FROM saving_rooms WHERE id = ?');
$roomStmt->execute([$roomId]);
$room = $roomStmt->fetch();
if (!$room) {
    http_response_code(404);
    exit;
}

$myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
$myStmt->execute([$roomId, $userId]);
$myStatus = $myStmt->fetchColumn();

$vis = (string)$room['visibility'];

if ($vis === 'private' && !$myStatus && !isAdmin($userId)) {
    $myEmail = strtolower(trim(getCurrentUserEmail() ?? ''));

    $inv = $db->prepare("SELECT 1 FROM saving_room_invites
                         WHERE room_id = ?
                           AND invite_mode='private_user'
                           AND status='active'
                           AND (expires_at IS NULL OR expires_at > NOW())
                           AND (invited_user_id = ? OR (invited_email IS NOT NULL AND invited_email = ?))
                         LIMIT 1");
    $inv->execute([$roomId, $userId, $myEmail]);
    $ok = (bool)$inv->fetchColumn();

    if (!$ok) {
        $token = trim((string)($_GET['invite'] ?? ''));
        if ($token !== '' && strlen($token) <= 200 && preg_match('/^[a-f0-9]{16,128}$/i', $token)) {
            $hash = hash('sha256', $token);
            $inv2 = $db->prepare("SELECT 1 FROM saving_room_invites
                                 WHERE room_id = ?
                                   AND invite_mode='private_user'
                                   AND invite_token_hash = ?
                                   AND status='active'
                                   AND (expires_at IS NULL OR expires_at > NOW())
                                 LIMIT 1");
            $inv2->execute([$roomId, $hash]);
            $ok = (bool)$inv2->fetchColumn();
        }
    }

    if (!$ok) {
        http_response_code(403);
        exit;
    }
}

if ($vis === 'unlisted' && !$myStatus && !isAdmin($userId)) {
    $token = trim((string)($_GET['invite'] ?? ''));
    if ($token === '' || strlen($token) > 200 || !preg_match('/^[a-f0-9]{16,128}$/i', $token)) {
        http_response_code(403);
        exit;
    }

    $hash = hash('sha256', $token);
    $inv = $db->prepare("SELECT 1 FROM saving_room_invites
                         WHERE room_id = ?
                           AND invite_mode='unlisted_link'
                           AND invite_token_hash = ?
                           AND status='active'
                           AND (expires_at IS NULL OR expires_at > NOW())
                         LIMIT 1");
    $inv->execute([$roomId, $hash]);
    if (!$inv->fetchColumn()) {
        http_response_code(403);
        exit;
    }
}

if (!$myStatus && !isAdmin($userId) && in_array($vis, ['public','unlisted'], true)) {
    // Mirror api/rooms.php activity restrictions.
    $lvlStmt = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
    $lvlStmt->execute([$userId]);
    $lvl = (int)($lvlStmt->fetchColumn() ?: 1);

    if ($lvl < (int)$room['required_trust_level']) {
        http_response_code(403);
        exit;
    }

    $rest = $db->prepare('SELECT restricted_until FROM user_restrictions WHERE user_id = ?');
    $rest->execute([$userId]);
    $until = $rest->fetchColumn();
    if ($until && strtotime((string)$until) > time()) {
        http_response_code(403);
        exit;
    }
}

header('Content-Type: text/event-stream; charset=utf-8');
header('Cache-Control: no-cache, no-transform');
header('Connection: keep-alive');
header('X-Accel-Buffering: no');

@ini_set('zlib.output_compression', '0');
@ini_set('output_buffering', 'off');

while (ob_get_level() > 0) {
    ob_end_flush();
}

$started = microtime(true);
$maxSeconds = 25.0;

$pollStmt = $db->prepare('SELECT id, event_type, public_payload_json, created_at
                          FROM saving_room_activity
                          WHERE room_id = ? AND id > ?
                          ORDER BY id ASC
                          LIMIT 50');

while ((microtime(true) - $started) < $maxSeconds) {
    if (connection_aborted()) break;

    $pollStmt->execute([$roomId, $lastId]);
    $rows = $pollStmt->fetchAll();

    if ($rows) {
        foreach ($rows as $r) {
            $id = (int)$r['id'];
            $payload = json_decode((string)($r['public_payload_json'] ?? ''), true);
            if (!is_array($payload)) $payload = [];

            $data = [
                'id' => $id,
                'event_type' => (string)$r['event_type'],
                'payload' => $payload,
                'created_at' => (string)$r['created_at'],
            ];

            echo 'id: ' . $id . "\n";
            echo "event: activity\n";
            echo 'data: ' . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";

            $lastId = $id;
        }

        @ob_flush();
        flush();
        continue;
    }

    echo ": ping\n\n";
    @ob_flush();
    flush();
    usleep(1500000);
}
