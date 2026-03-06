<?php
// ============================================================
//  API: /api/rooms.php
//  Joint saving rooms (creation + discovery + join request)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

$body = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? ($_GET['action'] ?? '');

function ensureUserTrustRowRooms(int $userId): void {
    $db = getDB();
    $db->prepare('INSERT IGNORE INTO user_trust (user_id, trust_level, completed_reveals_count) VALUES (?, 1, 0)')
       ->execute([(int)$userId]);
}

function getUserTrustLevel(int $userId): int {
    ensureUserTrustRowRooms($userId);
    $db = getDB();
    $stmt = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
    $stmt->execute([(int)$userId]);
    $lvl = (int)$stmt->fetchColumn();
    return $lvl > 0 ? $lvl : 1;
}

function userRestrictedUntil(int $userId): ?string {
    $db = getDB();
    $stmt = $db->prepare('SELECT restricted_until FROM user_restrictions WHERE user_id = ? AND restricted_until > NOW()');
    $stmt->execute([(int)$userId]);
    $v = $stmt->fetchColumn();
    return $v ? (string)$v : null;
}

function requireEligibleForRoom(int $userId, int $requiredTrustLevel): void {
    $restricted = userRestrictedUntil($userId);
    if ($restricted) {
        jsonResponse([
            'error' => 'You are in a restricted period and cannot join new rooms.',
            'error_code' => 'restricted_period',
            'restricted_until' => $restricted,
        ], 403);
    }

    $lvl = getUserTrustLevel($userId);
    if ($lvl < $requiredTrustLevel) {
        jsonResponse([
            'error' => 'Your trust level does not meet this room\'s requirement.',
            'error_code' => 'insufficient_trust_level',
            'required_level' => $requiredTrustLevel,
            'your_level' => $lvl,
        ], 403);
    }
}

function activityLog(string $roomId, string $eventType, array $payload): void {
    $db = getDB();
    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, $eventType, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

// ── DISCOVERY (public rooms only; filtered by trust level) ───
if ($action === 'discover') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $lvl = getUserTrustLevel($userId);

    $category = $_GET['category'] ?? '';
    $allowed = ['education','travel','business','emergency','community','other'];
    if ($category !== '' && !in_array($category, $allowed, true)) {
        jsonResponse(['error' => 'Invalid category'], 400);
    }

    $db = getDB();

    $sql = "SELECT r.id, r.purpose_category, r.goal_text, r.saving_type, r.required_trust_level,
                   r.participation_amount, r.periodicity, r.start_at, r.max_participants,
                   (SELECT COUNT(*) FROM saving_room_participants p WHERE p.room_id = r.id AND p.status IN ('approved','active')) AS approved_count
            FROM saving_rooms r
            WHERE r.visibility = 'public'
              AND r.room_state = 'lobby'
              AND r.required_trust_level <= ?
              AND r.lobby_state IN ('open','locked')";

    $params = [$lvl];

    if ($category !== '') {
        $sql .= " AND r.purpose_category = ?";
        $params[] = $category;
    }

    $sql .= " ORDER BY r.start_at ASC LIMIT 200";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rooms = $stmt->fetchAll();

    $out = [];
    foreach ($rooms as $r) {
        $approved = (int)$r['approved_count'];
        $max = (int)$r['max_participants'];
        $spots = max(0, $max - $approved);
        $out[] = [
            'id' => $r['id'],
            'category' => $r['purpose_category'],
            'goal' => $r['goal_text'],
            'saving_type' => $r['saving_type'],
            'required_level' => (int)$r['required_trust_level'],
            'participation_amount' => (string)$r['participation_amount'],
            'periodicity' => $r['periodicity'],
            'start_at' => $r['start_at'],
            'spots_remaining' => $spots,
            'max_participants' => $max,
        ];
    }

    jsonResponse(['success' => true, 'rooms' => $out]);
}

// ── CREATE ROOM ─────────────────────────────────────────────
if ($action === 'create_room') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();

    $goal = trim((string)($body['goal_text'] ?? ''));
    $purpose = (string)($body['purpose_category'] ?? 'other');
    $savingType = (string)($body['saving_type'] ?? '');
    $visibility = (string)($body['visibility'] ?? 'public');

    $requiredLevel = (int)($body['required_trust_level'] ?? 1);
    $minP = (int)($body['min_participants'] ?? 2);
    $maxP = (int)($body['max_participants'] ?? 0);

    $amount = (string)($body['participation_amount'] ?? '');
    $periodicity = (string)($body['periodicity'] ?? '');

    $startAt = (string)($body['start_at'] ?? '');
    $revealAt = (string)($body['reveal_at'] ?? '');

    $privacyMode = !empty($body['privacy_mode']) ? 1 : 0;
    $escrowPolicy = (string)($body['escrow_policy'] ?? 'redistribute');

    if ($goal === '' || strlen($goal) > 500) jsonResponse(['error' => 'Invalid goal'], 400);

    $allowedPurpose = ['education','travel','business','emergency','community','other'];
    if (!in_array($purpose, $allowedPurpose, true)) jsonResponse(['error' => 'Invalid purpose'], 400);

    if (!in_array($savingType, ['A','B'], true)) jsonResponse(['error' => 'Invalid saving type'], 400);

    if (!in_array($visibility, ['public','unlisted','private'], true)) jsonResponse(['error' => 'Invalid visibility'], 400);

    if ($requiredLevel < 1 || $requiredLevel > 3) jsonResponse(['error' => 'Invalid required trust level'], 400);
    if ($minP < 2) jsonResponse(['error' => 'Minimum participants must be at least 2'], 400);
    if ($maxP < $minP) jsonResponse(['error' => 'Max participants must be >= min participants'], 400);

    if (!in_array($periodicity, ['weekly','biweekly','monthly'], true)) jsonResponse(['error' => 'Invalid periodicity'], 400);

    if (!is_numeric($amount) || (float)$amount <= 0) jsonResponse(['error' => 'Invalid participation amount'], 400);

    if (!in_array($escrowPolicy, ['redistribute','refund_minus_fee'], true)) jsonResponse(['error' => 'Invalid escrow policy'], 400);

    // Maker is bound to required level
    requireEligibleForRoom($userId, $requiredLevel);

    $startTs = strtotime($startAt);
    $revealTs = strtotime($revealAt);
    if (!$startTs || !$revealTs) jsonResponse(['error' => 'Invalid dates'], 400);
    if ($startTs <= time() + 300) jsonResponse(['error' => 'Start date must be in the future'], 400);
    if ($revealTs <= $startTs) jsonResponse(['error' => 'Reveal date must be after start date'], 400);

    $roomId = generateUUID();

    $db = getDB();
    $db->beginTransaction();

    $db->prepare("INSERT INTO saving_rooms (
            id, maker_user_id, purpose_category, goal_text, saving_type, visibility,
            required_trust_level, min_participants, max_participants,
            participation_amount, periodicity, start_at, reveal_at,
            lobby_state, room_state, privacy_mode, escrow_policy
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?,
            'open', 'lobby', ?, ?
        )")
        ->execute([
            $roomId, $userId, $purpose, $goal, $savingType, $visibility,
            $requiredLevel, $minP, $maxP,
            $amount, $periodicity, date('Y-m-d H:i:s', $startTs), date('Y-m-d H:i:s', $revealTs),
            $privacyMode, $escrowPolicy,
        ]);

    // Maker is a participant (must still be approved for consistency; mark approved immediately)
    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status, approved_at) VALUES (?, ?, 'approved', NOW())")
       ->execute([$roomId, $userId]);

    activityLog($roomId, 'room_created', [
        'goal' => $goal,
        'saving_type' => $savingType,
        'visibility' => $visibility,
        'required_level' => $requiredLevel,
        'periodicity' => $periodicity,
        'start_at' => date('c', $startTs),
    ]);

    $db->commit();

    auditLog('room_create');
    jsonResponse(['success' => true, 'room_id' => $roomId]);
}

// ── REQUEST JOIN ────────────────────────────────────────────
if ($action === 'request_join') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $stmt = $db->prepare("SELECT id, maker_user_id, room_state, lobby_state, visibility, required_trust_level, max_participants, start_at
                          FROM saving_rooms WHERE id = ?");
    $stmt->execute([$roomId]);
    $room = $stmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['room_state'] !== 'lobby') jsonResponse(['error' => 'Room is not joinable'], 403);
    if ($room['lobby_state'] !== 'open') jsonResponse(['error' => 'Room lobby is locked'], 403);

    // Eligibility
    requireEligibleForRoom($userId, (int)$room['required_trust_level']);

    // Capacity check (approved + active)
    $cnt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status IN ('approved','active')");
    $cnt->execute([$roomId]);
    $approved = (int)$cnt->fetchColumn();
    if ($approved >= (int)$room['max_participants']) jsonResponse(['error' => 'Room is full'], 403);

    // Snapshot for maker
    ensureUserTrustRowRooms($userId);
    $lvl = getUserTrustLevel($userId);

    $strikesStmt = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 6 MONTH)");
    $strikesStmt->execute([$userId]);
    $strikeCount = (int)$strikesStmt->fetchColumn();

    $restrictedUntil = userRestrictedUntil($userId);

    // Upsert join request
    $db->prepare("INSERT INTO saving_room_join_requests (room_id, user_id, status, snapshot_level, snapshot_strikes_6m, snapshot_restricted_until)
                  VALUES (?, ?, 'pending', ?, ?, ?)
                  ON DUPLICATE KEY UPDATE status='pending', maker_decided_at=NULL, snapshot_level=VALUES(snapshot_level), snapshot_strikes_6m=VALUES(snapshot_strikes_6m), snapshot_restricted_until=VALUES(snapshot_restricted_until)")
       ->execute([$roomId, $userId, $lvl, $strikeCount, $restrictedUntil]);

    // Mirror in participants table as pending
    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status) VALUES (?, ?, 'pending')
                  ON DUPLICATE KEY UPDATE status='pending'")
       ->execute([$roomId, $userId]);

    activityLog($roomId, 'join_requested', ['count' => 1]);

    auditLog('room_join_request');
    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
