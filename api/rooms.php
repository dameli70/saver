<?php
// ============================================================
//  API: /api/rooms.php
//  Joint saving rooms (creation + discovery + join requests)
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

function requireEligibleForRoomApproval(int $userId, int $requiredTrustLevel): void {
    // Approval-time eligibility check must not block users who are already restricted
    // (restriction prevents joining new rooms; maker approval may happen after request).
    $lvl = getUserTrustLevel($userId);
    if ($lvl < $requiredTrustLevel) {
        jsonResponse([
            'error' => 'User does not meet this room\'s trust level requirement.',
            'error_code' => 'insufficient_trust_level',
            'required_level' => $requiredTrustLevel,
            'user_level' => $lvl,
        ], 403);
    }
}

function activityLog(string $roomId, string $eventType, array $payload): void {
    $db = getDB();
    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, $eventType, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function requireRoomMaker(string $roomId, int $userId): void {
    $db = getDB();
    $stmt = $db->prepare('SELECT maker_user_id FROM saving_rooms WHERE id = ?');
    $stmt->execute([$roomId]);
    $maker = (int)$stmt->fetchColumn();
    if ($maker !== $userId && !isAdmin($userId)) {
        jsonResponse(['error' => 'Only the room maker can perform this action'], 403);
    }
}

function countApprovedParticipants(string $roomId): int {
    $db = getDB();
    $stmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status IN ('approved','active')");
    $stmt->execute([$roomId]);
    return (int)$stmt->fetchColumn();
}

function roomExistsAndJoinable(string $roomId): array {
    $db = getDB();
    $stmt = $db->prepare("SELECT id, maker_user_id, room_state, lobby_state, visibility, required_trust_level, max_participants, min_participants, start_at, reveal_at, periodicity, participation_amount, saving_type, goal_text, purpose_category, privacy_mode
                          FROM saving_rooms WHERE id = ?");
    $stmt->execute([$roomId]);
    $room = $stmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);
    return $room;
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

// ── MY ROOMS (for UI navigation) ────────────────────────────
if ($action === 'my_rooms') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $db = getDB();

    $stmt = $db->prepare("SELECT r.id, r.goal_text, r.saving_type, r.visibility, r.room_state, r.lobby_state,
                                 r.required_trust_level, r.participation_amount, r.periodicity, r.start_at, r.reveal_at,
                                 r.max_participants, r.min_participants, r.maker_user_id,
                                 p.status AS my_status,
                                 (SELECT COUNT(*) FROM saving_room_participants p2 WHERE p2.room_id = r.id AND p2.status IN ('approved','active')) AS approved_count
                          FROM saving_room_participants p
                          JOIN saving_rooms r ON r.id = p.room_id
                          WHERE p.user_id = ?
                            AND p.status IN ('pending','approved','active','removed','completed')
                          ORDER BY r.start_at ASC
                          LIMIT 200");
    $stmt->execute([$userId]);
    $rows = $stmt->fetchAll();

    $out = [];
    foreach ($rows as $r) {
        $approved = (int)$r['approved_count'];
        $max = (int)$r['max_participants'];
        $out[] = [
            'id' => $r['id'],
            'goal' => $r['goal_text'],
            'saving_type' => $r['saving_type'],
            'visibility' => $r['visibility'],
            'room_state' => $r['room_state'],
            'lobby_state' => $r['lobby_state'],
            'required_level' => (int)$r['required_trust_level'],
            'participation_amount' => (string)$r['participation_amount'],
            'periodicity' => $r['periodicity'],
            'start_at' => $r['start_at'],
            'reveal_at' => $r['reveal_at'],
            'spots_remaining' => max(0, $max - $approved),
            'my_status' => $r['my_status'],
            'is_maker' => ((int)$r['maker_user_id'] === $userId) ? 1 : 0,
        ];
    }

    jsonResponse(['success' => true, 'rooms' => $out]);
}

// ── ROOM DETAIL ─────────────────────────────────────────────
if ($action === 'room_detail') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $room = roomExistsAndJoinable($roomId);

    $db = getDB();

    // Viewer must be eligible to even view public/unlisted; private requires membership or invitation (not yet implemented)
    $vis = (string)$room['visibility'];
    if ($vis === 'public') {
        requireEligibleForRoom($userId, (int)$room['required_trust_level']);
    }

    $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $myStmt->execute([$roomId, $userId]);
    $myStatus = $myStmt->fetchColumn();

    if ($vis === 'private' && !$myStatus && !isAdmin($userId)) {
        jsonResponse(['error' => 'Room is private'], 403);
    }

    $approvedCount = countApprovedParticipants($roomId);

    $participantsStmt = $db->prepare("SELECT p.user_id, p.status, u.email,
                                             (SELECT trust_level FROM user_trust WHERE user_id = p.user_id) AS trust_level,
                                             (SELECT COUNT(*) FROM user_strikes WHERE user_id = p.user_id AND created_at >= (NOW() - INTERVAL 6 MONTH)) AS strikes_6m,
                                             (SELECT restricted_until FROM user_restrictions WHERE user_id = p.user_id AND restricted_until > NOW()) AS restricted_until
                                      FROM saving_room_participants p
                                      JOIN users u ON u.id = p.user_id
                                      WHERE p.room_id = ?
                                        AND p.status IN ('approved','active','removed','completed')
                                      ORDER BY p.joined_at ASC");
    $participantsStmt->execute([$roomId]);
    $participants = $participantsStmt->fetchAll();

    $underfillStmt = $db->prepare("SELECT status, decision_deadline_at FROM saving_room_underfill_alerts WHERE room_id = ?");
    $underfillStmt->execute([$roomId]);
    $underfill = $underfillStmt->fetch();

    $activeCycleStmt = $db->prepare("SELECT id, cycle_index, due_at, grace_ends_at, status
                                    FROM saving_room_contribution_cycles
                                    WHERE room_id = ?
                                      AND status IN ('open','grace')
                                    ORDER BY cycle_index ASC
                                    LIMIT 1");
    $activeCycleStmt->execute([$roomId]);
    $activeCycle = $activeCycleStmt->fetch();

    jsonResponse([
        'success' => true,
        'room' => [
            'id' => $room['id'],
            'goal_text' => $room['goal_text'],
            'purpose_category' => $room['purpose_category'],
            'saving_type' => $room['saving_type'],
            'visibility' => $room['visibility'],
            'required_trust_level' => (int)$room['required_trust_level'],
            'participation_amount' => (string)$room['participation_amount'],
            'periodicity' => $room['periodicity'],
            'start_at' => $room['start_at'],
            'reveal_at' => $room['reveal_at'],
            'room_state' => $room['room_state'],
            'lobby_state' => $room['lobby_state'],
            'privacy_mode' => (int)$room['privacy_mode'],
            'min_participants' => (int)$room['min_participants'],
            'max_participants' => (int)$room['max_participants'],
            'approved_count' => $approvedCount,
            'spots_remaining' => max(0, (int)$room['max_participants'] - $approvedCount),
            'maker_user_id' => (int)$room['maker_user_id'],
            'is_maker' => ((int)$room['maker_user_id'] === $userId) ? 1 : 0,
            'my_status' => $myStatus ?: null,
            'underfill' => $underfill ? [
                'status' => $underfill['status'],
                'decision_deadline_at' => $underfill['decision_deadline_at'],
            ] : null,
            'active_cycle' => $activeCycle ? [
                'id' => (int)$activeCycle['id'],
                'cycle_index' => (int)$activeCycle['cycle_index'],
                'due_at' => $activeCycle['due_at'],
                'grace_ends_at' => $activeCycle['grace_ends_at'],
                'status' => $activeCycle['status'],
            ] : null,
        ],
        'participants' => $participants,
    ]);
}

// ── ACTIVITY (polling fallback) ─────────────────────────────
if ($action === 'activity') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $room = roomExistsAndJoinable($roomId);
    $vis = (string)$room['visibility'];

    $db = getDB();

    $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $myStmt->execute([$roomId, $userId]);
    $myStatus = $myStmt->fetchColumn();

    if ($vis === 'private' && !$myStatus && !isAdmin($userId)) {
        jsonResponse(['error' => 'Room is private'], 403);
    }

    if ($vis === 'public') {
        requireEligibleForRoom($userId, (int)$room['required_trust_level']);
    }

    $sinceId = (int)($_GET['since_id'] ?? 0);
    $limit = (int)($_GET['limit'] ?? 100);
    if ($limit < 1) $limit = 1;
    if ($limit > 200) $limit = 200;

    $stmt = $db->prepare('SELECT id, event_type, public_payload_json, created_at FROM saving_room_activity WHERE room_id = ? AND id > ? ORDER BY id ASC LIMIT ?');
    $stmt->bindValue(1, $roomId);
    $stmt->bindValue(2, $sinceId, PDO::PARAM_INT);
    $stmt->bindValue(3, $limit, PDO::PARAM_INT);
    $stmt->execute();

    $rows = $stmt->fetchAll();
    $out = [];
    foreach ($rows as $r) {
        $out[] = [
            'id' => (int)$r['id'],
            'event_type' => $r['event_type'],
            'payload' => json_decode((string)$r['public_payload_json'], true),
            'created_at' => $r['created_at'],
        ];
    }

    jsonResponse(['success' => true, 'events' => $out]);
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

    $room = roomExistsAndJoinable($roomId);

    if ($room['room_state'] !== 'lobby') jsonResponse(['error' => 'Room is not joinable'], 403);
    if ($room['lobby_state'] !== 'open') jsonResponse(['error' => 'Room lobby is locked'], 403);

    // Visibility gating (unlisted/private will be enforced when invites are implemented)
    if ($room['visibility'] === 'private') jsonResponse(['error' => 'Room is private'], 403);

    // Eligibility
    requireEligibleForRoom($userId, (int)$room['required_trust_level']);

    // Capacity check (approved + active)
    $db = getDB();
    $approved = countApprovedParticipants($roomId);
    if ($approved >= (int)$room['max_participants']) jsonResponse(['error' => 'Room is full'], 403);

    // Snapshot for maker
    $lvl = getUserTrustLevel($userId);

    $strikesStmt = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 6 MONTH)");
    $strikesStmt->execute([$userId]);
    $strikeCount = (int)$strikesStmt->fetchColumn();

    $restrictedUntil = userRestrictedUntil($userId);

    $db->prepare("INSERT INTO saving_room_join_requests (room_id, user_id, status, snapshot_level, snapshot_strikes_6m, snapshot_restricted_until)
                  VALUES (?, ?, 'pending', ?, ?, ?)
                  ON DUPLICATE KEY UPDATE status='pending', maker_decided_at=NULL, snapshot_level=VALUES(snapshot_level), snapshot_strikes_6m=VALUES(snapshot_strikes_6m), snapshot_restricted_until=VALUES(snapshot_restricted_until)")
       ->execute([$roomId, $userId, $lvl, $strikeCount, $restrictedUntil]);

    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status) VALUES (?, ?, 'pending')
                  ON DUPLICATE KEY UPDATE status='pending'")
       ->execute([$roomId, $userId]);

    activityLog($roomId, 'join_requested', ['count' => 1]);

    auditLog('room_join_request');
    jsonResponse(['success' => true]);
}

// ── MAKER: LIST JOIN REQUESTS ───────────────────────────────
if ($action === 'maker_join_requests') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $db = getDB();
    $stmt = $db->prepare("SELECT jr.id, jr.user_id, u.email, jr.status, jr.created_at,
                                 jr.snapshot_level, jr.snapshot_strikes_6m, jr.snapshot_restricted_until,
                                 (SELECT trust_level FROM user_trust WHERE user_id = jr.user_id) AS current_level,
                                 (SELECT COUNT(*) FROM user_strikes WHERE user_id = jr.user_id AND created_at >= (NOW() - INTERVAL 6 MONTH)) AS current_strikes_6m,
                                 (SELECT restricted_until FROM user_restrictions WHERE user_id = jr.user_id AND restricted_until > NOW()) AS current_restricted_until
                          FROM saving_room_join_requests jr
                          JOIN users u ON u.id = jr.user_id
                          WHERE jr.room_id = ?
                            AND jr.status = 'pending'
                          ORDER BY jr.created_at ASC
                          LIMIT 200");
    $stmt->execute([$roomId]);

    jsonResponse(['success' => true, 'requests' => $stmt->fetchAll()]);
}

// ── UNDERFILLED: MAKER DECISION ─────────────────────────────
if ($action === 'underfill_decide') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $decision = (string)($body['decision'] ?? '');

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if (!in_array($decision, ['extend_start','lower_min','cancel'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

    requireRoomMaker($roomId, $userId);

    $db = getDB();

    $room = roomExistsAndJoinable($roomId);
    if ($room['room_state'] !== 'lobby') jsonResponse(['error' => 'Room is not in lobby'], 403);

    $a = $db->prepare("SELECT status, decision_deadline_at FROM saving_room_underfill_alerts WHERE room_id = ?");
    $a->execute([$roomId]);
    $alert = $a->fetch();
    if (!$alert || $alert['status'] !== 'open') jsonResponse(['error' => 'No active underfilled-room decision'], 403);

    $deadlineTs = strtotime((string)$alert['decision_deadline_at']);
    if ($deadlineTs && time() > $deadlineTs) jsonResponse(['error' => 'Decision window expired'], 403);

    $approved = countApprovedParticipants($roomId);

    $db->beginTransaction();

    if ($decision === 'extend_start') {
        $newStartAt = (string)($body['new_start_at'] ?? '');
        $newRevealAt = (string)($body['new_reveal_at'] ?? '');

        $startTs = strtotime($newStartAt);
        $revealTs = strtotime($newRevealAt);

        if (!$startTs || !$revealTs) {
            $db->rollBack();
            jsonResponse(['error' => 'Invalid dates'], 400);
        }
        if ($startTs <= time() + 300) {
            $db->rollBack();
            jsonResponse(['error' => 'Start date must be in the future'], 400);
        }
        if ($revealTs <= $startTs) {
            $db->rollBack();
            jsonResponse(['error' => 'Reveal date must be after start date'], 400);
        }

        $extensionsUsed = (int)$room['extensions_used'];
        if ($extensionsUsed >= 2) {
            $db->rollBack();
            jsonResponse(['error' => 'Maximum extensions reached'], 403);
        }

        $oldStartTs = strtotime((string)$room['start_at']);
        if ($oldStartTs && $startTs > ($oldStartTs + (30 * 86400))) {
            $db->rollBack();
            jsonResponse(['error' => 'Each extension is capped at 30 days'], 403);
        }

        $db->prepare("UPDATE saving_rooms SET start_at = ?, reveal_at = ?, extensions_used = extensions_used + 1, updated_at=NOW() WHERE id = ?")
           ->execute([date('Y-m-d H:i:s', $startTs), date('Y-m-d H:i:s', $revealTs), $roomId]);

        $db->prepare("UPDATE saving_room_underfill_alerts SET status='resolved', resolved_at=NOW(), resolution_action='extend_start', resolution_payload=JSON_OBJECT('new_start_at', ?, 'new_reveal_at', ?) WHERE room_id = ?")
           ->execute([date('Y-m-d H:i:s', $startTs), date('Y-m-d H:i:s', $revealTs), $roomId]);

        activityLog($roomId, 'underfilled_resolved', ['action' => 'extend_start']);

    } else if ($decision === 'lower_min') {
        $newMin = (int)($body['new_min_participants'] ?? 0);
        if ($newMin < 2) {
            $db->rollBack();
            jsonResponse(['error' => 'Minimum participants must be at least 2'], 400);
        }
        if ($newMin > (int)$room['min_participants']) {
            $db->rollBack();
            jsonResponse(['error' => 'New minimum must be <= current minimum'], 400);
        }
        if ($approved < $newMin) {
            $db->rollBack();
            jsonResponse(['error' => 'New minimum cannot exceed current approved participants'], 400);
        }

        $db->prepare("UPDATE saving_rooms SET min_participants = ?, updated_at=NOW() WHERE id = ?")
           ->execute([$newMin, $roomId]);

        $db->prepare("UPDATE saving_room_underfill_alerts SET status='resolved', resolved_at=NOW(), resolution_action='lower_min', resolution_payload=JSON_OBJECT('new_min_participants', ?) WHERE room_id = ?")
           ->execute([$newMin, $roomId]);

        activityLog($roomId, 'underfilled_resolved', ['action' => 'lower_min', 'new_min_participants' => $newMin]);

    } else {
        $db->prepare("UPDATE saving_rooms SET room_state='cancelled', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
           ->execute([$roomId]);

        $db->prepare("UPDATE saving_room_underfill_alerts SET status='resolved', resolved_at=NOW(), resolution_action='cancel', resolution_payload=JSON_OBJECT('by_maker', 1) WHERE room_id = ?")
           ->execute([$roomId]);

        activityLog($roomId, 'room_cancelled_by_maker', ['reason' => 'underfilled']);
    }

    $db->commit();

    auditLog('room_underfill_decide');
    jsonResponse(['success' => true]);
}

// ── MAKER: APPROVE / DECLINE JOIN REQUEST ───────────────────
if ($action === 'review_join') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $requestId = (int)($body['request_id'] ?? 0);
    $decision = (string)($body['decision'] ?? '');
    if ($requestId <= 0) jsonResponse(['error' => 'request_id required'], 400);
    if (!in_array($decision, ['approve','decline'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

    $db = getDB();
    $req = $db->prepare('SELECT id, room_id, user_id, status FROM saving_room_join_requests WHERE id = ?');
    $req->execute([$requestId]);
    $jr = $req->fetch();
    if (!$jr) jsonResponse(['error' => 'Join request not found'], 404);

    $roomId = (string)$jr['room_id'];
    requireRoomMaker($roomId, $userId);

    $room = roomExistsAndJoinable($roomId);
    if ($room['room_state'] !== 'lobby' || $room['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting new participants'], 403);
    }

    $approved = countApprovedParticipants($roomId);
    if ($decision === 'approve' && $approved >= (int)$room['max_participants']) {
        jsonResponse(['error' => 'Room is already full'], 403);
    }

    $targetUserId = (int)$jr['user_id'];

    // Re-check eligibility at approval time
    requireEligibleForRoomApproval($targetUserId, (int)$room['required_trust_level']);

    $db->beginTransaction();

    if ($decision === 'approve') {
        $db->prepare("UPDATE saving_room_join_requests SET status='approved', maker_decided_at=NOW() WHERE id = ?")
           ->execute([$requestId]);

        $db->prepare("UPDATE saving_room_participants SET status='approved', approved_at=NOW() WHERE room_id = ? AND user_id = ?")
           ->execute([$roomId, $targetUserId]);

        activityLog($roomId, 'join_approved', ['count' => 1]);

        // Auto lock lobby if max reached
        $after = countApprovedParticipants($roomId);
        if ($after >= (int)$room['max_participants']) {
            $db->prepare("UPDATE saving_rooms SET lobby_state='locked', updated_at=NOW() WHERE id = ?")
               ->execute([$roomId]);
            activityLog($roomId, 'lobby_locked', ['reason' => 'max_participants_reached']);
        }

    } else {
        $db->prepare("UPDATE saving_room_join_requests SET status='declined', maker_decided_at=NOW() WHERE id = ?")
           ->execute([$requestId]);

        $db->prepare("UPDATE saving_room_participants SET status='declined' WHERE room_id = ? AND user_id = ?")
           ->execute([$roomId, $targetUserId]);

        activityLog($roomId, 'join_declined', ['count' => 1]);
    }

    $db->commit();

    auditLog('room_review_join');
    jsonResponse(['success' => true]);
}

// ── CONTRIBUTION: CONFIRM (server-side acknowledgement)
if ($action === 'confirm_contribution') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $cycleId = (int)($body['cycle_id'] ?? 0);
    $amount = (string)($body['amount'] ?? '');
    $reference = trim((string)($body['reference'] ?? ''));

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($cycleId <= 0) jsonResponse(['error' => 'cycle_id required'], 400);
    if (!is_numeric($amount) || (float)$amount <= 0) jsonResponse(['error' => 'Invalid amount'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT room_state, privacy_mode, participation_amount FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $requiredAmount = (float)$room['participation_amount'];
    $givenAmount = (float)$amount;
    if (abs($requiredAmount - $givenAmount) > 0.00001) {
        jsonResponse([
            'error' => 'Contribution amount must match the room participation amount.',
            'required_amount' => (string)$room['participation_amount'],
        ], 400);
    }

    $mem = $db->prepare("SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?");
    $mem->execute([$roomId, $userId]);
    $myStatus = (string)$mem->fetchColumn();
    if (!in_array($myStatus, ['active'], true)) jsonResponse(['error' => 'Not an active participant'], 403);

    $cy = $db->prepare('SELECT id, status, due_at, grace_ends_at FROM saving_room_contribution_cycles WHERE id = ? AND room_id = ?');
    $cy->execute([$cycleId, $roomId]);
    $cycle = $cy->fetch();
    if (!$cycle) jsonResponse(['error' => 'Cycle not found'], 404);

    if ($cycle['status'] === 'closed') jsonResponse(['error' => 'Cycle is closed'], 403);

    $dueTs = strtotime((string)$cycle['due_at']);
    $inGrace = ($dueTs && time() > $dueTs);

    $status = $inGrace ? 'paid_in_grace' : 'paid';

    $db->beginTransaction();

    $db->prepare("INSERT INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status, reference, confirmed_at)
                  VALUES (?, ?, ?, ?, ?, ?, NOW())
                  ON DUPLICATE KEY UPDATE amount=VALUES(amount), status=VALUES(status), reference=VALUES(reference), confirmed_at=NOW()")
       ->execute([$roomId, $userId, $cycleId, $amount, $status, $reference]);

    // Activity feed: show ✓ Contributed; show amount only if privacy mode is disabled.
    $payload = ['cycle_id' => $cycleId];
    if (empty($room['privacy_mode'])) {
        $payload['amount'] = $amount;
    }

    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, 'contribution_confirmed', json_encode($payload, JSON_UNESCAPED_UNICODE)]);

    $db->commit();

    auditLog('room_contribution_confirm');
    jsonResponse(['success' => true]);
}

jsonResponse(['error' => 'Unknown action'], 400);
