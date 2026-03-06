<?php
// ============================================================
//  API: /api/trust.php
//  Trust Passport (levels, strikes window, active rooms summary)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

$action = $_GET['action'] ?? '';

function ensureUserTrustRow(int $userId): void {
    $db = getDB();
    $db->prepare('INSERT IGNORE INTO user_trust (user_id, trust_level, completed_reveals_count) VALUES (?, 1, 0)')
       ->execute([(int)$userId]);
}

function strikesLast6MonthsCount(int $userId): int {
    $db = getDB();
    $stmt = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 6 MONTH)");
    $stmt->execute([(int)$userId]);
    return (int)$stmt->fetchColumn();
}

function getRestrictionUntil(int $userId): ?string {
    $db = getDB();
    $stmt = $db->prepare('SELECT restricted_until FROM user_restrictions WHERE user_id = ? AND restricted_until > NOW()');
    $stmt->execute([(int)$userId]);
    $v = $stmt->fetchColumn();
    return $v ? (string)$v : null;
}

function nextLevelHint(int $trustLevel, int $completedQualified): string {
    if ($trustLevel >= 3) return 'Max level reached.';

    if ($trustLevel === 1) {
        $remain = max(0, 2 - $completedQualified);
        if ($remain === 0) return 'Eligible for Level 2 after verification by system rules.';
        return $remain . ' more completed reveal of minimum 1 month to reach Level 2';
    }

    // Level 2 -> 3: 4–5 successful reveals (min 3 weeks each)
    $remain = max(0, 4 - $completedQualified);
    if ($remain === 0) return 'Eligible for Level 3 after verification by system rules.';
    return $remain . ' more completed reveal of minimum 3 weeks to reach Level 3';
}

if ($action === 'passport') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    ensureUserTrustRow($userId);

    $db = getDB();

    $trust = $db->prepare('SELECT trust_level, completed_reveals_count FROM user_trust WHERE user_id = ?');
    $trust->execute([$userId]);
    $t = $trust->fetch();

    $completed = $db->prepare('SELECT room_id, started_at, unlocked_at, duration_days, qualified_for_level FROM user_completed_reveals WHERE user_id = ? ORDER BY unlocked_at DESC LIMIT 20');
    $completed->execute([$userId]);
    $completedRows = $completed->fetchAll();

    $qualifiedCountStmt = $db->prepare('SELECT COUNT(*) FROM user_completed_reveals WHERE user_id = ? AND qualified_for_level = 1');
    $qualifiedCountStmt->execute([$userId]);
    $qualifiedCount = (int)$qualifiedCountStmt->fetchColumn();

    $activeRooms = $db->prepare("SELECT r.id, r.goal_text, r.saving_type, r.start_at, r.reveal_at, r.room_state, r.lobby_state
                                FROM saving_room_participants p
                                JOIN saving_rooms r ON r.id = p.room_id
                                WHERE p.user_id = ?
                                  AND p.status IN ('approved','active')
                                  AND r.room_state IN ('lobby','active')
                                ORDER BY r.start_at ASC
                                LIMIT 20");
    $activeRooms->execute([$userId]);
    $active = $activeRooms->fetchAll();

    $strikeCount = strikesLast6MonthsCount($userId);
    $restrictedUntil = getRestrictionUntil($userId);

    jsonResponse([
        'success' => true,
        'trust' => [
            'level' => (int)($t['trust_level'] ?? 1),
            'completed_reveals_count' => (int)($t['completed_reveals_count'] ?? 0),
            'strike_count_6m' => $strikeCount,
            'restricted_until' => $restrictedUntil,
            'next_level_hint' => nextLevelHint((int)($t['trust_level'] ?? 1), $qualifiedCount),
        ],
        'completed_reveals' => $completedRows,
        'active_rooms' => $active,
    ]);
}

if ($action === 'user_summary') {
    requireLogin();
    requireVerifiedEmail();

    $viewerId = (int)getCurrentUserId();

    $userId = (int)($_GET['user_id'] ?? 0);
    if ($userId <= 0) jsonResponse(['error' => 'user_id required'], 400);

    // Only room makers (or admin) should call this. Enforced in room endpoints too.
    if (!isAdmin($viewerId) && $viewerId === $userId) {
        // allow self
    }

    ensureUserTrustRow($userId);

    $db = getDB();
    $trust = $db->prepare('SELECT trust_level, completed_reveals_count FROM user_trust WHERE user_id = ?');
    $trust->execute([$userId]);
    $t = $trust->fetch();

    jsonResponse([
        'success' => true,
        'user' => [
            'user_id' => $userId,
            'trust_level' => (int)($t['trust_level'] ?? 1),
            'strike_count_6m' => strikesLast6MonthsCount($userId),
            'restricted_until' => getRestrictionUntil($userId),
        ],
    ]);
}

jsonResponse(['error' => 'Unknown action'], 400);
