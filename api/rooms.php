<?php
// ============================================================
//  API: /api/rooms.php
//  Joint saving rooms (creation + discovery + join requests)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/packages.php';
require_once __DIR__ . '/../includes/media_crypto.php';
header('Content-Type: application/json');
startSecureSession();

$body = json_decode(file_get_contents('php://input'), true);
if (!is_array($body)) $body = [];
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

function notifyOnceApi(int $userId, string $eventKey, string $tier, string $title, string $body, array $data = [], ?string $refType = null, ?string $refId = null, string $channelMask = ''): void {
    $db = getDB();

    if ($channelMask === '') {
        if ($tier === 'critical') $channelMask = 'push,inapp,email';
        else if ($tier === 'important') $channelMask = 'push,inapp';
        else $channelMask = 'inapp';
    }

    $db->prepare('INSERT IGNORE INTO notification_events (user_id, event_key, ref_type, ref_id) VALUES (?, ?, ?, ?)')
       ->execute([(int)$userId, $eventKey, $refType, $refId]);

    if ($db->lastInsertId() === '0') return;

    $db->prepare('INSERT INTO notifications (user_id, tier, channel_mask, title, body, data_json) VALUES (?, ?, ?, ?, ?, ?)')
       ->execute([(int)$userId, $tier, $channelMask, $title, $body, $data ? json_encode($data, JSON_UNESCAPED_UNICODE) : null]);
}

// ── Room account ledger (derived balance) ───────────────────
function roomLedgerGetBalance(PDO $db, string $roomId): float {
    if (!dbHasTable('saving_room_account_ledger')) return 0.0;
    $stmt = $db->prepare('SELECT balance_after FROM saving_room_account_ledger WHERE room_id = ? ORDER BY entry_seq DESC LIMIT 1');
    $stmt->execute([$roomId]);
    $v = $stmt->fetchColumn();
    return ($v === false || $v === null) ? 0.0 : (float)$v;
}

function roomLedgerInsert(PDO $db, string $roomId, string $entryType, string $entryKind, string $amount, string $sourceType, string $sourceId, ?int $createdByUserId = null): bool {
    if (!dbHasTable('saving_room_account_ledger')) return false;
    if (!in_array($entryType, ['credit','debit'], true)) throw new InvalidArgumentException('Invalid entryType');
    if (!in_array($entryKind, ['contribution','withdrawal'], true)) throw new InvalidArgumentException('Invalid entryKind');

    // Fast idempotency check.
    $chk = $db->prepare('SELECT 1 FROM saving_room_account_ledger WHERE room_id = ? AND source_type = ? AND source_id = ? LIMIT 1');
    $chk->execute([$roomId, $sourceType, $sourceId]);
    if ($chk->fetchColumn()) return false;

    // Lock last row to allocate entry_seq deterministically.
    $last = $db->prepare('SELECT entry_seq, balance_after FROM saving_room_account_ledger WHERE room_id = ? ORDER BY entry_seq DESC LIMIT 1 FOR UPDATE');
    $last->execute([$roomId]);
    $row = $last->fetch();

    $prevSeq = $row ? (int)$row['entry_seq'] : 0;
    $prevBal = $row ? (float)$row['balance_after'] : 0.0;

    $amt = (float)$amount;
    $newBal = ($entryType === 'credit') ? ($prevBal + $amt) : ($prevBal - $amt);
    $nextSeq = $prevSeq + 1;

    $ins = $db->prepare("INSERT IGNORE INTO saving_room_account_ledger
        (room_id, entry_seq, entry_type, entry_kind, amount, balance_after, source_type, source_id, created_by_user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");

    $ins->execute([
        $roomId,
        $nextSeq,
        $entryType,
        $entryKind,
        $amount,
        number_format($newBal, 2, '.', ''),
        $sourceType,
        $sourceId,
        $createdByUserId,
    ]);

    return ($ins->rowCount() > 0);
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

function ensureRoomSlotPositionAssigned(PDO $db, string $roomId, int $userId): void {
    if (!dbHasColumn('saving_room_participants', 'slot_position')) return;

    $cur = $db->prepare('SELECT slot_position FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $cur->execute([$roomId, (int)$userId]);
    $curSlot = $cur->fetchColumn();

    if ($curSlot !== null && $curSlot !== '') return;

    $maxStmt = $db->prepare("SELECT COALESCE(MAX(slot_position), 0) FROM saving_room_participants WHERE room_id = ?");
    $maxStmt->execute([$roomId]);
    $next = (int)$maxStmt->fetchColumn() + 1;

    $db->prepare('UPDATE saving_room_participants SET slot_position = ? WHERE room_id = ? AND user_id = ?')
       ->execute([$next, $roomId, (int)$userId]);
}

function getRoomSwapWindowInfo(array $room): array {
    $opens = null;
    $closes = null;

    if (!empty($room['swap_window_opens_at'])) {
        $opens = (string)$room['swap_window_opens_at'];
    } else if (!empty($room['swap_window_starts_at'])) {
        $opens = (string)$room['swap_window_starts_at'];
    } else if (!empty($room['swap_window_start_at'])) {
        $opens = (string)$room['swap_window_start_at'];
    }

    if (!empty($room['swap_window_closes_at'])) {
        $closes = (string)$room['swap_window_closes_at'];
    } else if (!empty($room['swap_window_ends_at'])) {
        $closes = (string)$room['swap_window_ends_at'];
    } else if (!empty($room['swap_window_end_at'])) {
        $closes = (string)$room['swap_window_end_at'];
    }

    if ($closes === null && !empty($room['start_at'])) {
        $closes = (string)$room['start_at'];
    }

    $now = time();
    $openOk = true;
    $closeOk = true;

    if ($opens !== null) {
        $ts = strtotime($opens);
        $openOk = !$ts || $now >= $ts;
    }
    if ($closes !== null) {
        $ts = strtotime($closes);
        $closeOk = !$ts || $now < $ts;
    }

    return [
        'opens_at' => $opens,
        'closes_at' => $closes,
        'is_open' => ($openOk && $closeOk) ? 1 : 0,
    ];
}

function swapRoomSlotPositions(PDO $db, string $roomId, int $userA, int $userB): bool {
    $queueCount = $db->prepare('SELECT COUNT(*) FROM saving_room_rotation_queue WHERE room_id = ?');
    $queueCount->execute([$roomId]);
    $hasQueue = (int)$queueCount->fetchColumn() > 0;

    if ($hasQueue) {
        $posStmt = $db->prepare('SELECT user_id, position FROM saving_room_rotation_queue WHERE room_id = ? AND user_id IN (?, ?)');
        $posStmt->execute([$roomId, (int)$userA, (int)$userB]);
        $rows = $posStmt->fetchAll();

        if (count($rows) !== 2) return false;

        $posA = null;
        $posB = null;
        foreach ($rows as $r) {
            if ((int)$r['user_id'] === $userA) $posA = (int)$r['position'];
            if ((int)$r['user_id'] === $userB) $posB = (int)$r['position'];
        }
        if ($posA === null || $posB === null) return false;

        $db->prepare('UPDATE saving_room_rotation_queue SET position = 0 WHERE room_id = ? AND user_id = ?')
           ->execute([$roomId, (int)$userA]);
        $db->prepare('UPDATE saving_room_rotation_queue SET position = ? WHERE room_id = ? AND user_id = ?')
           ->execute([$posA, $roomId, (int)$userB]);
        $db->prepare('UPDATE saving_room_rotation_queue SET position = ? WHERE room_id = ? AND user_id = ?')
           ->execute([$posB, $roomId, (int)$userA]);

        return true;
    }

    if (dbHasColumn('saving_room_participants', 'slot_position')) {
        ensureRoomSlotPositionAssigned($db, $roomId, $userA);
        ensureRoomSlotPositionAssigned($db, $roomId, $userB);

        $posStmt = $db->prepare("SELECT user_id, slot_position
                                 FROM saving_room_participants
                                 WHERE room_id = ? AND user_id IN (?, ?)");
        $posStmt->execute([$roomId, (int)$userA, (int)$userB]);
        $rows = $posStmt->fetchAll();
        if (count($rows) !== 2) return false;

        $posA = null;
        $posB = null;
        foreach ($rows as $r) {
            if ((int)$r['user_id'] === $userA) $posA = (int)$r['slot_position'];
            if ((int)$r['user_id'] === $userB) $posB = (int)$r['slot_position'];
        }
        if ($posA === null || $posB === null) return false;

        $db->prepare('UPDATE saving_room_participants SET slot_position = 0 WHERE room_id = ? AND user_id = ?')
           ->execute([$roomId, (int)$userA]);
        $db->prepare('UPDATE saving_room_participants SET slot_position = ? WHERE room_id = ? AND user_id = ?')
           ->execute([$posA, $roomId, (int)$userB]);
        $db->prepare('UPDATE saving_room_participants SET slot_position = ? WHERE room_id = ? AND user_id = ?')
           ->execute([$posB, $roomId, (int)$userA]);

        return true;
    }

    return false;
}

function roomExistsAndJoinable(string $roomId): array {
    $db = getDB();

    $cols = "id, maker_user_id, room_state, lobby_state, visibility, required_trust_level, max_participants, min_participants, start_at, reveal_at, periodicity, participation_amount, saving_type, goal_text, purpose_category, privacy_mode, escrow_policy, extensions_used";

    if (dbHasColumn('saving_rooms', 'platform_controlled')) {
        $cols .= ", platform_controlled";
    }

    foreach (['swap_window_opens_at','swap_window_closes_at','swap_window_starts_at','swap_window_ends_at','swap_window_start_at','swap_window_end_at'] as $c) {
        if (dbHasColumn('saving_rooms', $c)) {
            $cols .= ", {$c}";
        }
    }

    $stmt = $db->prepare("SELECT {$cols} FROM saving_rooms WHERE id = ?");
    $stmt->execute([$roomId]);
    $room = $stmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);
    return $room;
}

function hashInviteToken(string $token): string {
    return hash('sha256', $token);
}

function findActiveUnlistedInvite(PDO $db, string $roomId, string $token): ?array {
    $t = trim($token);
    if ($t === '' || strlen($t) > 200) return null;
    if (!preg_match('/^[a-f0-9]{16,128}$/i', $t)) return null;

    $hash = hashInviteToken($t);

    $stmt = $db->prepare("SELECT id, status, created_at, expires_at
                          FROM saving_room_invites
                          WHERE room_id = ?
                            AND invite_mode = 'unlisted_link'
                            AND invite_token_hash = ?
                            AND status = 'active'
                            AND (expires_at IS NULL OR expires_at > NOW())
                          LIMIT 1");
    $stmt->execute([$roomId, $hash]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function recordRoomSettlement(PDO $db, string $roomId, int $userId, string $policy, float $feeRate, string $reason): void {
    $sum = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM saving_room_contributions
                         WHERE room_id = ?
                           AND user_id = ?
                           AND status IN ('paid','paid_in_grace')");
    $sum->execute([$roomId, (int)$userId]);
    $total = round((float)$sum->fetchColumn(), 2);
    if ($total <= 0) return;

    $fee = 0.00;
    $refund = 0.00;

    if ($policy === 'refund_minus_fee') {
        $fee = round($total * $feeRate, 2);
        $refund = round($total - $fee, 2);
    }

    $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlements
                    (room_id, removed_user_id, policy, reason, fee_rate, total_contributed, platform_fee_amount, refund_amount, redistribution_json)
                  VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, NULL)")
       ->execute([
           $roomId,
           (int)$userId,
           $policy,
           $reason,
           number_format($feeRate, 4, '.', ''),
           number_format($total, 2, '.', ''),
           number_format($fee, 2, '.', ''),
           number_format($refund, 2, '.', ''),
       ]);
}

function advanceTypeBWindowAfterExit(PDO $db, string $roomId): void {
    $curStmt = $db->prepare("SELECT w.rotation_index, w.user_id
                             FROM saving_room_rotation_windows w
                             WHERE w.room_id = ?
                               AND w.status IN ('pending_votes','revealed','blocked_dispute','blocked_debt')
                             ORDER BY w.rotation_index DESC
                             LIMIT 1");
    $curStmt->execute([$roomId]);
    $cur = $curStmt->fetch();
    if (!$cur) return;

    $curIndex = (int)$cur['rotation_index'];

    // Close the current window.
    $db->prepare("UPDATE saving_room_rotation_windows
                  SET status='expired', expires_at=COALESCE(expires_at, NOW())
                  WHERE room_id = ? AND rotation_index = ?")
       ->execute([$roomId, $curIndex]);

    $db->prepare("UPDATE saving_room_rotation_queue
                  SET status='completed'
                  WHERE room_id = ? AND status='active_window'")
       ->execute([$roomId]);

    // Find the next queued active participant (Type B is one round only).
    $next = $db->prepare("SELECT q.user_id
                          FROM saving_room_rotation_queue q
                          JOIN saving_room_participants p
                            ON p.room_id = q.room_id
                           AND p.user_id = q.user_id
                          WHERE q.room_id = ?
                            AND q.status = 'queued'
                            AND p.status = 'active'
                          ORDER BY q.position ASC
                          LIMIT 1");
    $next->execute([$roomId]);
    $nextUserId = (int)$next->fetchColumn();

    if ($nextUserId <= 0) {
        activityLog($roomId, 'typeB_turn_voided', ['rotation_index' => $curIndex]);

        $db->prepare("UPDATE saving_rooms SET room_state='closed', updated_at=NOW() WHERE id = ? AND room_state='active'")
           ->execute([$roomId]);

        $db->prepare("UPDATE saving_room_participants SET status='completed', completed_at=NOW() WHERE room_id = ? AND status='active'")
           ->execute([$roomId]);

        activityLog($roomId, 'room_closed', []);
        return;
    }

    $db->prepare("INSERT IGNORE INTO saving_room_rotation_windows (room_id, user_id, rotation_index, status)
                  VALUES (?, ?, ?, 'pending_votes')")
       ->execute([$roomId, $nextUserId, $curIndex + 1]);

    $db->prepare("UPDATE saving_room_rotation_queue SET status='active_window' WHERE room_id = ? AND user_id = ?")
       ->execute([$roomId, $nextUserId]);

    activityLog($roomId, 'typeB_turn_advanced', ['rotation_index' => $curIndex + 1]);
}

// ── DISCOVERY (public rooms only; filtered by trust level) ───
if ($action === 'discover') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $lvl = getUserTrustLevel($userId);
    $restrictedUntil = userRestrictedUntil($userId);

    $category = $_GET['category'] ?? '';
    $allowed = ['education','travel','business','emergency','community','other'];
    if ($category !== '' && !in_array($category, $allowed, true)) {
        jsonResponse(['error' => 'Invalid category'], 400);
    }

    $db = getDB();

    $sql = "SELECT r.id, r.purpose_category, r.goal_text, r.saving_type, r.required_trust_level,
                   r.participation_amount, r.periodicity, r.start_at, r.max_participants,
                   r.room_state, r.lobby_state,
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
            'room_state' => $r['room_state'],
            'lobby_state' => $r['lobby_state'],
            'spots_remaining' => $spots,
            'max_participants' => $max,
        ];
    }

    jsonResponse([
        'success' => true,
        'your_trust_level' => $lvl,
        'restricted_until' => $restrictedUntil,
        'rooms' => $out,
    ]);
}

// ── DESTINATION ACCOUNTS (active, masked; for room creation) ─
if ($action === 'destination_accounts') {
    requireLogin();
    requireVerifiedEmail();

    $db = getDB();

    if (!dbHasTable('platform_destination_accounts')) {
        jsonResponse(['success' => true, 'accounts' => []]);
    }

    $sel = "a.id, a.account_type";
    $sel .= dbHasColumn('platform_destination_accounts', 'display_label') ? ", a.display_label" : ", NULL AS display_label";
    $sel .= ", a.mobile_money_number, a.bank_name, a.bank_account_number";

    // Optional crypto columns (keep backward compatibility with older schemas)
    $sel .= dbHasColumn('platform_destination_accounts', 'crypto_network') ? ", a.crypto_network" : ", NULL AS crypto_network";
    $sel .= dbHasColumn('platform_destination_accounts', 'crypto_address') ? ", a.crypto_address" : ", NULL AS crypto_address";

    // legacy naming (if any)
    $sel .= dbHasColumn('platform_destination_accounts', 'crypto_wallet_network') ? ", a.crypto_wallet_network" : ", NULL AS crypto_wallet_network";
    $sel .= dbHasColumn('platform_destination_accounts', 'crypto_wallet_address') ? ", a.crypto_wallet_address" : ", NULL AS crypto_wallet_address";

    $sql = "SELECT {$sel} FROM platform_destination_accounts a";
    if (dbHasTable('saving_room_accounts')) {
        $sql .= " LEFT JOIN saving_room_accounts ra ON ra.account_id = a.id WHERE a.is_active = 1 AND ra.account_id IS NULL";
    } else {
        $sql .= " WHERE a.is_active = 1";
    }
    $sql .= " ORDER BY a.id ASC";

    $rows = $db->query($sql)->fetchAll();

    $maskTail = function(string $s, int $n = 4): ?string {
        $str = trim($s);
        if ($str === '') return null;
        $keep = max(2, min(10, $n));
        return '••••' . substr($str, -$keep);
    };

    $maskCrypto = function(string $addr): ?string {
        $a = trim($addr);
        if ($a === '') return null;

        // For typical wallet addresses, show head + tail.
        // For short identifiers, fall back to a tail mask.
        if (strlen($a) >= 12) {
            return substr($a, 0, 6) . '…' . substr($a, -4);
        }

        $tail = substr($a, -min(4, strlen($a)));
        return '••••' . $tail;
    };

    $out = [];
    foreach ($rows as $r) {
        $type = (string)($r['account_type'] ?? '');
        $label = $r['display_label'] ? (string)$r['display_label'] : '';

        $mobileMasked = null;
        $bankName = null;
        $bankMasked = null;
        $cryptoNet = null;
        $cryptoAddrMasked = null;

        if ($type === 'mobile_money') {
            $mobileMasked = $maskTail((string)($r['mobile_money_number'] ?? ''), 4);
        } else if ($type === 'bank') {
            $bn = trim((string)($r['bank_name'] ?? ''));
            $bankName = ($bn !== '') ? $bn : null;
            $bankMasked = $maskTail((string)($r['bank_account_number'] ?? ''), 4);
        } else if ($type === 'crypto_wallet') {
            $net = trim((string)($r['crypto_network'] ?? ($r['crypto_wallet_network'] ?? '')));
            $addr = trim((string)($r['crypto_address'] ?? ($r['crypto_wallet_address'] ?? '')));
            $cryptoNet = ($net !== '') ? $net : null;
            $cryptoAddrMasked = $maskCrypto($addr);
        }

        $out[] = [
            'id' => (int)$r['id'],
            'account_type' => $type,
            'display_label' => $label !== '' ? $label : null,
            'mobile_money_masked' => $mobileMasked,
            'bank_name' => $bankName,
            'bank_account_masked' => $bankMasked,
            'crypto_network' => $cryptoNet,
            'crypto_address_masked' => $cryptoAddrMasked,
        ];
    }

    jsonResponse(['success' => true, 'accounts' => $out]);
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
                            AND p.status IN ('pending','approved','active','removed','completed','exited_prestart','exited_poststart')
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

    $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');

    $vis = (string)$room['visibility'];

    $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $myStmt->execute([$roomId, $userId]);
    $myStatus = $myStmt->fetchColumn();

    // Private rooms: require membership or an active private-user invite.
    $myInvite = null;
    if ($vis === 'private' && !$myStatus && !isAdmin($userId)) {
        $myEmail = strtolower(trim(getCurrentUserEmail() ?? ''));

        // Prefer in-app identity match, but also support token links (for invited emails that don't yet have a user).
        $inv = $db->prepare("SELECT i.id, i.status, i.expires_at, i.created_at
                             FROM saving_room_invites i
                             WHERE i.room_id = ?
                               AND i.invite_mode = 'private_user'
                               AND i.status = 'active'
                               AND (i.expires_at IS NULL OR i.expires_at > NOW())
                               AND (i.invited_user_id = ? OR (i.invited_email IS NOT NULL AND i.invited_email = ?))
                             ORDER BY i.created_at DESC
                             LIMIT 1");
        $inv->execute([$roomId, $userId, $myEmail]);
        $row = $inv->fetch();

        if (!$row) {
            $token = trim((string)($_GET['invite'] ?? ''));
            if ($token !== '' && strlen($token) <= 200 && preg_match('/^[a-f0-9]{16,128}$/i', $token)) {
                $hash = hashInviteToken($token);
                $inv2 = $db->prepare("SELECT i.id, i.status, i.expires_at, i.created_at
                                      FROM saving_room_invites i
                                      WHERE i.room_id = ?
                                        AND i.invite_mode = 'private_user'
                                        AND i.invite_token_hash = ?
                                        AND i.status = 'active'
                                        AND (i.expires_at IS NULL OR i.expires_at > NOW())
                                      ORDER BY i.created_at DESC
                                      LIMIT 1");
                $inv2->execute([$roomId, $hash]);
                $row = $inv2->fetch();
            }
        }

        if (!$row) {
            jsonResponse(['error' => 'Room is private'], 403);
        }

        $myInvite = [
            'id' => (int)$row['id'],
            'status' => $row['status'],
            'expires_at' => $row['expires_at'],
            'created_at' => $row['created_at'],
        ];
    }

    // Unlisted rooms: if you're not a participant, require a valid invite token.
    $unlistedAccess = 0;
    if ($vis === 'unlisted' && !$myStatus && !isAdmin($userId)) {
        $token = (string)($_GET['invite'] ?? '');
        $ok = findActiveUnlistedInvite($db, $roomId, $token);
        if (!$ok) {
            jsonResponse(['error' => 'Unlisted room requires a valid invite link'], 403);
        }
        $unlistedAccess = 1;
    }

    // Eligibility (trust level + restriction) applies only to non-participants viewing public/unlisted rooms.
    if (!$myStatus && !isAdmin($userId) && in_array($vis, ['public','unlisted'], true)) {
        requireEligibleForRoom($userId, (int)$room['required_trust_level']);
    }

    $approvedCount = countApprovedParticipants($roomId);

    $escrowSettlements = [];
    $canSeeEscrow = (((int)$room['maker_user_id'] === $userId) || isAdmin($userId));

    if ($canSeeEscrow) {
        $es = $db->prepare("SELECT s.removed_user_id, {$uNameExpr} AS removed_user_name, s.policy, s.total_contributed, s.platform_fee_amount, s.refund_amount, s.status, s.created_at
                            FROM saving_room_escrow_settlements s
                            JOIN users u ON u.id = s.removed_user_id
                            WHERE s.room_id = ?
                            ORDER BY s.created_at DESC
                            LIMIT 50");
        $es->execute([$roomId]);
        $escrowSettlements = $es->fetchAll();
    }

    $participantsStmt = $db->prepare("SELECT p.user_id, p.status, {$uNameExpr} AS display_name,
                                             (SELECT trust_level FROM user_trust WHERE user_id = p.user_id) AS trust_level,
                                             (SELECT COUNT(*) FROM user_strikes WHERE user_id = p.user_id AND created_at >= (NOW() - INTERVAL 6 MONTH)) AS strikes_6m,
                                             (SELECT restricted_until FROM user_restrictions WHERE user_id = p.user_id AND restricted_until > NOW()) AS restricted_until
                                      FROM saving_room_participants p
                                      JOIN users u ON u.id = p.user_id
                                      WHERE p.room_id = ?
                                        AND p.status IN ('approved','active','removed','completed','exited_prestart','exited_poststart')
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

    $destinationAccount = null;
    $canSeeDest = (((int)$room['maker_user_id'] === $userId) || isAdmin($userId) || in_array((string)$myStatus, ['approved','active'], true));
    if ($canSeeDest) {
        $sel = "a.id, a.account_type";

        if (dbHasColumn('platform_destination_accounts', 'display_label')) {
            $sel .= ', a.display_label';
        }

        $sel .= ", a.carrier_id, a.mobile_money_number,
                a.bank_name, a.bank_account_name, a.bank_account_number, a.bank_routing_number, a.bank_swift, a.bank_iban";

        foreach (['crypto_network','crypto_address'] as $c) {
            if (dbHasColumn('platform_destination_accounts', $c)) {
                $sel .= ", a.{$c}";
            }
        }

        if (dbHasColumn('platform_destination_accounts', 'code_rotated_at')) {
            $sel .= ', a.code_rotated_at';
        }
        if (dbHasColumn('platform_destination_accounts', 'code_rotation_version')) {
            $sel .= ', a.code_rotation_version';
        }

        if (dbHasColumn('saving_room_accounts', 'code_rotated_at')) {
            $sel .= ', ra.code_rotated_at AS room_code_rotated_at';
        }
        if (dbHasColumn('saving_room_accounts', 'code_rotation_version')) {
            $sel .= ', ra.code_rotation_version AS room_code_rotation_version';
        }

        $da = $db->prepare("SELECT {$sel}
                            FROM saving_room_accounts ra
                            JOIN platform_destination_accounts a ON a.id = ra.account_id
                            WHERE ra.room_id = ?
                            LIMIT 1");
        $da->execute([$roomId]);
        $destinationAccount = $da->fetch() ?: null;
    }

    $swapWindow = getRoomSwapWindowInfo($room);

    $slots = null;
    $slotSwaps = null;

    $canSeeSlots = (((int)$room['maker_user_id'] === $userId) || isAdmin($userId) || in_array((string)$myStatus, ['approved','active'], true));
    if ($canSeeSlots) {
        $slots = [];

        $q = $db->prepare("SELECT q.user_id, q.position, q.status AS queue_status,
                                  p.status AS participant_status,
                                  {$uNameExpr} AS display_name
                           FROM saving_room_rotation_queue q
                           JOIN saving_room_participants p
                             ON p.room_id = q.room_id
                            AND p.user_id = q.user_id
                           JOIN users u ON u.id = q.user_id
                           WHERE q.room_id = ?
                           ORDER BY q.position ASC");
        $q->execute([$roomId]);
        $rows = $q->fetchAll();

        if ($rows) {
            foreach ($rows as $r) {
                $slots[] = [
                    'user_id' => (int)$r['user_id'],
                    'display_name' => $r['display_name'],
                    'position' => (int)$r['position'],
                    'queue_status' => $r['queue_status'],
                    'participant_status' => $r['participant_status'],
                ];
            }
        } else if (dbHasColumn('saving_room_participants', 'slot_position')) {
            $p = $db->prepare("SELECT p.user_id, p.slot_position AS position, p.status AS participant_status,
                                      {$uNameExpr} AS display_name
                               FROM saving_room_participants p
                               JOIN users u ON u.id = p.user_id
                               WHERE p.room_id = ?
                                 AND p.status IN ('approved','active')
                               ORDER BY p.slot_position ASC");
            $p->execute([$roomId]);
            foreach ($p->fetchAll() as $r) {
                $slots[] = [
                    'user_id' => (int)$r['user_id'],
                    'display_name' => $r['display_name'],
                    'position' => (int)$r['position'],
                    'participant_status' => $r['participant_status'],
                ];
            }
        } else {
            $p = $db->prepare("SELECT p.user_id, p.status AS participant_status,
                                      {$uNameExpr} AS display_name,
                                      p.joined_at
                               FROM saving_room_participants p
                               JOIN users u ON u.id = p.user_id
                               WHERE p.room_id = ?
                                 AND p.status IN ('approved','active')
                               ORDER BY p.joined_at ASC");
            $p->execute([$roomId]);
            $i = 1;
            foreach ($p->fetchAll() as $r) {
                $slots[] = [
                    'user_id' => (int)$r['user_id'],
                    'display_name' => $r['display_name'],
                    'position' => $i,
                    'participant_status' => $r['participant_status'],
                ];
                $i++;
            }
        }

        if (dbHasTable('saving_room_slot_swaps')) {
            $uNameExpr2 = sqlRoomUserDisplayNameExpr('u2', 'id');

            $swapSel = "s.id, s.from_user_id, {$uNameExpr} AS from_name,
                        s.to_user_id, {$uNameExpr2} AS to_name,
                        s.status, s.created_at";
            $swapSel .= dbHasColumn('saving_room_slot_swaps', 'responded_at') ? ', s.responded_at' : ', NULL AS responded_at';
            $swapSel .= dbHasColumn('saving_room_slot_swaps', 'expires_at') ? ', s.expires_at' : ', NULL AS expires_at';

            $sw = $db->prepare("SELECT {$swapSel}
                                FROM saving_room_slot_swaps s
                                JOIN users u ON u.id = s.from_user_id
                                JOIN users u2 ON u2.id = s.to_user_id
                                WHERE s.room_id = ?
                                  AND s.status IN ('pending','accepted','declined','cancelled')
                                ORDER BY s.created_at DESC
                                LIMIT 50");
            $sw->execute([$roomId]);
            $slotSwaps = [];
            foreach ($sw->fetchAll() as $r) {
                $slotSwaps[] = [
                    'id' => (int)$r['id'],
                    'from_user_id' => (int)$r['from_user_id'],
                    'from_name' => $r['from_name'],
                    'to_user_id' => (int)$r['to_user_id'],
                    'to_name' => $r['to_name'],
                    'status' => $r['status'],
                    'created_at' => $r['created_at'],
                    'responded_at' => $r['responded_at'],
                    'expires_at' => $r['expires_at'],
                ];
            }
        }
    }

    $unlock = null;
    if ($room['saving_type'] === 'A') {
        $ue = $db->prepare('SELECT status, revealed_at, expires_at FROM saving_room_unlock_events WHERE room_id = ?');
        $ue->execute([$roomId]);
        $unlockEvent = $ue->fetch();

        $eligibleStatuses = ($room['room_state'] === 'lobby') ? ['approved'] : ['active'];

        $in = implode(',', array_fill(0, count($eligibleStatuses), '?'));
        $voteSql = "SELECT
                        SUM(CASE WHEN v.vote = 'approve' THEN 1 ELSE 0 END) AS approvals,
                        COUNT(p.user_id) AS eligible
                    FROM saving_room_participants p
                    LEFT JOIN saving_room_unlock_votes v
                           ON v.room_id = p.room_id
                          AND v.user_id = p.user_id
                          AND v.scope = 'typeA_room_unlock'
                          AND (v.target_rotation_index = 0 OR v.target_rotation_index IS NULL)
                    WHERE p.room_id = ?
                      AND p.status IN ({$in})";

        $params = array_merge([$roomId], $eligibleStatuses);
        $st = $db->prepare($voteSql);
        $st->execute($params);
        $vote = $st->fetch();

        $myVoteStmt = $db->prepare("SELECT vote
                                    FROM saving_room_unlock_votes
                                    WHERE room_id = ?
                                      AND user_id = ?
                                      AND scope='typeA_room_unlock'
                                      AND (target_rotation_index = 0 OR target_rotation_index IS NULL)
                                    ORDER BY id DESC
                                    LIMIT 1");
        $myVoteStmt->execute([$roomId, $userId]);
        $myVote = $myVoteStmt->fetchColumn();

        $unlock = [
            'event' => $unlockEvent ? [
                'status' => $unlockEvent['status'],
                'revealed_at' => $unlockEvent['revealed_at'],
                'expires_at' => $unlockEvent['expires_at'],
            ] : null,
            'votes' => [
                'approvals' => (int)($vote['approvals'] ?? 0),
                'eligible' => (int)($vote['eligible'] ?? 0),
            ],
            'my_vote' => $myVote ?: null,
        ];
    }

    $rotation = null;
    $rotationHistory = null;

    if ($room['saving_type'] === 'B' && (in_array($myStatus, ['active','approved'], true) || isAdmin($userId) || ((int)$room['maker_user_id'] === $userId))) {
        // Current window
        $sel = "w.id, w.user_id, w.rotation_index, w.status, w.revealed_at, w.expires_at";
        $sel .= dbHasColumn('saving_room_rotation_windows', 'approve_opens_at')
            ? ", w.approve_opens_at, w.approve_due_at"
            : ", NULL AS approve_opens_at, NULL AS approve_due_at";
        $sel .= ", w.dispute_window_ends_at, {$uNameExpr} AS turn_user_name";

        $sel .= dbHasColumn('saving_room_rotation_windows', 'delegate_user_id')
            ? ", w.delegate_user_id"
            : ", NULL AS delegate_user_id";

        $sel .= dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_at')
            ? ", w.withdrawal_confirmed_at, w.withdrawal_confirmed_by_user_id, w.withdrawal_reference, w.withdrawal_confirmed_role"
            : ", NULL AS withdrawal_confirmed_at, NULL AS withdrawal_confirmed_by_user_id, NULL AS withdrawal_reference, NULL AS withdrawal_confirmed_role";

        $win = $db->prepare("SELECT {$sel}
                             FROM saving_room_rotation_windows w
                             JOIN users u ON u.id = w.user_id
                             WHERE w.room_id = ?
                               AND w.status IN ('pending_votes','revealed','blocked_dispute','blocked_debt')
                             ORDER BY w.rotation_index DESC
                             LIMIT 1");
        $win->execute([$roomId]);
        $w = $win->fetch();

        $delegateName = null;
        $withdrawByName = null;

        if ($w) {
            if (!empty($w['delegate_user_id'])) {
                $d = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
                $d->execute([(int)$w['delegate_user_id']]);
                $delegateName = $d->fetchColumn() ?: null;
            }

            if (!empty($w['withdrawal_confirmed_by_user_id'])) {
                $c = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
                $c->execute([(int)$w['withdrawal_confirmed_by_user_id']]);
                $withdrawByName = $c->fetchColumn() ?: null;
            }

            $rotationIndex = (int)$w['rotation_index'];
            $turnUserId = (int)$w['user_id'];
            $makerId = (int)$room['maker_user_id'];

            $eligibleStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
            $eligibleStmt->execute([$roomId]);
            $eligibleActive = (int)$eligibleStmt->fetchColumn();

            // Eligible voters exclude the maker and the current turn user.
            $eligibleVoters = $eligibleActive;
            if ($makerId > 0) $eligibleVoters--;
            if ($turnUserId > 0 && $turnUserId !== $makerId) $eligibleVoters--;
            $eligibleVoters = max(0, $eligibleVoters);

            $required = (int)ceil($eligibleVoters * 0.5);

            $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                           WHERE room_id = ?
                                             AND scope = 'typeB_turn_unlock'
                                             AND target_rotation_index = ?
                                             AND vote = 'approve'
                                             AND user_id <> ?
                                             AND user_id <> ?");
            $approvalsStmt->execute([$roomId, $rotationIndex, $makerId, $turnUserId]);
            $approvalsRaw = (int)$approvalsStmt->fetchColumn();

            $rejectsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                         WHERE room_id = ?
                                           AND scope = 'typeB_turn_unlock'
                                           AND target_rotation_index = ?
                                           AND vote = 'reject'
                                           AND user_id <> ?
                                           AND user_id <> ?");
            $rejectsStmt->execute([$roomId, $rotationIndex, $makerId, $turnUserId]);
            $rejects = (int)$rejectsStmt->fetchColumn();

            $myVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                        WHERE room_id = ? AND user_id = ?
                                          AND scope='typeB_turn_unlock'
                                          AND target_rotation_index = ?");
            $myVoteStmt->execute([$roomId, $userId, $rotationIndex]);
            $myVote = $myVoteStmt->fetchColumn();

            $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                           WHERE room_id = ? AND user_id = ?
                                             AND scope='typeB_turn_unlock'
                                             AND target_rotation_index = ?");
            $makerVoteStmt->execute([$roomId, $makerId, $rotationIndex]);
            $makerVote = $makerVoteStmt->fetchColumn();

            $opensAt = (string)($w['approve_opens_at'] ?? '');
            $dueAt = (string)($w['approve_due_at'] ?? '');
            $nowTs = time();

            $isOpen = true;
            if ($opensAt !== '') {
                $oTs = strtotime($opensAt);
                $isOpen = $oTs ? ($nowTs >= $oTs) : true;
            }

            $isClosed = false;
            $secondsRemaining = null;
            if ($dueAt !== '') {
                $dTs = strtotime($dueAt);
                if ($dTs) {
                    $isClosed = ($nowTs >= $dTs);
                    if (!$isClosed) $secondsRemaining = max(0, $dTs - $nowTs);
                }
            }

            $approvalsEffective = $approvalsRaw;
            if ($isClosed) {
                // Missed votes count as approvals after due.
                $approvalsEffective = max(0, $eligibleVoters - $rejects);
            }

            $confirmed = !empty($w['withdrawal_confirmed_at']);
            $expTs = !empty($w['expires_at']) ? strtotime((string)$w['expires_at']) : null;
            $isExpired = ($expTs && $nowTs >= $expTs);

            // Reveal permission (turn user always; maker after 12h; delegate always; admin always)
            $canRevealCode = false;
            $revealRole = null;

            $isTurnUser = ($turnUserId === $userId);
            $isDelegate = (!empty($w['delegate_user_id']) && (int)$w['delegate_user_id'] === $userId);
            $isAdminUser = isAdmin($userId);
            $isMakerUser = ($makerId === $userId);

            $makerAccessOk = false;
            if (!empty($w['revealed_at'])) {
                try {
                    $dt = new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC'));
                    $g = $dt->modify('+12 hours')->getTimestamp();
                    $makerAccessOk = ($nowTs >= $g);
                } catch (Exception) {
                    $makerAccessOk = false;
                }
            }

            if ((string)$w['status'] === 'revealed' && ($myStatus === 'active' || $isAdminUser) && !$confirmed && !$isExpired) {
                if ($isTurnUser) {
                    $canRevealCode = true;
                    $revealRole = 'turn_user';
                } else if ($isDelegate) {
                    $canRevealCode = true;
                    $revealRole = 'delegate';
                } else if ($isAdminUser) {
                    $canRevealCode = true;
                    $revealRole = 'admin';
                } else if ($isMakerUser && $makerAccessOk) {
                    $canRevealCode = true;
                    $revealRole = 'maker';
                }
            }

            $canConfirmWithdrawal = false;
            if ((string)$w['status'] === 'revealed' && !$confirmed && !$isExpired) {
                if ($isTurnUser) {
                    $canConfirmWithdrawal = true;
                } else if ($isDelegate) {
                    $canConfirmWithdrawal = true;
                } else if ($isMakerUser && $makerAccessOk) {
                    $canConfirmWithdrawal = true;
                } else if ($isAdminUser && $makerAccessOk) {
                    $canConfirmWithdrawal = true;
                }
            }

            // Dispute info (latest open)
            $dispute = null;
            $disp = $db->prepare("SELECT d.id, d.status, d.reason, d.threshold_count_required, d.created_at, d.updated_at,
                                         {$uNameExpr} AS raised_by_name
                                  FROM saving_room_disputes d
                                  JOIN users u ON u.id = d.raised_by_user_id
                                  WHERE d.room_id = ?
                                    AND d.rotation_index = ?
                                    AND d.status IN ('open','threshold_met','escalated_admin')
                                  ORDER BY d.created_at DESC
                                  LIMIT 1");
            $disp->execute([$roomId, $rotationIndex]);
            $d = $disp->fetch();
            if ($d) {
                $ackStmt = $db->prepare('SELECT COUNT(*) FROM saving_room_dispute_ack WHERE dispute_id = ?');
                $ackStmt->execute([(int)$d['id']]);
                $ackCount = (int)$ackStmt->fetchColumn();

                $myAckStmt = $db->prepare('SELECT 1 FROM saving_room_dispute_ack WHERE dispute_id = ? AND user_id = ? LIMIT 1');
                $myAckStmt->execute([(int)$d['id'], $userId]);
                $myAck = (bool)$myAckStmt->fetchColumn();

                $dispute = [
                    'id' => (int)$d['id'],
                    'status' => $d['status'],
                    'reason' => $d['reason'],
                    'raised_by_name' => $d['raised_by_name'],
                    'threshold_required' => (int)$d['threshold_count_required'],
                    'ack_count' => $ackCount,
                    'my_ack' => $myAck ? 1 : 0,
                    'created_at' => $d['created_at'],
                    'updated_at' => $d['updated_at'],
                ];
            }

            $rotation = [
                'current' => [
                    'rotation_index' => $rotationIndex,
                    'status' => $w['status'],
                    'turn_user_id' => $turnUserId,
                    'turn_user_name' => $w['turn_user_name'],
                    'revealed_at' => $w['revealed_at'],
                    'expires_at' => $w['expires_at'],
                    'approve_opens_at' => $opensAt !== '' ? $opensAt : null,
                    'approve_due_at' => $dueAt !== '' ? $dueAt : null,
                    'grace_ends_at' => (!empty($w['revealed_at']) ? (new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC')))->modify('+12 hours')->format('Y-m-d H:i:s') : null),
                    'delegate_user_id' => !empty($w['delegate_user_id']) ? (int)$w['delegate_user_id'] : null,
                    'delegate_name' => $delegateName,
                    'can_set_delegate' => (dbHasColumn('saving_room_rotation_windows', 'delegate_user_id') && (string)$w['status'] === 'revealed' && $isTurnUser && !$confirmed && !$isExpired && (!empty($w['revealed_at']) ? ($nowTs < (new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC')))->modify('+12 hours')->getTimestamp()) : false)) ? 1 : 0,
                    'can_reveal_code' => $canRevealCode ? 1 : 0,
                    'reveal_role' => $revealRole,
                    'withdrawal_confirmed_at' => $w['withdrawal_confirmed_at'],
                    'withdrawal_reference' => $w['withdrawal_reference'],
                    'withdrawal_confirmed_role' => $w['withdrawal_confirmed_role'],
                    'withdrawal_confirmed_by_name' => $withdrawByName,
                    'can_confirm_withdrawal' => $canConfirmWithdrawal ? 1 : 0,
                ],
                'votes' => [
                    'approvals' => $approvalsEffective,
                    'approvals_raw' => $approvalsRaw,
                    'rejects' => $rejects,
                    'required' => $required,
                    'eligible' => $eligibleVoters,
                    'is_open' => $isOpen ? 1 : 0,
                    'is_closed' => $isClosed ? 1 : 0,
                    'seconds_remaining' => $secondsRemaining,
                    'opens_at' => $opensAt !== '' ? $opensAt : null,
                    'due_at' => $dueAt !== '' ? $dueAt : null,
                ],
                'my_vote' => $myVote ?: null,
                'maker_vote' => $makerVote ?: null,
                'dispute' => $dispute,
            ];
        }

        // Rotation history
        $hSel = "w.id AS window_id, w.rotation_index, w.user_id, w.status, w.revealed_at, w.expires_at, {$uNameExpr} AS turn_user_name";
        $hSel .= dbHasColumn('saving_room_rotation_windows', 'delegate_user_id') ? ", w.delegate_user_id" : ", NULL AS delegate_user_id";
        $hSel .= dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_at')
            ? ", w.withdrawal_confirmed_at, w.withdrawal_reference, w.withdrawal_confirmed_role, w.withdrawal_confirmed_by_user_id"
            : ", NULL AS withdrawal_confirmed_at, NULL AS withdrawal_reference, NULL AS withdrawal_confirmed_role, NULL AS withdrawal_confirmed_by_user_id";

        $cvLast = '';
        if (dbHasTable('saving_room_turn_code_views')) {
            $cvLast = ",
                (SELECT MAX(v2.viewed_at) FROM saving_room_turn_code_views v2 WHERE v2.room_id = w.room_id AND v2.rotation_index = w.rotation_index) AS code_last_viewed_at,
                (SELECT v3.viewer_role FROM saving_room_turn_code_views v3 WHERE v3.room_id = w.room_id AND v3.rotation_index = w.rotation_index ORDER BY v3.viewed_at DESC LIMIT 1) AS code_last_viewed_role,
                (SELECT v4.viewer_user_id FROM saving_room_turn_code_views v4 WHERE v4.room_id = w.room_id AND v4.rotation_index = w.rotation_index ORDER BY v4.viewed_at DESC LIMIT 1) AS code_last_viewed_by_user_id";
        } else {
            $cvLast = ", NULL AS code_last_viewed_at, NULL AS code_last_viewed_role, NULL AS code_last_viewed_by_user_id";
        }

        $ledgerSel = ", NULL AS collected_amount, NULL AS balance_after_withdrawal";
        $ledgerJoin = '';
        if (dbHasTable('saving_room_account_ledger')) {
            $ledgerSel = ", l.amount AS collected_amount, l.balance_after AS balance_after_withdrawal";
            $ledgerJoin = "LEFT JOIN saving_room_account_ledger l
                             ON l.room_id = w.room_id
                            AND l.source_type = 'withdrawal'
                            AND l.source_id = CAST(w.id AS CHAR)";
        }

        $histStmt = $db->prepare("SELECT {$hSel}{$cvLast}{$ledgerSel}
                                  FROM saving_room_rotation_windows w
                                  JOIN users u ON u.id = w.user_id
                                  {$ledgerJoin}
                                  WHERE w.room_id = ?
                                  ORDER BY w.rotation_index DESC
                                  LIMIT 30");
        $histStmt->execute([$roomId]);
        $rawHist = $histStmt->fetchAll();

        $rotationHistory = [];
        foreach ($rawHist as $hr) {
            $delegateName2 = null;
            if (!empty($hr['delegate_user_id'])) {
                $dn = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
                $dn->execute([(int)$hr['delegate_user_id']]);
                $delegateName2 = $dn->fetchColumn() ?: null;
            }

            $confirmedByName2 = null;
            if (!empty($hr['withdrawal_confirmed_by_user_id'])) {
                $cn = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
                $cn->execute([(int)$hr['withdrawal_confirmed_by_user_id']]);
                $confirmedByName2 = $cn->fetchColumn() ?: null;
            }

            $lastViewedByName = null;
            if (!empty($hr['code_last_viewed_by_user_id'])) {
                $vn = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
                $vn->execute([(int)$hr['code_last_viewed_by_user_id']]);
                $lastViewedByName = $vn->fetchColumn() ?: null;
            }

            $rotationHistory[] = [
                'window_id' => (int)$hr['window_id'],
                'rotation_index' => (int)$hr['rotation_index'],
                'status' => $hr['status'],
                'turn_user_name' => $hr['turn_user_name'],
                'revealed_at' => $hr['revealed_at'],
                'expires_at' => $hr['expires_at'],
                'delegate_name' => $delegateName2,
                'code_last_viewed_at' => $hr['code_last_viewed_at'],
                'code_last_viewed_role' => $hr['code_last_viewed_role'],
                'code_last_viewed_by_name' => $lastViewedByName,
                'withdrawal_confirmed_at' => $hr['withdrawal_confirmed_at'],
                'withdrawal_reference' => $hr['withdrawal_reference'],
                'withdrawal_confirmed_role' => $hr['withdrawal_confirmed_role'],
                'withdrawal_confirmed_by_name' => $confirmedByName2,
                'collected_amount' => ($hr['collected_amount'] !== null) ? (string)$hr['collected_amount'] : null,
                'balance_after_withdrawal' => ($hr['balance_after_withdrawal'] !== null) ? (string)$hr['balance_after_withdrawal'] : null,
            ];
        }
    }

    $exitRequest = null;
    if ($room['saving_type'] === 'B' && $room['room_state'] === 'active' && $myStatus === 'active') {
        $erSel = "er.id, er.requested_by_user_id, er.status, er.created_at";
        $erSel .= dbHasColumn('saving_room_exit_requests', 'reason') ? ", er.reason" : ", '' AS reason";
        $erSel .= dbHasColumn('saving_room_exit_requests', 'replacement_maker_user_id') ? ", er.replacement_maker_user_id" : ", NULL AS replacement_maker_user_id";
        $erSel .= ", {$uNameExpr} AS requested_by_name";

        $er = $db->prepare("SELECT {$erSel}
                            FROM saving_room_exit_requests er
                            JOIN users u ON u.id = er.requested_by_user_id
                            WHERE er.room_id = ? AND er.status = 'open'
                            ORDER BY er.created_at DESC
                            LIMIT 1");
        $er->execute([$roomId]);
        $req = $er->fetch();

        if ($req) {
            $activeCountStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
            $activeCountStmt->execute([$roomId]);
            $activeCount = (int)$activeCountStmt->fetchColumn();

            $requesterId = (int)$req['requested_by_user_id'];
            $makerId = (int)$room['maker_user_id'];

            $eligibleNonMaker = max(0, $activeCount - 1 - (($makerId === $requesterId) ? 0 : 1));
            $required = (int)ceil($eligibleNonMaker * 0.6);

            $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                           WHERE room_id = ?
                                             AND scope = 'typeB_exit_request'
                                             AND target_rotation_index = ?
                                             AND vote = 'approve'
                                             AND user_id <> ?
                                             AND user_id <> ?");
            $approvalsStmt->execute([$roomId, (int)$req['id'], $makerId, $requesterId]);
            $approvals = (int)$approvalsStmt->fetchColumn();

            $myVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                        WHERE room_id = ? AND user_id = ?
                                          AND scope='typeB_exit_request'
                                          AND target_rotation_index = ?");
            $myVoteStmt->execute([$roomId, $userId, (int)$req['id']]);
            $myVote = $myVoteStmt->fetchColumn();

            $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                           WHERE room_id = ? AND user_id = ?
                                             AND scope='typeB_exit_request'
                                             AND target_rotation_index = ?");
            $makerVoteStmt->execute([$roomId, $makerId, (int)$req['id']]);
            $makerVote = $makerVoteStmt->fetchColumn();

            $exitRequest = [
                'id' => (int)$req['id'],
                'status' => $req['status'],
                'requested_by_name' => $req['requested_by_name'],
                'reason' => $req['reason'] ?? '',
                'replacement_maker_user_id' => !empty($req['replacement_maker_user_id']) ? (int)$req['replacement_maker_user_id'] : null,
                'is_requester' => ($requesterId === $userId) ? 1 : 0,
                'created_at' => $req['created_at'],
                'votes' => [
                    'approvals' => $approvals,
                    'required' => $required,
                    'eligible_non_maker' => $eligibleNonMaker,
                    'maker_vote' => $makerVote ?: null,
                ],
                'my_vote' => $myVote ?: null,
            ];
        }
    }

    $isMaker = ((int)$room['maker_user_id'] === $userId) || isAdmin($userId);

    $settlements = [];
    if ($isMaker) {
        $sel = "s.removed_user_id, {$uNameExpr} AS removed_user_name, s.policy";
        $sel .= dbHasColumn('saving_room_escrow_settlements', 'reason') ? ", s.reason" : ", NULL AS reason";
        $sel .= dbHasColumn('saving_room_escrow_settlements', 'fee_rate') ? ", s.fee_rate" : ", NULL AS fee_rate";
        $sel .= ", s.total_contributed, s.platform_fee_amount, s.refund_amount, s.redistribution_json, s.status, s.created_at";

        $st = $db->prepare("SELECT {$sel}
                            FROM saving_room_escrow_settlements s
                            JOIN users u ON u.id = s.removed_user_id
                            WHERE s.room_id = ?
                            ORDER BY s.created_at DESC
                            LIMIT 200");
        $st->execute([$roomId]);
        $settlements = $st->fetchAll();
    }

    // Derived account balance (from proofs + withdrawals)
    $accountBalance = null;
    if (dbHasTable('saving_room_account_ledger')) {
        $b = $db->prepare('SELECT balance_after FROM saving_room_account_ledger WHERE room_id = ? ORDER BY entry_seq DESC LIMIT 1');
        $b->execute([$roomId]);
        $bal = $b->fetchColumn();
        $accountBalance = ($bal === false || $bal === null) ? '0.00' : (string)$bal;
    }

    $requiredWithdrawalAmount = null;
    if ($room['saving_type'] === 'B' && $room['room_state'] === 'active') {
        $activeCountStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
        $activeCountStmt->execute([$roomId]);
        $activeCount = (int)$activeCountStmt->fetchColumn();

        $requiredWithdrawalAmount = number_format(((float)$room['participation_amount']) * max(0, $activeCount), 2, '.', '');
    }

    jsonResponse([
        'success' => true,
        'room' => [
            'id' => $room['id'],
            'goal_text' => $room['goal_text'],
            'purpose_category' => $room['purpose_category'],
            'saving_type' => $room['saving_type'],
            'visibility' => $room['visibility'],
            'my_invite' => $myInvite,
            'unlisted_access' => $unlistedAccess,
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
            'platform_controlled' => isset($room['platform_controlled']) ? (int)$room['platform_controlled'] : 0,
            'my_status' => $myStatus ?: null,
            'account_balance' => $accountBalance,
            'required_withdrawal_amount' => $requiredWithdrawalAmount,
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
            'destination_account' => $destinationAccount,
            'swap_window' => $swapWindow,
            'slots' => $slots,
            'slot_swaps' => $slotSwaps,
            'unlock' => $unlock,
            'rotation' => $rotation,
            'rotation_history' => $rotationHistory,
            'exit_request' => $exitRequest,
        ],
        'participants' => $participants,
        'escrow_settlements' => $settlements,
    ]);
}

// ── SLOTS (Type B queue / lobby slots) ─────────────────────
if ($action === 'list_slots') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $room = roomExistsAndJoinable($roomId);

    $db = getDB();
    $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $myStmt->execute([$roomId, $userId]);
    $myStatus = $myStmt->fetchColumn();

    $canSeeSlots = (((int)$room['maker_user_id'] === $userId) || isAdmin($userId) || in_array((string)$myStatus, ['approved','active'], true));
    if (!$canSeeSlots) jsonResponse(['error' => 'Not an eligible participant'], 403);

    $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');

    $swapWindow = getRoomSwapWindowInfo($room);
    $slots = [];

    $q = $db->prepare("SELECT q.user_id, q.position, q.status AS queue_status,
                              p.status AS participant_status,
                              {$uNameExpr} AS display_name
                       FROM saving_room_rotation_queue q
                       JOIN saving_room_participants p
                         ON p.room_id = q.room_id
                        AND p.user_id = q.user_id
                       JOIN users u ON u.id = q.user_id
                       WHERE q.room_id = ?
                       ORDER BY q.position ASC");
    $q->execute([$roomId]);
    $rows = $q->fetchAll();

    if ($rows) {
        foreach ($rows as $r) {
            $slots[] = [
                'user_id' => (int)$r['user_id'],
                'display_name' => $r['display_name'],
                'position' => (int)$r['position'],
                'queue_status' => $r['queue_status'],
                'participant_status' => $r['participant_status'],
            ];
        }
    } else if (dbHasColumn('saving_room_participants', 'slot_position')) {
        $p = $db->prepare("SELECT p.user_id, p.slot_position AS position, p.status AS participant_status,
                                  {$uNameExpr} AS display_name
                           FROM saving_room_participants p
                           JOIN users u ON u.id = p.user_id
                           WHERE p.room_id = ?
                             AND p.status IN ('approved','active')
                           ORDER BY p.slot_position ASC");
        $p->execute([$roomId]);
        foreach ($p->fetchAll() as $r) {
            $slots[] = [
                'user_id' => (int)$r['user_id'],
                'display_name' => $r['display_name'],
                'position' => (int)$r['position'],
                'participant_status' => $r['participant_status'],
            ];
        }
    } else {
        $p = $db->prepare("SELECT p.user_id, p.status AS participant_status,
                                  {$uNameExpr} AS display_name,
                                  p.joined_at
                           FROM saving_room_participants p
                           JOIN users u ON u.id = p.user_id
                           WHERE p.room_id = ?
                             AND p.status IN ('approved','active')
                           ORDER BY p.joined_at ASC");
        $p->execute([$roomId]);
        $i = 1;
        foreach ($p->fetchAll() as $r) {
            $slots[] = [
                'user_id' => (int)$r['user_id'],
                'display_name' => $r['display_name'],
                'position' => $i,
                'participant_status' => $r['participant_status'],
            ];
            $i++;
        }
    }

    $slotSwaps = null;
    if (dbHasTable('saving_room_slot_swaps')) {
        $uNameExpr2 = sqlRoomUserDisplayNameExpr('u2', 'id');

        $swapSel = "s.id, s.from_user_id, {$uNameExpr} AS from_name,
                    s.to_user_id, {$uNameExpr2} AS to_name,
                    s.status, s.created_at";
        $swapSel .= dbHasColumn('saving_room_slot_swaps', 'responded_at') ? ', s.responded_at' : ', NULL AS responded_at';
        $swapSel .= dbHasColumn('saving_room_slot_swaps', 'expires_at') ? ', s.expires_at' : ', NULL AS expires_at';

        $sw = $db->prepare("SELECT {$swapSel}
                            FROM saving_room_slot_swaps s
                            JOIN users u ON u.id = s.from_user_id
                            JOIN users u2 ON u2.id = s.to_user_id
                            WHERE s.room_id = ?
                              AND s.status IN ('pending','accepted','declined','cancelled')
                            ORDER BY s.created_at DESC
                            LIMIT 50");
        $sw->execute([$roomId]);
        $slotSwaps = [];
        foreach ($sw->fetchAll() as $r) {
            $slotSwaps[] = [
                'id' => (int)$r['id'],
                'from_user_id' => (int)$r['from_user_id'],
                'from_name' => $r['from_name'],
                'to_user_id' => (int)$r['to_user_id'],
                'to_name' => $r['to_name'],
                'status' => $r['status'],
                'created_at' => $r['created_at'],
                'responded_at' => $r['responded_at'],
                'expires_at' => $r['expires_at'],
            ];
        }
    }

    jsonResponse([
        'success' => true,
        'swap_window' => $swapWindow,
        'slots' => $slots,
        'slot_swaps' => $slotSwaps,
    ]);
}

if ($action === 'request_swap') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $toUserId = (int)($body['to_user_id'] ?? 0);

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($toUserId < 1) jsonResponse(['error' => 'to_user_id required'], 400);
    if ($toUserId === $userId) jsonResponse(['error' => 'Cannot swap with yourself'], 400);

    if (!dbHasTable('saving_room_slot_swaps')) {
        jsonResponse(['error' => 'Slot swaps are unavailable. Apply database migrations.'], 409);
    }

    $room = roomExistsAndJoinable($roomId);
    $swapWindow = getRoomSwapWindowInfo($room);
    if (empty($swapWindow['is_open'])) jsonResponse(['error' => 'Swap window is closed'], 403);

    $db = getDB();

    $me = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $me->execute([$roomId, $userId]);
    $myStatus = (string)$me->fetchColumn();
    if (!in_array($myStatus, ['approved','active'], true)) jsonResponse(['error' => 'Not an eligible participant'], 403);

    $them = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $them->execute([$roomId, $toUserId]);
    $toStatus = (string)$them->fetchColumn();
    if (!in_array($toStatus, ['approved','active'], true)) jsonResponse(['error' => 'Target user is not an eligible participant'], 403);

    $existing = $db->prepare("SELECT id FROM saving_room_slot_swaps
                              WHERE room_id = ?
                                AND status = 'pending'
                                AND ((from_user_id = ? AND to_user_id = ?)
                                     OR (from_user_id = ? AND to_user_id = ?))
                              LIMIT 1");
    $existing->execute([$roomId, $userId, $toUserId, $toUserId, $userId]);
    if ($existing->fetchColumn()) jsonResponse(['error' => 'A swap request between these users is already pending'], 409);

    $expiresAt = (string)($swapWindow['closes_at'] ?? '');
    if ($expiresAt === '') $expiresAt = (string)($room['start_at'] ?? '');

    $cols = ['room_id','from_user_id','to_user_id','status'];
    $vals = [$roomId, $userId, $toUserId, 'pending'];

    if (dbHasColumn('saving_room_slot_swaps', 'expires_at')) {
        $cols[] = 'expires_at';
        $vals[] = $expiresAt !== '' ? $expiresAt : null;
    }

    $ph = implode(',', array_fill(0, count($cols), '?'));
    $db->prepare('INSERT INTO saving_room_slot_swaps (' . implode(',', $cols) . ') VALUES (' . $ph . ')')
       ->execute($vals);

    $swapId = (int)$db->lastInsertId();

    activityLog($roomId, 'slot_swap_requested', ['swap_id' => $swapId]);

    auditLog('room_slot_swap_request');
    jsonResponse(['success' => true, 'swap_id' => $swapId, 'expires_at' => $expiresAt]);
}

if ($action === 'respond_swap') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $swapId = (int)($body['swap_id'] ?? ($body['request_id'] ?? 0));
    $decision = (string)($body['decision'] ?? '');

    if ($swapId < 1) jsonResponse(['error' => 'swap_id required'], 400);
    if (!in_array($decision, ['accept','decline'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

    if (!dbHasTable('saving_room_slot_swaps')) {
        jsonResponse(['error' => 'Slot swaps are unavailable. Apply database migrations.'], 409);
    }

    $db = getDB();

    $sel = 'id, room_id, from_user_id, to_user_id, status';
    $sel .= dbHasColumn('saving_room_slot_swaps', 'expires_at') ? ', expires_at' : ', NULL AS expires_at';

    $stmt = $db->prepare("SELECT {$sel} FROM saving_room_slot_swaps WHERE id = ? LIMIT 1");
    $stmt->execute([$swapId]);
    $swap = $stmt->fetch();

    if (!$swap) jsonResponse(['error' => 'Swap request not found'], 404);
    if ((int)$swap['to_user_id'] !== $userId) jsonResponse(['error' => 'Not your swap request'], 403);
    if ((string)$swap['status'] !== 'pending') jsonResponse(['error' => 'Swap request is not pending'], 409);

    $exp = (string)($swap['expires_at'] ?? '');
    if ($exp !== '' && time() >= strtotime($exp)) {
        $db->prepare("UPDATE saving_room_slot_swaps SET status='cancelled', responded_at=NOW() WHERE id = ? AND status='pending'")
           ->execute([$swapId]);
        jsonResponse(['error' => 'Swap request has expired'], 403);
    }

    $room = roomExistsAndJoinable((string)$swap['room_id']);
    $swapWindow = getRoomSwapWindowInfo($room);
    if (empty($swapWindow['is_open'])) jsonResponse(['error' => 'Swap window is closed'], 403);

    if ($decision === 'decline') {
        $db->prepare("UPDATE saving_room_slot_swaps SET status='declined', responded_at=NOW() WHERE id = ? AND status='pending'")
           ->execute([$swapId]);

        activityLog((string)$swap['room_id'], 'slot_swap_declined', ['swap_id' => $swapId]);

        auditLog('room_slot_swap_decline');
        jsonResponse(['success' => true]);
    }

    $db->beginTransaction();

    $upd = $db->prepare("UPDATE saving_room_slot_swaps SET status='accepted', responded_at=NOW() WHERE id = ? AND status='pending'");
    $upd->execute([$swapId]);

    if ($upd->rowCount() < 1) {
        $db->commit();
        auditLog('room_slot_swap_accept');
        jsonResponse(['success' => true, 'accepted' => 1]);
    }

    $ok = swapRoomSlotPositions($db, (string)$swap['room_id'], (int)$swap['from_user_id'], (int)$swap['to_user_id']);
    if (!$ok) {
        $db->rollBack();
        jsonResponse(['error' => 'Slots are not available to swap in this room'], 409);
    }

    activityLog((string)$swap['room_id'], 'slot_swap_accepted', ['swap_id' => $swapId]);

    $db->commit();

    auditLog('room_slot_swap_accept');
    jsonResponse(['success' => true, 'accepted' => 1]);
}

if ($action === 'cancel_swap') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $swapId = (int)($body['swap_id'] ?? ($body['request_id'] ?? 0));

    if ($swapId < 1) jsonResponse(['error' => 'swap_id required'], 400);

    if (!dbHasTable('saving_room_slot_swaps')) {
        jsonResponse(['error' => 'Slot swaps are unavailable. Apply database migrations.'], 409);
    }

    $db = getDB();

    $stmt = $db->prepare('SELECT id, room_id, from_user_id, status FROM saving_room_slot_swaps WHERE id = ? LIMIT 1');
    $stmt->execute([$swapId]);
    $swap = $stmt->fetch();

    if (!$swap) jsonResponse(['error' => 'Swap request not found'], 404);
    if ((int)$swap['from_user_id'] !== $userId) jsonResponse(['error' => 'Not your swap request'], 403);
    if ((string)$swap['status'] !== 'pending') jsonResponse(['error' => 'Swap request is not pending'], 409);

    $db->prepare("UPDATE saving_room_slot_swaps SET status='cancelled', responded_at=NOW() WHERE id = ? AND status='pending'")
       ->execute([$swapId]);

    activityLog((string)$swap['room_id'], 'slot_swap_cancelled', ['swap_id' => $swapId]);

    auditLog('room_slot_swap_cancel');
    jsonResponse(['success' => true]);
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
                $hash = hashInviteToken($token);
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
            jsonResponse(['error' => 'Room is private'], 403);
        }
    }

    if ($vis === 'unlisted' && !$myStatus && !isAdmin($userId)) {
        $token = (string)($_GET['invite'] ?? '');
        if (!findActiveUnlistedInvite($db, $roomId, $token)) {
            jsonResponse(['error' => 'Unlisted room requires a valid invite link'], 403);
        }
    }

    if (!$myStatus && !isAdmin($userId) && in_array($vis, ['public','unlisted'], true)) {
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

// ── CREATE ROOM ────────────────────────────────────────────
if ($action === 'create_room') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();

    // Enforce package limits (active rooms).
    packagesEnforceLimitOrJson($userId, 'rooms');

    $purpose = (string)($body['purpose_category'] ?? 'other');
    $goal = trim((string)($body['goal_text'] ?? ''));
    $savingType = (string)($body['saving_type'] ?? 'A');
    $visibility = (string)($body['visibility'] ?? 'public');
    $requiredLevel = (int)($body['required_trust_level'] ?? 1);

    $minP = (int)($body['min_participants'] ?? 2);
    $maxP = (int)($body['max_participants'] ?? 0);

    $amount = (string)($body['participation_amount'] ?? '');
    $periodicity = (string)($body['periodicity'] ?? 'weekly');

    $startAtRaw = trim((string)($body['start_at'] ?? ''));
    $revealAtRaw = trim((string)($body['reveal_at'] ?? ''));

    $privacyMode = !empty($body['privacy_mode']) ? 1 : 0;

    $isAdminUser = isAdmin($userId);
    $escrowPolicy = $isAdminUser ? (string)($body['escrow_policy'] ?? 'redistribute') : 'redistribute';

    $allowedPurpose = ['education','travel','business','emergency','community','other'];
    if (!in_array($purpose, $allowedPurpose, true)) jsonResponse(['error' => 'Invalid purpose_category'], 400);
    if ($goal === '' || strlen($goal) > 500) jsonResponse(['error' => 'Invalid goal_text'], 400);
    if (!in_array($savingType, ['A','B'], true)) jsonResponse(['error' => 'Invalid saving_type'], 400);
    if (!in_array($visibility, ['public','unlisted','private'], true)) jsonResponse(['error' => 'Invalid visibility'], 400);
    if (!in_array($requiredLevel, [1,2,3], true)) jsonResponse(['error' => 'Invalid required_trust_level'], 400);

    if ($minP < 2) jsonResponse(['error' => 'min_participants must be at least 2'], 400);
    if ($maxP < $minP) jsonResponse(['error' => 'max_participants must be >= min_participants'], 400);
    if ($maxP > 50) jsonResponse(['error' => 'max_participants too large'], 400);

    if (!is_numeric($amount) || (float)$amount <= 0) jsonResponse(['error' => 'Invalid participation_amount'], 400);
    if (!in_array($periodicity, ['weekly','biweekly','monthly'], true)) jsonResponse(['error' => 'Invalid periodicity'], 400);

    if ($startAtRaw === '') jsonResponse(['error' => 'start_at required'], 400);
    if ($savingType === 'A' && $revealAtRaw === '') jsonResponse(['error' => 'reveal_at required'], 400);

    try {
        $startDt = new DateTimeImmutable($startAtRaw, new DateTimeZone('UTC'));
    } catch (Exception) {
        jsonResponse(['error' => 'Invalid start date'], 400);
    }

    $nowUtc = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if ($startDt <= $nowUtc->modify('+5 minutes')) jsonResponse(['error' => 'Start date must be in the future'], 400);

    if ($savingType === 'A') {
        try {
            $revealDt = new DateTimeImmutable($revealAtRaw, new DateTimeZone('UTC'));
        } catch (Exception) {
            jsonResponse(['error' => 'Invalid reveal date'], 400);
        }

        if ($revealDt <= $startDt) jsonResponse(['error' => 'Reveal date must be after start date'], 400);

    } else {
        $periodInterval = null;
        if ($periodicity === 'biweekly') $periodInterval = new DateInterval('P14D');
        else if ($periodicity === 'monthly') $periodInterval = new DateInterval('P1M');
        else $periodInterval = new DateInterval('P7D');

        $revealDt = $startDt->add($periodInterval)->sub(new DateInterval('P1D'));
    }

    $startStr = $startDt->format('Y-m-d H:i:s');
    $revealStr = $revealDt->format('Y-m-d H:i:s');

    if (!in_array($escrowPolicy, ['redistribute','refund_minus_fee'], true)) jsonResponse(['error' => 'Invalid escrow_policy'], 400);

    requireEligibleForRoom($userId, $requiredLevel);

    $db = getDB();

    $acctSelect = "id, account_type";
    foreach (['unlock_code_enc','code_rotated_at','code_rotation_version'] as $c) {
        if (dbHasColumn('platform_destination_accounts', $c)) {
            $acctSelect .= ", {$c}";
        }
    }

    $destinationAccountId = (int)($body['destination_account_id'] ?? 0);
    $destinationAccountType = (string)($body['destination_account_type'] ?? '');

    $allowedDestTypes = ['mobile_money','bank','crypto_wallet'];
    if ($destinationAccountType !== '' && !in_array($destinationAccountType, $allowedDestTypes, true)) {
        jsonResponse(['error' => 'Invalid destination_account_type'], 400);
    }

    if ($destinationAccountId <= 0) {
        jsonResponse(['error' => 'destination_account_id required', 'error_code' => 'destination_account_required'], 400);
    }

    $acctStmt = $db->prepare("SELECT {$acctSelect}
                              FROM platform_destination_accounts
                              WHERE id = ? AND is_active = 1
                              LIMIT 1");
    $acctStmt->execute([$destinationAccountId]);
    $acct = $acctStmt->fetch();
    if (!$acct) {
        jsonResponse(['error' => 'Destination account not found or inactive'], 400);
    }

    if ($destinationAccountType !== '' && (string)($acct['account_type'] ?? '') !== $destinationAccountType) {
        jsonResponse(['error' => 'Selected destination account does not match destination_account_type'], 400);
    }

    $acctId = (int)$acct['id'];

    $acctUnlockEnc = null;
    if (is_array($acct) && array_key_exists('unlock_code_enc', $acct)) {
        $v = $acct['unlock_code_enc'];
        if ($v !== null && $v !== '') {
            $acctUnlockEnc = (string)$v;
        }
    }

    $acctCodeRotatedAt = (is_array($acct) && array_key_exists('code_rotated_at', $acct)) ? ($acct['code_rotated_at'] ?? null) : null;
    $acctCodeRotationVersion = (is_array($acct) && array_key_exists('code_rotation_version', $acct)) ? (int)($acct['code_rotation_version'] ?? 1) : 1;

    $roomId = generateUUID();

    $db->beginTransaction();

    if (dbHasTable('saving_room_accounts')) {
        $used = $db->prepare('SELECT room_id FROM saving_room_accounts WHERE account_id = ? LIMIT 1');
        $used->execute([$acctId]);
        $usedRoomId = $used->fetchColumn();
        if ($usedRoomId) {
            $db->rollBack();
            jsonResponse([
                'error' => 'Destination account is already assigned to another room',
                'error_code' => 'destination_account_in_use',
                'room_id' => (string)$usedRoomId,
            ], 409);
        }
    }

    $db->prepare("INSERT INTO saving_rooms
                    (id, maker_user_id, purpose_category, goal_text, saving_type, visibility,
                     required_trust_level, min_participants, max_participants,
                     participation_amount, periodicity, start_at, reveal_at,
                     privacy_mode, escrow_policy)
                  VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
       ->execute([
           $roomId,
           $userId,
           $purpose,
           $goal,
           $savingType,
           $visibility,
           $requiredLevel,
           $minP,
           $maxP,
           $amount,
           $periodicity,
           $startStr,
           $revealStr,
           $privacyMode,
           $escrowPolicy,
       ]);

    // Maker joins as approved participant.
    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status, approved_at)
                  VALUES (?, ?, 'approved', NOW())")
       ->execute([$roomId, $userId]);

    ensureRoomSlotPositionAssigned($db, $roomId, $userId);

    // Link destination account + snapshot per-room unlock code (if supported by schema).
    $cols = ['room_id', 'account_id'];
    $vals = [$roomId, $acctId];

    if (dbHasColumn('saving_room_accounts', 'unlock_code_enc')) {
        $cols[] = 'unlock_code_enc';
        $vals[] = $acctUnlockEnc;
    }

    if (dbHasColumn('saving_room_accounts', 'code_rotated_at')) {
        $cols[] = 'code_rotated_at';
        $vals[] = $acctCodeRotatedAt;
    }

    if (dbHasColumn('saving_room_accounts', 'code_rotation_version')) {
        $cols[] = 'code_rotation_version';
        $vals[] = $acctCodeRotationVersion;
    }

    $placeholders = implode(',', array_fill(0, count($cols), '?'));
    $db->prepare('INSERT INTO saving_room_accounts (' . implode(',', $cols) . ') VALUES (' . $placeholders . ')')
       ->execute($vals);

    activityLog($roomId, 'room_created', ['visibility' => $visibility, 'saving_type' => $savingType]);

    $db->commit();

    auditLog('room_create');
    jsonResponse(['success' => true, 'room_id' => $roomId]);
}

// ── REQUEST JOIN ───────────────────────
if ($action === 'request_join') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();

    // Enforce package limits (active rooms).
    packagesEnforceLimitOrJson($userId, 'rooms');

    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $room = roomExistsAndJoinable($roomId);
    $vis = (string)$room['visibility'];

    if ($vis === 'private') {
        jsonResponse(['error' => 'This room is private and requires an invite.'], 403);
    }

    $db = getDB();

    if ($vis === 'unlisted') {
        $token = (string)($body['invite_token'] ?? '');
        if (!findActiveUnlistedInvite($db, $roomId, $token)) {
            jsonResponse(['error' => 'Unlisted room requires a valid invite link'], 403);
        }
    }

    if ($room['room_state'] !== 'lobby' || $room['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting join requests'], 403);
    }

    requireEligibleForRoom($userId, (int)$room['required_trust_level']);

    $approvedCount = countApprovedParticipants($roomId);
    if ($approvedCount >= (int)$room['max_participants']) {
        jsonResponse(['error' => 'Room is full'], 403);
    }

    $existingPart = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $existingPart->execute([$roomId, $userId]);
    $ps = $existingPart->fetchColumn();
    if ($ps && !in_array((string)$ps, ['declined'], true)) {
        jsonResponse(['error' => 'You already have a participant status in this room'], 409);
    }

    $lvl = getUserTrustLevel($userId);
    $stmt = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 6 MONTH)");
    $stmt->execute([$userId]);
    $strikes6m = (int)$stmt->fetchColumn();

    $restrictedUntil = userRestrictedUntil($userId);

    $db->beginTransaction();

    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status)
                  VALUES (?, ?, 'pending')
                  ON DUPLICATE KEY UPDATE status='pending'")
       ->execute([$roomId, $userId]);

    $db->prepare("INSERT INTO saving_room_join_requests
                    (room_id, user_id, status, snapshot_level, snapshot_strikes_6m, snapshot_restricted_until)
                  VALUES
                    (?, ?, 'pending', ?, ?, ?)
                  ON DUPLICATE KEY UPDATE
                    status='pending',
                    snapshot_level=VALUES(snapshot_level),
                    snapshot_strikes_6m=VALUES(snapshot_strikes_6m),
                    snapshot_restricted_until=VALUES(snapshot_restricted_until),
                    created_at=NOW()")
       ->execute([$roomId, $userId, $lvl, $strikes6m, $restrictedUntil]);

    activityLog($roomId, 'join_requested', []);

    $db->commit();

    auditLog('room_join_request');
    jsonResponse(['success' => true]);
}

// ── MAKER: INVITE USER (private rooms) ─────────────────────
if ($action === 'invite_user') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $email  = strtolower(trim((string)($body['email'] ?? '')));

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['error' => 'Valid email required'], 400);

    requireRoomMaker($roomId, $userId);

    $room = roomExistsAndJoinable($roomId);
    if ((string)$room['visibility'] !== 'private') {
        jsonResponse(['error' => 'Invites are only required for private rooms.'], 400);
    }

    if ($room['room_state'] !== 'lobby' || $room['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting invites right now'], 403);
    }

    $approvedCount = countApprovedParticipants($roomId);
    if ($approvedCount >= (int)$room['max_participants']) {
        jsonResponse(['error' => 'Room is full'], 403);
    }

    $db = getDB();

    $u = $db->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $u->execute([$email]);
    $invitedUserId = (int)$u->fetchColumn();
    if ($invitedUserId === $userId) jsonResponse(['error' => 'You cannot invite yourself'], 400);

    $token = bin2hex(random_bytes(16));
    $hash = hashInviteToken($token);

    $expiresAt = (string)$room['start_at'];

    $db->beginTransaction();

    // Revoke any prior active invite for this email / user.
    $db->prepare("UPDATE saving_room_invites
                  SET status='revoked', responded_at=NOW()
                  WHERE room_id = ?
                    AND invite_mode = 'private_user'
                    AND status = 'active'
                    AND ((invited_user_id IS NOT NULL AND invited_user_id = ?)
                         OR (invited_email IS NOT NULL AND invited_email = ?))")
       ->execute([$roomId, $invitedUserId > 0 ? $invitedUserId : null, $email]);

    $db->prepare("INSERT INTO saving_room_invites (room_id, invite_mode, invite_token_hash, invited_user_id, invited_email, status, expires_at)
                  VALUES (?, 'private_user', ?, ?, ?, 'active', ?)")
       ->execute([$roomId, $hash, $invitedUserId > 0 ? $invitedUserId : null, $email, $expiresAt]);

    $inviteId = (int)$db->lastInsertId();

    activityLog($roomId, 'invite_created', ['mode' => 'private_user']);

    $link = getAppBaseUrl() . '/room.php?id=' . rawurlencode($roomId) . '&invite=' . rawurlencode($token);

    if ($invitedUserId > 0) {
        notifyOnceApi(
            $invitedUserId,
            'room_invited',
            'important',
            'You have been invited to a private saving room',
            'Open the room to accept or decline the invite.',
            ['room_id' => $roomId, 'invite_id' => $inviteId],
            'room',
            $roomId
        );
    } else {
        // Best-effort email delivery (user may not exist yet).
        sendEmail(
            $email,
            APP_NAME . ' — Private room invite',
            "You have been invited to a private saving room.\n\nOpen this link after you have created an account and verified your email:\n\n{$link}\n\nThis invite expires at: {$expiresAt}\n"
        );
    }

    $db->commit();

    auditLog('room_invite_user');
    jsonResponse(['success' => true, 'invite_id' => $inviteId, 'invite_link' => $link]);
}

// ── USER: RESPOND TO INVITE ────────────────────────────────
if ($action === 'respond_invite') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId   = (int)getCurrentUserId();
    $inviteId = (int)($body['invite_id'] ?? 0);
    $decision = (string)($body['decision'] ?? '');

    if ($inviteId < 1) jsonResponse(['error' => 'invite_id required'], 400);
    if (!in_array($decision, ['accept','decline'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

    $db = getDB();

    $stmt = $db->prepare("SELECT i.id, i.room_id, i.invite_mode, i.invited_user_id, i.invited_email, i.status, i.expires_at,
                                 r.visibility, r.room_state, r.lobby_state, r.required_trust_level, r.max_participants, r.maker_user_id
                          FROM saving_room_invites i
                          JOIN saving_rooms r ON r.id = i.room_id
                          WHERE i.id = ?
                          LIMIT 1");
    $stmt->execute([$inviteId]);
    $inv = $stmt->fetch();

    if (!$inv) jsonResponse(['error' => 'Invite not found'], 404);
    if ((string)$inv['invite_mode'] !== 'private_user') jsonResponse(['error' => 'Invalid invite mode'], 400);

    $myEmail = strtolower(trim(getCurrentUserEmail() ?? ''));
    $invEmail = strtolower(trim((string)($inv['invited_email'] ?? '')));
    $invUserId = (int)($inv['invited_user_id'] ?? 0);

    if (!($invUserId === $userId || ($invUserId <= 0 && $invEmail !== '' && $invEmail === $myEmail))) {
        jsonResponse(['error' => 'Not your invite'], 403);
    }

    if ((string)$inv['status'] !== 'active') jsonResponse(['error' => 'Invite is not active'], 409);
    if (!empty($inv['expires_at']) && strtotime((string)$inv['expires_at']) <= time()) {
        $db->prepare("UPDATE saving_room_invites SET status='expired', responded_at=NOW() WHERE id = ? AND status='active'")
           ->execute([$inviteId]);
        jsonResponse(['error' => 'Invite has expired'], 403);
    }

    $roomId = (string)$inv['room_id'];
    $makerId = (int)$inv['maker_user_id'];

    if ($decision === 'decline') {
        $db->prepare("UPDATE saving_room_invites SET status='declined', responded_at=NOW() WHERE id = ? AND status='active'")
           ->execute([$inviteId]);
        activityLog($roomId, 'invite_declined', []);

        if ($makerId > 0) {
            notifyOnceApi(
                $makerId,
                'room_invite_declined',
                'important',
                'Room invite declined',
                'A user declined your invite to a private room.',
                ['room_id' => $roomId, 'invite_id' => $inviteId],
                'room',
                $roomId
            );
        }

        auditLog('room_invite_decline');
        jsonResponse(['success' => true]);
    }

    if ((string)$inv['visibility'] !== 'private') {
        jsonResponse(['error' => 'This room is not private'], 400);
    }
    if ((string)$inv['room_state'] !== 'lobby' || (string)$inv['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting invites right now'], 403);
    }

    requireEligibleForRoom($userId, (int)$inv['required_trust_level']);

    $approvedCount = countApprovedParticipants($roomId);
    if ($approvedCount >= (int)$inv['max_participants']) {
        jsonResponse(['error' => 'Room is full'], 403);
    }

    $db->beginTransaction();

    $db->prepare("UPDATE saving_room_invites
                  SET status='accepted', responded_at=NOW(), invited_user_id = COALESCE(invited_user_id, ?)
                  WHERE id = ? AND status='active'")
       ->execute([$userId, $inviteId]);

    $db->prepare("INSERT INTO saving_room_participants (room_id, user_id, status, approved_at)
                  VALUES (?, ?, 'approved', NOW())
                  ON DUPLICATE KEY UPDATE status='approved', approved_at=NOW()")
       ->execute([$roomId, $userId]);

    ensureRoomSlotPositionAssigned($db, $roomId, $userId);

    activityLog($roomId, 'invite_accepted', []);

    if ($makerId > 0) {
        notifyOnceApi(
            $makerId,
            'room_invite_accepted',
            'important',
            'Room invite accepted',
            'A user accepted your invite to a private room.',
            ['room_id' => $roomId, 'invite_id' => $inviteId],
            'room',
            $roomId
        );
    }

    $db->commit();

    auditLog('room_invite_accept');
    jsonResponse(['success' => true]);
}

// ── MAKER: UNLISTED INVITE INFO ────────────────────────────
if ($action === 'unlisted_invite_info') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $room = roomExistsAndJoinable($roomId);
    if ((string)$room['visibility'] !== 'unlisted') {
        jsonResponse(['error' => 'Room is not unlisted'], 400);
    }

    $db = getDB();

    $stmt = $db->prepare("SELECT id, status, created_at, expires_at
                          FROM saving_room_invites
                          WHERE room_id = ?
                            AND invite_mode = 'unlisted_link'
                          ORDER BY created_at DESC
                          LIMIT 1");
    $stmt->execute([$roomId]);
    $row = $stmt->fetch();

    $active = false;
    if ($row && (string)$row['status'] === 'active') {
        $active = empty($row['expires_at']) || strtotime((string)$row['expires_at']) > time();
    }

    jsonResponse([
        'success' => true,
        'invite' => $row ? [
            'id' => (int)$row['id'],
            'status' => (string)$row['status'],
            'created_at' => $row['created_at'],
            'expires_at' => $row['expires_at'],
            'is_active' => $active ? 1 : 0,
        ] : null,
    ]);
}

// ── MAKER: CREATE/ROTATE UNLISTED INVITE LINK ───────────────
if ($action === 'unlisted_invite_create') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $room = roomExistsAndJoinable($roomId);
    if ((string)$room['visibility'] !== 'unlisted') {
        jsonResponse(['error' => 'Room is not unlisted'], 400);
    }

    if ($room['room_state'] !== 'lobby' || $room['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting join requests right now'], 403);
    }

    $token = bin2hex(random_bytes(16));
    $hash = hashInviteToken($token);

    $expiresAt = (string)$room['start_at'];

    $db = getDB();
    $db->beginTransaction();

    $db->prepare("UPDATE saving_room_invites
                  SET status='revoked', responded_at=NOW()
                  WHERE room_id = ?
                    AND invite_mode = 'unlisted_link'
                    AND status = 'active'")
       ->execute([$roomId]);

    $db->prepare("INSERT INTO saving_room_invites (room_id, invite_mode, invite_token_hash, status, expires_at)
                  VALUES (?, 'unlisted_link', ?, 'active', ?)")
       ->execute([$roomId, $hash, $expiresAt]);

    $inviteId = (int)$db->lastInsertId();

    activityLog($roomId, 'invite_created', ['mode' => 'unlisted_link']);

    $db->commit();

    auditLog('room_unlisted_invite_create');

    $link = getAppBaseUrl() . '/room.php?id=' . rawurlencode($roomId) . '&invite=' . rawurlencode($token);

    jsonResponse([
        'success' => true,
        'invite_id' => $inviteId,
        'expires_at' => $expiresAt,
        'link' => $link,
    ]);
}

// ── MAKER: REVOKE UNLISTED INVITE LINK ──────────────────────
if ($action === 'unlisted_invite_revoke') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $room = roomExistsAndJoinable($roomId);
    if ((string)$room['visibility'] !== 'unlisted') {
        jsonResponse(['error' => 'Room is not unlisted'], 400);
    }

    $db = getDB();

    $db->prepare("UPDATE saving_room_invites
                  SET status='revoked', responded_at=NOW()
                  WHERE room_id = ?
                    AND invite_mode = 'unlisted_link'
                    AND status = 'active'")
       ->execute([$roomId]);

    activityLog($roomId, 'invite_revoked', ['mode' => 'unlisted_link']);

    auditLog('room_unlisted_invite_revoke');
    jsonResponse(['success' => true]);
}

// ── MAKER: LIST INVITES (private rooms) ─────────────────────
if ($action === 'maker_invites') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $db = getDB();

    $stmt = $db->prepare("SELECT i.id, i.status, i.expires_at, i.created_at,
                                 COALESCE(u.email, i.invited_email) AS email
                          FROM saving_room_invites i
                          LEFT JOIN users u ON u.id = i.invited_user_id
                          WHERE i.room_id = ?
                            AND i.invite_mode = 'private_user'
                          ORDER BY i.created_at DESC
                          LIMIT 200");
    $stmt->execute([$roomId]);

    jsonResponse(['success' => true, 'invites' => $stmt->fetchAll()]);
}

// ── MAKER: REVOKE INVITE ───────────────────────────────────
if ($action === 'revoke_invite') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $inviteId = (int)($body['invite_id'] ?? 0);
    if ($inviteId < 1) jsonResponse(['error' => 'invite_id required'], 400);

    $db = getDB();

    $st = $db->prepare("SELECT id, room_id FROM saving_room_invites WHERE id = ? LIMIT 1");
    $st->execute([$inviteId]);
    $inv = $st->fetch();
    if (!$inv) jsonResponse(['error' => 'Invite not found'], 404);

    requireRoomMaker((string)$inv['room_id'], $userId);

    $db->prepare("UPDATE saving_room_invites SET status='revoked', responded_at=NOW() WHERE id = ? AND status='active'")
       ->execute([$inviteId]);

    activityLog((string)$inv['room_id'], 'invite_revoked', []);

    auditLog('room_invite_revoke');
    jsonResponse(['success' => true]);
}

// ── MAKER: LIST PENDING JOIN REQUESTS ───────────────────────
if ($action === 'maker_join_requests') {
    requireLogin();
    requireVerifiedEmail();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    requireRoomMaker($roomId, $userId);

    $db = getDB();

    $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');

    $stmt = $db->prepare("SELECT jr.id, jr.user_id, {$uNameExpr} AS display_name, jr.status, jr.snapshot_level, jr.snapshot_strikes_6m, jr.snapshot_restricted_until, jr.created_at,
                                 (SELECT trust_level FROM user_trust WHERE user_id = jr.user_id) AS current_level,
                                 (SELECT COUNT(*) FROM user_strikes WHERE user_id = jr.user_id AND created_at >= (NOW() - INTERVAL 6 MONTH)) AS current_strikes_6m,
                                 (SELECT restricted_until FROM user_restrictions WHERE user_id = jr.user_id AND restricted_until > NOW()) AS current_restricted_until
                          FROM saving_room_join_requests jr
                          JOIN users u ON u.id = jr.user_id
                          WHERE jr.room_id = ?
                            AND jr.status = 'pending'
                          ORDER BY jr.created_at ASC");
    $stmt->execute([$roomId]);

    jsonResponse(['success' => true, 'requests' => $stmt->fetchAll()]);
}

// ── MAKER: REVIEW JOIN REQUEST ──────────────────────────────
if ($action === 'review_join') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $reqId = (int)($body['request_id'] ?? 0);
    $decision = (string)($body['decision'] ?? '');

    if ($reqId <= 0) jsonResponse(['error' => 'request_id required'], 400);
    if (!in_array($decision, ['approve','decline'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

    $db = getDB();

    $reqStmt = $db->prepare('SELECT id, room_id, user_id, status FROM saving_room_join_requests WHERE id = ?');
    $reqStmt->execute([$reqId]);
    $req = $reqStmt->fetch();
    if (!$req) jsonResponse(['error' => 'Request not found'], 404);
    if ($req['status'] !== 'pending') jsonResponse(['error' => 'Request is not pending'], 409);

    $room = roomExistsAndJoinable((string)$req['room_id']);
    requireRoomMaker((string)$req['room_id'], $userId);

    if ($room['room_state'] !== 'lobby' || $room['lobby_state'] !== 'open') {
        jsonResponse(['error' => 'Room is not accepting approvals'], 403);
    }

    if ($decision === 'approve') {
        $approvedCount = countApprovedParticipants((string)$req['room_id']);
        if ($approvedCount >= (int)$room['max_participants']) {
            jsonResponse(['error' => 'Room is full'], 403);
        }

        requireEligibleForRoomApproval((int)$req['user_id'], (int)$room['required_trust_level']);
    }

    $db->beginTransaction();

    if ($decision === 'approve') {
        $db->prepare("UPDATE saving_room_join_requests SET status='approved', maker_decided_at=NOW() WHERE id = ?")
           ->execute([$reqId]);

        $db->prepare("UPDATE saving_room_participants SET status='approved', approved_at=NOW() WHERE room_id = ? AND user_id = ?")
           ->execute([(string)$req['room_id'], (int)$req['user_id']]);

        ensureRoomSlotPositionAssigned($db, (string)$req['room_id'], (int)$req['user_id']);

        activityLog((string)$req['room_id'], 'join_approved', []);

        $newCount = countApprovedParticipants((string)$req['room_id']);
        if ($newCount >= (int)$room['max_participants']) {
            $db->prepare("UPDATE saving_rooms SET lobby_state='locked', updated_at=NOW() WHERE id = ?")
               ->execute([(string)$req['room_id']]);
            activityLog((string)$req['room_id'], 'lobby_locked', ['reason' => 'capacity_reached']);
        }

    } else {
        $db->prepare("UPDATE saving_room_join_requests SET status='declined', maker_decided_at=NOW() WHERE id = ?")
           ->execute([$reqId]);

        $db->prepare("UPDATE saving_room_participants SET status='declined' WHERE room_id = ? AND user_id = ?")
           ->execute([(string)$req['room_id'], (int)$req['user_id']]);

        activityLog((string)$req['room_id'], 'join_declined', []);
    }

    $db->commit();

    auditLog('room_review_join');
    jsonResponse(['success' => true]);
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
        $newStartAtRaw = (string)($body['new_start_at'] ?? '');
        $newRevealAtRaw = (string)($body['new_reveal_at'] ?? '');

        try {
            $startDt = new DateTimeImmutable($newStartAtRaw, new DateTimeZone('UTC'));
        } catch (Exception) {
            $db->rollBack();
            jsonResponse(['error' => 'Invalid start date'], 400);
        }

        $nowUtc = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        if ($startDt <= $nowUtc->modify('+5 minutes')) {
            $db->rollBack();
            jsonResponse(['error' => 'Start date must be in the future'], 400);
        }

        if ((string)($room['saving_type'] ?? '') === 'A') {
            try {
                $revealDt = new DateTimeImmutable($newRevealAtRaw, new DateTimeZone('UTC'));
            } catch (Exception) {
                $db->rollBack();
                jsonResponse(['error' => 'Invalid reveal date'], 400);
            }

            if ($revealDt <= $startDt) {
                $db->rollBack();
                jsonResponse(['error' => 'Reveal date must be after start date'], 400);
            }
        } else {
            $per = (string)($room['periodicity'] ?? 'weekly');
            $periodInterval = null;
            if ($per === 'biweekly') $periodInterval = new DateInterval('P14D');
            else if ($per === 'monthly') $periodInterval = new DateInterval('P1M');
            else $periodInterval = new DateInterval('P7D');

            $revealDt = $startDt->add($periodInterval)->sub(new DateInterval('P1D'));
        }

        $extensionsUsed = (int)$room['extensions_used'];
        if ($extensionsUsed >= 2) {
            $db->rollBack();
            jsonResponse(['error' => 'Maximum extensions reached'], 403);
        }

        $oldStartRaw = (string)$room['start_at'];
        if ($oldStartRaw !== '') {
            try {
                $oldStartDt = new DateTimeImmutable($oldStartRaw, new DateTimeZone('UTC'));
                if ($startDt > $oldStartDt->modify('+30 days')) {
                    $db->rollBack();
                    jsonResponse(['error' => 'Each extension is capped at 30 days'], 403);
                }
            } catch (Exception) {
                // Ignore: fall back to allowing the extension.
            }
        }

        $startStr = $startDt->format('Y-m-d H:i:s');
        $revealStr = $revealDt->format('Y-m-d H:i:s');

        $db->prepare("UPDATE saving_rooms SET start_at = ?, reveal_at = ?, extensions_used = extensions_used + 1, updated_at=NOW() WHERE id = ?")
           ->execute([$startStr, $revealStr, $roomId]);

        // Keep invite expiry aligned to the (possibly extended) start date.
        $db->prepare("UPDATE saving_room_invites SET expires_at = ? WHERE room_id = ? AND status = 'active'")
           ->execute([$startStr, $roomId]);

        $db->prepare("UPDATE saving_room_underfill_alerts SET status='resolved', resolved_at=NOW(), resolution_action='extend_start', resolution_payload=JSON_OBJECT('new_start_at', ?, 'new_reveal_at', ?) WHERE room_id = ?")
           ->execute([$startStr, $revealStr, $roomId]);

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

        $db->prepare("UPDATE saving_room_join_requests SET status='cancelled', maker_decided_at=NOW() WHERE room_id = ? AND status='pending'")
           ->execute([$roomId]);

        $db->prepare("UPDATE saving_room_participants
                      SET status='exited_prestart', removed_at=NOW(), removal_reason='room_cancelled_underfilled'
                      WHERE room_id = ? AND status IN ('pending','approved')")
           ->execute([$roomId]);

        $paidUsers = $db->prepare("SELECT DISTINCT user_id FROM saving_room_contributions WHERE room_id = ? AND status IN ('paid','paid_in_grace')");
        $paidUsers->execute([$roomId]);
        foreach ($paidUsers->fetchAll() as $pu) {
            recordRoomSettlement($db, $roomId, (int)$pu['user_id'], 'refund_minus_fee', 0.00, 'room_cancelled_underfilled');
        }

        $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status='exited_prestart'");
        $parts->execute([$roomId]);
        foreach ($parts->fetchAll() as $p) {
            notifyOnceApi(
                (int)$p['user_id'],
                'room_cancelled_underfilled',
                'important',
                'Room cancelled',
                'This saving room was cancelled before it started due to being underfilled.',
                ['room_id' => $roomId],
                'room',
                $roomId
            );
        }

        activityLog($roomId, 'room_cancelled_by_maker', ['reason' => 'underfilled']);
    }

    $db->commit();

    auditLog('room_underfill_decide');
    jsonResponse(['success' => true]);
}

// ── TYPE A: UNLOCK VOTE (consensus)
if ($action === 'typeA_vote') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $vote = (string)($body['vote'] ?? '');

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if (!in_array($vote, ['approve','reject'], true)) jsonResponse(['error' => 'Invalid vote'], 400);

    $db = getDB();
    $roomStmt = $db->prepare('SELECT saving_type, room_state, reveal_at FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'A') jsonResponse(['error' => 'Not a Type A room'], 400);
    if (!in_array($room['room_state'], ['lobby','active'], true)) jsonResponse(['error' => 'Room is not votable'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if (!in_array($st, ['approved','active'], true)) jsonResponse(['error' => 'Not an eligible participant'], 403);

    $existingVoteStmt = $db->prepare("SELECT vote
                                     FROM saving_room_unlock_votes
                                     WHERE room_id = ?
                                       AND user_id = ?
                                       AND scope='typeA_room_unlock'
                                       AND (target_rotation_index = 0 OR target_rotation_index IS NULL)
                                     ORDER BY id DESC
                                     LIMIT 1");
    $existingVoteStmt->execute([$roomId, $userId]);
    $existingVote = (string)($existingVoteStmt->fetchColumn() ?: '');

    if ($existingVote !== '') {
        if ($existingVote === $vote) {
            auditLog('room_typeA_vote');
            jsonResponse(['success' => true, 'no_change' => 1]);
        }

        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $existingVote,
        ], 409);
    }

    // One-shot vote: insert once, no updates.
    $db->prepare("INSERT IGNORE INTO saving_room_unlock_votes (room_id, user_id, scope, target_rotation_index, vote)
                  VALUES (?, ?, 'typeA_room_unlock', 0, ?)")
       ->execute([$roomId, $userId, $vote]);

    // Defensive check (handles rare race conditions).
    $existingVoteStmt->execute([$roomId, $userId]);
    $storedVote = (string)($existingVoteStmt->fetchColumn() ?: '');
    if ($storedVote !== $vote) {
        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $storedVote,
        ], 409);
    }

    // Log aggregate only (no user_id)
    $eligibleStatuses = ($room['room_state'] === 'lobby') ? ['approved'] : ['active'];
    $in = implode(',', array_fill(0, count($eligibleStatuses), '?'));
    $voteSql = "SELECT
                    SUM(CASE WHEN v.vote = 'approve' THEN 1 ELSE 0 END) AS approvals,
                    COUNT(p.user_id) AS eligible
                FROM saving_room_participants p
                LEFT JOIN saving_room_unlock_votes v
                       ON v.room_id = p.room_id
                      AND v.user_id = p.user_id
                      AND v.scope = 'typeA_room_unlock'
                      AND (v.target_rotation_index = 0 OR v.target_rotation_index IS NULL)
                WHERE p.room_id = ?
                  AND p.status IN ({$in})";
    $params = array_merge([$roomId], $eligibleStatuses);
    $stmt = $db->prepare($voteSql);
    $stmt->execute($params);
    $agg = $stmt->fetch();

    activityLog($roomId, 'unlock_vote_updated', [
        'scope' => 'typeA',
        'approvals' => (int)($agg['approvals'] ?? 0),
        'eligible' => (int)($agg['eligible'] ?? 0),
    ]);

    auditLog('room_typeA_vote');
    jsonResponse(['success' => true]);
}

// ── TYPE A: REVEAL UNLOCK CODE
if ($action === 'typeA_reveal') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, reveal_at, privacy_mode FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'A') jsonResponse(['error' => 'Not a Type A room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $revealTs = strtotime((string)$room['reveal_at']);
    if (!$revealTs || time() < $revealTs) {
        jsonResponse(['error' => 'Reveal date has not arrived'], 403);
    }

    // Ensure unanimous approval among active participants
    $stmt = $db->prepare("SELECT
                            SUM(CASE WHEN v.vote = 'approve' THEN 1 ELSE 0 END) AS approvals,
                            COUNT(p.user_id) AS eligible
                          FROM saving_room_participants p
                          LEFT JOIN saving_room_unlock_votes v
                                 ON v.room_id = p.room_id
                                AND v.user_id = p.user_id
                                AND v.scope = 'typeA_room_unlock'
                                AND (v.target_rotation_index = 0 OR v.target_rotation_index IS NULL)
                          WHERE p.room_id = ?
                            AND p.status = 'active'");
    $stmt->execute([$roomId]);
    $agg = $stmt->fetch();

    $approvals = (int)($agg['approvals'] ?? 0);
    $eligible = (int)($agg['eligible'] ?? 0);

    if ($eligible < 1 || $approvals < $eligible) {
        jsonResponse([
            'error' => '100% participant approval required before unlock.',
            'approvals' => $approvals,
            'eligible' => $eligible,
        ], 403);
    }

    // Resolve destination account + decrypt per-room unlock code
    $sel = "a.id";
    if (dbHasColumn('platform_destination_accounts', 'unlock_code_enc')) {
        $sel .= ", a.unlock_code_enc AS template_unlock_code_enc";
    } else {
        $sel .= ", NULL AS template_unlock_code_enc";
    }

    if (dbHasColumn('saving_room_accounts', 'unlock_code_enc')) {
        $sel .= ', ra.unlock_code_enc AS room_unlock_code_enc';
    } else {
        $sel .= ', NULL AS room_unlock_code_enc';
    }

    $acctStmt = $db->prepare("SELECT {$sel}
                              FROM saving_room_accounts ra
                              JOIN platform_destination_accounts a ON a.id = ra.account_id
                              WHERE ra.room_id = ?
                              LIMIT 1");
    $acctStmt->execute([$roomId]);
    $acct = $acctStmt->fetch();

    if (!$acct) {
        jsonResponse(['error' => 'Destination account is not configured for this room'], 500);
    }

    $enc = '';
    if (!empty($acct['room_unlock_code_enc'])) {
        $enc = (string)$acct['room_unlock_code_enc'];
    } else if (!empty($acct['template_unlock_code_enc'])) {
        $enc = (string)$acct['template_unlock_code_enc'];
    }

    if ($enc === '') {
        jsonResponse(['error' => 'Destination account is not configured for this room'], 500);
    }

    $unlockCode = decryptFromDb($enc);

    // Create / update unlock event status
    $ev = $db->prepare('SELECT status, revealed_at, expires_at FROM saving_room_unlock_events WHERE room_id = ?');
    $ev->execute([$roomId]);
    $event = $ev->fetch();

    if ($event && $event['status'] === 'expired') {
        jsonResponse(['error' => 'Unlock window has expired'], 403);
    }

    $now = date('Y-m-d H:i:s');

    if (!$event || $event['status'] !== 'revealed') {
        $expires = (new DateTimeImmutable('now'))->modify('+72 hours')->format('Y-m-d H:i:s');
        $db->prepare("INSERT INTO saving_room_unlock_events (room_id, status, revealed_at, expires_at)
                      VALUES (?, 'revealed', ?, ?)
                      ON DUPLICATE KEY UPDATE status='revealed', revealed_at=COALESCE(revealed_at, VALUES(revealed_at)), expires_at=COALESCE(expires_at, VALUES(expires_at))")
           ->execute([$roomId, $now, $expires]);

        activityLog($roomId, 'unlock_revealed', ['expires_at' => $expires]);

        // Notify all participants that the unlock window is open (no code in notification)
        $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
        $parts->execute([$roomId]);
        foreach ($parts->fetchAll() as $p) {
            $uid = (int)$p['user_id'];
            notifyOnceApi(
                $uid,
                'typeA_unlock_revealed',
                'critical',
                'Unlock window opened',
                'Your Type A room unlock code is now available for 72 hours. Coordinate withdrawal and keep the code secure.',
                ['room_id' => $roomId, 'expires_at' => $expires],
                'room',
                $roomId
            );
        }

        $event = ['status' => 'revealed', 'revealed_at' => $now, 'expires_at' => $expires];
    }

    auditLog('room_typeA_reveal');

    jsonResponse([
        'success' => true,
        'code' => $unlockCode,
        'revealed_at' => $event['revealed_at'],
        'expires_at' => $event['expires_at'],
    ]);
}

// ── TYPE B: TURN VOTE (50% maker gate + 50% participant gate)
if ($action === 'typeB_vote') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $vote = (string)($body['vote'] ?? '');

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if (!in_array($vote, ['approve','reject'], true)) jsonResponse(['error' => 'Invalid vote'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $wSel = "rotation_index, status, user_id";
    if (dbHasColumn('saving_room_rotation_windows', 'approve_opens_at')) {
        $wSel .= ", approve_opens_at, approve_due_at";
    } else {
        $wSel .= ", NULL AS approve_opens_at, NULL AS approve_due_at";
    }

    $winStmt = $db->prepare("SELECT {$wSel}
                             FROM saving_room_rotation_windows
                             WHERE room_id = ?
                               AND status IN ('pending_votes','revealed','blocked_dispute','blocked_debt')
                             ORDER BY rotation_index DESC
                             LIMIT 1");
    $winStmt->execute([$roomId]);
    $w = $winStmt->fetch();
    if (!$w) jsonResponse(['error' => 'Rotation window not initialized'], 500);

    $rotationIndex = (int)$w['rotation_index'];
    $turnUserId = (int)$w['user_id'];

    if ($w['status'] !== 'pending_votes') {
        jsonResponse(['error' => 'Voting is closed for the current rotation window'], 403);
    }

    // Turn user cannot vote on their own turn.
    if ($turnUserId === $userId) {
        jsonResponse(['error' => 'Turn user cannot vote on their own turn'], 403);
    }

    $nowTs = time();
    $opensAt = (string)($w['approve_opens_at'] ?? '');
    $dueAt = (string)($w['approve_due_at'] ?? '');

    if ($opensAt !== '') {
        $oTs = strtotime($opensAt);
        if ($oTs && $nowTs < $oTs) {
            jsonResponse(['error' => 'Approval window has not opened yet'], 403);
        }
    }
    if ($dueAt !== '') {
        $dTs = strtotime($dueAt);
        if ($dTs && $nowTs >= $dTs) {
            jsonResponse(['error' => 'Approval window is closed'], 403);
        }
    }

    $existingVoteStmt = $db->prepare("SELECT vote
                                     FROM saving_room_unlock_votes
                                     WHERE room_id = ?
                                       AND user_id = ?
                                       AND scope='typeB_turn_unlock'
                                       AND target_rotation_index = ?
                                     LIMIT 1");
    $existingVoteStmt->execute([$roomId, $userId, $rotationIndex]);
    $existingVote = (string)($existingVoteStmt->fetchColumn() ?: '');

    if ($existingVote !== '') {
        if ($existingVote === $vote) {
            auditLog('room_typeB_vote');
            jsonResponse(['success' => true, 'no_change' => 1]);
        }

        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $existingVote,
        ], 409);
    }

    // One-shot vote: insert once, no updates.
    $db->prepare("INSERT IGNORE INTO saving_room_unlock_votes (room_id, user_id, scope, target_rotation_index, vote)
                  VALUES (?, ?, 'typeB_turn_unlock', ?, ?)")
       ->execute([$roomId, $userId, $rotationIndex, $vote]);

    // Defensive check (handles rare race conditions).
    $existingVoteStmt->execute([$roomId, $userId, $rotationIndex]);
    $storedVote = (string)($existingVoteStmt->fetchColumn() ?: '');
    if ($storedVote !== $vote) {
        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $storedVote,
        ], 409);
    }

    $eligibleStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $eligibleStmt->execute([$roomId]);
    $eligibleActive = (int)$eligibleStmt->fetchColumn();

    $makerId = (int)$room['maker_user_id'];

    $eligibleVoters = $eligibleActive;
    if ($makerId > 0) $eligibleVoters--;
    if ($turnUserId > 0 && $turnUserId !== $makerId) $eligibleVoters--;
    $eligibleVoters = max(0, $eligibleVoters);

    $required = (int)ceil($eligibleVoters * 0.5);

    $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                   WHERE room_id = ?
                                     AND scope = 'typeB_turn_unlock'
                                     AND target_rotation_index = ?
                                     AND vote = 'approve'
                                     AND user_id <> ?
                                     AND user_id <> ?");
    $approvalsStmt->execute([$roomId, $rotationIndex, $makerId, $turnUserId]);
    $approvals = (int)$approvalsStmt->fetchColumn();

    $rejectsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                 WHERE room_id = ?
                                   AND scope = 'typeB_turn_unlock'
                                   AND target_rotation_index = ?
                                   AND vote = 'reject'
                                   AND user_id <> ?
                                   AND user_id <> ?");
    $rejectsStmt->execute([$roomId, $rotationIndex, $makerId, $turnUserId]);
    $rejects = (int)$rejectsStmt->fetchColumn();

    $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                   WHERE room_id = ? AND user_id = ?
                                     AND scope='typeB_turn_unlock'
                                     AND target_rotation_index = ?");
    $makerVoteStmt->execute([$roomId, $makerId, $rotationIndex]);
    $makerVote = $makerVoteStmt->fetchColumn();

    activityLog($roomId, 'rotation_vote_updated', [
        'rotation_index' => $rotationIndex,
        'approvals' => $approvals,
        'rejects' => $rejects,
        'required' => $required,
        'eligible' => $eligibleVoters,
        'maker_vote' => $makerVote ?: null,
        'approve_due_at' => $dueAt !== '' ? $dueAt : null,
    ]);

    auditLog('room_typeB_vote');
    jsonResponse(['success' => true]);
}

// ── TYPE B: EXIT REQUEST (create)
if ($action === 'typeB_exit_request_create') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $reason = trim((string)($body['reason'] ?? ''));
    if ($reason === '') jsonResponse(['error' => 'Reason is required'], 400);

    $replacementMakerId = null;
    $isMakerRequester = ((int)$room['maker_user_id'] === $userId);

    if ($isMakerRequester && dbHasColumn('saving_room_exit_requests', 'replacement_maker_user_id')) {
        $replacementMakerId = (int)($body['replacement_maker_user_id'] ?? 0);
        if ($replacementMakerId <= 0) {
            // Explicitly allow platform controlled rooms.
            $replacementMakerId = null;
        } else {
            // Replacement must be an active participant.
            $chk = $db->prepare("SELECT 1 FROM saving_room_participants WHERE room_id = ? AND user_id = ? AND status='active' LIMIT 1");
            $chk->execute([$roomId, $replacementMakerId]);
            if (!(bool)$chk->fetchColumn()) {
                jsonResponse(['error' => 'Replacement maker must be an active participant'], 400);
            }
        }
    }

    $ex = $db->prepare("SELECT id FROM saving_room_exit_requests WHERE room_id = ? AND status = 'open' LIMIT 1");
    $ex->execute([$roomId]);
    if ($ex->fetchColumn()) jsonResponse(['error' => 'An exit request is already open'], 409);

    $cols = ['room_id','requested_by_user_id','status'];
    $vals = [$roomId, $userId, 'open'];

    if (dbHasColumn('saving_room_exit_requests', 'reason')) {
        $cols[] = 'reason';
        $vals[] = $reason;
    }
    if (dbHasColumn('saving_room_exit_requests', 'replacement_maker_user_id')) {
        $cols[] = 'replacement_maker_user_id';
        $vals[] = $replacementMakerId;
    }

    $sql = 'INSERT INTO saving_room_exit_requests (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);

    $reqId = (int)$db->lastInsertId();

    activityLog($roomId, 'exit_requested', ['exit_request_id' => $reqId]);

    $makerId = (int)$room['maker_user_id'];
    if ($makerId > 0) {
        notifyOnceApi(
            $makerId,
            'typeB_exit_requested_maker',
            'important',
            'Exit request submitted (Type B)',
            'A participant requested to exit this Type B room. Maker approval + participant votes are required.',
            ['room_id' => $roomId, 'exit_request_id' => $reqId],
            'exit_request',
            (string)$reqId
        );
    }

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active' AND user_id <> ?");
    $parts->execute([$roomId, $userId]);
    foreach ($parts->fetchAll() as $p) {
        $uid = (int)$p['user_id'];
        if ($uid === $makerId) continue;

        notifyOnceApi(
            $uid,
            'typeB_exit_requested_participant',
            'important',
            'Exit request opened (Type B)',
            'A participant requested to exit your Type B room. Your vote may be required.',
            ['room_id' => $roomId, 'exit_request_id' => $reqId],
            'exit_request',
            (string)$reqId
        );
    }

    auditLog('room_typeB_exit_request');
    jsonResponse(['success' => true, 'exit_request_id' => $reqId]);
}

// ── TYPE B: EXIT REQUEST (vote)
if ($action === 'typeB_exit_request_vote') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $reqId  = (int)($body['exit_request_id'] ?? 0);
    $vote   = (string)($body['vote'] ?? '');

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($reqId < 1) jsonResponse(['error' => 'exit_request_id required'], 400);
    if (!in_array($vote, ['approve','reject'], true)) jsonResponse(['error' => 'Invalid vote'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $reqSel = "id, requested_by_user_id, status";
    $reqSel .= dbHasColumn('saving_room_exit_requests', 'replacement_maker_user_id') ? ", replacement_maker_user_id" : ", NULL AS replacement_maker_user_id";

    $reqStmt = $db->prepare("SELECT {$reqSel} FROM saving_room_exit_requests WHERE id = ? AND room_id = ? LIMIT 1");
    $reqStmt->execute([$reqId, $roomId]);
    $req = $reqStmt->fetch();
    if (!$req) jsonResponse(['error' => 'Exit request not found'], 404);
    if ((string)$req['status'] !== 'open') jsonResponse(['error' => 'Exit request is not open'], 409);

    $requesterId = (int)$req['requested_by_user_id'];
    if ($requesterId === $userId) jsonResponse(['error' => 'Requester cannot vote'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $existingVoteStmt = $db->prepare("SELECT vote
                                     FROM saving_room_unlock_votes
                                     WHERE room_id = ?
                                       AND user_id = ?
                                       AND scope='typeB_exit_request'
                                       AND target_rotation_index = ?
                                     LIMIT 1");
    $existingVoteStmt->execute([$roomId, $userId, $reqId]);
    $existingVote = (string)($existingVoteStmt->fetchColumn() ?: '');

    if ($existingVote !== '') {
        if ($existingVote === $vote) {
            auditLog('room_typeB_exit_vote');
            jsonResponse(['success' => true, 'no_change' => 1]);
        }

        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $existingVote,
        ], 409);
    }

    // One-shot vote: insert once, no updates.
    $db->prepare("INSERT IGNORE INTO saving_room_unlock_votes (room_id, user_id, scope, target_rotation_index, vote)
                  VALUES (?, ?, 'typeB_exit_request', ?, ?)")
       ->execute([$roomId, $userId, $reqId, $vote]);

    // Defensive check (handles rare race conditions).
    $existingVoteStmt->execute([$roomId, $userId, $reqId]);
    $storedVote = (string)($existingVoteStmt->fetchColumn() ?: '');
    if ($storedVote !== $vote) {
        jsonResponse([
            'error' => 'Vote already cast and cannot be changed.',
            'error_code' => 'vote_locked',
            'existing_vote' => $storedVote,
        ], 409);
    }

    $activeCountStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $activeCountStmt->execute([$roomId]);
    $activeCount = (int)$activeCountStmt->fetchColumn();

    $makerId = (int)$room['maker_user_id'];
    $eligibleNonMaker = max(0, $activeCount - 1 - (($makerId === $requesterId) ? 0 : 1));
    $required = (int)ceil($eligibleNonMaker * 0.6);

    $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                   WHERE room_id = ?
                                     AND scope = 'typeB_exit_request'
                                     AND target_rotation_index = ?
                                     AND vote = 'approve'
                                     AND user_id <> ?
                                     AND user_id <> ?");
    $approvalsStmt->execute([$roomId, $reqId, $makerId, $requesterId]);
    $approvals = (int)$approvalsStmt->fetchColumn();

    $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                   WHERE room_id = ? AND user_id = ?
                                     AND scope='typeB_exit_request'
                                     AND target_rotation_index = ?");
    $makerVoteStmt->execute([$roomId, $makerId, $reqId]);
    $makerVote = (string)($makerVoteStmt->fetchColumn() ?: '');

    activityLog($roomId, 'exit_vote_updated', [
        'exit_request_id' => $reqId,
        'approvals' => $approvals,
        'required' => $required,
        'eligible_non_maker' => $eligibleNonMaker,
        'maker_vote' => ($makerVote !== '' ? $makerVote : null),
    ]);

    $approved = ($makerVote === 'approve') && ($approvals >= $required);

    if ($approved) {
        $db->beginTransaction();

        $upd = $db->prepare("UPDATE saving_room_exit_requests
                              SET status='approved', resolved_at=NOW(), resolved_by_user_id=?
                              WHERE id = ? AND status='open'");
        $upd->execute([$userId, $reqId]);

        if ($upd->rowCount() < 1) {
            $db->rollBack();
            auditLog('room_typeB_exit_vote');
            jsonResponse(['success' => true, 'approved' => 1]);
        }

        $db->prepare("UPDATE saving_room_participants
                      SET status='exited_poststart', removed_at=NOW(), removal_reason='exit_request'
                      WHERE room_id = ? AND user_id = ? AND status='active'")
           ->execute([$roomId, $requesterId]);

        $db->prepare("UPDATE saving_room_rotation_queue SET status='skipped_removed' WHERE room_id = ? AND user_id = ?")
           ->execute([$roomId, $requesterId]);

        // If the exiting user is in the current active window, advance the rotation.
        $curWinUser = $db->prepare("SELECT user_id FROM saving_room_rotation_windows
                                    WHERE room_id = ? AND status IN ('pending_votes','revealed','blocked_dispute','blocked_debt')
                                    ORDER BY rotation_index DESC LIMIT 1");
        $curWinUser->execute([$roomId]);
        $turnUserId = (int)$curWinUser->fetchColumn();
        if ($turnUserId === $requesterId) {
            advanceTypeBWindowAfterExit($db, $roomId);
        }

        // Record settlement ledger: refund minus 20% platform fee.
        recordRoomSettlement($db, $roomId, $requesterId, 'refund_minus_fee', 0.20, 'exit_request');

        // If the requester is the maker, transfer maker responsibility.
        $effectiveMakerId = $makerId;
        $platformControlled = 0;
        if ($requesterId === $makerId) {
            $effectiveMakerId = 0;
            $platformControlled = 0;

            $rep = !empty($req['replacement_maker_user_id']) ? (int)$req['replacement_maker_user_id'] : 0;
            if ($rep > 0 && $rep !== $requesterId) {
                $effectiveMakerId = $rep;
            } else {
                $platformControlled = 1;
                $adm = $db->query("SELECT id FROM users WHERE is_admin = 1 ORDER BY id ASC LIMIT 1")->fetchColumn();
                $effectiveMakerId = $adm ? (int)$adm : $makerId;
            }

            $set = 'maker_user_id = ?';
            $params = [$effectiveMakerId];
            if (dbHasColumn('saving_rooms', 'platform_controlled')) {
                $set .= ', platform_controlled = ?';
                $params[] = $platformControlled;
            }
            $params[] = $roomId;
            $db->prepare("UPDATE saving_rooms SET {$set}, updated_at=NOW() WHERE id = ?")
               ->execute($params);
        }

        activityLog($roomId, 'exit_approved', ['exit_request_id' => $reqId]);

        $db->commit();

        notifyOnceApi(
            $requesterId,
            'typeB_exit_approved',
            'important',
            'Exit request approved',
            'Your exit request was approved. Your room status was updated and a settlement record was created (refund minus 20% platform fee).',
            ['room_id' => $roomId, 'exit_request_id' => $reqId],
            'exit_request',
            (string)$reqId
        );

        $notifyMakerId = $makerId;
        if ($requesterId === $makerId) {
            $notifyMakerId = $effectiveMakerId;
        }

        if ($platformControlled) {
            $admins = $db->query("SELECT id FROM users WHERE is_admin = 1")->fetchAll();
            foreach ($admins as $a) {
                $aid = (int)$a['id'];
                notifyOnceApi(
                    $aid,
                    'typeB_room_platform_controlled',
                    'important',
                    'Room maker exited (platform-controlled)',
                    'The room maker exited. The room is now platform-controlled and requires admin oversight.',
                    ['room_id' => $roomId, 'exit_request_id' => $reqId],
                    'room',
                    $roomId
                );
            }
        } else if ($notifyMakerId > 0 && $notifyMakerId !== $requesterId) {
            notifyOnceApi(
                $notifyMakerId,
                'typeB_exit_approved_maker',
                'important',
                'Exit request approved',
                'An exit request was approved and the participant has exited.',
                ['room_id' => $roomId, 'exit_request_id' => $reqId],
                'exit_request',
                (string)$reqId
            );
        }

        $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
        $parts->execute([$roomId]);
        foreach ($parts->fetchAll() as $p) {
            $uid = (int)$p['user_id'];
            if ($uid === $notifyMakerId) continue;
            if ($uid === $requesterId) continue;

            notifyOnceApi(
                $uid,
                'typeB_exit_approved_participant',
                'informational',
                'Participant exited (Type B)',
                'An exit request was approved and a participant exited this room.',
                ['room_id' => $roomId, 'exit_request_id' => $reqId],
                'exit_request',
                (string)$reqId
            );
        }
    }

    auditLog('room_typeB_exit_vote');
    jsonResponse(['success' => true, 'approved' => $approved ? 1 : 0]);
}

// ── TYPE B: EXIT REQUEST (cancel)
if ($action === 'typeB_exit_request_cancel') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $reqId  = (int)($body['exit_request_id'] ?? 0);

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($reqId < 1) jsonResponse(['error' => 'exit_request_id required'], 400);

    $db = getDB();

    $reqStmt = $db->prepare("SELECT id, requested_by_user_id, status FROM saving_room_exit_requests WHERE id = ? AND room_id = ? LIMIT 1");
    $reqStmt->execute([$reqId, $roomId]);
    $req = $reqStmt->fetch();
    if (!$req) jsonResponse(['error' => 'Exit request not found'], 404);
    if ((string)$req['status'] !== 'open') jsonResponse(['error' => 'Exit request is not open'], 409);

    if ((int)$req['requested_by_user_id'] !== $userId) jsonResponse(['error' => 'Not your exit request'], 403);

    $db->beginTransaction();

    $db->prepare("UPDATE saving_room_exit_requests
                  SET status='cancelled', resolved_at=NOW(), resolved_by_user_id=?
                  WHERE id = ? AND status='open'")
       ->execute([$userId, $reqId]);

    $db->prepare("DELETE FROM saving_room_unlock_votes WHERE room_id = ? AND scope='typeB_exit_request' AND target_rotation_index = ?")
       ->execute([$roomId, $reqId]);

    activityLog($roomId, 'exit_cancelled', ['exit_request_id' => $reqId]);

    $db->commit();

    $makerStmt = $db->prepare('SELECT maker_user_id FROM saving_rooms WHERE id = ?');
    $makerStmt->execute([$roomId]);
    $makerId = (int)$makerStmt->fetchColumn();

    if ($makerId > 0) {
        notifyOnceApi(
            $makerId,
            'typeB_exit_cancelled_maker',
            'informational',
            'Exit request cancelled (Type B)',
            'The exit request was cancelled by the requester.',
            ['room_id' => $roomId, 'exit_request_id' => $reqId],
            'exit_request',
            (string)$reqId
        );
    }

    auditLog('room_typeB_exit_cancel');
    jsonResponse(['success' => true]);
}

// ── TYPE B: DELEGATE TURN ACCESS (turn user) ───────────────
if ($action === 'typeB_set_delegate') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    if (!dbHasColumn('saving_room_rotation_windows', 'delegate_user_id')) {
        jsonResponse(['error' => 'Delegation is unavailable. Apply database migrations.'], 409);
    }

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $delegateId = (int)($body['delegate_user_id'] ?? 0);

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($delegateId === $userId) jsonResponse(['error' => 'Cannot delegate to yourself'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $winStmt = $db->prepare("SELECT id, user_id, rotation_index, status, revealed_at, expires_at,
                                    " . (dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_at') ? "withdrawal_confirmed_at" : "NULL AS withdrawal_confirmed_at") . "
                             FROM saving_room_rotation_windows
                             WHERE room_id = ?
                               AND status = 'revealed'
                             ORDER BY rotation_index DESC
                             LIMIT 1");
    $winStmt->execute([$roomId]);
    $w = $winStmt->fetch();
    if (!$w) jsonResponse(['error' => 'No revealed rotation window'], 403);

    if ((int)$w['user_id'] !== $userId) jsonResponse(['error' => 'Only the current turn user can set a delegate'], 403);
    if (!empty($w['withdrawal_confirmed_at'])) jsonResponse(['error' => 'Withdrawal already confirmed'], 409);

    $expTs = !empty($w['expires_at']) ? strtotime((string)$w['expires_at']) : null;
    if ($expTs && time() >= $expTs) jsonResponse(['error' => 'Unlock window has expired'], 403);

    try {
        $revDt = new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC'));
    } catch (Exception) {
        jsonResponse(['error' => 'Reveal timestamp missing'], 409);
    }

    $graceEndsTs = $revDt->modify('+12 hours')->getTimestamp();
    if (time() >= $graceEndsTs) {
        jsonResponse(['error' => 'Delegate can only be set within the first 12 hours of the unlock window'], 403);
    }

    if ($delegateId > 0) {
        $p = $db->prepare("SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?");
        $p->execute([$roomId, $delegateId]);
        if ((string)$p->fetchColumn() !== 'active') {
            jsonResponse(['error' => 'Delegate must be an active participant'], 403);
        }
    }

    if (dbHasColumn('saving_room_rotation_windows', 'delegate_set_at')) {
        $db->prepare('UPDATE saving_room_rotation_windows SET delegate_user_id = ?, delegate_set_at = NOW() WHERE id = ?')
           ->execute([$delegateId > 0 ? $delegateId : null, (int)$w['id']]);
    } else {
        $db->prepare('UPDATE saving_room_rotation_windows SET delegate_user_id = ? WHERE id = ?')
           ->execute([$delegateId > 0 ? $delegateId : null, (int)$w['id']]);
    }

    $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');
    $delegateName = null;
    if ($delegateId > 0) {
        $nm = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
        $nm->execute([$delegateId]);
        $delegateName = $nm->fetchColumn() ?: null;
    }

    activityLog($roomId, 'typeB_delegate_set', [
        'rotation_index' => (int)$w['rotation_index'],
        'delegate_name' => $delegateName,
    ]);

    auditLog('room_typeB_delegate_set');
    jsonResponse(['success' => true]);
}

// ── TYPE B: CONFIRM WITHDRAWAL (turn user / delegate / maker / admin) ──
if ($action === 'typeB_confirm_withdrawal') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    if (!dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_at')) {
        jsonResponse(['error' => 'Withdrawal confirmation is unavailable. Apply database migrations.'], 409);
    }

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $ref = trim((string)($body['reference'] ?? ''));
    if (strlen($ref) > 120) $ref = substr($ref, 0, 120);

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id, participation_amount FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $pStatus = (string)$mem->fetchColumn();
    if ($pStatus !== 'active' && !isAdmin($userId)) jsonResponse(['error' => 'Not an active participant'], 403);

    $sel = "id, user_id, rotation_index, status, revealed_at, expires_at";
    $sel .= dbHasColumn('saving_room_rotation_windows', 'delegate_user_id') ? ", delegate_user_id" : ", NULL AS delegate_user_id";
    $sel .= ", withdrawal_confirmed_at";

    $winStmt = $db->prepare("SELECT {$sel}
                             FROM saving_room_rotation_windows
                             WHERE room_id = ?
                               AND status = 'revealed'
                             ORDER BY rotation_index DESC
                             LIMIT 1");
    $winStmt->execute([$roomId]);
    $w = $winStmt->fetch();
    if (!$w) jsonResponse(['error' => 'No revealed rotation window'], 403);

    if (!empty($w['withdrawal_confirmed_at'])) {
        jsonResponse(['success' => true, 'already_confirmed' => 1]);
    }

    $expTs = !empty($w['expires_at']) ? strtotime((string)$w['expires_at']) : null;
    if ($expTs && time() >= $expTs) jsonResponse(['error' => 'Unlock window has expired'], 403);

    // Withdrawal confirmation requires the derived room balance to be sufficient.
    $activeCountStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $activeCountStmt->execute([$roomId]);
    $activeCount = (int)$activeCountStmt->fetchColumn();

    $requiredWithdrawalAmount = number_format(((float)$room['participation_amount']) * max(0, $activeCount), 2, '.', '');

    if (dbHasTable('saving_room_account_ledger')) {
        $bal = roomLedgerGetBalance($db, $roomId);
        if ($bal + 0.00001 < (float)$requiredWithdrawalAmount) {
            jsonResponse([
                'error' => 'Insufficient room balance to confirm withdrawal',
                'error_code' => 'insufficient_balance',
                'balance' => number_format($bal, 2, '.', ''),
                'required_withdrawal_amount' => $requiredWithdrawalAmount,
            ], 409);
        }
    }

    try {
        $revDt = new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC'));
    } catch (Exception) {
        jsonResponse(['error' => 'Reveal timestamp missing'], 409);
    }

    $graceEndsTs = $revDt->modify('+12 hours')->getTimestamp();
    $afterGrace = time() >= $graceEndsTs;

    $role = null;
    if ((int)$w['user_id'] === $userId) {
        $role = 'turn_user';
    } else if (!empty($w['delegate_user_id']) && (int)$w['delegate_user_id'] === $userId) {
        $role = 'delegate';
    } else if ((int)$room['maker_user_id'] === $userId) {
        if (!$afterGrace) jsonResponse(['error' => 'Maker can confirm only after the 12-hour grace period'], 403);
        $role = 'maker';
    } else if (isAdmin($userId)) {
        if (!$afterGrace) jsonResponse(['error' => 'Admin can confirm only after the 12-hour grace period'], 403);
        $role = 'admin';
    } else {
        jsonResponse(['error' => 'Not authorized to confirm withdrawal'], 403);
    }

    $sets = ["withdrawal_confirmed_at = NOW()", "expires_at = NOW()"]; // end window
    $params = [];

    if (dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_by_user_id')) {
        $sets[] = 'withdrawal_confirmed_by_user_id = ?';
        $params[] = $userId;
    }

    if (dbHasColumn('saving_room_rotation_windows', 'withdrawal_reference')) {
        $sets[] = 'withdrawal_reference = ?';
        $params[] = ($ref === '' ? null : $ref);
    }

    if (dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_role')) {
        $sets[] = 'withdrawal_confirmed_role = ?';
        $params[] = $role;
    }

    $params[] = (int)$w['id'];

    $db->beginTransaction();

    $sql = "UPDATE saving_room_rotation_windows SET " . implode(', ', $sets) . " WHERE id = ? AND withdrawal_confirmed_at IS NULL";
    $st = $db->prepare($sql);
    $st->execute($params);

    // Another request may have confirmed between our read and write.
    if ($st->rowCount() < 1) {
        $db->rollBack();
        jsonResponse(['success' => true, 'already_confirmed' => 1]);
    }

    // Ledger debit (derived from confirmed withdrawals).
    if (dbHasTable('saving_room_account_ledger')) {
        $ok = roomLedgerInsert($db, $roomId, 'debit', 'withdrawal', $requiredWithdrawalAmount, 'withdrawal', (string)$w['id'], $userId);
        if (!$ok) {
            $db->rollBack();
            jsonResponse(['error' => 'Failed to record ledger debit'], 500);
        }
    }

    $db->commit();

    activityLog($roomId, 'typeB_withdrawal_confirmed', [
        'rotation_index' => (int)$w['rotation_index'],
        'role' => $role,
    ]);

    auditLog('room_typeB_withdrawal_confirm');
    jsonResponse(['success' => true]);
}

// ── TYPE B: REVEAL TURN UNLOCK CODE (turn user / delegate / maker-after-grace)
if ($action === 'typeB_reveal') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();
    requireStrongAuth();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $pStatus = (string)$mem->fetchColumn();
    if ($pStatus !== 'active' && !isAdmin($userId)) jsonResponse(['error' => 'Not an active participant'], 403);

    $sel = "id, user_id, rotation_index, status, revealed_at, expires_at";
    $sel .= dbHasColumn('saving_room_rotation_windows', 'delegate_user_id') ? ", delegate_user_id" : ", NULL AS delegate_user_id";
    $sel .= dbHasColumn('saving_room_rotation_windows', 'withdrawal_confirmed_at') ? ", withdrawal_confirmed_at" : ", NULL AS withdrawal_confirmed_at";

    $winStmt = $db->prepare("SELECT {$sel}
                             FROM saving_room_rotation_windows
                             WHERE room_id = ?
                               AND status = 'revealed'
                             ORDER BY rotation_index DESC
                             LIMIT 1");
    $winStmt->execute([$roomId]);
    $w = $winStmt->fetch();
    if (!$w) jsonResponse(['error' => 'No revealed rotation window'], 403);

    if (!empty($w['withdrawal_confirmed_at'])) {
        jsonResponse(['error' => 'Withdrawal already confirmed'], 409);
    }

    $expTs = !empty($w['expires_at']) ? strtotime((string)$w['expires_at']) : null;
    if ($expTs && time() >= $expTs) jsonResponse(['error' => 'Unlock window has expired'], 403);

    try {
        $revDt = new DateTimeImmutable((string)$w['revealed_at'], new DateTimeZone('UTC'));
    } catch (Exception) {
        jsonResponse(['error' => 'Reveal timestamp missing'], 409);
    }

    $graceEndsTs = $revDt->modify('+12 hours')->getTimestamp();
    $afterGrace = time() >= $graceEndsTs;

    $role = null;
    if ((int)$w['user_id'] === $userId) {
        $role = 'turn_user';
    } else if (!empty($w['delegate_user_id']) && (int)$w['delegate_user_id'] === $userId) {
        $role = 'delegate';
    } else if ((int)$room['maker_user_id'] === $userId) {
        if (!$afterGrace) jsonResponse(['error' => 'Maker access is available after the 12-hour grace period'], 403);
        $role = 'maker';
    } else if (isAdmin($userId)) {
        if (!$afterGrace) jsonResponse(['error' => 'Admin access is available after the 12-hour grace period'], 403);
        $role = 'admin';
    } else {
        jsonResponse(['error' => 'Not authorized to reveal the code'], 403);
    }

    $selAcct = "";
    if (dbHasColumn('platform_destination_accounts', 'unlock_code_enc')) {
        $selAcct .= "a.unlock_code_enc AS template_unlock_code_enc";
    } else {
        $selAcct .= "NULL AS template_unlock_code_enc";
    }

    if (dbHasColumn('saving_room_accounts', 'unlock_code_enc')) {
        $selAcct .= ', ra.unlock_code_enc AS room_unlock_code_enc';
    } else {
        $selAcct .= ', NULL AS room_unlock_code_enc';
    }

    $acctStmt = $db->prepare("SELECT {$selAcct}
                              FROM saving_room_accounts ra
                              JOIN platform_destination_accounts a ON a.id = ra.account_id
                              WHERE ra.room_id = ?
                              LIMIT 1");
    $acctStmt->execute([$roomId]);
    $acct = $acctStmt->fetch();

    if (!$acct) jsonResponse(['error' => 'Destination account is not configured for this room'], 500);

    $enc = '';
    if (!empty($acct['room_unlock_code_enc'])) {
        $enc = (string)$acct['room_unlock_code_enc'];
    } else if (!empty($acct['template_unlock_code_enc'])) {
        $enc = (string)$acct['template_unlock_code_enc'];
    }

    if ($enc === '') jsonResponse(['error' => 'Destination account is not configured for this room'], 500);

    $unlockCode = decryptFromDb($enc);

    $logged = true;
    if (dbHasTable('saving_room_turn_code_views')) {
        $ins = $db->prepare("INSERT INTO saving_room_turn_code_views (room_id, rotation_index, viewer_user_id, viewer_role)
                             VALUES (?, ?, ?, ?)
                             ON DUPLICATE KEY UPDATE viewed_at = NOW(), viewer_role = VALUES(viewer_role)");
        $ins->execute([$roomId, (int)$w['rotation_index'], $userId, $role]);
        $logged = ((int)$ins->rowCount() === 1);
    }

    if ($logged) {
        $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');
        $nm = $db->prepare("SELECT {$uNameExpr} AS name FROM users u WHERE u.id = ? LIMIT 1");
        $nm->execute([$userId]);
        $viewerName = $nm->fetchColumn() ?: null;

        activityLog($roomId, 'typeB_code_accessed', [
            'rotation_index' => (int)$w['rotation_index'],
            'role' => $role,
            'viewer_name' => $viewerName,
        ]);
    }

    auditLog('room_typeB_reveal');

    jsonResponse([
        'success' => true,
        'code' => $unlockCode,
        'rotation_index' => (int)$w['rotation_index'],
        'revealed_at' => $w['revealed_at'],
        'expires_at' => $w['expires_at'],
        'role' => $role,
    ]);
}

// ── TYPE B: RAISE DISPUTE (24h window after reveal)
if ($action === 'typeB_raise_dispute') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $reason = trim((string)($body['reason'] ?? ''));

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if (strlen($reason) > 500) jsonResponse(['error' => 'Reason too long'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $winStmt = $db->prepare("SELECT id, rotation_index, status, dispute_window_ends_at
                             FROM saving_room_rotation_windows
                             WHERE room_id = ?
                               AND status IN ('revealed','blocked_dispute')
                             ORDER BY rotation_index DESC
                             LIMIT 1");
    $winStmt->execute([$roomId]);
    $w = $winStmt->fetch();
    if (!$w) jsonResponse(['error' => 'No revealed rotation window'], 403);

    $rotationIndex = (int)$w['rotation_index'];

    $ends = (string)($w['dispute_window_ends_at'] ?? '');
    if ($ends === '' || time() >= strtotime($ends)) {
        jsonResponse(['error' => 'Dispute window has ended'], 403);
    }

    $existing = $db->prepare("SELECT id, status FROM saving_room_disputes
                              WHERE room_id = ? AND rotation_index = ?
                                AND status IN ('open','threshold_met','escalated_admin')
                              ORDER BY created_at DESC
                              LIMIT 1");
    $existing->execute([$roomId, $rotationIndex]);
    $ex = $existing->fetch();
    if ($ex) {
        jsonResponse(['success' => true, 'dispute_id' => (int)$ex['id'], 'status' => $ex['status']]);
    }

    $eligibleStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $eligibleStmt->execute([$roomId]);
    $eligible = (int)$eligibleStmt->fetchColumn();
    $required = (int)max(1, ceil($eligible * 0.5));

    $db->beginTransaction();

    $db->prepare("INSERT INTO saving_room_disputes
                    (room_id, rotation_index, raised_by_user_id, reason, status, threshold_count_required, created_at, updated_at)
                  VALUES
                    (?, ?, ?, ?, 'open', ?, NOW(), NOW())")
       ->execute([$roomId, $rotationIndex, $userId, ($reason === '' ? null : $reason), $required]);

    $disputeId = (int)$db->lastInsertId();

    $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id) VALUES (?, ?)')
       ->execute([$disputeId, $userId]);

    $ackStmt = $db->prepare('SELECT COUNT(*) FROM saving_room_dispute_ack WHERE dispute_id = ?');
    $ackStmt->execute([$disputeId]);
    $ackCount = (int)$ackStmt->fetchColumn();

    activityLog($roomId, 'dispute_raised', ['rotation_index' => $rotationIndex, 'ack_count' => $ackCount, 'required' => $required]);

    $escalated = false;
    if ($ackCount >= $required) {
        $escalated = true;

        $db->prepare("UPDATE saving_room_disputes SET status='escalated_admin', updated_at=NOW() WHERE id = ?")
           ->execute([$disputeId]);

        $db->prepare("UPDATE saving_room_rotation_windows SET status='blocked_dispute' WHERE room_id = ? AND rotation_index = ? AND status = 'revealed'")
           ->execute([$roomId, $rotationIndex]);

        activityLog($roomId, 'rotation_blocked_dispute', ['rotation_index' => $rotationIndex]);
    }

    $db->commit();

    $makerId = (int)$room['maker_user_id'];
    if ($makerId > 0) {
        notifyOnceApi(
            $makerId,
            'typeB_dispute_raised',
            'important',
            'Dispute raised (Type B)',
            'A dispute was raised for the current Type B rotation turn. Participants can acknowledge it within the dispute window.',
            ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'dispute_id' => $disputeId],
            'dispute',
            (string)$disputeId
        );
    }

    if ($escalated) {
        $admins = $db->query("SELECT id FROM users WHERE is_admin = 1")->fetchAll();
        foreach ($admins as $a) {
            $aid = (int)$a['id'];
            notifyOnceApi(
                $aid,
                'typeB_dispute_escalated',
                'critical',
                'Type B dispute requires review',
                'A Type B rotation dispute has reached the acknowledgment threshold and requires admin review.',
                ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'dispute_id' => $disputeId],
                'dispute',
                (string)$disputeId
            );
        }
    }

    auditLog('room_typeB_dispute_raise');

    jsonResponse([
        'success' => true,
        'dispute' => [
            'id' => $disputeId,
            'status' => ($ackCount >= $required) ? 'escalated_admin' : 'open',
            'reason' => ($reason === '' ? null : $reason),
            'threshold_required' => $required,
            'ack_count' => $ackCount,
            'my_ack' => 1,
        ],
    ]);
}

// ── TYPE B: ACKNOWLEDGE DISPUTE
if ($action === 'typeB_ack_dispute') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    $userId = (int)getCurrentUserId();
    $roomId = (string)($body['room_id'] ?? '');
    $disputeId = (int)($body['dispute_id'] ?? 0);

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($disputeId <= 0) jsonResponse(['error' => 'dispute_id required'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT saving_type, room_state, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    if ($room['saving_type'] !== 'B') jsonResponse(['error' => 'Not a Type B room'], 400);
    if ($room['room_state'] !== 'active') jsonResponse(['error' => 'Room is not active'], 403);

    $mem = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $mem->execute([$roomId, $userId]);
    $st = (string)$mem->fetchColumn();
    if ($st !== 'active') jsonResponse(['error' => 'Not an active participant'], 403);

    $disp = $db->prepare('SELECT id, room_id, rotation_index, status, threshold_count_required FROM saving_room_disputes WHERE id = ?');
    $disp->execute([$disputeId]);
    $d = $disp->fetch();
    if (!$d) jsonResponse(['error' => 'Dispute not found'], 404);
    if ((string)$d['room_id'] !== $roomId) jsonResponse(['error' => 'Dispute does not belong to room'], 403);

    if (!in_array((string)$d['status'], ['open','threshold_met','escalated_admin'], true)) {
        jsonResponse(['error' => 'Dispute is not open'], 409);
    }

    $rotationIndex = (int)$d['rotation_index'];

    $winStmt = $db->prepare('SELECT dispute_window_ends_at FROM saving_room_rotation_windows WHERE room_id = ? AND rotation_index = ? LIMIT 1');
    $winStmt->execute([$roomId, $rotationIndex]);
    $ends = (string)$winStmt->fetchColumn();
    if ($ends === '' || time() >= strtotime($ends)) {
        jsonResponse(['error' => 'Dispute window has ended'], 403);
    }

    $db->beginTransaction();

    $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id) VALUES (?, ?)')
       ->execute([$disputeId, $userId]);

    $ackStmt = $db->prepare('SELECT COUNT(*) FROM saving_room_dispute_ack WHERE dispute_id = ?');
    $ackStmt->execute([$disputeId]);
    $ackCount = (int)$ackStmt->fetchColumn();

    activityLog($roomId, 'dispute_ack_updated', ['rotation_index' => $rotationIndex, 'ack_count' => $ackCount, 'required' => (int)$d['threshold_count_required']]);

    $escalated = false;
    if ($ackCount >= (int)$d['threshold_count_required']) {
        $escalated = true;

        $db->prepare("UPDATE saving_room_disputes SET status='escalated_admin', updated_at=NOW() WHERE id = ? AND status <> 'escalated_admin'")
           ->execute([$disputeId]);

        $db->prepare("UPDATE saving_room_rotation_windows SET status='blocked_dispute' WHERE room_id = ? AND rotation_index = ? AND status = 'revealed'")
           ->execute([$roomId, $rotationIndex]);

        activityLog($roomId, 'rotation_blocked_dispute', ['rotation_index' => $rotationIndex]);
    }

    $db->commit();

    if ($escalated) {
        // Notify admins
        $admins = $db->query("SELECT id FROM users WHERE is_admin = 1")->fetchAll();
        foreach ($admins as $a) {
            $aid = (int)$a['id'];
            notifyOnceApi(
                $aid,
                'typeB_dispute_escalated',
                'critical',
                'Type B dispute requires review',
                'A Type B rotation dispute has reached the acknowledgment threshold and requires admin review.',
                ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'dispute_id' => $disputeId],
                'dispute',
                (string)$disputeId
            );
        }

        // Notify maker
        $makerId = (int)$room['maker_user_id'];
        if ($makerId > 0) {
            notifyOnceApi(
                $makerId,
                'typeB_dispute_escalated_maker',
                'critical',
                'Dispute escalated (Type B)',
                'A Type B dispute has reached the acknowledgment threshold and the rotation is now blocked pending admin review.',
                ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'dispute_id' => $disputeId],
                'dispute',
                (string)$disputeId
            );
        }
    }

    auditLog('room_typeB_dispute_ack');

    jsonResponse(['success' => true, 'ack_count' => $ackCount]);
}

// ── CONTRIBUTION PROOFS (list; participants can view all)
if ($action === 'contribution_proofs') {
    requireLogin();
    requireVerifiedEmail();

    if (!dbHasTable('saving_room_contribution_proofs')) {
        jsonResponse(['error' => 'Contribution proofs are unavailable. Apply database migrations.'], 409);
    }

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_GET['room_id'] ?? '');
    $beforeId = (int)($_GET['before_id'] ?? 0);
    $limit = (int)($_GET['limit'] ?? 80);
    $limit = max(1, min(200, $limit));

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);

    $db = getDB();

    $roomStmt = $db->prepare('SELECT id, maker_user_id FROM saving_rooms WHERE id = ?');
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) jsonResponse(['error' => 'Room not found'], 404);

    $makerId = (int)($room['maker_user_id'] ?? 0);

    $myStmt = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
    $myStmt->execute([$roomId, $userId]);
    $myStatus = (string)($myStmt->fetchColumn() ?: '');

    $isAllowed = isAdmin($userId) || ($makerId === $userId) || in_array($myStatus, ['approved','active','completed'], true);
    if (!$isAllowed) jsonResponse(['error' => 'Not an eligible participant'], 403);

    $uNameExpr = sqlRoomUserDisplayNameExpr('u', 'id');

    $where = "p.room_id = ?";
    $params = [$roomId];
    if ($beforeId > 0) {
        $where .= " AND p.id < ?";
        $params[] = $beforeId;
    }

    $sql = "SELECT
                p.id AS proof_id,
                p.user_id,
                {$uNameExpr} AS display_name,
                p.original_filename,
                p.content_type,
                p.size_bytes,
                p.reference_snapshot,
                p.created_at AS proof_created_at,

                c.id AS contribution_id,
                c.amount,
                c.status,
                c.reference,
                c.confirmed_at,

                cy.id AS cycle_id,
                cy.cycle_index,
                cy.due_at
            FROM saving_room_contribution_proofs p
            JOIN saving_room_contributions c ON c.id = p.contribution_id
            JOIN saving_room_contribution_cycles cy ON cy.id = c.cycle_id
            JOIN users u ON u.id = p.user_id
            WHERE {$where}
            ORDER BY p.id DESC
            LIMIT {$limit}";

    $st = $db->prepare($sql);
    $st->execute($params);

    $rows = $st->fetchAll();
    $nextBeforeId = null;
    if ($rows) {
        $last = end($rows);
        $nextBeforeId = (int)($last['proof_id'] ?? 0);
        if ($nextBeforeId <= 0) $nextBeforeId = null;
    }

    jsonResponse([
        'success' => true,
        'proofs' => $rows,
        'next_before_id' => $nextBeforeId,
    ]);
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

// ── CONTRIBUTION: CONFIRM WITH PROOF (multipart/form-data)
// POST /api/rooms.php?action=confirm_contribution_with_proof
if ($action === 'confirm_contribution_with_proof') {
    requireLogin();
    requireVerifiedEmail();
    requireCsrf();

    if (!dbHasTable('saving_room_contribution_proofs')) {
        jsonResponse(['error' => 'Contribution proofs are unavailable. Apply database migrations.'], 409);
    }

    $userId = (int)getCurrentUserId();
    $roomId = (string)($_POST['room_id'] ?? '');
    $cycleId = (int)($_POST['cycle_id'] ?? 0);
    $amount = (string)($_POST['amount'] ?? '');
    $reference = trim((string)($_POST['reference'] ?? ''));

    if ($roomId === '' || strlen($roomId) !== 36) jsonResponse(['error' => 'Invalid room_id'], 400);
    if ($cycleId <= 0) jsonResponse(['error' => 'cycle_id required'], 400);
    if (!is_numeric($amount) || (float)$amount <= 0) jsonResponse(['error' => 'Invalid amount'], 400);

    if (empty($_FILES['proof']) || !is_array($_FILES['proof'])) {
        jsonResponse(['error' => 'proof file required'], 400);
    }

    $f = $_FILES['proof'];
    if (!empty($f['error'])) jsonResponse(['error' => 'Upload failed'], 400);

    $size = (int)($f['size'] ?? 0);
    // Avoid numeric separators for compatibility with older PHP versions (<7.4).
    if ($size <= 0 || $size > 5000000) jsonResponse(['error' => 'File too large (max 5MB)'], 400);

    $tmp = (string)($f['tmp_name'] ?? '');
    if ($tmp === '' || !is_uploaded_file($tmp)) jsonResponse(['error' => 'Invalid upload'], 400);

    $raw = file_get_contents($tmp);
    if ($raw === false || $raw === '') jsonResponse(['error' => 'Could not read upload'], 400);

    $contentType = (string)($f['type'] ?? '');
    $allowed = ['image/png','image/jpeg','image/jpg','image/webp'];
    if ($contentType === '' || !in_array(strtolower($contentType), $allowed, true)) {
        jsonResponse(['error' => 'Unsupported file type'], 400);
    }

    $shaBin = hash('sha256', $raw, true);

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

    $cidStmt = $db->prepare('SELECT id FROM saving_room_contributions WHERE room_id = ? AND cycle_id = ? AND user_id = ? LIMIT 1');
    $cidStmt->execute([$roomId, $cycleId, $userId]);
    $contributionId = (int)$cidStmt->fetchColumn();
    if ($contributionId <= 0) {
        $db->rollBack();
        jsonResponse(['error' => 'Failed to resolve contribution_id'], 500);
    }

    // Dedup proof by (contribution_id, sha256)
    $dup = $db->prepare('SELECT id, reference_snapshot FROM saving_room_contribution_proofs WHERE contribution_id = ? AND user_id = ? AND sha256 = ? LIMIT 1');
    $dup->execute([$contributionId, $userId, $shaBin]);
    $existing = $dup->fetch();

    $referenceSnapshot = null;
    if ($existing) {
        $referenceSnapshot = $existing['reference_snapshot'] ?? null;
    } else {
        $enc = mediaEncryptBytes($raw);
        $referenceSnapshot = bin2hex(random_bytes(12));

        $db->prepare('INSERT INTO saving_room_contribution_proofs
            (room_id, contribution_id, user_id, reference_snapshot, original_filename, content_type, size_bytes, sha256, enc_cipher, iv, tag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
           ->execute([
               $roomId,
               $contributionId,
               $userId,
               $referenceSnapshot,
               substr((string)($f['name'] ?? ''), 0, 255) ?: null,
               strtolower($contentType),
               $size,
               $shaBin,
               $enc['cipher'],
               $enc['iv'],
               $enc['tag'],
           ]);
    }

    // Ledger credit (derived from proofs + contributions)
    roomLedgerInsert($db, $roomId, 'credit', 'contribution', $amount, 'contribution', (string)$contributionId, $userId);

    // Activity feed: show ✓ Contributed; show amount only if privacy mode is disabled.
    $payload = ['cycle_id' => $cycleId];
    if (empty($room['privacy_mode'])) {
        $payload['amount'] = $amount;
    }

    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, 'contribution_confirmed', json_encode($payload, JSON_UNESCAPED_UNICODE)]);

    $db->commit();

    auditLog('room_contribution_confirm');
    jsonResponse(['success' => true, 'reference_snapshot' => $referenceSnapshot]);
}

jsonResponse(['error' => 'Unknown action'], 400);
