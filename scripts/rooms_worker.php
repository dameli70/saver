<?php
// ============================================================
//  LOCKSMITH — Saving Rooms Worker (cron)
//
//  Run every 1-5 minutes:
//    php scripts/rooms_worker.php
//
//  Responsibilities (incremental rollout):
//   - lobby lock at start date
//   - start room at start date
//   - underfilled alerts at T-72h
//   - auto-cancel if no decision within 24h
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This worker must be run from the command line.\n");
    exit(1);
}

require_once __DIR__ . '/../config/database.php';

function db(): PDO {
    return getDB();
}

function logLine(string $s): void {
    fwrite(STDOUT, '[' . date('c') . '] ' . $s . "\n");
}

function activityLog(PDO $db, string $roomId, string $eventType, array $payload): void {
    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, $eventType, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function notify(PDO $db, int $userId, string $tier, string $title, string $body, array $data = [], string $channelMask = ''): void {
    if ($channelMask === '') {
        // Critical is push+inapp+email; important is push+inapp; informational is inapp.
        if ($tier === 'critical') $channelMask = 'push,inapp,email';
        else if ($tier === 'important') $channelMask = 'push,inapp';
        else $channelMask = 'inapp';
    }

    $db->prepare('INSERT INTO notifications (user_id, tier, channel_mask, title, body, data_json) VALUES (?, ?, ?, ?, ?, ?)')
       ->execute([$userId, $tier, $channelMask, $title, $body, $data ? json_encode($data, JSON_UNESCAPED_UNICODE) : null]);
}

function approvedCount(PDO $db, string $roomId): int {
    $stmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status IN ('approved','active')");
    $stmt->execute([$roomId]);
    return (int)$stmt->fetchColumn();
}

$db = db();

// ───────────────────────────────────────────────────────────
//  1) Lock lobby when start date arrives (if still open)
// ───────────────────────────────────────────────────────────
$roomsToLock = $db->query("SELECT id FROM saving_rooms WHERE room_state = 'lobby' AND lobby_state = 'open' AND start_at <= NOW() LIMIT 500")->fetchAll();
foreach ($roomsToLock as $r) {
    $roomId = (string)$r['id'];
    $db->prepare("UPDATE saving_rooms SET lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);
    activityLog($db, $roomId, 'lobby_locked', ['reason' => 'start_date_reached']);
    logLine("Lobby locked: {$roomId}");
}

// ───────────────────────────────────────────────────────────
//  2) Start rooms when start date arrives
// ───────────────────────────────────────────────────────────
$roomsToStart = $db->query("SELECT id FROM saving_rooms WHERE room_state = 'lobby' AND start_at <= NOW() LIMIT 500")->fetchAll();
foreach ($roomsToStart as $r) {
    $roomId = (string)$r['id'];

    $db->prepare("UPDATE saving_rooms SET room_state='active', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    // Promote approved participants to active
    $db->prepare("UPDATE saving_room_participants SET status='active' WHERE room_id = ? AND status='approved'")
       ->execute([$roomId]);

    activityLog($db, $roomId, 'room_started', []);
    logLine("Room started: {$roomId}");
}

// ───────────────────────────────────────────────────────────
//  3) Underfilled room alerts at T-72h
//     If approved_count < min_participants by 72 hours before start:
//       - alert maker
//       - maker has 24 hours to act
// ───────────────────────────────────────────────────────────
$roomsForAlert = $db->query("SELECT id, maker_user_id, min_participants, start_at
                             FROM saving_rooms
                             WHERE room_state = 'lobby'
                               AND start_at > NOW()
                               AND start_at <= (NOW() + INTERVAL 72 HOUR)
                               AND start_at > (NOW() + INTERVAL 48 HOUR)
                               AND id NOT IN (SELECT room_id FROM saving_room_underfill_alerts)
                             LIMIT 500")->fetchAll();

foreach ($roomsForAlert as $r) {
    $roomId = (string)$r['id'];
    $makerId = (int)$r['maker_user_id'];
    $min = (int)$r['min_participants'];
    $cnt = approvedCount($db, $roomId);

    if ($cnt >= $min) continue;

    $deadline = (new DateTimeImmutable('now'))->modify('+24 hours')->format('Y-m-d H:i:s');

    $db->prepare("INSERT INTO saving_room_underfill_alerts (room_id, alerted_at, decision_deadline_at, status)
                  VALUES (?, NOW(), ?, 'open')")
       ->execute([$roomId, $deadline]);

    activityLog($db, $roomId, 'underfilled_alerted', ['approved_count' => $cnt, 'min_participants' => $min, 'decision_deadline_at' => $deadline]);

    notify(
        $db,
        $makerId,
        'important',
        'Room underfilled — action required',
        'Your saving room has not reached its minimum participant count. Choose to extend the start date, lower the minimum if permitted, or cancel for refunds. If you take no action within 24 hours, the room will auto-cancel.',
        ['room_id' => $roomId, 'decision_deadline_at' => $deadline]
    );

    logLine("Underfilled alert created: {$roomId} ({$cnt}/{$min})");
}

// ───────────────────────────────────────────────────────────
//  4) Auto-cancel underfilled rooms with expired decision window
// ───────────────────────────────────────────────────────────
$expired = $db->query("SELECT a.room_id, r.maker_user_id
                       FROM saving_room_underfill_alerts a
                       JOIN saving_rooms r ON r.id = a.room_id
                       WHERE a.status = 'open'
                         AND a.decision_deadline_at <= NOW()
                         AND r.room_state = 'lobby'
                       LIMIT 500")->fetchAll();

foreach ($expired as $row) {
    $roomId = (string)$row['room_id'];
    $makerId = (int)$row['maker_user_id'];

    $db->beginTransaction();

    $db->prepare("UPDATE saving_rooms SET room_state='cancelled', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    $db->prepare("UPDATE saving_room_underfill_alerts SET status='expired', resolved_at=NOW(), resolution_action='cancel', resolution_payload=JSON_OBJECT('auto', 1) WHERE room_id = ? AND status='open'")
       ->execute([$roomId]);

    // Note: refunds are handled in the contribution/escrow layer (implemented in later worker milestones)
    activityLog($db, $roomId, 'room_auto_cancelled_underfilled', ['reason' => 'no_action_after_alert']);

    $db->commit();

    notify(
        $db,
        $makerId,
        'important',
        'Room cancelled (underfilled)',
        'No action was taken after the underfilled-room alert. The room has been cancelled and refunds will be processed according to policy.',
        ['room_id' => $roomId]
    );

    logLine("Auto-cancelled underfilled room: {$roomId}");
}

logLine('Done.');
