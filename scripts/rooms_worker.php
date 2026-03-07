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
//   - contribution cycles (generate)
//   - grace windows + strike enforcement (generate notifications + strikes)
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

function notifyOnce(PDO $db, int $userId, string $eventKey, string $tier, string $title, string $body, array $data = [], string $refType = null, string $refId = null, string $channelMask = ''): void {
    if ($channelMask === '') {
        // Critical is push+inapp+email; important is push+inapp; informational is inapp.
        if ($tier === 'critical') $channelMask = 'push,inapp,email';
        else if ($tier === 'important') $channelMask = 'push,inapp';
        else $channelMask = 'inapp';
    }

    // Dedup: if we already emitted this event for this user+ref, do nothing.
    $rt = $refType;
    $rid = $refId;

    $db->prepare('INSERT IGNORE INTO notification_events (user_id, event_key, ref_type, ref_id) VALUES (?, ?, ?, ?)')
       ->execute([$userId, $eventKey, $rt, $rid]);

    if ($db->lastInsertId() === '0') return;

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
function periodSpec(string $periodicity): array {
    if ($periodicity === 'biweekly') return ['interval' => 'P14D', 'seconds' => 14 * 86400];
    if ($periodicity === 'monthly') return ['interval' => 'P1M', 'seconds' => 30 * 86400];
    return ['interval' => 'P7D', 'seconds' => 7 * 86400];
}

function ensureTrustRow(PDO $db, int $userId): void {
    $db->prepare('INSERT IGNORE INTO user_trust (user_id, trust_level, completed_reveals_count) VALUES (?, 1, 0)')
       ->execute([(int)$userId]);
}

function strikes6m(PDO $db, int $userId): int {
    $s = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (NOW() - INTERVAL 6 MONTH)");
    $s->execute([(int)$userId]);
    return (int)$s->fetchColumn();
}

function applyStrike(PDO $db, int $userId, string $strikeType, string $roomId = null, int $cycleId = null): void {
    $db->prepare('INSERT INTO user_strikes (user_id, room_id, cycle_id, strike_type) VALUES (?, ?, ?, ?)')
       ->execute([(int)$userId, $roomId, $cycleId, $strikeType]);

    // Level regression rule: 3+ strikes in 6 months -> demote one level (once per 6-month window)
    ensureTrustRow($db, $userId);

    $t = $db->prepare('SELECT trust_level, last_level_change_at FROM user_trust WHERE user_id = ?');
    $t->execute([(int)$userId]);
    $row = $t->fetch();
    $lvl = (int)($row['trust_level'] ?? 1);
    $last = $row['last_level_change_at'] ? strtotime((string)$row['last_level_change_at']) : null;

    $count = strikes6m($db, $userId);
    if ($count >= 3) {
        // 30-day join cooldown
        $until = (new DateTimeImmutable('now'))->modify('+30 days')->format('Y-m-d H:i:s');
        $db->prepare("INSERT INTO user_restrictions (user_id, restricted_until, reason, updated_at)
                      VALUES (?, ?, 'strikes_6m', NOW())
                      ON DUPLICATE KEY UPDATE restricted_until = GREATEST(restricted_until, VALUES(restricted_until)), reason='strikes_6m', updated_at=NOW()")
           ->execute([(int)$userId, $until]);

        // Demote at most once per 6-month window
        $sixMonthsAgo = time() - (183 * 86400);
        if ($lvl > 1 && (!$last || $last < $sixMonthsAgo)) {
            $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
               ->execute([max(1, $lvl - 1), (int)$userId]);
        }
    }
}

function ensureContributionRow(PDO $db, string $roomId, int $userId, int $cycleId, string $amount): void {
    $db->prepare("INSERT IGNORE INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status)
                  VALUES (?, ?, ?, ?, 'unpaid')")
       ->execute([$roomId, (int)$userId, (int)$cycleId, $amount]);
}

foreach ($roomsToStart as $r) {
    $roomId = (string)$r['id'];

    $roomStmt = $db->prepare("SELECT id, periodicity, participation_amount, maker_user_id FROM saving_rooms WHERE id = ?");
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();

    $db->prepare("UPDATE saving_rooms SET room_state='active', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    // Promote approved participants to active
    $db->prepare("UPDATE saving_room_participants SET status='active' WHERE room_id = ? AND status='approved'")
       ->execute([$roomId]);

    // Create first contribution cycle due at start time (cycle_index=1)
    // Grace window ends in 48 hours.
    $db->prepare("INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status)
                  VALUES (?, 1, NOW(), (NOW() + INTERVAL 48 HOUR), 'open')")
       ->execute([$roomId]);

    // Ensure each active participant has a contribution row for cycle 1
    $cycleIdStmt = $db->prepare("SELECT id FROM saving_room_contribution_cycles WHERE room_id = ? AND cycle_index = 1");
    $cycleIdStmt->execute([$roomId]);
    $cycleId = (int)$cycleIdStmt->fetchColumn();

    if ($cycleId > 0) {
        $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
        $parts->execute([$roomId]);
        $amount = (string)$room['participation_amount'];
        foreach ($parts->fetchAll() as $p) {
            ensureContributionRow($db, $roomId, (int)$p['user_id'], $cycleId, $amount);
        }
    }

    activityLog($db, $roomId, 'room_started', []);
    logLine("Room started: {$roomId}");
}

// ───────────────────────────────────────────────────────────
//  2b) Generate future contribution cycles for active rooms
//      We keep at least 2 upcoming cycles.
// ───────────────────────────────────────────────────────────
$activeRooms = $db->query("SELECT id, periodicity, participation_amount FROM saving_rooms WHERE room_state='active' LIMIT 500")->fetchAll();
foreach ($activeRooms as $r) {
    $roomId = (string)$r['id'];
    $period = (string)$r['periodicity'];
    $spec = periodSpec($period);

    $last = $db->prepare("SELECT cycle_index, due_at FROM saving_room_contribution_cycles WHERE room_id = ? ORDER BY cycle_index DESC LIMIT 1");
    $last->execute([$roomId]);
    $lastRow = $last->fetch();
    if (!$lastRow) continue;

    $lastIdx = (int)$lastRow['cycle_index'];
    $lastDue = new DateTimeImmutable((string)$lastRow['due_at']);

    // ensure at least two future cycles exist
    for ($i = 1; $i <= 2; $i++) {
        $nextIdx = $lastIdx + $i;
        $nextDue = $lastDue->add(new DateInterval($spec['interval']));
        // advance lastDue for each loop
        $lastDue = $nextDue;

        $db->prepare("INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status)
                      VALUES (?, ?, ?, DATE_ADD(?, INTERVAL 48 HOUR), 'open')")
           ->execute([$roomId, $nextIdx, $nextDue->format('Y-m-d H:i:s'), $nextDue->format('Y-m-d H:i:s')]);
    }
}

// ───────────────────────────────────────────────────────────
//  2c) Contribution enforcement: grace window + strike
// ───────────────────────────────────────────────────────────
$cycles = $db->query("SELECT c.id, c.room_id, c.cycle_index, c.due_at, c.grace_ends_at, c.status,
                             r.privacy_mode, r.participation_amount
                      FROM saving_room_contribution_cycles c
                      JOIN saving_rooms r ON r.id = c.room_id
                      WHERE r.room_state='active'
                        AND c.status IN ('open','grace')
                        AND c.due_at <= (NOW() + INTERVAL 24 HOUR)
                      ORDER BY c.due_at ASC
                      LIMIT 800")->fetchAll();

foreach ($cycles as $c) {
    $cycleId = (int)$c['id'];
    $roomId = (string)$c['room_id'];
    $dueAt = new DateTimeImmutable((string)$c['due_at']);
    $graceEnds = new DateTimeImmutable((string)$c['grace_ends_at']);
    $status = (string)$c['status'];

    // Important notification: due in 24 hours (per participant)
    $dueIn = $dueAt->getTimestamp() - time();

    $parts = $db->prepare("SELECT p.user_id
                           FROM saving_room_participants p
                           WHERE p.room_id = ?
                             AND p.status = 'active'");
    $parts->execute([$roomId]);
    $pRows = $parts->fetchAll();

    foreach ($pRows as $p) {
        $uid = (int)$p['user_id'];

        ensureContributionRow($db, $roomId, $uid, $cycleId, (string)$c['participation_amount']);

        if ($dueIn > 0 && $dueIn <= 24 * 3600) {
            notifyOnce(
                $db,
                $uid,
                'contribution_due_24h',
                'important',
                'Contribution due in 24 hours',
                'A contribution is due in one of your saving rooms within the next 24 hours.',
                ['room_id' => $roomId, 'cycle_id' => $cycleId, 'due_at' => $c['due_at']],
                'cycle',
                (string)$cycleId
            );
        }
    }

    // Move into grace if due has passed
    if ($status === 'open' && time() >= $dueAt->getTimestamp()) {
        $db->prepare("UPDATE saving_room_contribution_cycles SET status='grace' WHERE id = ?")
           ->execute([$cycleId]);
        activityLog($db, $roomId, 'grace_window_started', ['cycle_id' => $cycleId, 'cycle_index' => (int)$c['cycle_index']]);
    }

    // Grace reminders at +1h, +24h, +47h after due
    if (time() >= $dueAt->getTimestamp()) {
        $elapsed = time() - $dueAt->getTimestamp();

        $marks = [
            1 * 3600 => 'contribution_grace_h1',
            24 * 3600 => 'contribution_grace_h24',
            47 * 3600 => 'contribution_grace_h47',
        ];

        foreach ($marks as $sec => $key) {
            if ($elapsed >= $sec && $elapsed < ($sec + 600)) {
                foreach ($pRows as $p) {
                    $uid = (int)$p['user_id'];
                    // Only notify users who are still unpaid
                    $st = $db->prepare("SELECT status FROM saving_room_contributions WHERE cycle_id = ? AND user_id = ?");
                    $st->execute([$cycleId, $uid]);
                    $cur = (string)$st->fetchColumn();
                    if (in_array($cur, ['paid','paid_in_grace'], true)) continue;

                    notifyOnce(
                        $db,
                        $uid,
                        $key,
                        'important',
                        'Contribution grace window',
                        'Your contribution is overdue and in the grace period.',
                        ['room_id' => $roomId, 'cycle_id' => $cycleId, 'grace_ends_at' => $c['grace_ends_at']],
                        'cycle',
                        (string)$cycleId
                    );
                }
            }
        }

        // Critical: grace ending in 6 hours
        $remaining = $graceEnds->getTimestamp() - time();
        if ($remaining > 0 && $remaining <= 6 * 3600) {
            foreach ($pRows as $p) {
                $uid = (int)$p['user_id'];
                $st = $db->prepare("SELECT status FROM saving_room_contributions WHERE cycle_id = ? AND user_id = ?");
                $st->execute([$cycleId, $uid]);
                $cur = (string)$st->fetchColumn();
                if (in_array($cur, ['paid','paid_in_grace'], true)) continue;

                notifyOnce(
                    $db,
                    $uid,
                    'contribution_grace_ending_6h',
                    'critical',
                    'Contribution grace window ending in 6 hours',
                    'Your grace period is ending soon. Contribute now to avoid a strike.',
                    ['room_id' => $roomId, 'cycle_id' => $cycleId, 'grace_ends_at' => $c['grace_ends_at']],
                    'cycle',
                    (string)$cycleId
                );
            }
        }

        // If grace ended: mark missed + strike
        if ($status !== 'closed' && time() >= $graceEnds->getTimestamp()) {
            $db->prepare("UPDATE saving_room_contribution_cycles SET status='closed' WHERE id = ?")
               ->execute([$cycleId]);

            foreach ($pRows as $p) {
                $uid = (int)$p['user_id'];

                $st = $db->prepare("SELECT status FROM saving_room_contributions WHERE cycle_id = ? AND user_id = ?");
                $st->execute([$cycleId, $uid]);
                $cur = (string)$st->fetchColumn();
                if (in_array($cur, ['paid','paid_in_grace'], true)) continue;

                $db->prepare("UPDATE saving_room_contributions SET status='missed' WHERE cycle_id = ? AND user_id = ?")
                   ->execute([$cycleId, $uid]);

                applyStrike($db, $uid, 'missed_contribution', $roomId, $cycleId);

                $db->prepare("UPDATE saving_room_participants SET missed_contributions_count = missed_contributions_count + 1 WHERE room_id = ? AND user_id = ?")
                   ->execute([$roomId, $uid]);

                activityLog($db, $roomId, 'strike_logged', ['cycle_id' => $cycleId]);

                // Two missed contributions in same room -> automatic removal
                $mc = $db->prepare("SELECT missed_contributions_count FROM saving_room_participants WHERE room_id = ? AND user_id = ?");
                $mc->execute([$roomId, $uid]);
                $missed = (int)$mc->fetchColumn();

                if ($missed >= 2) {
                    $db->prepare("UPDATE saving_room_participants SET status='removed', removed_at=NOW(), removal_reason='two_missed_contributions' WHERE room_id = ? AND user_id = ?")
                       ->execute([$roomId, $uid]);

                    activityLog($db, $roomId, 'participant_removed', ['reason' => 'two_missed_contributions']);

                    notifyOnce(
                        $db,
                        $uid,
                        'removed_from_room',
                        'critical',
                        'You have been removed from a room',
                        'You were removed after missing two contributions in this room. Funds are held in escrow and will be handled according to the room policy.',
                        ['room_id' => $roomId],
                        'room',
                        $roomId
                    );
                }
            }
        }
    }
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

    notifyOnce(
        $db,
        $makerId,
        'room_underfilled_alert',
        'important',
        'Room underfilled — action required',
        'Your saving room has not reached its minimum participant count. Choose to extend the start date, lower the minimum if permitted, or cancel for refunds. If you take no action within 24 hours, the room will auto-cancel.',
        ['room_id' => $roomId, 'decision_deadline_at' => $deadline],
        'room',
        $roomId
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

    notifyOnce(
        $db,
        $makerId,
        'room_underfilled_auto_cancelled',
        'important',
        'Room cancelled (underfilled)',
        'No action was taken after the underfilled-room alert. The room has been cancelled and refunds will be processed according to policy.',
        ['room_id' => $roomId],
        'room',
        $roomId
    );

    logLine("Auto-cancelled underfilled room: {$roomId}");
}

logLine('Done.');
