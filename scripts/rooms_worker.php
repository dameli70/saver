<?php
// ============================================================
//  LOCKSMITH — Saving Rooms Worker (cron)
//
//  Run every 1–5 minutes:
//    php scripts/rooms_worker.php
//
//  Responsibilities:
//   - lobby lock / room start
//   - contribution cycles + grace reminders + strike enforcement
//   - participant removal after 2 missed contributions + escrow settlement record
//   - underfilled alerts (T-72h) + auto-cancel after 24h
//   - Type A unlock expiry warnings + close + trust completion update
//   - Type B rotation processing (vote->reveal, expiry->advance)
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This worker must be run from the command line.\n");
    exit(1);
}

// Prevent concurrent runs (cron overlap).
$lockPath = __DIR__ . '/rooms_worker.lock';
$lockFp = @fopen($lockPath, 'c');
if (!$lockFp) {
    fwrite(STDERR, "Could not open lock file: {$lockPath}\n");
    exit(1);
}
if (!flock($lockFp, LOCK_EX | LOCK_NB)) {
    // Another instance is running.
    fwrite(STDOUT, "[" . date('c') . "] Another rooms_worker is running; exiting.\n");
    exit(0);
}
register_shutdown_function(function() use ($lockFp) {
    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);
});

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

function notifyOnce(PDO $db, int $userId, string $eventKey, string $tier, string $title, string $body, array $data = [], ?string $refType = null, ?string $refId = null, string $channelMask = ''): void {
    if ($channelMask === '') {
        if ($tier === 'critical') $channelMask = 'push,inapp,email';
        else if ($tier === 'important') $channelMask = 'push,inapp';
        else $channelMask = 'inapp';
    }

    $db->prepare('INSERT IGNORE INTO notification_events (user_id, event_key, ref_type, ref_id) VALUES (?, ?, ?, ?)')
       ->execute([$userId, $eventKey, $refType, $refId]);

    if ($db->lastInsertId() === '0') return;

    $db->prepare('INSERT INTO notifications (user_id, tier, channel_mask, title, body, data_json) VALUES (?, ?, ?, ?, ?, ?)')
       ->execute([$userId, $tier, $channelMask, $title, $body, $data ? json_encode($data, JSON_UNESCAPED_UNICODE) : null]);
}

function approvedCount(PDO $db, string $roomId): int {
    $stmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status IN ('approved','active')");
    $stmt->execute([$roomId]);
    return (int)$stmt->fetchColumn();
}

function periodInterval(string $periodicity): DateInterval {
    if ($periodicity === 'biweekly') return new DateInterval('P14D');
    if ($periodicity === 'monthly') return new DateInterval('P1M');
    return new DateInterval('P7D');
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

function applyStrike(PDO $db, int $userId, string $strikeType, ?string $roomId = null, ?int $cycleId = null): void {
    $db->prepare('INSERT INTO user_strikes (user_id, room_id, cycle_id, strike_type) VALUES (?, ?, ?, ?)')
       ->execute([(int)$userId, $roomId, $cycleId, $strikeType]);

    ensureTrustRow($db, $userId);

    $count = strikes6m($db, $userId);
    if ($count < 3) return;

    $until = (new DateTimeImmutable('now'))->modify('+30 days')->format('Y-m-d H:i:s');
    $db->prepare("INSERT INTO user_restrictions (user_id, restricted_until, reason, updated_at)
                  VALUES (?, ?, 'strikes_6m', NOW())
                  ON DUPLICATE KEY UPDATE restricted_until = GREATEST(restricted_until, VALUES(restricted_until)), reason='strikes_6m', updated_at=NOW()")
       ->execute([(int)$userId, $until]);

    // Trust level regression: at most once per 6-month window
    $t = $db->prepare('SELECT trust_level, last_level_change_at FROM user_trust WHERE user_id = ?');
    $t->execute([(int)$userId]);
    $row = $t->fetch();

    $lvl = (int)($row['trust_level'] ?? 1);
    $last = $row && $row['last_level_change_at'] ? strtotime((string)$row['last_level_change_at']) : null;
    $sixMonthsAgo = time() - (183 * 86400);

    if ($lvl > 1 && (!$last || $last < $sixMonthsAgo)) {
        $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
           ->execute([max(1, $lvl - 1), (int)$userId]);
    }
}

function ensureContributionRow(PDO $db, string $roomId, int $userId, int $cycleId, string $amount): void {
    $db->prepare("INSERT IGNORE INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status)
                  VALUES (?, ?, ?, ?, 'unpaid')")
       ->execute([$roomId, (int)$userId, (int)$cycleId, $amount]);
}

function updateTrustAfterCompletion(PDO $db, int $userId): void {
    ensureTrustRow($db, $userId);

    $db->prepare('UPDATE user_trust SET completed_reveals_count = (SELECT COUNT(*) FROM user_completed_reveals WHERE user_id = ?) WHERE user_id = ?')
       ->execute([(int)$userId, (int)$userId]);

    $curStmt = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
    $curStmt->execute([(int)$userId]);
    $cur = (int)$curStmt->fetchColumn();

    $counts = $db->prepare('SELECT
                                SUM(CASE WHEN duration_days >= 30 THEN 1 ELSE 0 END) AS month_ok,
                                SUM(CASE WHEN duration_days >= 21 THEN 1 ELSE 0 END) AS wk3_ok
                            FROM user_completed_reveals
                            WHERE user_id = ?');
    $counts->execute([(int)$userId]);
    $c = $counts->fetch();

    $monthOk = (int)($c['month_ok'] ?? 0);
    $wk3Ok = (int)($c['wk3_ok'] ?? 0);

    $target = 1;
    if ($monthOk >= 2) $target = 2;
    if ($wk3Ok >= 4) $target = 3;

    if ($target > $cur) {
        $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
           ->execute([$target, (int)$userId]);
    }
}

function initTypeBRotation(PDO $db, string $roomId): void {
    $cnt = $db->prepare('SELECT COUNT(*) FROM saving_room_rotation_queue WHERE room_id = ?');
    $cnt->execute([$roomId]);
    if ((int)$cnt->fetchColumn() > 0) return;

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status='active' ORDER BY joined_at ASC");
    $parts->execute([$roomId]);
    $rows = $parts->fetchAll();
    if (!$rows) return;

    $pos = 1;
    foreach ($rows as $r) {
        $db->prepare("INSERT IGNORE INTO saving_room_rotation_queue (room_id, user_id, position, status)
                      VALUES (?, ?, ?, 'queued')")
           ->execute([$roomId, (int)$r['user_id'], $pos]);
        $pos++;
    }

    $firstUser = (int)$rows[0]['user_id'];

    $db->prepare("INSERT IGNORE INTO saving_room_rotation_windows (room_id, user_id, rotation_index, status)
                  VALUES (?, ?, 1, 'pending_votes')")
       ->execute([$roomId, $firstUser]);

    $db->prepare("UPDATE saving_room_rotation_queue SET status='active_window' WHERE room_id = ? AND user_id = ?")
       ->execute([$roomId, $firstUser]);

    activityLog($db, $roomId, 'typeB_turn_advanced', ['rotation_index' => 1]);
}

function recordEscrowSettlement(PDO $db, string $roomId, int $removedUserId, string $policy, string $reason = 'two_missed_contributions', float $feeRate = 0.10): void {
    $sum = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM saving_room_contributions
                         WHERE room_id = ?
                           AND user_id = ?
                           AND status IN ('paid','paid_in_grace')");
    $sum->execute([$roomId, (int)$removedUserId]);
    $total = round((float)$sum->fetchColumn(), 2);

    if ($total <= 0) return;

    $fee = 0.00;
    $refund = 0.00;
    $redistribution = null;

    if ($policy === 'refund_minus_fee') {
        $fee = round($total * $feeRate, 2);
        $refund = round($total - $fee, 2);
    } else {
        $recipients = $db->prepare("SELECT p.user_id,
                                           COALESCE(SUM(c.amount), 0) AS paid_sum
                                    FROM saving_room_participants p
                                    LEFT JOIN saving_room_contributions c
                                      ON c.room_id = p.room_id
                                     AND c.user_id = p.user_id
                                     AND c.status IN ('paid','paid_in_grace')
                                    WHERE p.room_id = ?
                                      AND p.status = 'active'
                                      AND p.user_id <> ?
                                    GROUP BY p.user_id
                                    ORDER BY p.user_id ASC");
        $recipients->execute([$roomId, (int)$removedUserId]);
        $rows = $recipients->fetchAll();

        $n = count($rows);
        if ($n > 0) {
            $weightTotal = 0.0;
            foreach ($rows as $r) $weightTotal += (float)$r['paid_sum'];

            $dist = [];
            $running = 0.0;

            for ($i = 0; $i < $n; $i++) {
                $uid = (int)$rows[$i]['user_id'];

                if ($i === ($n - 1)) {
                    $amt = round($total - $running, 2);
                } else {
                    if ($weightTotal > 0) {
                        $amt = round($total * ((float)$rows[$i]['paid_sum'] / $weightTotal), 2);
                    } else {
                        $amt = round($total / $n, 2);
                    }
                    $running = round($running + $amt, 2);
                }

                if ($amt <= 0) continue;
                $dist[] = ['user_id' => $uid, 'amount' => number_format($amt, 2, '.', '')];
            }

            $redistribution = $dist;
        }
    }

    $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlements
                    (room_id, removed_user_id, policy, reason, fee_rate, total_contributed, platform_fee_amount, refund_amount, redistribution_json)
                  VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?)")
       ->execute([
           $roomId,
           (int)$removedUserId,
           $policy,
           $reason,
           number_format($feeRate, 4, '.', ''),
           number_format($total, 2, '.', ''),
           number_format($fee, 2, '.', ''),
           number_format($refund, 2, '.', ''),
           $redistribution ? json_encode($redistribution, JSON_UNESCAPED_UNICODE) : null,
       ]);
}

$db = db();

// ───────────────────────────────────────────────────────────
//  1) Lock lobby when start date arrives
// ───────────────────────────────────────────────────────────
$roomsToLock = $db->query("SELECT id FROM saving_rooms WHERE room_state='lobby' AND lobby_state='open' AND start_at <= NOW() LIMIT 500")->fetchAll();
foreach ($roomsToLock as $r) {
    $roomId = (string)$r['id'];
    $db->prepare("UPDATE saving_rooms SET lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);
    activityLog($db, $roomId, 'lobby_locked', ['reason' => 'start_date_reached']);
    logLine("Lobby locked: {$roomId}");
}

// ───────────────────────────────────────────────────────────
//  2) Start rooms
// ───────────────────────────────────────────────────────────
$roomsToStart = $db->query("SELECT id, participation_amount, saving_type FROM saving_rooms WHERE room_state='lobby' AND start_at <= NOW() LIMIT 500")->fetchAll();
foreach ($roomsToStart as $r) {
    $roomId = (string)$r['id'];

    $roomStmt = $db->prepare("SELECT id, start_at, periodicity, participation_amount, maker_user_id FROM saving_rooms WHERE id = ?");
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();

    $db->prepare("UPDATE saving_rooms SET room_state='active', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    // Promote approved participants to active
    $db->prepare("UPDATE saving_room_participants SET status='active' WHERE room_id = ? AND status='approved'")
       ->execute([$roomId]);

    // Create first contribution cycle due at the scheduled start date (cycle_index=1)
    // Grace window ends 48 hours after due.
    $db->prepare("INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status)
                  VALUES (?, 1, ?, DATE_ADD(?, INTERVAL 48 HOUR), 'open')")
       ->execute([$roomId, $room['start_at'], $room['start_at']]);

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
//  2b) Ensure future contribution cycles exist
// ───────────────────────────────────────────────────────────
$activeRooms = $db->query("SELECT id, periodicity FROM saving_rooms WHERE room_state='active' LIMIT 800")->fetchAll();
foreach ($activeRooms as $r) {
    $roomId = (string)$r['id'];
    $period = (string)$r['periodicity'];

    $last = $db->prepare("SELECT cycle_index, due_at FROM saving_room_contribution_cycles WHERE room_id = ? ORDER BY cycle_index DESC LIMIT 1");
    $last->execute([$roomId]);
    $lastRow = $last->fetch();
    if (!$lastRow) continue;

    $lastIdx = (int)$lastRow['cycle_index'];
    $lastDue = new DateTimeImmutable((string)$lastRow['due_at']);

    $due = $lastDue;
    for ($i = 1; $i <= 2; $i++) {
        $nextIdx = $lastIdx + $i;
        $due = $due->add(periodInterval($period));

        $db->prepare("INSERT IGNORE INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status)
                      VALUES (?, ?, ?, DATE_ADD(?, INTERVAL 48 HOUR), 'open')")
           ->execute([$roomId, $nextIdx, $due->format('Y-m-d H:i:s'), $due->format('Y-m-d H:i:s')]);
    }
}

// ───────────────────────────────────────────────────────────
//  2c) Contribution enforcement
// ───────────────────────────────────────────────────────────
$cycles = $db->query("SELECT c.id, c.room_id, c.cycle_index, c.due_at, c.grace_ends_at, c.status,
                             r.participation_amount
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

    $dueIn = $dueAt->getTimestamp() - time();

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status='active'");
    $parts->execute([$roomId]);
    $pRows = $parts->fetchAll();

    foreach ($pRows as $p) {
        $uid = (int)$p['user_id'];
        ensureContributionRow($db, $roomId, $uid, $cycleId, (string)$c['participation_amount']);

        if ($dueIn > 0 && $dueIn <= 24 * 3600) {
            $st = $db->prepare("SELECT status FROM saving_room_contributions WHERE cycle_id = ? AND user_id = ?");
            $st->execute([$cycleId, $uid]);
            $cur = (string)$st->fetchColumn();
            if (in_array($cur, ['paid','paid_in_grace'], true)) continue;

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

    if ($status === 'open' && time() >= $dueAt->getTimestamp()) {
        $db->prepare("UPDATE saving_room_contribution_cycles SET status='grace' WHERE id = ?")
           ->execute([$cycleId]);
        activityLog($db, $roomId, 'grace_window_started', ['cycle_id' => $cycleId, 'cycle_index' => (int)$c['cycle_index']]);
        $status = 'grace';
    }

    if (time() < $dueAt->getTimestamp()) continue;

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

    if (time() < $graceEnds->getTimestamp()) continue;

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

        $mc = $db->prepare("SELECT missed_contributions_count FROM saving_room_participants WHERE room_id = ? AND user_id = ?");
        $mc->execute([$roomId, $uid]);
        $missed = (int)$mc->fetchColumn();

        if ($missed >= 2) {
            $roomInfo = $db->prepare("SELECT escrow_policy, maker_user_id FROM saving_rooms WHERE id = ?");
            $roomInfo->execute([$roomId]);
            $ri = $roomInfo->fetch();
            $policy = $ri ? (string)$ri['escrow_policy'] : 'redistribute';
            $makerId = $ri ? (int)$ri['maker_user_id'] : 0;

            $db->prepare("UPDATE saving_room_participants SET status='removed', removed_at=NOW(), removal_reason='two_missed_contributions' WHERE room_id = ? AND user_id = ?")
               ->execute([$roomId, $uid]);

            recordEscrowSettlement($db, $roomId, $uid, $policy);

            activityLog($db, $roomId, 'participant_removed', ['reason' => 'two_missed_contributions']);
            activityLog($db, $roomId, 'escrow_settlement_recorded', ['policy' => $policy]);

            notifyOnce(
                $db,
                $uid,
                'removed_from_room',
                'critical',
                'You have been removed from a room',
                'You were removed after missing two contributions in this room. Your contributed funds are held in escrow and will be handled according to the room policy.',
                ['room_id' => $roomId, 'escrow_policy' => $policy],
                'room',
                $roomId
            );

            if ($makerId > 0) {
                notifyOnce(
                    $db,
                    $makerId,
                    'escrow_settlement_recorded',
                    'important',
                    'Escrow settlement recorded',
                    'A participant was removed after missing contributions. Their contributed funds have been recorded for escrow handling under the room policy.',
                    ['room_id' => $roomId, 'escrow_policy' => $policy],
                    'room',
                    $roomId
                );
            }
        }
    }
}

// ───────────────────────────────────────────────────────────
//  3) Underfilled room alerts at T-72h
// ───────────────────────────────────────────────────────────
$roomsForAlert = $db->query("SELECT id, maker_user_id, min_participants
                             FROM saving_rooms
                             WHERE room_state='lobby'
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

    activityLog($db, $roomId, 'underfilled_alerted', [
        'approved_count' => $cnt,
        'min_participants' => $min,
        'decision_deadline_at' => $deadline,
    ]);

    notifyOnce(
        $db,
        $makerId,
        'room_underfilled_alert',
        'important',
        'Room underfilled — action required',
        'Your saving room has not reached its minimum participant count. Choose to extend the start date, lower the minimum if permitted, or cancel. If you take no action within 24 hours, the room will auto-cancel.',
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
                       WHERE a.status='open'
                         AND a.decision_deadline_at <= NOW()
                         AND r.room_state='lobby'
                       LIMIT 500")->fetchAll();

foreach ($expired as $row) {
    $roomId = (string)$row['room_id'];
    $makerId = (int)$row['maker_user_id'];

    $db->beginTransaction();

    $db->prepare("UPDATE saving_rooms SET room_state='cancelled', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    $db->prepare("UPDATE saving_room_underfill_alerts
                  SET status='expired', resolved_at=NOW(), resolution_action='cancel', resolution_payload=JSON_OBJECT('auto', 1)
                  WHERE room_id = ? AND status='open'")
       ->execute([$roomId]);

    // Mark pending join requests / participants as exited pre-start.
    $db->prepare("UPDATE saving_room_join_requests SET status='cancelled', maker_decided_at=NOW() WHERE room_id = ? AND status='pending'")
       ->execute([$roomId]);

    $db->prepare("UPDATE saving_room_participants
                  SET status='exited_prestart', removed_at=NOW(), removal_reason='room_cancelled_underfilled'
                  WHERE room_id = ? AND status IN ('pending','approved')")
       ->execute([$roomId]);

    // Create settlement entries for any already-recorded contributions (fee=0 for cancellation).
    $paidUsers = $db->prepare("SELECT DISTINCT user_id FROM saving_room_contributions WHERE room_id = ? AND status IN ('paid','paid_in_grace')");
    $paidUsers->execute([$roomId]);
    foreach ($paidUsers->fetchAll() as $pu) {
        $uid = (int)$pu['user_id'];
        recordEscrowSettlement($db, $roomId, $uid, 'refund_minus_fee', 'room_cancelled_underfilled', 0.00);
    }

    activityLog($db, $roomId, 'room_auto_cancelled_underfilled', ['reason' => 'no_action_after_alert']);

    $db->commit();

    notifyOnce(
        $db,
        $makerId,
        'room_underfilled_auto_cancelled',
        'important',
        'Room cancelled (underfilled)',
        'No action was taken after the underfilled-room alert. The room has been cancelled.',
        ['room_id' => $roomId],
        'room',
        $roomId
    );

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'exited_prestart'");
    $parts->execute([$roomId]);
    foreach ($parts->fetchAll() as $p) {
        $uid = (int)$p['user_id'];
        notifyOnce(
            $db,
            $uid,
            'room_cancelled_underfilled',
            'important',
            'Room cancelled',
            'This saving room was cancelled before it started due to being underfilled.',
            ['room_id' => $roomId],
            'room',
            $roomId
        );
    }

    logLine("Auto-cancelled underfilled room: {$roomId}");
}

// ───────────────────────────────────────────────────────────
//  5) Type A unlock expiry warnings + close
// ───────────────────────────────────────────────────────────
$typeAWarn = $db->query("SELECT ue.room_id, ue.expires_at
                         FROM saving_room_unlock_events ue
                         JOIN saving_rooms r ON r.id = ue.room_id
                         WHERE r.saving_type = 'A'
                           AND r.room_state = 'active'
                           AND ue.status = 'revealed'
                           AND ue.expires_at > NOW()
                           AND ue.expires_at <= (NOW() + INTERVAL 12 HOUR)
                         LIMIT 500")->fetchAll();

foreach ($typeAWarn as $x) {
    $roomId = (string)$x['room_id'];

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $parts->execute([$roomId]);
    foreach ($parts->fetchAll() as $p) {
        $uid = (int)$p['user_id'];
        notifyOnce(
            $db,
            $uid,
            'typeA_unlock_expiring_12h',
            'critical',
            'Unlock code expires in 12 hours',
            'The unlock window for one of your Type A rooms expires in 12 hours. Coordinate withdrawal before it closes.',
            ['room_id' => $roomId, 'expires_at' => $x['expires_at']],
            'room',
            $roomId
        );
    }
}

$typeAExpired = $db->query("SELECT ue.room_id, ue.revealed_at, ue.expires_at
                            FROM saving_room_unlock_events ue
                            JOIN saving_rooms r ON r.id = ue.room_id
                            WHERE r.saving_type = 'A'
                              AND r.room_state = 'active'
                              AND ue.status = 'revealed'
                              AND ue.expires_at <= NOW()
                            LIMIT 200")->fetchAll();

foreach ($typeAExpired as $x) {
    $roomId = (string)$x['room_id'];

    $roomStmt = $db->prepare("SELECT id, start_at FROM saving_rooms WHERE id = ?");
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();
    if (!$room) continue;

    $unlockedAt = (string)($x['revealed_at'] ?? '');
    if ($unlockedAt === '') {
        $unlockedAt = date('Y-m-d H:i:s');
    }

    $startedAt = (string)$room['start_at'];
    $dur = 0;
    $stTs = strtotime($startedAt);
    $unTs = strtotime($unlockedAt);
    if ($stTs && $unTs && $unTs >= $stTs) {
        $dur = (int)floor(($unTs - $stTs) / 86400);
    }

    $db->beginTransaction();

    $db->prepare("UPDATE saving_room_unlock_events SET status='expired' WHERE room_id = ? AND status='revealed'")
       ->execute([$roomId]);

    $db->prepare("UPDATE saving_rooms SET room_state='closed', updated_at=NOW() WHERE id = ? AND room_state='active'")
       ->execute([$roomId]);

    $db->prepare("UPDATE saving_room_participants SET status='completed', completed_at=NOW() WHERE room_id = ? AND status='active'")
       ->execute([$roomId]);

    activityLog($db, $roomId, 'unlock_expired', ['expires_at' => $x['expires_at']]);
    activityLog($db, $roomId, 'room_closed', []);

    $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'completed'");
    $parts->execute([$roomId]);

    foreach ($parts->fetchAll() as $p) {
        $uid = (int)$p['user_id'];
        $db->prepare("INSERT IGNORE INTO user_completed_reveals (user_id, room_id, started_at, unlocked_at, duration_days, qualified_for_level)
                      VALUES (?, ?, ?, ?, ?, 1)")
           ->execute([$uid, $roomId, $startedAt, $unlockedAt, $dur]);
        updateTrustAfterCompletion($db, $uid);
    }

    $db->commit();

    logLine("Type A room closed after unlock expiry: {$roomId}");

    $acctStmt = $db->prepare("SELECT account_id FROM saving_room_accounts WHERE room_id = ? LIMIT 1");
    $acctStmt->execute([$roomId]);
    $accountId = $acctStmt->fetchColumn();

    if ($accountId) {
        $admins = $db->query("SELECT id FROM users WHERE is_admin = 1")->fetchAll();
        foreach ($admins as $a) {
            $aid = (int)$a['id'];
            notifyOnce(
                $db,
                $aid,
                'destination_account_rotation_required',
                'critical',
                'Destination account unlock code rotation required',
                'A Type A room unlock window has expired. Rotate the destination account unlock code now.',
                ['account_id' => (int)$accountId, 'room_id' => $roomId],
                'account',
                (string)$accountId
            );
        }
    }
}

// ───────────────────────────────────────────────────────────
//  6) Type B rotation windows (vote -> reveal, expiry -> advance)
// ───────────────────────────────────────────────────────────
$typeBRooms = $db->query("SELECT id FROM saving_rooms WHERE saving_type='B' AND room_state='active' LIMIT 400")->fetchAll();
foreach ($typeBRooms as $r) {
    initTypeBRotation($db, (string)$r['id']);
}

$pendingWins = $db->query("SELECT w.id, w.room_id, w.user_id, w.rotation_index, r.maker_user_id
                           FROM saving_room_rotation_windows w
                           JOIN saving_rooms r ON r.id = w.room_id
                           WHERE r.saving_type='B'
                             AND r.room_state='active'
                             AND w.status='pending_votes'
                           ORDER BY w.created_at ASC
                           LIMIT 400")->fetchAll();

foreach ($pendingWins as $w) {
    $roomId = (string)$w['room_id'];
    $rotationIndex = (int)$w['rotation_index'];
    $turnUserId = (int)$w['user_id'];
    $makerId = (int)$w['maker_user_id'];

    $eligibleStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
    $eligibleStmt->execute([$roomId]);
    $eligible = (int)$eligibleStmt->fetchColumn();

    $required = (int)ceil(max(0, $eligible - 1) * 0.5);

    $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                   WHERE room_id = ?
                                     AND scope = 'typeB_turn_unlock'
                                     AND target_rotation_index = ?
                                     AND vote = 'approve'
                                     AND user_id <> ?");
    $approvalsStmt->execute([$roomId, $rotationIndex, $makerId]);
    $approvals = (int)$approvalsStmt->fetchColumn();

    $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                   WHERE room_id = ?
                                     AND scope = 'typeB_turn_unlock'
                                     AND target_rotation_index = ?
                                     AND user_id = ?");
    $makerVoteStmt->execute([$roomId, $rotationIndex, $makerId]);
    $makerVote = (string)$makerVoteStmt->fetchColumn();

    if ($makerVote !== 'approve') continue;
    if ($required > 0 && $approvals < $required) continue;

    // Block rotation reveal if the turn user has past-due unpaid contributions in this room.
    $debt = $db->prepare("SELECT COUNT(*)
                          FROM saving_room_contributions c
                          JOIN saving_room_contribution_cycles cy ON cy.id = c.cycle_id
                          WHERE c.room_id = ?
                            AND c.user_id = ?
                            AND c.status = 'unpaid'
                            AND cy.due_at <= NOW()");
    $debt->execute([$roomId, $turnUserId]);
    if ((int)$debt->fetchColumn() > 0) {
        $db->prepare("UPDATE saving_room_rotation_windows SET status='blocked_debt' WHERE id = ? AND status='pending_votes'")
           ->execute([(int)$w['id']]);

        activityLog($db, $roomId, 'rotation_blocked_debt', ['rotation_index' => $rotationIndex]);

        notifyOnce(
            $db,
            $turnUserId,
            'typeB_turn_blocked_debt',
            'important',
            'Type B turn blocked (unpaid contribution)',
            'Your Type B turn cannot be revealed until you clear your past-due unpaid contribution(s) in this room.',
            ['room_id' => $roomId, 'rotation_index' => $rotationIndex],
            'room',
            $roomId . ':' . $rotationIndex
        );

        continue;
    }

    $expires = (new DateTimeImmutable('now'))->modify('+72 hours')->format('Y-m-d H:i:s');
    $disputeEnds = (new DateTimeImmutable('now'))->modify('+24 hours')->format('Y-m-d H:i:s');

    $db->prepare("UPDATE saving_room_rotation_windows
                  SET status='revealed', revealed_at=NOW(), expires_at=?, dispute_window_ends_at=?
                  WHERE id = ? AND status='pending_votes'")
       ->execute([$expires, $disputeEnds, (int)$w['id']]);

    activityLog($db, $roomId, 'typeB_turn_revealed', ['rotation_index' => $rotationIndex, 'expires_at' => $expires]);

    notifyOnce(
        $db,
        $turnUserId,
        'typeB_turn_opened',
        'critical',
        'Your Type B turn was approved',
        'Your turn unlock window is now open for 72 hours. You can reveal the unlock code in the room page.',
        ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'expires_at' => $expires],
        'room',
        $roomId . ':' . $rotationIndex
    );
}

$blockedDebtWins = $db->query("SELECT w.id, w.room_id, w.user_id, w.rotation_index
                              FROM saving_room_rotation_windows w
                              JOIN saving_rooms r ON r.id = w.room_id
                              WHERE r.saving_type='B'
                                AND r.room_state='active'
                                AND w.status='blocked_debt'
                              ORDER BY w.created_at ASC
                              LIMIT 400")->fetchAll();

foreach ($blockedDebtWins as $w) {
    $roomId = (string)$w['room_id'];
    $turnUserId = (int)$w['user_id'];
    $rotationIndex = (int)$w['rotation_index'];

    $debt = $db->prepare("SELECT COUNT(*)
                          FROM saving_room_contributions c
                          JOIN saving_room_contribution_cycles cy ON cy.id = c.cycle_id
                          WHERE c.room_id = ?
                            AND c.user_id = ?
                            AND c.status = 'unpaid'
                            AND cy.due_at <= NOW()");
    $debt->execute([$roomId, $turnUserId]);

    if ((int)$debt->fetchColumn() === 0) {
        $db->prepare("UPDATE saving_room_rotation_windows SET status='pending_votes' WHERE id = ? AND status='blocked_debt'")
           ->execute([(int)$w['id']]);

        activityLog($db, $roomId, 'rotation_unblocked_debt', ['rotation_index' => $rotationIndex]);
    }
}

$expiredWins = $db->query("SELECT w.id, w.room_id, w.user_id, w.rotation_index
                           FROM saving_room_rotation_windows w
                           JOIN saving_rooms r ON r.id = w.room_id
                           WHERE r.saving_type='B'
                             AND r.room_state='active'
                             AND w.status='revealed'
                             AND w.expires_at <= NOW()
                           ORDER BY w.expires_at ASC
                           LIMIT 200")->fetchAll();

foreach ($expiredWins as $w) {
    $roomId = (string)$w['room_id'];
    $rotationIndex = (int)$w['rotation_index'];

    $db->beginTransaction();

    $db->prepare("UPDATE saving_room_rotation_windows SET status='expired' WHERE id = ? AND status='revealed'")
       ->execute([(int)$w['id']]);

    $db->prepare("UPDATE saving_room_rotation_queue SET status='completed' WHERE room_id = ? AND user_id = ? AND status='active_window'")
       ->execute([$roomId, (int)$w['user_id']]);

    activityLog($db, $roomId, 'typeB_turn_expired', ['rotation_index' => $rotationIndex]);

    $nextIndex = $rotationIndex + 1;
    $guard = 0;
    $nextUserId = null;

    while ($guard < 80) {
        $guard++;

        $next = $db->prepare("SELECT user_id FROM saving_room_rotation_queue WHERE room_id = ? AND status='queued' ORDER BY position ASC LIMIT 1");
        $next->execute([$roomId]);
        $candidate = $next->fetchColumn();

        if (!$candidate) {
            $db->prepare("UPDATE saving_room_rotation_queue SET status='queued' WHERE room_id = ? AND status='completed'")
               ->execute([$roomId]);
            $next->execute([$roomId]);
            $candidate = $next->fetchColumn();
            if (!$candidate) break;
        }

        $candId = (int)$candidate;
        $st = $db->prepare("SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?");
        $st->execute([$roomId, $candId]);
        $pStatus = (string)$st->fetchColumn();

        if ($pStatus !== 'active') {
            $db->prepare("UPDATE saving_room_rotation_queue SET status='skipped_removed' WHERE room_id = ? AND user_id = ?")
               ->execute([$roomId, $candId]);
            continue;
        }

        $nextUserId = $candId;
        break;
    }

    if ($nextUserId !== null) {
        $db->prepare("INSERT IGNORE INTO saving_room_rotation_windows (room_id, user_id, rotation_index, status)
                      VALUES (?, ?, ?, 'pending_votes')")
           ->execute([$roomId, (int)$nextUserId, $nextIndex]);

        $db->prepare("UPDATE saving_room_rotation_queue SET status='active_window' WHERE room_id = ? AND user_id = ?")
           ->execute([$roomId, (int)$nextUserId]);

        activityLog($db, $roomId, 'typeB_turn_advanced', ['rotation_index' => $nextIndex]);
    }

    $db->commit();

    logLine("Type B turn expired/advanced: {$roomId} #{$rotationIndex}");
}

logLine('Done.');
