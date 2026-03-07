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

date_default_timezone_set('UTC');

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
$roomsToLock = $db->query("SELECT id FROM saving_rooms WHERE room_state = 'lobby' AND lobby_state = 'open' AND start_at <= UTC_TIMESTAMP() LIMIT 500")->fetchAll();
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
$roomsToStart = $db->query("SELECT id FROM saving_rooms WHERE room_state = 'lobby' AND start_at <= UTC_TIMESTAMP() LIMIT 500")->fetchAll();
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
    $s = $db->prepare("SELECT COUNT(*) FROM user_strikes WHERE user_id = ? AND created_at >= (UTC_TIMESTAMP() - INTERVAL 6 MONTH)");
    $s->execute([(int)$userId]);
    return (int)$s->fetchColumn();
}

function applyStrike(PDO $db, int $userId, string $strikeType, string $roomId = null, int $cycleId = null): void {
    $db->prepare('INSERT INTO user_strikes (user_id, room_id, cycle_id, strike_type) VALUES (?, ?, ?, ?)')
       ->execute([(int)$userId, $roomId, $cycleId, $strikeType]);

    ensureTrustRow($db, $userId);

    $t = $db->prepare('SELECT trust_level, last_level_change_at FROM user_trust WHERE user_id = ?');
    $t->execute([(int)$userId]);
    $row = $t->fetch();

    $lvl = (int)($row['trust_level'] ?? 1);
    if ($lvl < 1) $lvl = 1;

    $lastChangeTs = null;
    if (!empty($row['last_level_change_at'])) {
        $lastChangeTs = strtotime((string)$row['last_level_change_at']);
    }

    $count = strikes6m($db, $userId);
    if ($count >= 3) {
        // 30-day join cooldown
        $until = (new DateTimeImmutable('now'))->modify('+30 days')->format('Y-m-d H:i:s');
        $db->prepare("INSERT INTO user_restrictions (user_id, restricted_until, reason, updated_at)
                      VALUES (?, ?, 'strikes_6m', NOW())
                      ON DUPLICATE KEY UPDATE restricted_until = GREATEST(restricted_until, VALUES(restricted_until)), reason='strikes_6m', updated_at=NOW()")
           ->execute([(int)$userId, $until]);

        // Level regression: demote once per rolling 6-month window.
        $sixMonthsAgo = time() - (183 * 86400);
        if ($lvl > 1 && (!$lastChangeTs || $lastChangeTs < $sixMonthsAgo)) {
            $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
               ->execute([max(1, $lvl - 1), (int)$userId]);
        }
    }
}

function shuffleSecure(array &$arr): void {
    $n = count($arr);
    for ($i = $n - 1; $i > 0; $i--) {
        $j = random_int(0, $i);
        $tmp = $arr[$i];
        $arr[$i] = $arr[$j];
        $arr[$j] = $tmp;
    }
}

function updateTrustAfterCompletion(PDO $db, int $userId): void {
    ensureTrustRow($db, $userId);

    $cnt = $db->prepare('SELECT COUNT(*) FROM user_completed_reveals WHERE user_id = ?');
    $cnt->execute([(int)$userId]);
    $completed = (int)$cnt->fetchColumn();

    $db->prepare('UPDATE user_trust SET completed_reveals_count = ? WHERE user_id = ?')
       ->execute([$completed, (int)$userId]);

    $countsStmt = $db->prepare('SELECT
                                    SUM(CASE WHEN duration_days >= 30 THEN 1 ELSE 0 END) AS month_ok,
                                    SUM(CASE WHEN duration_days >= 21 THEN 1 ELSE 0 END) AS wk3_ok
                                FROM user_completed_reveals
                                WHERE user_id = ?');
    $countsStmt->execute([(int)$userId]);
    $counts = $countsStmt->fetch();

    $monthOk = (int)($counts['month_ok'] ?? 0);
    $wk3Ok = (int)($counts['wk3_ok'] ?? 0);

    $t = $db->prepare('SELECT trust_level FROM user_trust WHERE user_id = ?');
    $t->execute([(int)$userId]);
    $lvl = (int)$t->fetchColumn();
    if ($lvl < 1) $lvl = 1;

    $newLvl = $lvl;
    if ($newLvl < 2 && $monthOk >= 2) {
        $newLvl = 2;
    }
    if ($newLvl < 3 && $newLvl >= 2 && $wk3Ok >= 4) {
        $newLvl = 3;
    }

    if ($newLvl !== $lvl) {
        $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
           ->execute([$newLvl, (int)$userId]);
    }
}

function ensureContributionRow(PDO $db, string $roomId, int $userId, int $cycleId, string $amount): void {
    $db->prepare("INSERT IGNORE INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status)
                  VALUES (?, ?, ?, ?, 'unpaid')")
       ->execute([$roomId, (int)$userId, (int)$cycleId, $amount]);
}

function recordEscrowSettlement(PDO $db, string $roomId, int $removedUserId, string $policy, ?int $triggerCycleId = null): void {
    $sum = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM saving_room_contributions
                         WHERE room_id = ?
                           AND user_id = ?
                           AND status IN ('paid','paid_in_grace')");
    $sum->execute([$roomId, (int)$removedUserId]);
    $total = (float)$sum->fetchColumn();

    if ($total <= 0) return;

    $totalRounded = round($total, 2);

    $fee = 0.00;
    $settled = $totalRounded;

    if ($policy === 'refund_minus_fee') {
        $fee = round($totalRounded * 0.10, 2);
        $settled = round($totalRounded - $fee, 2);
    }

    $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlements
                    (room_id, removed_user_id, policy, total_contributed, platform_fee_amount, settled_amount, trigger_cycle_id)
                  VALUES (?, ?, ?, ?, ?, ?, ?)")
       ->execute([$roomId, (int)$removedUserId, $policy, $totalRounded, $fee, $settled, $triggerCycleId]);

    if ($db->lastInsertId() === '0') return;

    $settlementId = (int)$db->lastInsertId();

    if ($policy === 'refund_minus_fee') {
        $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlement_allocations
                        (settlement_id, beneficiary_kind, beneficiary_user_id, amount)
                      VALUES (?, 'user', ?, ?)")
           ->execute([$settlementId, (int)$removedUserId, $settled]);

        if ($fee > 0) {
            $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlement_allocations
                            (settlement_id, beneficiary_kind, beneficiary_user_id, amount)
                          VALUES (?, 'platform', NULL, ?)")
               ->execute([$settlementId, $fee]);
        }

        return;
    }

    // redistribute
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
    if ($n <= 0) return;

    $weightTotal = 0.0;
    foreach ($rows as $r) $weightTotal += (float)$r['paid_sum'];

    $allocs = [];
    $running = 0.00;

    for ($i = 0; $i < $n; $i++) {
        $uid = (int)$rows[$i]['user_id'];
        if ($i === ($n - 1)) {
            $amt = round($totalRounded - $running, 2);
        } else {
            if ($weightTotal > 0) {
                $amt = round($totalRounded * ((float)$rows[$i]['paid_sum'] / $weightTotal), 2);
            } else {
                $amt = round($totalRounded / $n, 2);
            }
            $running = round($running + $amt, 2);
        }
        if ($amt <= 0) continue;
        $allocs[] = [$uid, $amt];
    }

    foreach ($allocs as [$uid, $amt]) {
        $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlement_allocations
                        (settlement_id, beneficiary_kind, beneficiary_user_id, amount)
                      VALUES (?, 'user', ?, ?)")
           ->execute([$settlementId, (int)$uid, $amt]);
    }
}

foreach ($roomsToStart as $r) {
    $roomId = (string)$r['id'];

    $roomStmt = $db->prepare("SELECT id, periodicity, participation_amount, maker_user_id, saving_type FROM saving_rooms WHERE id = ?");
    $roomStmt->execute([$roomId]);
    $room = $roomStmt->fetch();

    $db->prepare("UPDATE saving_rooms SET room_state='active', lobby_state='locked', updated_at=NOW() WHERE id = ? AND room_state='lobby'")
       ->execute([$roomId]);

    // Promote approved participants to active
    $db->prepare("UPDATE saving_room_participants SET status='active' WHERE room_id = ? AND status='approved'")
       ->execute([$roomId]);

    // Create unlock event scaffolding
    if (!empty($room['saving_type']) && $room['saving_type'] === 'A') {
        $db->prepare("INSERT IGNORE INTO saving_room_unlock_events (room_id, status, created_at) VALUES (?, 'pending', NOW())")
           ->execute([$roomId]);
    }

    // Create Type B rotation order + first window
    if (!empty($room['saving_type']) && $room['saving_type'] === 'B') {
        $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active' ORDER BY joined_at ASC");
        $parts->execute([$roomId]);
        $ids = array_map(fn($x) => (int)$x['user_id'], $parts->fetchAll());

        if (count($ids) >= 2) {
            shuffleSecure($ids);

            $pos = 1;
            foreach ($ids as $uid) {
                $st = ($pos === 1) ? 'active_window' : 'queued';
                $db->prepare("INSERT IGNORE INTO saving_room_rotation_queue (room_id, user_id, position, status) VALUES (?, ?, ?, ?)")
                   ->execute([$roomId, $uid, $pos, $st]);
                $pos++;
            }

            $firstUserId = (int)$ids[0];
            $db->prepare("INSERT IGNORE INTO saving_room_rotation_windows (room_id, user_id, rotation_index, status) VALUES (?, ?, 1, 'pending_votes')")
               ->execute([$roomId, $firstUserId]);

            activityLog($db, $roomId, 'rotation_queue_created', ['rotation_index' => 1]);
        }
    }

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
                             r.privacy_mode, r.participation_amount, r.escrow_policy, r.maker_user_id
                      FROM saving_room_contribution_cycles c
                      JOIN saving_rooms r ON r.id = c.room_id
                      WHERE r.room_state='active'
                        AND c.status IN ('open','grace')
                        AND c.due_at <= (UTC_TIMESTAMP() + INTERVAL 24 HOUR)
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
                    // Fetch room escrow policy + maker
                    $roomInfo = $db->prepare("SELECT escrow_policy, maker_user_id FROM saving_rooms WHERE id = ?");
                    $roomInfo->execute([$roomId]);
                    $ri = $roomInfo->fetch();
                    $policy = $ri ? (string)$ri['escrow_policy'] : 'redistribute';
                    $makerId = $ri ? (int)$ri['maker_user_id'] : 0;

                    $db->prepare("UPDATE saving_room_participants SET status='removed', removed_at=NOW(), removal_reason='two_missed_contributions' WHERE room_id = ? AND user_id = ?")
                       ->execute([$roomId, $uid]);

                    // Record escrow settlement ledger (refund_minus_fee or redistribute)
                    recordEscrowSettlement($db, $roomId, $uid, $policy, $cycleId);

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
                } else {
                        // Proportional redistribution across remaining active participants,
                        // weighted by each participant's total paid contributions.
                        $pStmt = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
                        $pStmt->execute([$roomId]);
                        $remaining = $pStmt->fetchAll();

                        $weights = [];
                        $weightSum = 0.0;
                        foreach ($remaining as $rp) {
                            $rid = (int)$rp['user_id'];
                            $wStmt = $db->prepare("SELECT COALESCE(SUM(amount), 0) FROM saving_room_contributions
                                                   WHERE room_id = ? AND user_id = ? AND status IN ('paid','paid_in_grace')");
                            $wStmt->execute([$roomId, $rid]);
                            $w = (float)$wStmt->fetchColumn();
                            $weights[$rid] = $w;
                            $weightSum += $w;
                        }

                        $dist = [];
                        if (count($remaining) > 0 && $total > 0) {
                            if ($weightSum <= 0) {
                                $each = round($total / count($remaining), 2);
                                $acc = 0.0;
                                for ($i = 0; $i < count($remaining); $i++) {
                                    $rid = (int)$remaining[$i]['user_id'];
                                    $amt = ($i === (count($remaining) - 1)) ? round($total - $acc, 2) : $each;
                                    $acc += $amt;
                                    $dist[] = ['user_id' => $rid, 'amount' => $amt];
                                }
                            } else {
                                $acc = 0.0;
                                $keys = array_keys($weights);
                                for ($i = 0; $i < count($keys); $i++) {
                                    $rid = (int)$keys[$i];
                                    $raw = ($weights[$rid] / $weightSum) * $total;
                                    $amt = round($raw, 2);
                                    if ($i === (count($keys) - 1)) {
                                        $amt = round($total - $acc, 2);
                                    }
                                    $acc += $amt;
                                    $dist[] = ['user_id' => $rid, 'amount' => $amt];
                                }
                            }
                        }

                        $redistribution = $dist;
                    }

                    $db->prepare("INSERT IGNORE INTO saving_room_escrow_settlements
                                    (room_id, removed_user_id, policy, reason, fee_rate, total_contributed, platform_fee_amount, refund_amount, redistribution_json)
                                  VALUES
                                    (?, ?, ?, ?, ?, ?, ?, ?, ?)")
                       ->execute([
                           $roomId,
                           $uid,
                           $policy,
                           'two_missed_contributions',
                           number_format(($policy === 'refund_minus_fee') ? 0.10 : 0.0000, 4, '.', ''),
                           number_format($total, 2, '.', ''),
                           number_format($fee, 2, '.', ''),
                           number_format($refund, 2, '.', ''),
                           $redistribution ? json_encode($redistribution, JSON_UNESCAPED_UNICODE) : null,
                       ]);

                    $payload = ['policy' => $policy];
                    if (empty($c['privacy_mode'])) {
                        $payload['total_contributed'] = number_format($total, 2, '.', '');
                        if ($policy === 'refund_minus_fee') {
                            $payload['platform_fee_amount'] = number_format($fee, 2, '.', '');
                            $payload['refund_amount'] = number_format($refund, 2, '.', '');
                        }
                    }

                    activityLog($db, $roomId, 'escrow_settlement_recorded', $payload);

                    notifyOnce(
                        $db,
                        (int)$c['maker_user_id'],
                        'escrow_settlement_recorded',
                        'important',
                        'Escrow settlement recorded',
                        'A participant was removed for missed contributions. Their contributed funds have been handled according to the room escrow policy.',
                        ['room_id' => $roomId, 'policy' => $policy],
                        'room',
                        $roomId
                    );
                }
            }
        }
    }
}

// ───────────────────────────────────────────────────────────
//  2d) Type A unlock expiry warnings + close
// ───────────────────────────────────────────────────────────
$typeAWarn = $db->query("SELECT ue.room_id, ue.expires_at
                         FROM saving_room_unlock_events ue
                         JOIN saving_rooms r ON r.id = ue.room_id
                         WHERE r.saving_type = 'A'
                           AND r.room_state = 'active'
                           AND ue.status = 'revealed'
                           AND ue.expires_at > UTC_TIMESTAMP()
                           AND ue.expires_at <= (UTC_TIMESTAMP() + INTERVAL 12 HOUR)
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
                              AND ue.expires_at <= UTC_TIMESTAMP()
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

    // Notify admins to rotate unlock code for the destination account
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
//  2e) Type B rotation windows
// ───────────────────────────────────────────────────────────
$typeBWindows = $db->query("SELECT w.id, w.room_id, w.user_id, w.rotation_index, w.status, w.revealed_at, w.expires_at,
                                   r.maker_user_id, r.privacy_mode
                            FROM saving_room_rotation_windows w
                            JOIN saving_rooms r ON r.id = w.room_id
                            WHERE r.saving_type = 'B'
                              AND r.room_state = 'active'
                              AND w.status IN ('pending_votes','revealed','blocked_dispute')
                            ORDER BY w.created_at ASC
                            LIMIT 500")->fetchAll();

foreach ($typeBWindows as $w) {
    $winId = (int)$w['id'];
    $roomId = (string)$w['room_id'];
    $turnUserId = (int)$w['user_id'];
    $rotationIndex = (int)$w['rotation_index'];
    $st = (string)$w['status'];

    if (in_array($st, ['blocked_dispute','blocked_debt'], true)) {
        continue;
    }

    $disp = $db->prepare("SELECT status FROM saving_room_disputes
                          WHERE room_id = ? AND rotation_index = ?
                            AND status IN ('open','threshold_met','escalated_admin')
                          LIMIT 1");
    $disp->execute([$roomId, $rotationIndex]);
    $dispStatus = $disp->fetchColumn();

    if ($dispStatus) {
        $db->prepare("UPDATE saving_room_rotation_windows SET status='blocked_dispute' WHERE id = ?")
           ->execute([$winId]);
        activityLog($db, $roomId, 'rotation_blocked_dispute', ['rotation_index' => $rotationIndex]);
        continue;
    }

    if ($st === 'pending_votes') {
        $eligibleStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
        $eligibleStmt->execute([$roomId]);
        $eligible = (int)$eligibleStmt->fetchColumn();
        if ($eligible < 1) continue;

        $need = (int)ceil(max(0, $eligible - 1) * 0.5);
        if ($need < 0) $need = 0;

        $approvalsStmt = $db->prepare("SELECT COUNT(*) FROM saving_room_unlock_votes
                                       WHERE room_id = ?
                                         AND scope = 'typeB_turn_unlock'
                                         AND target_rotation_index = ?
                                         AND vote = 'approve'
                                         AND user_id <> ?");
        $approvalsStmt->execute([$roomId, $rotationIndex, (int)$w['maker_user_id']]);
        $approvals = (int)$approvalsStmt->fetchColumn();

        $makerVoteStmt = $db->prepare("SELECT vote FROM saving_room_unlock_votes
                                       WHERE room_id = ?
                                         AND user_id = ?
                                         AND scope = 'typeB_turn_unlock'
                                         AND target_rotation_index = ?");
        $makerVoteStmt->execute([$roomId, (int)$w['maker_user_id'], $rotationIndex]);
        $makerVote = (string)$makerVoteStmt->fetchColumn();

        if ($makerVote === 'approve' && $approvals >= $need) {
            $expires = (new DateTimeImmutable('now'))->modify('+72 hours')->format('Y-m-d H:i:s');

            $db->prepare("UPDATE saving_room_rotation_windows
                          SET status='revealed', revealed_at=NOW(), expires_at=?, dispute_window_ends_at=?
                          WHERE id = ? AND status='pending_votes'")
               ->execute([$expires, $expires, $winId]);

            activityLog($db, $roomId, 'typeB_turn_revealed', ['rotation_index' => $rotationIndex, 'expires_at' => $expires]);

            notifyOnce(
                $db,
                $turnUserId,
                'typeB_turn_revealed',
                'critical',
                'Your turn unlock window is open',
                'The destination account unlock code is available to you for 72 hours. Keep it secure and do not share it.',
                ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'expires_at' => $expires],
                'rotation',
                $roomId . ':' . $rotationIndex
            );

            $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'active'");
            $parts->execute([$roomId]);
            foreach ($parts->fetchAll() as $p) {
                $uid = (int)$p['user_id'];
                if ($uid === $turnUserId) continue;
                notifyOnce(
                    $db,
                    $uid,
                    'typeB_turn_opened',
                    'informational',
                    'Rotation unlock window opened',
                    'A participant rotation window has opened in one of your Type B rooms.',
                    ['room_id' => $roomId, 'rotation_index' => $rotationIndex, 'expires_at' => $expires],
                    'rotation',
                    $roomId . ':' . $rotationIndex
                );
            }
        }
    }

    if ($st === 'revealed') {
        if (empty($w['expires_at'])) continue;
        $expTs = strtotime((string)$w['expires_at']);
        if ($expTs && time() >= $expTs) {
            $db->beginTransaction();

            $db->prepare("UPDATE saving_room_rotation_windows SET status='expired' WHERE id = ? AND status='revealed'")
               ->execute([$winId]);

            activityLog($db, $roomId, 'typeB_turn_expired', ['rotation_index' => $rotationIndex]);

            $db->prepare("UPDATE saving_room_rotation_queue SET status='completed' WHERE room_id = ? AND user_id = ?")
               ->execute([$roomId, $turnUserId]);

            $next = $db->prepare("SELECT user_id, position FROM saving_room_rotation_queue
                                  WHERE room_id = ? AND status = 'queued'
                                  ORDER BY position ASC
                                  LIMIT 1");
            $next->execute([$roomId]);
            $nextRow = $next->fetch();

            if ($nextRow) {
                $nextUserId = (int)$nextRow['user_id'];
                $nextIndex = $rotationIndex + 1;

                $db->prepare("UPDATE saving_room_rotation_queue SET status='active_window' WHERE room_id = ? AND user_id = ?")
                   ->execute([$roomId, $nextUserId]);

                $db->prepare("INSERT IGNORE INTO saving_room_rotation_windows (room_id, user_id, rotation_index, status)
                              VALUES (?, ?, ?, 'pending_votes')")
                   ->execute([$roomId, $nextUserId, $nextIndex]);

                activityLog($db, $roomId, 'typeB_turn_advanced', ['rotation_index' => $nextIndex]);

                $db->commit();

            } else {
                $roomStmt = $db->prepare("SELECT id, start_at FROM saving_rooms WHERE id = ?");
                $roomStmt->execute([$roomId]);
                $room = $roomStmt->fetch();

                $unlockedAt = date('Y-m-d H:i:s');
                $startedAt = $room ? (string)$room['start_at'] : $unlockedAt;

                $dur = 0;
                $stTs = strtotime($startedAt);
                $unTs = strtotime($unlockedAt);
                if ($stTs && $unTs && $unTs >= $stTs) {
                    $dur = (int)floor(($unTs - $stTs) / 86400);
                }

                $db->prepare("UPDATE saving_rooms SET room_state='closed', updated_at=NOW() WHERE id = ? AND room_state='active'")
                   ->execute([$roomId]);

                $db->prepare("UPDATE saving_room_participants SET status='completed', completed_at=NOW() WHERE room_id = ? AND status='active'")
                   ->execute([$roomId]);

                activityLog($db, $roomId, 'room_closed', ['reason' => 'rotation_complete']);

                $parts = $db->prepare("SELECT user_id FROM saving_room_participants WHERE room_id = ? AND status = 'completed'");
                $parts->execute([$roomId]);

                foreach ($parts->fetchAll() as $p) {
                    $uid = (int)$p['user_id'];
                    $qualified = ($dur >= 21) ? 1 : 0;
                    $db->prepare("INSERT IGNORE INTO user_completed_reveals (user_id, room_id, started_at, unlocked_at, duration_days, qualified_for_level)
                                  VALUES (?, ?, ?, ?, ?, ?)")
                       ->execute([$uid, $roomId, $startedAt, $unlockedAt, $dur, $qualified]);
                    updateTrustAfterCompletion($db, $uid);
                }

                $db->commit();

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
                            'A Type B rotation has completed. Rotate the destination account unlock code now.',
                            ['account_id' => (int)$accountId, 'room_id' => $roomId],
                            'account',
                            (string)$accountId
                        );
                    }
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
                               AND start_at > UTC_TIMESTAMP()
                               AND start_at <= (UTC_TIMESTAMP() + INTERVAL 72 HOUR)
                               AND start_at > (UTC_TIMESTAMP() + INTERVAL 48 HOUR)
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
                         AND a.decision_deadline_at <= UTC_TIMESTAMP()
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
