<?php
// ============================================================
//  Controle — Saving Rooms Schedule Audit (CLI)
//
//  Usage:
//    php scripts/rooms_audit_schedule.php
//
//  Prints any detected timeline anomalies that could cause
//  confusing UI or overlapping enforcement windows.
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script must be run from the command line.\n");
    exit(1);
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/helpers.php';

function db(): PDO {
    return getDB();
}

function hasTable(PDO $db, string $table): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1");
    $stmt->execute([$table]);
    return (bool)$stmt->fetchColumn();
}

function hasColumn(PDO $db, string $table, string $column): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
    $stmt->execute([$table, $column]);
    return (bool)$stmt->fetchColumn();
}

function dt(?string $s): ?DateTimeImmutable {
    $v = trim((string)$s);
    if ($v === '') return null;

    // Treat MySQL DATETIME (no timezone) as UTC.
    try {
        return new DateTimeImmutable($v, new DateTimeZone('UTC'));
    } catch (Throwable $e) {
        return null;
    }
}

function fmtDt(?DateTimeImmutable $d): string {
    if (!$d) return '—';
    return $d->format('Y-m-d H:i:s') . 'Z';
}

function periodInterval(string $periodicity): DateInterval {
    if ($periodicity === 'weekly') return new DateInterval('P7D');
    if ($periodicity === 'biweekly') return new DateInterval('P14D');
    if ($periodicity === 'monthly') return new DateInterval('P1M');
    return new DateInterval('P7D');
}

function roomSwapClose(array $room): ?DateTimeImmutable {
    foreach (['swap_window_closes_at','swap_window_ends_at','swap_window_end_at'] as $c) {
        if (!empty($room[$c])) {
            return dt((string)$room[$c]);
        }
    }
    return null;
}

$db = db();

if (!hasTable($db, 'saving_rooms')) {
    fwrite(STDERR, "saving_rooms table not found.\n");
    exit(1);
}

$swapCols = [];
foreach (['swap_window_opens_at','swap_window_closes_at','swap_window_starts_at','swap_window_ends_at','swap_window_start_at','swap_window_end_at'] as $c) {
    if (hasColumn($db, 'saving_rooms', $c)) $swapCols[] = $c;
}

$cols = array_merge(['id','saving_type','room_state','lobby_state','start_at','reveal_at','periodicity'], $swapCols);
$sel = implode(', ', array_map(fn($c) => 'r.' . $c, $cols));

$rooms = $db->query("SELECT {$sel} FROM saving_rooms r ORDER BY r.start_at ASC LIMIT 5000")->fetchAll();

$issues = 0;

foreach ($rooms as $r) {
    $roomId = (string)$r['id'];
    $type = (string)($r['saving_type'] ?? '');
    $state = (string)($r['room_state'] ?? '');

    $startAt = dt((string)($r['start_at'] ?? ''));
    $revealAt = dt((string)($r['reveal_at'] ?? ''));

    $swapClose = roomSwapClose($r);

    // 1) Type A: reveal should not be before start.
    if ($type === 'A' && $startAt && $revealAt && $revealAt < $startAt) {
        $issues++;
        fwrite(STDOUT, "[reveal_before_start] room={$roomId} start=" . fmtDt($startAt) . " reveal=" . fmtDt($revealAt) . "\n");
    }

    // 2) Swap window close should not be after the (configured) start date.
    // If it is, the UI may show a swap window that overlaps the start.
    if ($swapClose && $startAt && $swapClose > $startAt) {
        $issues++;
        fwrite(STDOUT, "[swap_closes_after_start] room={$roomId} start=" . fmtDt($startAt) . " swap_closes=" . fmtDt($swapClose) . " state={$state}\n");
    }

    // 3) Contribution cycles: grace must not overlap the next due.
    if (hasTable($db, 'saving_room_contribution_cycles')) {
        $cycles = $db->prepare("SELECT cycle_index, due_at, grace_ends_at FROM saving_room_contribution_cycles WHERE room_id = ? ORDER BY cycle_index ASC LIMIT 12");
        $cycles->execute([$roomId]);
        $rows = $cycles->fetchAll();

        for ($i = 0; $i < (count($rows) - 1); $i++) {
            $a = $rows[$i];
            $b = $rows[$i + 1];

            $aGrace = dt((string)($a['grace_ends_at'] ?? ''));
            $bDue = dt((string)($b['due_at'] ?? ''));

            if ($aGrace && $bDue && $aGrace > $bDue) {
                $issues++;
                fwrite(STDOUT, "[cycle_grace_overlaps_next_due] room={$roomId} cycle=" . (int)$a['cycle_index'] . " grace_ends=" . fmtDt($aGrace) . " next_due(cycle " . (int)$b['cycle_index'] . ")=" . fmtDt($bDue) . "\n");
                break;
            }
        }

        // Also flag if the first due is before the configured start.
        $due1 = null;
        foreach ($rows as $cy) {
            if ((int)$cy['cycle_index'] !== 1) continue;
            $due1 = dt((string)($cy['due_at'] ?? ''));
            if ($startAt && $due1 && $due1 < $startAt) {
                $issues++;
                fwrite(STDOUT, "[cycle1_due_before_start] room={$roomId} start=" . fmtDt($startAt) . " cycle1_due=" . fmtDt($due1) . "\n");
            }
            break;
        }

        // Type B: when a swap window exists, the first due should be swap_close + periodicity.
        if ($type === 'B' && $swapClose && $due1) {
            if ($due1 < $swapClose) {
                $issues++;
                fwrite(STDOUT, "[cycle1_due_before_swap_close] room={$roomId} swap_closes=" . fmtDt($swapClose) . " cycle1_due=" . fmtDt($due1) . "\n");
            } else {
                $period = (string)($r['periodicity'] ?? 'weekly');
                $expected = $swapClose->add(periodInterval($period));
                if ($due1 < $expected) {
                    $issues++;
                    fwrite(STDOUT, "[cycle1_due_before_swap_plus_period] room={$roomId} periodicity={$period} swap_closes=" . fmtDt($swapClose) . " expected_due=" . fmtDt($expected) . " cycle1_due=" . fmtDt($due1) . "\n");
                }
            }
        }
    }

    // 4) Type B rotation: there should not be multiple concurrent active windows.
    if ($type === 'B' && hasTable($db, 'saving_room_rotation_windows')) {
        $wSel = 'rotation_index, status';
        if (hasColumn($db, 'saving_room_rotation_windows', 'approve_opens_at')) $wSel .= ', approve_opens_at';
        if (hasColumn($db, 'saving_room_rotation_windows', 'approve_due_at')) $wSel .= ', approve_due_at';
        if (hasColumn($db, 'saving_room_rotation_windows', 'revealed_at')) $wSel .= ', revealed_at';
        if (hasColumn($db, 'saving_room_rotation_windows', 'expires_at')) $wSel .= ', expires_at';

        $stmt = $db->prepare("SELECT {$wSel} FROM saving_room_rotation_windows WHERE room_id = ? AND status IN ('pending_votes','revealed','blocked_dispute','blocked_debt') ORDER BY rotation_index DESC LIMIT 10");
        $stmt->execute([$roomId]);
        $wins = $stmt->fetchAll();

        if (count($wins) > 1) {
            $issues++;
            fwrite(STDOUT, "[multiple_active_rotation_windows] room={$roomId} count=" . count($wins) . "\n");
        }

        foreach ($wins as $w) {
            $o = isset($w['approve_opens_at']) ? dt((string)$w['approve_opens_at']) : null;
            $d = isset($w['approve_due_at']) ? dt((string)$w['approve_due_at']) : null;
            if ($o && $d && $d < $o) {
                $issues++;
                fwrite(STDOUT, "[approve_due_before_open] room={$roomId} turn=" . (int)$w['rotation_index'] . " opens=" . fmtDt($o) . " due=" . fmtDt($d) . "\n");
            }
        }
    }
}

if ($issues > 0) {
    fwrite(STDOUT, "\nFound {$issues} potential schedule issue(s).\n");
    exit(2);
}

fwrite(STDOUT, "No schedule overlaps detected in the audited set.\n");
exit(0);
