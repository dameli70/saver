<?php
// ============================================================
//  Controle — Time Locks Worker (cron)
//
//  Run every 5–10 minutes:
//    php scripts/locks_worker.php
//
//  Responsibilities:
//   - in-app notifications for lock reminders (T-24h, T-1h, ready)
//   - optional email reminders (Account toggle)
//
//  Notes:
//   - Server enforces reveal_date in UTC.
//   - Uses notification_events to dedupe.
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This worker must be run from the command line.\n");
    exit(1);
}

$lockPath = __DIR__ . '/locks_worker.lock';
$lockFp = @fopen($lockPath, 'c');
if (!$lockFp) {
    fwrite(STDERR, "Could not open lock file: {$lockPath}\n");
    exit(1);
}
if (!flock($lockFp, LOCK_EX | LOCK_NB)) {
    fwrite(STDOUT, "[" . date('c') . "] Another locks_worker is running; exiting.\n");
    exit(0);
}
register_shutdown_function(function() use ($lockFp) {
    @flock($lockFp, LOCK_UN);
    @fclose($lockFp);
});

require_once __DIR__ . '/../includes/helpers.php';

function logLine(string $s): void {
    fwrite(STDOUT, '[' . date('c') . '] ' . $s . "\n");
}

function notifyOnce(PDO $db, int $userId, string $eventKey, string $tier, string $title, string $body, array $data = [], ?string $refType = null, ?string $refId = null, string $channelMask = 'inapp'): ?int {
    $db->prepare('INSERT IGNORE INTO notification_events (user_id, event_key, ref_type, ref_id) VALUES (?, ?, ?, ?)')
       ->execute([$userId, $eventKey, $refType, $refId]);

    if ($db->lastInsertId() === '0') return null;

    $db->prepare('INSERT INTO notifications (user_id, tier, channel_mask, title, body, data_json) VALUES (?, ?, ?, ?, ?, ?)')
       ->execute([$userId, $tier, $channelMask, $title, $body, $data ? json_encode($data, JSON_UNESCAPED_UNICODE) : null]);

    return (int)$db->lastInsertId();
}

function sendEmailForNotification(PDO $db, int $notificationId, string $to, string $subject, string $body): void {
    sendEmail($to, $subject, $body);
    $db->prepare('UPDATE notifications SET sent_email_at = NOW() WHERE id = ?')->execute([(int)$notificationId]);
}

$db = getDB();

// Cache email prefs per user to reduce DB chatter.
$emailPrefCache = [];

function wantsEmail(int $userId, array &$cache): bool {
    if (array_key_exists($userId, $cache)) return (bool)$cache[$userId];
    $cache[$userId] = userWantsEmailTimeLockReminders($userId) ? 1 : 0;
    return (bool)$cache[$userId];
}

$base = getAppBaseUrl();
$codesUrl = $base . '/my_codes.php';

// ───────────────────────────────────────────────────────────
//  T-24h reminders
// ───────────────────────────────────────────────────────────
$rows = $db->query("SELECT l.id, l.user_id, l.label, l.reveal_date, u.email
                   FROM locks l
                   JOIN users u ON u.id = l.user_id
                   WHERE l.is_active = 1
                     AND l.confirmation_status = 'confirmed'
                     AND u.email_verified_at IS NOT NULL
                     AND l.reveal_date > UTC_TIMESTAMP()
                     AND l.reveal_date <= (UTC_TIMESTAMP() + INTERVAL 24 HOUR)")
           ->fetchAll();

foreach ($rows as $r) {
    $lockId = (string)$r['id'];
    $userId = (int)$r['user_id'];
    $label = normalizeDisplayText($r['label'] ?? null);
    $revealAt = (string)$r['reveal_date'];

    $title = 'Time lock unlocks within 24h';
    $body  = ($label ? ('"' . $label . '" ') : 'A time lock ') . 'becomes eligible to reveal at ' . $revealAt . ' UTC.';

    $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

    $nid = notifyOnce($db, $userId, 'lock_reveal_24h', 'important', $title, $body, ['lock_id' => $lockId], 'lock', $lockId, $mask);
    if (!$nid) continue;

    if (wantsEmail($userId, $emailPrefCache)) {
        $subj = APP_NAME . ' — ' . $title;
        $msg = "Your time lock is almost ready.\n\n";
        if ($label) $msg .= "Label: {$label}\n";
        $msg .= "Unlocks at (UTC): {$revealAt}\n\n";
        $msg .= "Open: {$codesUrl}#lock-{$lockId}\n";
        sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
    }
}

// ───────────────────────────────────────────────────────────
//  T-1h reminders
// ───────────────────────────────────────────────────────────
$rows = $db->query("SELECT l.id, l.user_id, l.label, l.reveal_date, u.email
                   FROM locks l
                   JOIN users u ON u.id = l.user_id
                   WHERE l.is_active = 1
                     AND l.confirmation_status = 'confirmed'
                     AND u.email_verified_at IS NOT NULL
                     AND l.reveal_date > UTC_TIMESTAMP()
                     AND l.reveal_date <= (UTC_TIMESTAMP() + INTERVAL 1 HOUR)")
           ->fetchAll();

foreach ($rows as $r) {
    $lockId = (string)$r['id'];
    $userId = (int)$r['user_id'];
    $label = normalizeDisplayText($r['label'] ?? null);
    $revealAt = (string)$r['reveal_date'];

    $title = 'Time lock unlocks within 1h';
    $body  = ($label ? ('"' . $label . '" ') : 'A time lock ') . 'becomes eligible to reveal at ' . $revealAt . ' UTC.';

    $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

    $nid = notifyOnce($db, $userId, 'lock_reveal_1h', 'important', $title, $body, ['lock_id' => $lockId], 'lock', $lockId, $mask);
    if (!$nid) continue;

    if (wantsEmail($userId, $emailPrefCache)) {
        $subj = APP_NAME . ' — ' . $title;
        $msg = "Your time lock is almost ready.\n\n";
        if ($label) $msg .= "Label: {$label}\n";
        $msg .= "Unlocks at (UTC): {$revealAt}\n\n";
        $msg .= "Open: {$codesUrl}#lock-{$lockId}\n";
        sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
    }
}

// ───────────────────────────────────────────────────────────
//  Ready notifications (first time it becomes eligible)
// ───────────────────────────────────────────────────────────
$rows = $db->query("SELECT l.id, l.user_id, l.label, l.reveal_date, u.email
                   FROM locks l
                   JOIN users u ON u.id = l.user_id
                   WHERE l.is_active = 1
                     AND l.confirmation_status = 'confirmed'
                     AND u.email_verified_at IS NOT NULL
                     AND l.revealed_at IS NULL
                     AND l.reveal_date <= UTC_TIMESTAMP()
                     AND l.reveal_date >= (UTC_TIMESTAMP() - INTERVAL 48 HOUR)")
           ->fetchAll();

foreach ($rows as $r) {
    $lockId = (string)$r['id'];
    $userId = (int)$r['user_id'];
    $label = normalizeDisplayText($r['label'] ?? null);
    $revealAt = (string)$r['reveal_date'];

    $title = 'Time lock ready';
    $body  = ($label ? ('"' . $label . '" ') : 'A time lock ') . 'is now eligible to reveal.';

    $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

    $nid = notifyOnce($db, $userId, 'lock_ready', 'important', $title, $body, ['lock_id' => $lockId], 'lock', $lockId, $mask);
    if (!$nid) continue;

    if (wantsEmail($userId, $emailPrefCache)) {
        $subj = APP_NAME . ' — ' . $title;
        $msg = "Your time lock is ready to reveal.\n\n";
        if ($label) $msg .= "Label: {$label}\n";
        $msg .= "Unlock time (UTC): {$revealAt}\n\n";
        $msg .= "Open: {$codesUrl}#lock-{$lockId}\n";
        sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
    }
}

// ───────────────────────────────────────────────────────────
//  Wallet locks (carrier PIN flows)
// ───────────────────────────────────────────────────────────
$hasWallet = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' LIMIT 1")->fetchColumn();
$hasWalletSetup = $hasWallet && (bool)$db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'wallet_locks' AND column_name = 'setup_status' LIMIT 1")->fetchColumn();

if ($hasWallet && $hasWalletSetup) {
    // T-24h
    $rows = $db->query("SELECT w.id, w.user_id, w.label, w.unlock_at, u.email
                       FROM wallet_locks w
                       JOIN users u ON u.id = w.user_id
                       WHERE w.is_active = 1
                         AND w.setup_status = 'active'
                         AND u.email_verified_at IS NOT NULL
                         AND w.unlock_at > UTC_TIMESTAMP()
                         AND w.unlock_at <= (UTC_TIMESTAMP() + INTERVAL 24 HOUR)")
               ->fetchAll();

    foreach ($rows as $r) {
        $wid = (string)$r['id'];
        $userId = (int)$r['user_id'];
        $label = normalizeDisplayText($r['label'] ?? null);
        $revealAt = (string)$r['unlock_at'];

        $title = 'Time lock unlocks within 24h';
        $body  = ($label ? ('"' . $label . '" ') : 'A wallet time lock ') . 'becomes eligible to reveal at ' . $revealAt . ' UTC.';

        $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

        $nid = notifyOnce($db, $userId, 'wallet_lock_reveal_24h', 'important', $title, $body, ['wallet_lock_id' => $wid], 'wallet_lock', $wid, $mask);
        if (!$nid) continue;

        if (wantsEmail($userId, $emailPrefCache)) {
            $subj = APP_NAME . ' — ' . $title;
            $msg = "Your wallet time lock is almost ready.\n\n";
            if ($label) $msg .= "Label: {$label}\n";
            $msg .= "Unlocks at (UTC): {$revealAt}\n\n";
            $msg .= "Open: {$codesUrl}#wallet-{$wid}\n";
            sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
        }
    }

    // T-1h
    $rows = $db->query("SELECT w.id, w.user_id, w.label, w.unlock_at, u.email
                       FROM wallet_locks w
                       JOIN users u ON u.id = w.user_id
                       WHERE w.is_active = 1
                         AND w.setup_status = 'active'
                         AND u.email_verified_at IS NOT NULL
                         AND w.unlock_at > UTC_TIMESTAMP()
                         AND w.unlock_at <= (UTC_TIMESTAMP() + INTERVAL 1 HOUR)")
               ->fetchAll();

    foreach ($rows as $r) {
        $wid = (string)$r['id'];
        $userId = (int)$r['user_id'];
        $label = normalizeDisplayText($r['label'] ?? null);
        $revealAt = (string)$r['unlock_at'];

        $title = 'Time lock unlocks within 1h';
        $body  = ($label ? ('"' . $label . '" ') : 'A wallet time lock ') . 'becomes eligible to reveal at ' . $revealAt . ' UTC.';

        $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

        $nid = notifyOnce($db, $userId, 'wallet_lock_reveal_1h', 'important', $title, $body, ['wallet_lock_id' => $wid], 'wallet_lock', $wid, $mask);
        if (!$nid) continue;

        if (wantsEmail($userId, $emailPrefCache)) {
            $subj = APP_NAME . ' — ' . $title;
            $msg = "Your wallet time lock is almost ready.\n\n";
            if ($label) $msg .= "Label: {$label}\n";
            $msg .= "Unlocks at (UTC): {$revealAt}\n\n";
            $msg .= "Open: {$codesUrl}#wallet-{$wid}\n";
            sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
        }
    }

    // Ready
    $rows = $db->query("SELECT w.id, w.user_id, w.label, w.unlock_at, u.email
                       FROM wallet_locks w
                       JOIN users u ON u.id = w.user_id
                       WHERE w.is_active = 1
                         AND w.setup_status = 'active'
                         AND u.email_verified_at IS NOT NULL
                         AND w.revealed_at IS NULL
                         AND w.unlock_at <= UTC_TIMESTAMP()
                         AND w.unlock_at >= (UTC_TIMESTAMP() - INTERVAL 48 HOUR)")
               ->fetchAll();

    foreach ($rows as $r) {
        $wid = (string)$r['id'];
        $userId = (int)$r['user_id'];
        $label = normalizeDisplayText($r['label'] ?? null);
        $revealAt = (string)$r['unlock_at'];

        $title = 'Time lock ready';
        $body  = ($label ? ('"' . $label . '" ') : 'A wallet time lock ') . 'is now eligible to reveal.';

        $mask = wantsEmail($userId, $emailPrefCache) ? 'inapp,email' : 'inapp';

        $nid = notifyOnce($db, $userId, 'wallet_lock_ready', 'important', $title, $body, ['wallet_lock_id' => $wid], 'wallet_lock', $wid, $mask);
        if (!$nid) continue;

        if (wantsEmail($userId, $emailPrefCache)) {
            $subj = APP_NAME . ' — ' . $title;
            $msg = "Your wallet time lock is ready to reveal.\n\n";
            if ($label) $msg .= "Label: {$label}\n";
            $msg .= "Unlock time (UTC): {$revealAt}\n\n";
            $msg .= "Open: {$codesUrl}#wallet-{$wid}\n";
            sendEmailForNotification($db, $nid, (string)$r['email'], $subj, $msg);
        }
    }
}

logLine('Done.');
