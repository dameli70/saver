<?php
// ============================================================
//  LOCKSMITH — Locks Worker (cron)
//
//  Run every 1–5 minutes:
//    php scripts/locks_worker.php
//
//  Responsibilities:
//   - Mark stale "pending" locks as "auto_saved" so they don't remain stuck
//     indefinitely if the user closes the page before confirming.
// ============================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This worker must be run from the command line.\n");
    exit(1);
}

require_once __DIR__ . '/../config/database.php';

date_default_timezone_set('UTC');

function logLine(string $s): void {
    fwrite(STDOUT, '[' . date('c') . '] ' . $s . "\n");
}

$db = getDB();

// If a lock sits in "pending" past the UI's autosave window, flip it to "auto_saved".
// This matches the product promise while still requiring user activation.
$stmt = $db->prepare("\
    UPDATE locks
    SET confirmation_status = 'auto_saved', auto_saved_at = UTC_TIMESTAMP()
    WHERE is_active = 1
      AND confirmation_status = 'pending'
      AND created_at <= (UTC_TIMESTAMP() - INTERVAL 2 MINUTE)\
");
$stmt->execute();

logLine('locks auto-save sweep: updated ' . $stmt->rowCount() . ' row(s)');
