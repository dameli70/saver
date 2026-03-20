<?php
// ============================================================
//  Controle — Type B demo seeder (CLI)
//
//  Generates ONLY Type B rooms in a set of deterministic scenarios
//  so you can test UI + API behavior across the full Type B lifecycle.
//
//  Usage:
//    php scripts/typeb_demo_seed.php
//    php scripts/typeb_demo_seed.php --user_id=5
//    php scripts/typeb_demo_seed.php --user_email=user@example.com
//
//  Notes:
//  - This script is intentionally "dev tooling". It will reset/rebuild
//    previously created DEMO Type B rooms (by goal_text prefix).
//  - It does not touch non-demo rooms.
// ============================================================

if (PHP_SAPI !== 'cli') {
    http_response_code(400);
    echo "CLI only\n";
    exit(1);
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../includes/media_crypto.php';

const TYPEB_DEMO_PREFIX = 'DEMO Type B - ';

function typebDemoHasTable(PDO $db, string $table): bool {
    static $cache = [];
    if (array_key_exists($table, $cache)) return (bool)$cache[$table];

    $st = $db->prepare("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1");
    $st->execute([$table]);
    $cache[$table] = (bool)$st->fetchColumn();
    $st->closeCursor();
    return (bool)$cache[$table];
}

function typebDemoHasColumn(PDO $db, string $table, string $column): bool {
    static $cache = [];
    $k = $table . '.' . $column;
    if (array_key_exists($k, $cache)) return (bool)$cache[$k];

    $st = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
    $st->execute([$table, $column]);
    $cache[$k] = (bool)$st->fetchColumn();
    $st->closeCursor();
    return (bool)$cache[$k];
}

function typebDemoNow(string $modify = 'now'): string {
    $dt = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if ($modify !== 'now') {
        $dt = $dt->modify($modify);
    }
    return $dt->format('Y-m-d H:i:s');
}

function typebDemoUuid(): string {
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

function typebDemoAppEncKey(): string {
    return hash('sha256', (string)APP_HMAC_SECRET, true);
}

function typebDemoEncryptForDb(string $plaintext): string {
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', typebDemoAppEncKey(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) {
        throw new RuntimeException('Encryption failed');
    }

    return base64_encode($iv) . '.' . base64_encode($tag) . '.' . base64_encode($cipher);
}

function typebDemoHashLoginPassword(string $password): string {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function typebDemoHashVaultVerifier(string $passphrase): string {
    return password_hash($passphrase, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

function typebDemoEnsureUser(PDO $db, string $email, string $displayName, string $demoPassword = 'DemoPass123!'): int {
    if (!typebDemoHasTable($db, 'users')) {
        throw new RuntimeException('Missing users table');
    }

    $emailNorm = strtolower(trim($email));

    $sel = $db->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $sel->execute([$emailNorm]);
    $id = (int)($sel->fetchColumn() ?: 0);
    $sel->closeCursor();

    if ($id > 0) {
        // Keep display name fresh if supported.
        if (typebDemoHasColumn($db, 'users', 'room_display_name')) {
            $db->prepare('UPDATE users SET room_display_name = ? WHERE id = ?')->execute([$displayName, $id]);
        }
        if (typebDemoHasColumn($db, 'users', 'email_verified_at')) {
            $db->prepare('UPDATE users SET email_verified_at = COALESCE(email_verified_at, ?) WHERE id = ?')->execute([typebDemoNow('now'), $id]);
        }
        return $id;
    }

    $salt = bin2hex(random_bytes(32));
    $vaultVerifier = typebDemoHashVaultVerifier(bin2hex(random_bytes(32)) . $salt);

    $cols = ['email', 'login_hash', 'vault_verifier', 'vault_verifier_salt', 'is_admin'];
    $vals = [$emailNorm, typebDemoHashLoginPassword($demoPassword), $vaultVerifier, $salt, 0];

    if (typebDemoHasColumn($db, 'users', 'email_verified_at')) {
        $cols[] = 'email_verified_at';
        $vals[] = typebDemoNow('now');
    }

    if (typebDemoHasColumn($db, 'users', 'room_display_name')) {
        $cols[] = 'room_display_name';
        $vals[] = $displayName;
    }

    if (typebDemoHasColumn($db, 'users', 'onboarding_completed_at')) {
        $cols[] = 'onboarding_completed_at';
        $vals[] = typebDemoNow('-2 days');
    }

    if (typebDemoHasColumn($db, 'users', 'require_webauthn')) {
        $cols[] = 'require_webauthn';
        $vals[] = 0;
    }

    if (typebDemoHasColumn($db, 'users', 'vault_active_slot')) {
        $cols[] = 'vault_active_slot';
        $vals[] = 1;
    }

    $sql = 'INSERT INTO users (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);

    return (int)$db->lastInsertId();
}

function typebDemoEnsureTrust(PDO $db, int $userId, int $level = 3): void {
    if (!typebDemoHasTable($db, 'user_trust')) return;
    if (!typebDemoHasColumn($db, 'user_trust', 'user_id') || !typebDemoHasColumn($db, 'user_trust', 'trust_level')) return;

    $cols = ['user_id', 'trust_level'];
    $vals = [$userId, $level];

    if (typebDemoHasColumn($db, 'user_trust', 'completed_reveals_count')) {
        $cols[] = 'completed_reveals_count';
        $vals[] = 0;
    }
    if (typebDemoHasColumn($db, 'user_trust', 'last_level_change_at')) {
        $cols[] = 'last_level_change_at';
        $vals[] = typebDemoNow('now');
    }

    $sql = 'INSERT INTO user_trust (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')'
        . ' ON DUPLICATE KEY UPDATE trust_level=VALUES(trust_level)';

    $db->prepare($sql)->execute($vals);
}

function typebDemoEnsureDestinationAccount(PDO $db): int {
    if (!typebDemoHasTable($db, 'platform_destination_accounts')) {
        throw new RuntimeException('Missing platform_destination_accounts table');
    }

    $st = $db->query("SELECT id FROM platform_destination_accounts WHERE is_active = 1 ORDER BY id ASC LIMIT 1");
    $id = (int)($st->fetchColumn() ?: 0);
    $st->closeCursor();
    if ($id > 0) return $id;

    $cols = ['account_type', 'is_active'];
    $vals = ['bank', 1];

    foreach (['display_label','bank_name','bank_account_name','bank_account_number','bank_routing_number','bank_swift','bank_iban','created_at'] as $c) {
        if (!typebDemoHasColumn($db, 'platform_destination_accounts', $c)) continue;
        $cols[] = $c;

        if ($c === 'display_label') $vals[] = 'Demo Bank Account';
        else if ($c === 'bank_name') $vals[] = 'DEMO BANK';
        else if ($c === 'bank_account_name') $vals[] = 'Controle Demo';
        else if ($c === 'bank_account_number') $vals[] = '000123456789';
        else if ($c === 'bank_routing_number') $vals[] = '000111';
        else if ($c === 'bank_swift') $vals[] = 'DEMOXXXX';
        else if ($c === 'bank_iban') $vals[] = 'TG00DEMO000000000000';
        else if ($c === 'created_at') $vals[] = typebDemoNow('now');
        else $vals[] = null;
    }

    $sql = 'INSERT INTO platform_destination_accounts (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);

    return (int)$db->lastInsertId();
}

function typebDemoUpsertRoomAccount(PDO $db, string $roomId, int $accountId, string $unlockCodePlain): void {
    if (!typebDemoHasTable($db, 'saving_room_accounts')) return;

    $cols = ['room_id', 'account_id'];
    $vals = [$roomId, $accountId];

    if (typebDemoHasColumn($db, 'saving_room_accounts', 'unlock_code_enc')) {
        $cols[] = 'unlock_code_enc';
        $vals[] = typebDemoEncryptForDb($unlockCodePlain);
    }

    if (typebDemoHasColumn($db, 'saving_room_accounts', 'code_rotated_at')) {
        $cols[] = 'code_rotated_at';
        $vals[] = typebDemoNow('-2 days');
    }

    if (typebDemoHasColumn($db, 'saving_room_accounts', 'code_rotation_version')) {
        $cols[] = 'code_rotation_version';
        $vals[] = 1;
    }

    if (typebDemoHasColumn($db, 'saving_room_accounts', 'created_at')) {
        $cols[] = 'created_at';
        $vals[] = typebDemoNow('now');
    }

    if (typebDemoHasColumn($db, 'saving_room_accounts', 'updated_at')) {
        $cols[] = 'updated_at';
        $vals[] = typebDemoNow('now');
    }

    $sql = 'INSERT INTO saving_room_accounts (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')'
        . ' ON DUPLICATE KEY UPDATE account_id=VALUES(account_id)';

    if (in_array('unlock_code_enc', $cols, true)) {
        $sql .= ', unlock_code_enc=VALUES(unlock_code_enc)';
    }
    if (in_array('code_rotated_at', $cols, true)) {
        $sql .= ', code_rotated_at=VALUES(code_rotated_at)';
    }
    if (in_array('code_rotation_version', $cols, true)) {
        $sql .= ', code_rotation_version=VALUES(code_rotation_version)';
    }
    if (in_array('updated_at', $cols, true)) {
        $sql .= ', updated_at=VALUES(updated_at)';
    }

    $db->prepare($sql)->execute($vals);
}

function typebDemoFindOrCreateRoom(PDO $db, string $goalText, int $makerUserId): string {
    if (!typebDemoHasTable($db, 'saving_rooms')) {
        throw new RuntimeException('Missing saving_rooms table');
    }

    $find = $db->prepare("SELECT id FROM saving_rooms WHERE goal_text = ? AND saving_type = 'B' LIMIT 1");
    $find->execute([$goalText]);
    $existing = (string)($find->fetchColumn() ?: '');
    $find->closeCursor();

    if ($existing !== '') {
        return $existing;
    }

    $roomId = typebDemoUuid();

    $cols = [
        'id',
        'maker_user_id',
        'purpose_category',
        'goal_text',
        'saving_type',
        'visibility',
        'required_trust_level',
        'min_participants',
        'max_participants',
        'participation_amount',
        'periodicity',
        'start_at',
        'reveal_at',
        'lobby_state',
        'room_state',
        'privacy_mode',
        'escrow_policy',
    ];

    $vals = [
        $roomId,
        $makerUserId,
        'community',
        $goalText,
        'B',
        'public',
        1,
        2,
        6,
        '50.00',
        'weekly',
        typebDemoNow('now'),
        typebDemoNow('now'),
        'open',
        'lobby',
        1,
        'redistribute',
    ];

    foreach (['platform_controlled','extensions_used','updated_at'] as $c) {
        if (!typebDemoHasColumn($db, 'saving_rooms', $c)) continue;
        $cols[] = $c;
        if ($c === 'platform_controlled') $vals[] = 0;
        else if ($c === 'extensions_used') $vals[] = 0;
        else if ($c === 'updated_at') $vals[] = null;
        else $vals[] = null;
    }

    // Swap window variants
    foreach (['swap_window_ends_at','swap_window_closes_at','swap_window_end_at'] as $c) {
        if (!typebDemoHasColumn($db, 'saving_rooms', $c)) continue;
        $cols[] = $c;
        $vals[] = null;
    }

    $sql = 'INSERT INTO saving_rooms (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);

    return $roomId;
}

function typebDemoResetRoomData(PDO $db, string $roomId): void {
    // Only reset known room-scoped tables.
    // Note: saving_room_dispute_ack does NOT have room_id; it will cascade when disputes are deleted.
    $tables = [
        'saving_room_activity',
        'saving_room_unlock_votes',
        'saving_room_turn_code_views',
        'saving_room_disputes',
        'saving_room_exit_requests',
        'saving_room_slot_swaps',
        'saving_room_rotation_windows',
        'saving_room_rotation_queue',
        'saving_room_account_ledger',
        // contributions are via cycles; deleting cycles will cascade.
        'saving_room_contribution_proofs',
        'saving_room_contributions',
        'saving_room_contribution_cycles',
        'saving_room_accounts',
        'saving_room_join_requests',
        'saving_room_invites',
    ];

    foreach ($tables as $t) {
        if (!typebDemoHasTable($db, $t)) continue;
        $db->prepare("DELETE FROM {$t} WHERE room_id = ?")->execute([$roomId]);
    }

    if (typebDemoHasTable($db, 'saving_room_participants')) {
        $db->prepare('DELETE FROM saving_room_participants WHERE room_id = ?')->execute([$roomId]);
    }
}

function typebDemoUpdateRoom(PDO $db, string $roomId, array $patch): void {
    if (!$patch) return;

    $sets = [];
    $vals = [];

    foreach ($patch as $k => $v) {
        if (!typebDemoHasColumn($db, 'saving_rooms', $k)) continue;
        $sets[] = "{$k} = ?";
        $vals[] = $v;
    }

    if (!$sets) return;

    $vals[] = $roomId;
    $db->prepare('UPDATE saving_rooms SET ' . implode(', ', $sets) . ' WHERE id = ?')->execute($vals);
}

function typebDemoSetParticipant(PDO $db, string $roomId, int $userId, string $status, int $slotPos = 0): void {
    if (!typebDemoHasTable($db, 'saving_room_participants')) return;

    $cols = ['room_id', 'user_id', 'status'];
    $vals = [$roomId, $userId, $status];

    if (typebDemoHasColumn($db, 'saving_room_participants', 'joined_at')) {
        $cols[] = 'joined_at';
        $vals[] = typebDemoNow('-3 days');
    }

    if (typebDemoHasColumn($db, 'saving_room_participants', 'approved_at')) {
        $cols[] = 'approved_at';
        $vals[] = in_array($status, ['approved', 'active', 'completed'], true) ? typebDemoNow('-2 days') : null;
    }

    if (typebDemoHasColumn($db, 'saving_room_participants', 'slot_position')) {
        $cols[] = 'slot_position';
        $vals[] = $slotPos;
    }

    $sql = 'INSERT INTO saving_room_participants (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')'
        . ' ON DUPLICATE KEY UPDATE status=VALUES(status)';

    if (in_array('approved_at', $cols, true)) {
        $sql .= ', approved_at=COALESCE(approved_at, VALUES(approved_at))';
    }
    if (in_array('slot_position', $cols, true)) {
        $sql .= ', slot_position=VALUES(slot_position)';
    }

    $db->prepare($sql)->execute($vals);
}

function typebDemoSetQueue(PDO $db, string $roomId, array $orderedUserIds, ?int $activeUserId, int $rotationIndex = 1): void {
    if (!typebDemoHasTable($db, 'saving_room_rotation_queue')) return;

    $sql = "INSERT INTO saving_room_rotation_queue (room_id, user_id, position, status, slot_locked_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE position=VALUES(position), status=VALUES(status), slot_locked_at=VALUES(slot_locked_at)";

    $ins = $db->prepare($sql);

    foreach (array_values($orderedUserIds) as $i => $uid) {
        $pos = $i + 1;
        $st = ($activeUserId !== null && (int)$uid === (int)$activeUserId) ? 'active_window' : 'queued';
        $lockedAt = ($st === 'active_window') ? typebDemoNow('-2 hours') : null;
        $ins->execute([$roomId, (int)$uid, $pos, $st, $lockedAt, typebDemoNow('-4 days')]);
    }
}

function typebDemoUpsertRotationWindow(PDO $db, string $roomId, int $rotationIndex, int $turnUserId, array $patch): int {
    if (!typebDemoHasTable($db, 'saving_room_rotation_windows')) {
        throw new RuntimeException('Missing saving_room_rotation_windows table');
    }

    $baseCols = ['room_id', 'user_id', 'rotation_index', 'status', 'created_at'];
    $baseVals = [$roomId, $turnUserId, $rotationIndex, (string)($patch['status'] ?? 'pending_votes'), typebDemoNow('-2 days')];

    $cols = $baseCols;
    $vals = $baseVals;

    $optional = [
        'delegate_user_id',
        'delegate_set_at',
        'approve_opens_at',
        'approve_due_at',
        'revealed_at',
        'expires_at',
        'withdrawal_confirmed_at',
        'withdrawal_confirmed_by_user_id',
        'withdrawal_reference',
        'withdrawal_confirmed_role',
        'dispute_window_ends_at',
    ];

    foreach ($optional as $c) {
        if (!typebDemoHasColumn($db, 'saving_room_rotation_windows', $c)) continue;
        if (!array_key_exists($c, $patch)) continue;
        $cols[] = $c;
        $vals[] = $patch[$c];
    }

    $sql = 'INSERT INTO saving_room_rotation_windows (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')'
        . " ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), status=VALUES(status)";

    foreach ($optional as $c) {
        if (!typebDemoHasColumn($db, 'saving_room_rotation_windows', $c)) continue;
        if (!array_key_exists($c, $patch)) continue;
        $sql .= ", {$c}=VALUES({$c})";
    }

    $db->prepare($sql)->execute($vals);

    $sel = $db->prepare('SELECT id FROM saving_room_rotation_windows WHERE room_id = ? AND rotation_index = ? LIMIT 1');
    $sel->execute([$roomId, $rotationIndex]);
    $id = (int)($sel->fetchColumn() ?: 0);
    $sel->closeCursor();

    if ($id < 1) throw new RuntimeException('Failed to resolve rotation window id');
    return $id;
}

function typebDemoInsertVote(PDO $db, string $roomId, int $userId, string $scope, int $targetIndex, string $vote, string $createdAt): void {
    if (!typebDemoHasTable($db, 'saving_room_unlock_votes')) return;

    $cols = ['room_id', 'user_id', 'scope', 'target_rotation_index', 'vote'];
    $vals = [$roomId, $userId, $scope, $targetIndex, $vote];

    if (typebDemoHasColumn($db, 'saving_room_unlock_votes', 'created_at')) {
        $cols[] = 'created_at';
        $vals[] = $createdAt;
    }

    $sql = 'INSERT IGNORE INTO saving_room_unlock_votes (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);
}

function typebDemoInsertActivity(PDO $db, string $roomId, string $eventType, array $payload, string $createdAt): void {
    if (!typebDemoHasTable($db, 'saving_room_activity')) return;

    $sql = 'INSERT INTO saving_room_activity (room_id, event_type, public_payload_json, created_at) VALUES (?, ?, ?, ?)';
    $db->prepare($sql)->execute([$roomId, $eventType, json_encode($payload, JSON_UNESCAPED_UNICODE), $createdAt]);
}

function typebDemoInsertCycle(PDO $db, string $roomId, int $cycleIndex, string $dueAt, string $graceEndsAt, string $status): int {
    if (!typebDemoHasTable($db, 'saving_room_contribution_cycles')) return 0;

    $db->prepare('INSERT INTO saving_room_contribution_cycles (room_id, cycle_index, due_at, grace_ends_at, status, created_at)
                  VALUES (?, ?, ?, ?, ?, NOW())
                  ON DUPLICATE KEY UPDATE due_at=VALUES(due_at), grace_ends_at=VALUES(grace_ends_at), status=VALUES(status)')
       ->execute([$roomId, $cycleIndex, $dueAt, $graceEndsAt, $status]);

    $st = $db->prepare('SELECT id FROM saving_room_contribution_cycles WHERE room_id = ? AND cycle_index = ? LIMIT 1');
    $st->execute([$roomId, $cycleIndex]);
    $id = (int)($st->fetchColumn() ?: 0);
    $st->closeCursor();
    return $id;
}

function typebDemoUpsertContribution(PDO $db, string $roomId, int $cycleId, int $userId, string $amount, string $status, ?string $reference, ?string $confirmedAt): void {
    if (!typebDemoHasTable($db, 'saving_room_contributions')) return;

    $db->prepare('INSERT INTO saving_room_contributions (room_id, user_id, cycle_id, amount, status, reference, confirmed_at, created_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
                  ON DUPLICATE KEY UPDATE amount=VALUES(amount), status=VALUES(status), reference=VALUES(reference), confirmed_at=VALUES(confirmed_at)')
       ->execute([$roomId, $userId, $cycleId, $amount, $status, $reference, $confirmedAt]);
}

function typebDemoFindContributionId(PDO $db, string $roomId, int $cycleId, int $userId): int {
    if (!typebDemoHasTable($db, 'saving_room_contributions')) return 0;

    $st = $db->prepare('SELECT id FROM saving_room_contributions WHERE room_id = ? AND cycle_id = ? AND user_id = ? LIMIT 1');
    $st->execute([$roomId, $cycleId, $userId]);
    $id = (int)($st->fetchColumn() ?: 0);
    $st->closeCursor();
    return $id;
}

function typebDemoPngBytes(): string {
    // 1x1 transparent PNG.
    $b64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMB/6X4nfoAAAAASUVORK5CYII=';
    $raw = base64_decode($b64, true);
    return $raw !== false ? $raw : "";
}

function typebDemoInsertProof(PDO $db, string $roomId, int $contributionId, int $userId, ?string $referenceSnapshot, ?string $originalFilename, string $contentType, string $bytes, ?string $createdAt = null): int {
    if (!typebDemoHasTable($db, 'saving_room_contribution_proofs')) return 0;
    if ($contributionId < 1) return 0;

    $contentType = strtolower(trim($contentType));
    if ($contentType === '') $contentType = 'image/png';

    $size = strlen($bytes);
    if ($size < 1) return 0;

    $shaBin = hash('sha256', $bytes, true);
    $enc = mediaEncryptBytes($bytes);

    $ref = $referenceSnapshot;
    if ($ref === null || trim($ref) === '') {
        $ref = bin2hex(random_bytes(12));
    }

    $cols = ['room_id','contribution_id','user_id','reference_snapshot','original_filename','content_type','size_bytes','sha256','enc_cipher','iv','tag'];
    $vals = [$roomId, $contributionId, $userId, $ref, ($originalFilename !== null && $originalFilename !== '') ? substr($originalFilename, 0, 255) : null, $contentType, $size, $shaBin, $enc['cipher'], $enc['iv'], $enc['tag']];

    if ($createdAt !== null && typebDemoHasColumn($db, 'saving_room_contribution_proofs', 'created_at')) {
        $cols[] = 'created_at';
        $vals[] = $createdAt;
    }

    $sql = 'INSERT INTO saving_room_contribution_proofs (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $db->prepare($sql)->execute($vals);

    return (int)$db->lastInsertId();
}

function typebDemoInsertLedgerFromEntries(PDO $db, string $roomId, array $entries): void {
    if (!typebDemoHasTable($db, 'saving_room_account_ledger')) return;

    $cols = ['room_id','entry_seq','entry_type','entry_kind','amount','balance_after','source_type','source_id'];
    if (typebDemoHasColumn($db, 'saving_room_account_ledger', 'created_by_user_id')) $cols[] = 'created_by_user_id';
    if (typebDemoHasColumn($db, 'saving_room_account_ledger', 'created_at')) $cols[] = 'created_at';

    $sql = 'INSERT IGNORE INTO saving_room_account_ledger (' . implode(',', $cols) . ') VALUES (' . implode(',', array_fill(0, count($cols), '?')) . ')';
    $ins = $db->prepare($sql);

    $bal = 0.0;
    $seq = 1;

    foreach ($entries as $e) {
        $amt = (float)$e['amount'];
        if ($e['entry_type'] === 'credit') $bal += $amt;
        else $bal -= $amt;

        $vals = [];
        foreach ($cols as $c) {
            if ($c === 'room_id') $vals[] = $roomId;
            else if ($c === 'entry_seq') $vals[] = $seq;
            else if ($c === 'entry_type') $vals[] = (string)$e['entry_type'];
            else if ($c === 'entry_kind') $vals[] = (string)$e['entry_kind'];
            else if ($c === 'amount') $vals[] = (string)$e['amount'];
            else if ($c === 'balance_after') $vals[] = number_format($bal, 2, '.', '');
            else if ($c === 'source_type') $vals[] = (string)$e['source_type'];
            else if ($c === 'source_id') $vals[] = (string)$e['source_id'];
            else if ($c === 'created_by_user_id') $vals[] = isset($e['created_by_user_id']) ? (int)$e['created_by_user_id'] : null;
            else if ($c === 'created_at') $vals[] = (string)($e['created_at'] ?? typebDemoNow('now'));
            else $vals[] = null;
        }

        $ins->execute($vals);
        $seq++;
    }
}

function typebDemoEnsureRoom(PDO $db, int $destAccountId, string $goalText, int $makerId, array $roomPatch, callable $seedFn): array {
    $roomId = typebDemoFindOrCreateRoom($db, $goalText, $makerId);

    // Safety: only reset rooms that follow our prefix.
    if (str_starts_with($goalText, TYPEB_DEMO_PREFIX)) {
        typebDemoResetRoomData($db, $roomId);
    }

    // Normalize swap window variants for schema compatibility.
    if (array_key_exists('swap_window_ends_at', $roomPatch)) {
        $v = $roomPatch['swap_window_ends_at'];
        foreach (['swap_window_ends_at','swap_window_closes_at','swap_window_end_at'] as $k) {
            if (!array_key_exists($k, $roomPatch)) $roomPatch[$k] = $v;
        }
    }

    // Always enforce the intended maker for the scenario.
    $roomPatch['maker_user_id'] = $makerId;

    // Apply room patch after reset.
    typebDemoUpdateRoom($db, $roomId, $roomPatch);

    // Ensure account mapping (needed for reveal flows).
    typebDemoUpsertRoomAccount($db, $roomId, $destAccountId, 'DEMO-UNLOCK-' . substr($roomId, 0, 8));

    // Seed the scenario-specific data.
    $seedFn($roomId);

    // Mark in activity.
    typebDemoInsertActivity($db, $roomId, 'room_seeded', ['demo' => 1, 'type' => 'B'], typebDemoNow('now'));

    return ['id' => $roomId, 'goal' => $goalText];
}

// ───────────────────────────────────────────────────────────
// Main
// ───────────────────────────────────────────────────────────

$args = getopt('', ['user_id::', 'user_email::']);

$db = getDB();

if (!typebDemoHasTable($db, 'saving_rooms')) {
    fwrite(STDERR, "Missing saving_rooms table\n");
    exit(1);
}

$demoPassword = 'DemoPass123!';

// Resolve primary user (the account you plan to log in as).
$primaryUserId = 0;

if (!empty($args['user_id'])) {
    $primaryUserId = (int)$args['user_id'];
}

if ($primaryUserId < 1 && !empty($args['user_email'])) {
    $email = strtolower(trim((string)$args['user_email']));
    $st = $db->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $st->execute([$email]);
    $primaryUserId = (int)($st->fetchColumn() ?: 0);
    $st->closeCursor();
}

// If no user specified, pick the first user.
if ($primaryUserId < 1) {
    $st = $db->query('SELECT id FROM users ORDER BY id ASC LIMIT 1');
    $primaryUserId = (int)($st->fetchColumn() ?: 0);
    $st->closeCursor();
}

// If there are no users at all, create a primary demo user.
if ($primaryUserId < 1) {
    $primaryUserId = typebDemoEnsureUser($db, 'typeb.primary@example.com', 'TypeB Primary', $demoPassword);
}

// Ensure we have enough demo users to model roles.
$u1 = $primaryUserId;
$u2 = typebDemoEnsureUser($db, 'typeb.maker@example.com', 'TypeB Maker', $demoPassword);
$u3 = typebDemoEnsureUser($db, 'typeb.turn@example.com', 'TypeB Turn User', $demoPassword);
$u4 = typebDemoEnsureUser($db, 'typeb.participant1@example.com', 'TypeB Participant 1', $demoPassword);
$u5 = typebDemoEnsureUser($db, 'typeb.participant2@example.com', 'TypeB Participant 2', $demoPassword);
$u6 = typebDemoEnsureUser($db, 'typeb.participant3@example.com', 'TypeB Participant 3', $demoPassword);

foreach ([$u1, $u2, $u3, $u4, $u5, $u6] as $uid) {
    if ($uid > 0) typebDemoEnsureTrust($db, (int)$uid, 3);
}

$destAccountId = typebDemoEnsureDestinationAccount($db);

$outRooms = [];

$db->beginTransaction();
try {
    // 1) Lobby (waiting for min participants)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Lobby (waiting for min participants)',
        $u2,
        [
            'saving_type' => 'B',
            'visibility' => 'public',
            'room_state' => 'lobby',
            'lobby_state' => 'open',
            'min_participants' => 5,
            'max_participants' => 10,
            'participation_amount' => '50.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('now'),
            'reveal_at' => typebDemoNow('now'),
            'swap_window_ends_at' => null,
        ],
        function (string $roomId) use ($db, $u1, $u2, $u4, $u5): void {
            // Approved count < min
            typebDemoSetParticipant($db, $roomId, $u2, 'approved', 1);
            typebDemoSetParticipant($db, $roomId, $u1, 'approved', 2);
            typebDemoSetParticipant($db, $roomId, $u4, 'approved', 3);

            // Pending join request user (if available)
            if (typebDemoHasTable($db, 'saving_room_join_requests')) {
                $jrCols = [];
                $jrVals = [];

                foreach (['room_id','user_id','status','snapshot_level','snapshot_strikes_6m','snapshot_restricted_until','created_at'] as $c) {
                    if (!typebDemoHasColumn($db, 'saving_room_join_requests', $c)) continue;
                    $jrCols[] = $c;

                    if ($c === 'room_id') $jrVals[] = $roomId;
                    else if ($c === 'user_id') $jrVals[] = (int)$u5;
                    else if ($c === 'status') $jrVals[] = 'pending';
                    else if ($c === 'snapshot_level') $jrVals[] = 3;
                    else if ($c === 'snapshot_strikes_6m') $jrVals[] = 0;
                    else if ($c === 'snapshot_restricted_until') $jrVals[] = null;
                    else if ($c === 'created_at') $jrVals[] = typebDemoNow('-10 minutes');
                    else $jrVals[] = null;
                }

                if ($jrCols) {
                    $db->prepare('INSERT IGNORE INTO saving_room_join_requests (' . implode(',', $jrCols) . ') VALUES (' . implode(',', array_fill(0, count($jrCols), '?')) . ')')
                       ->execute($jrVals);
                }
            }

            typebDemoInsertActivity($db, $roomId, 'room_created', ['demo' => 1], typebDemoNow('-3 days'));
        }
    );

    // 2) Swap window (open) + pending swap requests
    $swapEnds = typebDemoNow('+6 hours');
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Swap window (open + swap requests)',
        $u2,
        [
            'room_state' => 'swap_window',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '75.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-1 day'),
            'reveal_at' => typebDemoNow('-1 day'),
            'swap_window_ends_at' => $swapEnds,
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4, $swapEnds): void {
            // Approved participants (>= min)
            typebDemoSetParticipant($db, $roomId, $u2, 'approved', 1);
            typebDemoSetParticipant($db, $roomId, $u1, 'approved', 2);
            typebDemoSetParticipant($db, $roomId, $u3, 'approved', 3);
            typebDemoSetParticipant($db, $roomId, $u4, 'approved', 4);

            typebDemoSetQueue($db, $roomId, [$u2, $u1, $u3, $u4], null);

            if (typebDemoHasTable($db, 'saving_room_slot_swaps')) {
                // Ensure exactly one pending and one declined swap for UI testing.
                $db->prepare("INSERT INTO saving_room_slot_swaps (room_id, from_user_id, to_user_id, status, expires_at, created_at)
                              VALUES (?, ?, ?, 'pending', ?, ?)")
                   ->execute([$roomId, $u1, $u3, $swapEnds, typebDemoNow('-2 hours')]);

                $db->prepare("INSERT INTO saving_room_slot_swaps (room_id, from_user_id, to_user_id, status, expires_at, created_at, responded_at)
                              VALUES (?, ?, ?, 'declined', ?, ?, ?)")
                   ->execute([$roomId, $u4, $u1, $swapEnds, typebDemoNow('-3 hours'), typebDemoNow('-2 hours')]);
            }

            typebDemoInsertActivity($db, $roomId, 'swap_window_started', ['closes_at' => $swapEnds, 'demo' => 1], typebDemoNow('-1 hour'));
        }
    );

    // 3) Active + pending votes (opens in future) => no vote buttons
    $opensFuture = typebDemoNow('+2 hours');
    $dueFuture = typebDemoNow('+10 hours');

    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Active (pending votes, opens in future)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '40.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-10 days'),
            'reveal_at' => typebDemoNow('-10 days'),
            'swap_window_ends_at' => null,
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4, $opensFuture, $dueFuture): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u2, $u4], $u3);

            $winId = typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'pending_votes',
                'approve_opens_at' => $opensFuture,
                'approve_due_at' => $dueFuture,
            ]);

            // Contributions + balance
            $c1 = typebDemoInsertCycle($db, $roomId, 1, typebDemoNow('+5 days'), typebDemoNow('+7 days'), 'open');
            if ($c1 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c1, $u2, '40.00', 'paid', 'DEMO-PAID-001', typebDemoNow('-1 day'));
                typebDemoUpsertContribution($db, $roomId, $c1, $u1, '40.00', 'unpaid', null, null);
                typebDemoUpsertContribution($db, $roomId, $c1, $u3, '40.00', 'paid', 'DEMO-PAID-002', typebDemoNow('-12 hours'));
                typebDemoUpsertContribution($db, $roomId, $c1, $u4, '40.00', 'paid_in_grace', 'DEMO-PAID-003', typebDemoNow('-2 hours'));
            }

            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '120.00', 'source_type' => 'seed', 'source_id' => 'seed:active_future', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-3 hours')],
            ]);

            typebDemoInsertActivity($db, $roomId, 'typeB_turn_revealed', ['rotation_index' => 1, 'window_id' => $winId, 'demo' => 1], typebDemoNow('-30 minutes'));
        }
    );

    // 4) Active + pending votes (open now) where primary user can vote (participant)
    $opensPast = typebDemoNow('-1 hour');
    $dueSoon = typebDemoNow('+6 hours');

    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Active (pending votes, open now)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '25.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-20 days'),
            'reveal_at' => typebDemoNow('-20 days'),
            'swap_window_ends_at' => null,
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4, $opensPast, $dueSoon): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u2, $u4], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'pending_votes',
                'approve_opens_at' => $opensPast,
                'approve_due_at' => $dueSoon,
            ]);

            $c1 = typebDemoInsertCycle($db, $roomId, 1, typebDemoNow('+4 days'), typebDemoNow('+6 days'), 'open');
            if ($c1 > 0) {
                $png = typebDemoPngBytes();
                foreach ([$u2,$u1,$u3,$u4] as $uid) {
                    typebDemoUpsertContribution($db, $roomId, $c1, (int)$uid, '25.00', 'paid', 'DEMO-CYCLE1-' . $uid, typebDemoNow('-10 hours'));
                    $cid = typebDemoFindContributionId($db, $roomId, $c1, (int)$uid);
                    typebDemoInsertProof($db, $roomId, $cid, (int)$uid, null, 'demo-proof-' . $uid . '.png', 'image/png', $png, typebDemoNow('-9 hours'));
                }
            }

            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '100.00', 'source_type' => 'seed', 'source_id' => 'seed:vote_open', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-10 hours')],
            ]);

            typebDemoInsertActivity($db, $roomId, 'rotation_vote_updated', ['rotation_index' => 1, 'demo' => 1], typebDemoNow('-20 minutes'));
        }
    );

    // 5) Active + pending votes (closed) => no vote buttons, shows closed text
    $opensPast2 = typebDemoNow('-12 hours');
    $duePast = typebDemoNow('-1 hour');

    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Active (pending votes, closed)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '30.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-30 days'),
            'reveal_at' => typebDemoNow('-30 days'),
            'swap_window_ends_at' => null,
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4, $opensPast2, $duePast): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u2, $u4], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'pending_votes',
                'approve_opens_at' => $opensPast2,
                'approve_due_at' => $duePast,
            ]);

            // Simulate a reject vote to see approvalsEffective logic after close.
            typebDemoInsertVote($db, $roomId, $u1, 'typeB_turn_unlock', 1, 'reject', typebDemoNow('-2 hours'));

            typebDemoInsertActivity($db, $roomId, 'rotation_vote_updated', ['rotation_index' => 1, 'demo' => 1], typebDemoNow('-90 minutes'));
        }
    );

    // 6) Active + maker-only vote (2 participants) => maker sees vote buttons even when eligible=0
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Active (maker-only vote; 2 participants)',
        $u1,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 2,
            'max_participants' => 2,
            'participation_amount' => '60.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-15 days'),
            'reveal_at' => typebDemoNow('-15 days'),
            'swap_window_ends_at' => null,
        ],
        function (string $roomId) use ($db, $u1, $u3): void {
            typebDemoSetParticipant($db, $roomId, $u1, 'active', 1);
            typebDemoSetParticipant($db, $roomId, $u3, 'active', 2);

            typebDemoSetQueue($db, $roomId, [$u3, $u1], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'pending_votes',
                'approve_opens_at' => typebDemoNow('-30 minutes'),
                'approve_due_at' => typebDemoNow('+6 hours'),
            ]);

            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '120.00', 'source_type' => 'seed', 'source_id' => 'seed:maker_only', 'created_by_user_id' => $u1, 'created_at' => typebDemoNow('-2 hours')],
            ]);
        }
    );

    // 7) Revealed (turn user = primary) + can set delegate (within 12h)
    $revealedAt = typebDemoNow('-1 hour');
    $expiresAt = typebDemoNow('+2 days');
    $disputeEnds = typebDemoNow('+8 hours');

    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Revealed (turn user; can set delegate + confirm withdrawal)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '55.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-40 days'),
            'reveal_at' => typebDemoNow('-40 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4, $revealedAt, $expiresAt, $disputeEnds): void {
            foreach ([$u2,$u1,$u3,$u4] as $i => $uid) {
                typebDemoSetParticipant($db, $roomId, (int)$uid, 'active', $i + 1);
            }

            typebDemoSetQueue($db, $roomId, [$u1, $u2, $u3, $u4], $u1);

            $winId = typebDemoUpsertRotationWindow($db, $roomId, 1, $u1, [
                'status' => 'revealed',
                'revealed_at' => $revealedAt,
                'expires_at' => $expiresAt,
                'dispute_window_ends_at' => $disputeEnds,
            ]);

            // Sufficient balance to allow confirmation.
            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '220.00', 'source_type' => 'seed', 'source_id' => 'seed:revealed_turn', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-6 hours')],
            ]);

            typebDemoInsertActivity($db, $roomId, 'typeB_turn_revealed', ['rotation_index' => 1, 'window_id' => $winId, 'demo' => 1], $revealedAt);
        }
    );

    // 8) Revealed (maker can reveal after 12h)
    $revealedAtOld = typebDemoNow('-13 hours');

    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Revealed (maker can reveal after 12h)',
        $u1,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '35.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-25 days'),
            'reveal_at' => typebDemoNow('-25 days'),
        ],
        function (string $roomId) use ($db, $u1, $u3, $u4, $u5, $revealedAtOld): void {
            foreach ([$u1,$u3,$u4,$u5] as $i => $uid) {
                typebDemoSetParticipant($db, $roomId, (int)$uid, 'active', $i + 1);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u4, $u5], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'revealed',
                'revealed_at' => $revealedAtOld,
                'expires_at' => typebDemoNow('+2 days'),
                'delegate_user_id' => null,
            ]);

            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '140.00', 'source_type' => 'seed', 'source_id' => 'seed:revealed_maker', 'created_by_user_id' => $u1, 'created_at' => typebDemoNow('-20 hours')],
            ]);
        }
    );

    // 9) Revealed (delegate can reveal)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Revealed (delegate can reveal)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '45.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-60 days'),
            'reveal_at' => typebDemoNow('-60 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4): void {
            foreach ([$u2,$u3,$u1,$u4] as $i => $uid) {
                typebDemoSetParticipant($db, $roomId, (int)$uid, 'active', $i + 1);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u2, $u1, $u4], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'revealed',
                'revealed_at' => typebDemoNow('-2 hours'),
                'expires_at' => typebDemoNow('+2 days'),
                'delegate_user_id' => $u1,
                'delegate_set_at' => typebDemoNow('-90 minutes'),
            ]);

            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '180.00', 'source_type' => 'seed', 'source_id' => 'seed:revealed_delegate', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-2 hours')],
            ]);
        }
    );

    // 10) Blocked (unpaid contribution)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Blocked debt (unpaid contribution)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '20.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-18 days'),
            'reveal_at' => typebDemoNow('-18 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u2, $u4], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'blocked_debt',
                'approve_opens_at' => typebDemoNow('-1 day'),
                'approve_due_at' => typebDemoNow('+1 day'),
            ]);

            // Create an active cycle in grace with unpaid contributions.
            $c1 = typebDemoInsertCycle($db, $roomId, 1, typebDemoNow('-1 day'), typebDemoNow('+2 days'), 'grace');
            if ($c1 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c1, $u3, '20.00', 'unpaid', null, null);
                typebDemoUpsertContribution($db, $roomId, $c1, $u1, '20.00', 'paid', 'DEMO-PAID-DEBT-1', typebDemoNow('-3 hours'));
                typebDemoUpsertContribution($db, $roomId, $c1, $u2, '20.00', 'paid', 'DEMO-PAID-DEBT-2', typebDemoNow('-4 hours'));
                typebDemoUpsertContribution($db, $roomId, $c1, $u4, '20.00', 'paid', 'DEMO-PAID-DEBT-3', typebDemoNow('-5 hours'));
            }

            typebDemoInsertActivity($db, $roomId, 'typeB_turn_blocked_debt', ['rotation_index' => 1, 'demo' => 1], typebDemoNow('-1 hour'));
        }
    );

    // 11) Blocked (dispute open)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Blocked dispute (open dispute + acks)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '22.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-70 days'),
            'reveal_at' => typebDemoNow('-70 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u3, $u1, $u2, $u4], $u3);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'blocked_dispute',
                'revealed_at' => typebDemoNow('-3 hours'),
                'expires_at' => typebDemoNow('+2 days'),
                'dispute_window_ends_at' => typebDemoNow('+10 hours'),
            ]);

            if (typebDemoHasTable($db, 'saving_room_disputes')) {
                $db->prepare("INSERT INTO saving_room_disputes (room_id, rotation_index, raised_by_user_id, reason, status, threshold_count_required, created_at)
                              VALUES (?, 1, ?, 'Demo dispute: incorrect payout', 'open', 2, ?)")
                   ->execute([$roomId, $u4, typebDemoNow('-1 hour')]);

                $dispId = (int)$db->lastInsertId();

                if ($dispId > 0 && typebDemoHasTable($db, 'saving_room_dispute_ack')) {
                    $db->prepare('INSERT IGNORE INTO saving_room_dispute_ack (dispute_id, user_id, created_at) VALUES (?, ?, ?)')
                       ->execute([$dispId, $u1, typebDemoNow('-30 minutes')]);
                }
            }

            typebDemoInsertActivity($db, $roomId, 'dispute_raised', ['rotation_index' => 1, 'demo' => 1], typebDemoNow('-55 minutes'));
        }
    );

    // 12) Exit request (open) + votes
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Exit request (open + votes)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '15.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-90 days'),
            'reveal_at' => typebDemoNow('-90 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            if (typebDemoHasTable($db, 'saving_room_exit_requests')) {
                $db->prepare("INSERT INTO saving_room_exit_requests (room_id, requested_by_user_id, reason, status, created_at)
                              VALUES (?, ?, 'Demo exit request', 'open', ?)")
                   ->execute([$roomId, $u3, typebDemoNow('-2 hours')]);

                $reqId = (int)$db->lastInsertId();

                if ($reqId > 0) {
                    // Maker approves, participant votes.
                    typebDemoInsertVote($db, $roomId, $u2, 'typeB_exit_request', $reqId, 'approve', typebDemoNow('-90 minutes'));
                    typebDemoInsertVote($db, $roomId, $u1, 'typeB_exit_request', $reqId, 'approve', typebDemoNow('-80 minutes'));

                    typebDemoInsertActivity($db, $roomId, 'exit_requested', ['exit_request_id' => $reqId, 'demo' => 1], typebDemoNow('-2 hours'));
                    typebDemoInsertActivity($db, $roomId, 'exit_vote_updated', ['exit_request_id' => $reqId, 'demo' => 1], typebDemoNow('-70 minutes'));
                }
            }
        }
    );

    // 13) Rotation history with collected amounts (ledger withdrawal entries source_id=window_id)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Rotation history (collected amount column)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '10.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-200 days'),
            'reveal_at' => typebDemoNow('-200 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u3, $u4): void {
            foreach ([[$u2,1],[$u1,2],[$u3,3],[$u4,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            // Window #1: expired (past)
            $w1 = typebDemoUpsertRotationWindow($db, $roomId, 1, $u3, [
                'status' => 'expired',
                'revealed_at' => typebDemoNow('-25 days'),
                'expires_at' => typebDemoNow('-24 days'),
                'withdrawal_confirmed_at' => typebDemoNow('-24 days'),
                'withdrawal_confirmed_by_user_id' => $u2,
                'withdrawal_reference' => 'DEMO-WD-001',
                'withdrawal_confirmed_role' => 'maker',
            ]);

            // Window #2: revealed (current)
            $w2 = typebDemoUpsertRotationWindow($db, $roomId, 2, $u1, [
                'status' => 'revealed',
                'revealed_at' => typebDemoNow('-2 hours'),
                'expires_at' => typebDemoNow('+3 days'),
            ]);

            typebDemoSetQueue($db, $roomId, [$u1, $u2, $u3, $u4], $u1, 2);

            if (typebDemoHasTable($db, 'saving_room_turn_code_views')) {
                $db->prepare('INSERT IGNORE INTO saving_room_turn_code_views (room_id, rotation_index, viewer_user_id, viewer_role, viewed_at)
                              VALUES (?, 1, ?, \'maker\', ?)')
                   ->execute([$roomId, $u2, typebDemoNow('-24 days')]);
            }

            // Ledger: contributions then withdrawal for window #1, leaving balance; then contributions for window #2.
            typebDemoInsertLedgerFromEntries($db, $roomId, [
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '40.00', 'source_type' => 'seed', 'source_id' => 'seed:hist_credit1', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-26 days')],
                ['entry_type' => 'debit', 'entry_kind' => 'withdrawal', 'amount' => '30.00', 'source_type' => 'withdrawal', 'source_id' => (string)$w1, 'created_by_user_id' => $u3, 'created_at' => typebDemoNow('-24 days')],
                ['entry_type' => 'credit', 'entry_kind' => 'contribution', 'amount' => '40.00', 'source_type' => 'seed', 'source_id' => 'seed:hist_credit2', 'created_by_user_id' => $u2, 'created_at' => typebDemoNow('-3 hours')],
            ]);

            typebDemoInsertActivity($db, $roomId, 'typeB_withdrawal_confirmed', ['rotation_index' => 1, 'amount' => '30.00', 'turn_user_name' => 'Demo', 'demo' => 1], typebDemoNow('-24 days'));
            typebDemoInsertActivity($db, $roomId, 'typeB_turn_revealed', ['rotation_index' => 2, 'window_id' => $w2, 'demo' => 1], typebDemoNow('-2 hours'));
        }
    );

    // 14) Proof tasks + proof gallery (rooms_proofs.php + room_proofs.php)
    $outRooms[] = typebDemoEnsureRoom(
        $db,
        $destAccountId,
        TYPEB_DEMO_PREFIX . 'Proof tasks + gallery (upcoming/overdue/missed + proofs)',
        $u2,
        [
            'room_state' => 'active',
            'lobby_state' => 'locked',
            'min_participants' => 3,
            'max_participants' => 6,
            'participation_amount' => '33.00',
            'periodicity' => 'weekly',
            'start_at' => typebDemoNow('-7 days'),
            'reveal_at' => typebDemoNow('-7 days'),
        ],
        function (string $roomId) use ($db, $u1, $u2, $u4, $u5): void {
            foreach ([[$u2,1],[$u1,2],[$u4,3],[$u5,4]] as $row) {
                typebDemoSetParticipant($db, $roomId, (int)$row[0], 'active', (int)$row[1]);
            }

            typebDemoSetQueue($db, $roomId, [$u4, $u1, $u2, $u5], $u4);

            typebDemoUpsertRotationWindow($db, $roomId, 1, $u4, [
                'status' => 'pending_votes',
                'approve_opens_at' => typebDemoNow('-2 hours'),
                'approve_due_at' => typebDemoNow('+1 day'),
            ]);

            $png = typebDemoPngBytes();

            // Cycle #1: upcoming (primary user has NOT contributed yet)
            $c1 = typebDemoInsertCycle($db, $roomId, 1, typebDemoNow('+5 days'), typebDemoNow('+7 days'), 'open');
            if ($c1 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c1, $u1, '33.00', 'unpaid', null, null);

                foreach ([$u2,$u4,$u5] as $uid) {
                    typebDemoUpsertContribution($db, $roomId, $c1, (int)$uid, '33.00', 'paid', 'DEMO-PROOF-UPCOMING-' . $uid, typebDemoNow('-6 hours'));
                    $cid = typebDemoFindContributionId($db, $roomId, $c1, (int)$uid);
                    typebDemoInsertProof($db, $roomId, $cid, (int)$uid, null, 'proof-cycle1-' . $uid . '.png', 'image/png', $png, typebDemoNow('-6 hours'));
                }
            }

            // Cycle #2: overdue in grace (primary still unpaid)
            $c2 = typebDemoInsertCycle($db, $roomId, 2, typebDemoNow('-1 day'), typebDemoNow('+1 day'), 'grace');
            if ($c2 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c2, $u1, '33.00', 'unpaid', null, null);

                typebDemoUpsertContribution($db, $roomId, $c2, $u2, '33.00', 'paid', 'DEMO-PROOF-GRACE-MAKER', typebDemoNow('-3 hours'));
                $cid2m = typebDemoFindContributionId($db, $roomId, $c2, $u2);
                typebDemoInsertProof($db, $roomId, $cid2m, $u2, null, 'proof-cycle2-maker.png', 'image/png', $png, typebDemoNow('-3 hours'));

                typebDemoUpsertContribution($db, $roomId, $c2, $u4, '33.00', 'paid_in_grace', 'DEMO-PROOF-GRACE-1', typebDemoNow('-2 hours'));
                $cid2 = typebDemoFindContributionId($db, $roomId, $c2, $u4);
                typebDemoInsertProof($db, $roomId, $cid2, $u4, null, 'proof-cycle2-1.png', 'image/png', $png, typebDemoNow('-2 hours'));

                typebDemoUpsertContribution($db, $roomId, $c2, $u5, '33.00', 'paid_in_grace', 'DEMO-PROOF-GRACE-2', typebDemoNow('-90 minutes'));
                $cid2b = typebDemoFindContributionId($db, $roomId, $c2, $u5);
                typebDemoInsertProof($db, $roomId, $cid2b, $u5, null, 'proof-cycle2-2.png', 'image/png', $png, typebDemoNow('-90 minutes'));
            }

            // Cycle #3: missed contribution (shows in rooms_proofs task list)
            $c3 = typebDemoInsertCycle($db, $roomId, 3, typebDemoNow('-12 days'), typebDemoNow('-10 days'), 'closed');
            if ($c3 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c3, $u1, '33.00', 'missed', null, null);
            }

            // Cycle #4: paid + proof for primary (shows in "My proofs")
            $c4 = typebDemoInsertCycle($db, $roomId, 4, typebDemoNow('-20 days'), typebDemoNow('-18 days'), 'closed');
            if ($c4 > 0) {
                typebDemoUpsertContribution($db, $roomId, $c4, $u1, '33.00', 'paid', 'DEMO-PROOF-PAID', typebDemoNow('-19 days'));
                $cid4 = typebDemoFindContributionId($db, $roomId, $c4, $u1);
                typebDemoInsertProof($db, $roomId, $cid4, $u1, null, 'proof-primary.png', 'image/png', $png, typebDemoNow('-19 days'));
            }

            typebDemoInsertActivity($db, $roomId, 'room_created', ['demo' => 1], typebDemoNow('-7 days'));
        }
    );

    $db->commit();

} catch (Throwable $e) {
    $db->rollBack();
    fwrite(STDERR, 'Seed failed: ' . $e->getMessage() . "\n");
    exit(1);
}

// Output

echo "\nType B demo data generated.\n\n";
echo "Demo password (for newly created demo accounts): {$demoPassword}\n\n";

echo "Rooms:\n";
foreach ($outRooms as $r) {
    echo "- {$r['goal']}: {$r['id']}\n";
}

echo "\nUseful logins (if created):\n";
echo "- typeb.maker@example.com\n";
echo "- typeb.turn@example.com\n";
echo "- typeb.participant1@example.com\n";
echo "- typeb.participant2@example.com\n";
echo "- typeb.participant3@example.com\n";

echo "\nPrimary user_id used for scenario coverage: {$u1}\n";
