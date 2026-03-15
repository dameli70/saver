<?php
// ============================================================
//  API: /api/admin.php
//  Super admin dashboard data endpoints
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/packages.php';
header('Content-Type: application/json');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireAdmin();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function intParam(mixed $v, int $default = 0): int {
    if ($v === null) return $default;
    if (is_int($v)) return $v;
    $s = trim((string)$v);
    if ($s === '' || !preg_match('/^-?\d+$/', $s)) return $default;
    return (int)$s;
}

function hasColumn(PDO $db, string $table, string $column): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
    $stmt->execute([$table, $column]);
    return (bool)$stmt->fetchColumn();
}

function roomActivity(PDO $db, string $roomId, string $eventType, array $payload): void {
    $db->prepare('INSERT INTO saving_room_activity (room_id, event_type, public_payload_json) VALUES (?, ?, ?)')
       ->execute([$roomId, $eventType, json_encode($payload, JSON_UNESCAPED_UNICODE)]);
}

function notifyOnceAdmin(PDO $db, int $userId, string $eventKey, string $tier, string $title, string $body, array $data = [], string $refType = null, string $refId = null, string $channelMask = ''): void {
    try {
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
    } catch (Throwable) {
        // Best effort: do not break admin actions if notifications tables are missing.
        return;
    }
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

function applyStrikeDb(PDO $db, int $userId, string $strikeType, ?string $roomId = null): void {
    $db->prepare('INSERT INTO user_strikes (user_id, room_id, cycle_id, strike_type) VALUES (?, ?, NULL, ?)')
       ->execute([(int)$userId, $roomId, $strikeType]);

    ensureTrustRow($db, $userId);

    $t = $db->prepare('SELECT trust_level, last_level_change_at FROM user_trust WHERE user_id = ?');
    $t->execute([(int)$userId]);
    $row = $t->fetch();
    $lvl = (int)($row['trust_level'] ?? 1);
    $last = $row['last_level_change_at'] ? strtotime((string)$row['last_level_change_at']) : null;

    $count = strikes6m($db, $userId);
    if ($count >= 3) {
        $until = (new DateTimeImmutable('now'))->modify('+30 days')->format('Y-m-d H:i:s');
        $db->prepare("INSERT INTO user_restrictions (user_id, restricted_until, reason, updated_at)
                      VALUES (?, ?, 'strikes_6m', NOW())
                      ON DUPLICATE KEY UPDATE restricted_until = GREATEST(restricted_until, VALUES(restricted_until)), reason='strikes_6m', updated_at=NOW()")
           ->execute([(int)$userId, $until]);

        $sixMonthsAgo = time() - (183 * 86400);
        if ($lvl > 1 && (!$last || $last < $sixMonthsAgo)) {
            $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
               ->execute([max(1, $lvl - 1), (int)$userId]);
        }
    }
}

function advanceTypeBWindow(PDO $db, string $roomId, int $rotationIndex): void {
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
        $st = $db->prepare('SELECT status FROM saving_room_participants WHERE room_id = ? AND user_id = ?');
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

        roomActivity($db, $roomId, 'typeB_turn_advanced', ['rotation_index' => $nextIndex]);
    }
}

if ($method === 'GET') {
    $action = $_GET['action'] ?? '';

    // ── USERS LIST ───────────────────────────────────────────
    if ($action === 'users') {
        $db = getDB();
        $rows = $db->query("
            SELECT
                u.id,
                u.email,
                u.is_admin,
                u.email_verified_at,
                u.verification_sent_at,
                u.created_at,
                u.last_login,
                COALESCE(ut.trust_level, 1) AS trust_level,
                COUNT(l.id) AS codes_total,
                SUM(CASE WHEN l.is_active = 1 THEN 1 ELSE 0 END) AS codes_active
            FROM users u
            LEFT JOIN user_trust ut ON ut.user_id = u.id
            LEFT JOIN locks l ON l.user_id = u.id
            GROUP BY u.id, u.email, u.is_admin, u.email_verified_at, u.verification_sent_at, u.created_at, u.last_login, ut.trust_level
            ORDER BY u.created_at DESC
        ")->fetchAll();

        jsonResponse(['success' => true, 'users' => $rows]);
    }

    // ── CODES LIST ───────────────────────────────────────────
    if ($action === 'codes') {
        $db = getDB();

        $limit  = intParam($_GET['limit'] ?? 200, 200);
        $offset = intParam($_GET['offset'] ?? 0, 0);
        $limit  = max(1, min(500, $limit));
        $offset = max(0, $offset);

        $userId = intParam($_GET['user_id'] ?? 0, 0);
        $q      = trim((string)($_GET['q'] ?? ''));
        $includeInactive = !empty($_GET['include_inactive']);

        $where = [];
        $params = [];

        if (!$includeInactive) {
            $where[] = 'l.is_active = 1';
        }
        if ($userId > 0) {
            $where[] = 'l.user_id = ?';
            $params[] = $userId;
        }
        if ($q !== '') {
            $where[] = '(u.email LIKE ? OR l.label LIKE ?)';
            $params[] = '%' . $q . '%';
            $params[] = '%' . $q . '%';
        }

        $sql = "
            SELECT
                l.id,
                l.user_id,
                u.email AS user_email,
                l.label,
                l.password_type,
                l.password_length,
                l.hint,
                l.reveal_date,
                l.confirmation_status,
                l.copied_at,
                l.confirmed_at,
                l.rejected_at,
                l.auto_saved_at,
                l.revealed_at,
                l.is_active,
                l.created_at
            FROM locks l
            JOIN users u ON u.id = l.user_id
        ";

        if (!empty($where)) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }

        $sql .= ' ORDER BY l.created_at DESC LIMIT :limit OFFSET :offset';

        $stmt = $db->prepare($sql);
        foreach ($params as $i => $p) {
            $stmt->bindValue($i + 1, $p);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        jsonResponse(['success' => true, 'codes' => $stmt->fetchAll(), 'limit' => $limit, 'offset' => $offset]);
    }

    // ── CODE DETAIL ──────────────────────────────────────────
    if ($action === 'code_detail') {
        $lockId = trim((string)($_GET['lock_id'] ?? ''));
        if ($lockId === '') jsonResponse(['error' => 'lock_id required'], 400);

        $db = getDB();
        $stmt = $db->prepare("
            SELECT
                l.*, u.email AS user_email
            FROM locks l
            JOIN users u ON u.id = l.user_id
            WHERE l.id = ?
            LIMIT 1
        ");
        $stmt->execute([$lockId]);
        $row = $stmt->fetch();
        if (!$row) jsonResponse(['error' => 'Code not found'], 404);

        jsonResponse(['success' => true, 'code' => $row]);
    }

    // ── CARRIERS LIST ───────────────────────────────────────
    if ($action === 'carriers') {
        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

        $hasWalletCols = hasColumn($db, 'carriers', 'wallet_default_action')
            && hasColumn($db, 'carriers', 'wallet_allow_open_dialer')
            && hasColumn($db, 'carriers', 'wallet_allow_copy_ussd');

        if ($hasWalletCols) {
            $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, wallet_allow_open_dialer, wallet_allow_copy_ussd, wallet_default_action, is_active, created_at, updated_at FROM carriers ORDER BY name ASC")->fetchAll();
            foreach ($rows as &$r) {
                $r['wallet_allow_open_dialer'] = (int)$r['wallet_allow_open_dialer'];
                $r['wallet_allow_copy_ussd'] = (int)$r['wallet_allow_copy_ussd'];
                $r['wallet_default_action'] = (string)$r['wallet_default_action'];
            }
            unset($r);
        } else {
            $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at FROM carriers ORDER BY name ASC")->fetchAll();
            foreach ($rows as &$r) {
                $r['wallet_allow_open_dialer'] = 1;
                $r['wallet_allow_copy_ussd'] = 1;
                $r['wallet_default_action'] = 'open_dialer';
            }
            unset($r);
        }

        jsonResponse(['success' => true, 'carriers' => $rows]);
    }

    // ── DESTINATION ACCOUNTS (saving rooms) ─────────────────
    if ($action === 'destination_accounts') {
        $db = getDB();
        $rows = $db->query("SELECT id, account_type, carrier_id, mobile_money_number, bank_name, bank_account_name, bank_account_number, bank_routing_number, bank_swift, bank_iban,
                                   code_rotated_at, code_rotation_version, is_active, created_at, updated_at
                            FROM platform_destination_accounts
                            ORDER BY id DESC")->fetchAll();
        jsonResponse(['success' => true, 'accounts' => $rows]);
    }

    if ($action === 'room_accounts') {
        $db = getDB();
        $limit  = intParam($_GET['limit'] ?? 200, 200);
        $limit  = max(1, min(500, $limit));

        $rows = $db->query("SELECT r.id AS room_id, r.goal_text, r.saving_type, r.room_state, r.start_at, r.reveal_at,
                                   a.account_id,
                                   pda.account_type, pda.mobile_money_number, pda.bank_name, pda.bank_account_number,
                                   pda.code_rotation_version, pda.is_active
                            FROM saving_rooms r
                            LEFT JOIN saving_room_accounts a ON a.room_id = r.id
                            LEFT JOIN platform_destination_accounts pda ON pda.id = a.account_id
                            ORDER BY r.created_at DESC
                            LIMIT {$limit}")->fetchAll();
        jsonResponse(['success' => true, 'rooms' => $rows]);
    }

    // ── DISPUTES (saving rooms) ─────────────────────────────
    if ($action === 'disputes') {
        $db = getDB();

        $limit  = intParam($_GET['limit'] ?? 200, 200);
        $limit  = max(1, min(500, $limit));

        $includeResolved = !empty($_GET['include_resolved']);

        $where = $includeResolved ? '' : "WHERE d.status IN ('open','threshold_met','escalated_admin')";

        $sql = "SELECT
                    d.id,
                    d.room_id,
                    d.rotation_index,
                    d.status,
                    d.reason,
                    d.threshold_count_required,
                    d.created_at,
                    d.updated_at,
                    r.goal_text,
                    u.email AS raised_by_email,
                    (SELECT COUNT(*) FROM saving_room_dispute_ack a WHERE a.dispute_id = d.id) AS ack_count
                FROM saving_room_disputes d
                JOIN saving_rooms r ON r.id = d.room_id
                JOIN users u ON u.id = d.raised_by_user_id
                {$where}
                ORDER BY d.created_at DESC
                LIMIT {$limit}";

        $rows = $db->query($sql)->fetchAll();
        jsonResponse(['success' => true, 'disputes' => $rows]);
    }

    // ── ESCROW SETTLEMENTS (saving rooms) ───────────────────
    if ($action === 'escrow_settlements') {
        $db = getDB();

        $limit  = intParam($_GET['limit'] ?? 200, 200);
        $limit  = max(1, min(500, $limit));

        $includeProcessed = !empty($_GET['include_processed']);

        $where = $includeProcessed ? '' : "WHERE s.status = 'recorded'";

        $sql = "SELECT
                    s.id,
                    s.room_id,
                    r.goal_text,
                    r.escrow_policy,
                    r.maker_user_id,
                    mu.email AS maker_email,
                    s.removed_user_id,
                    ru.email AS removed_user_email,
                    s.policy,
                    s.reason,
                    s.fee_rate,
                    s.total_contributed,
                    s.platform_fee_amount,
                    s.refund_amount,
                    s.redistribution_json,
                    s.status,
                    s.created_at,
                    s.processed_at
                FROM saving_room_escrow_settlements s
                JOIN saving_rooms r ON r.id = s.room_id
                JOIN users ru ON ru.id = s.removed_user_id
                LEFT JOIN users mu ON mu.id = r.maker_user_id
                {$where}
                ORDER BY s.created_at DESC
                LIMIT {$limit}";

        $rows = [];
        foreach ($db->query($sql)->fetchAll() as $r) {
            $rows[] = [
                'id' => (int)$r['id'],
                'room_id' => (string)$r['room_id'],
                'goal_text' => $r['goal_text'],
                'maker_user_id' => (int)$r['maker_user_id'],
                'maker_email' => $r['maker_email'],
                'removed_user_id' => (int)$r['removed_user_id'],
                'removed_user_email' => $r['removed_user_email'],
                'policy' => $r['policy'],
                'reason' => $r['reason'] ?? null,
                'fee_rate' => isset($r['fee_rate']) ? (string)$r['fee_rate'] : null,
                'total_contributed' => (string)$r['total_contributed'],
                'platform_fee_amount' => (string)$r['platform_fee_amount'],
                'refund_amount' => (string)$r['refund_amount'],
                'redistribution' => $r['redistribution_json'] ? json_decode((string)$r['redistribution_json'], true) : null,
                'status' => $r['status'],
                'created_at' => $r['created_at'],
                'processed_at' => $r['processed_at'],
            ];
        }

        jsonResponse(['success' => true, 'settlements' => $rows]);
    }

    // ── AUDIT LOG ────────────────────────────────────────────
    if ($action === 'audit') {
        $db = getDB();

        $limit  = intParam($_GET['limit'] ?? 200, 200);
        $offset = intParam($_GET['offset'] ?? 0, 0);
        $limit  = max(1, min(500, $limit));
        $offset = max(0, $offset);

        $q = trim((string)($_GET['q'] ?? ''));

        $where = [];
        $params = [];
        if ($q !== '') {
            $where[] = '(u.email LIKE ? OR a.action LIKE ? OR a.lock_id LIKE ?)';
            $params[] = '%' . $q . '%';
            $params[] = '%' . $q . '%';
            $params[] = '%' . $q . '%';
        }

        $sql = "
            SELECT
                a.id,
                a.user_id,
                u.email AS user_email,
                a.lock_id,
                a.action,
                a.ip_address,
                a.user_agent,
                a.created_at
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id
        ";

        if (!empty($where)) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }

        $sql .= ' ORDER BY a.created_at DESC LIMIT :limit OFFSET :offset';

        $stmt = $db->prepare($sql);
        foreach ($params as $i => $p) {
            $stmt->bindValue($i + 1, $p);
        }
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        jsonResponse(['success' => true, 'audit' => $stmt->fetchAll(), 'limit' => $limit, 'offset' => $offset]);
    }

    // ── PACKAGES / PURCHASES ─────────────────────────────────
    if ($action === 'packages') {
        if (!hasPackagesTables()) {
            jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
        }

        $db = getDB();
        packagesSeedDefaults($db);

        $packages = packagesGetAll($db, false);
        $purchases = $db->query("SELECT pp.id, pp.user_id, u.email AS user_email, pp.package_id, p.name AS package_name, pp.status, pp.created_at, pp.decided_at
                                 FROM package_purchases pp
                                 JOIN users u ON u.id = pp.user_id
                                 JOIN packages p ON p.id = pp.package_id
                                 ORDER BY pp.created_at DESC
                                 LIMIT 500")->fetchAll();
        $assignments = $db->query("SELECT up.user_id, u.email AS user_email, up.package_id, p.name AS package_name, up.assigned_at, up.is_active
                                   FROM user_packages up
                                   JOIN users u ON u.id = up.user_id
                                   JOIN packages p ON p.id = up.package_id
                                   ORDER BY up.assigned_at DESC
                                   LIMIT 500")->fetchAll();

        jsonResponse(['success' => true, 'packages' => $packages, 'purchases' => $purchases, 'assignments' => $assignments]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

if ($method === 'POST') {
    requireCsrf();

    $body = json_decode(file_get_contents('php://input'), true);
    $action = (string)($body['action'] ?? '');

    // ── CREATE USER ──────────────────────────────────────────
    if ($action === 'create_user') {
        requireStrongAuth();

        $email        = strtolower(trim((string)($body['email'] ?? '')));
        $loginPwd     = (string)($body['login_password'] ?? '');
        $trustLevel   = intParam($body['trust_level'] ?? 1, 1);
        $makeAdmin    = !empty($body['is_admin']);
        $markVerified = !empty($body['mark_verified']);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['error' => 'Invalid email'], 400);
        if (strlen($loginPwd) < 8) jsonResponse(['error' => 'Login password must be at least 8 characters'], 400);
        if (!in_array($trustLevel, [1, 2, 3], true)) $trustLevel = 1;

        $db = getDB();
        $check = $db->prepare('SELECT id FROM users WHERE email = ?');
        $check->execute([$email]);
        if ($check->fetch()) jsonResponse(['error' => 'Email already registered'], 409);

        $loginHash = hashLoginPassword($loginPwd);

        // Vault passphrase is never sent to the server.
        // Legacy schema still requires verifier fields, so we store non-usable placeholders.
        $vaultVerifierSalt = bin2hex(random_bytes(32));
        $vaultVerifier = hashVaultVerifier(bin2hex(random_bytes(32)) . $vaultVerifierSalt);

        $emailVerifiedAt = $markVerified ? (new DateTime())->format('Y-m-d H:i:s') : null;

        $stmt = $db->prepare("INSERT INTO users (email, login_hash, vault_verifier, vault_verifier_salt, is_admin, email_verified_at, email_verification_hash, email_verification_expires_at, verification_sent_at)
                              VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)");
        $stmt->execute([
            $email,
            $loginHash,
            $vaultVerifier,
            $vaultVerifierSalt,
            $makeAdmin ? 1 : 0,
            $emailVerifiedAt,
        ]);

        $userId = (int)$db->lastInsertId();
        ensureTrustRow($db, $userId);
        if ($trustLevel !== 1) {
            $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
               ->execute([$trustLevel, $userId]);
        }

        // Ensure key platform defaults are set for the user (for older installs / partial migrations).
        if (hasColumn($db, 'users', 'vault_active_slot')) {
            $db->prepare('UPDATE users SET vault_active_slot = 1 WHERE id = ?')->execute([$userId]);
        }
        if (hasColumn($db, 'users', 'vault_check_iterations')) {
            $db->prepare('UPDATE users SET vault_check_iterations = ? WHERE id = ?')->execute([PBKDF2_ITERATIONS, $userId]);
        }
        if (hasColumn($db, 'users', 'require_webauthn')) {
            $db->prepare('UPDATE users SET require_webauthn = 0 WHERE id = ?')->execute([$userId]);
        }

        $devVerifyUrl = null;
        if (!$markVerified) {
            $devVerifyUrl = issueEmailVerification($userId, $email);
        }

        auditLog('admin_create_user', null, getCurrentUserId());
        jsonResponse(['success' => true, 'user_id' => $userId, 'dev_verify_url' => $devVerifyUrl]);
    }

    // ── SET ADMIN FLAG ───────────────────────────────────────
    if ($action === 'set_admin') {
        requireStrongAuth();

        $userId = intParam($body['user_id'] ?? 0, 0);
        $isAdmin = !empty($body['is_admin']) ? 1 : 0;
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);

        $db = getDB();

        if ($isAdmin === 0) {
            $admins = (int)$db->query('SELECT COUNT(*) FROM users WHERE is_admin = 1')->fetchColumn();
            $cur = $db->prepare('SELECT is_admin FROM users WHERE id = ?');
            $cur->execute([$userId]);
            $row = $cur->fetch();
            if (!empty($row['is_admin']) && $admins <= 1) {
                jsonResponse(['error' => 'Cannot remove admin from the last admin user'], 400);
            }
        }

        $db->prepare('UPDATE users SET is_admin = ? WHERE id = ?')->execute([$isAdmin, $userId]);

        // If the admin is modifying themselves, refresh the session.
        if ($userId === (int)getCurrentUserId()) {
            $_SESSION['is_admin'] = $isAdmin;
        }

        auditLog('admin_set_admin', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── MARK VERIFIED / UNVERIFIED ───────────────────────────
    if ($action === 'set_verified') {
        requireStrongAuth();

        $userId = intParam($body['user_id'] ?? 0, 0);
        $verified = !empty($body['verified']) ? 1 : 0;
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);

        $db = getDB();
        if ($verified) {
            $db->prepare('UPDATE users SET email_verified_at = NOW(), email_verification_hash = NULL, email_verification_expires_at = NULL WHERE id = ?')
               ->execute([$userId]);

            if (hasColumn($db, 'users', 'vault_active_slot')) {
                $db->prepare('UPDATE users SET vault_active_slot = 1 WHERE id = ?')->execute([$userId]);
            }
            if (hasColumn($db, 'users', 'vault_check_iterations')) {
                $db->prepare('UPDATE users SET vault_check_iterations = ? WHERE id = ?')->execute([PBKDF2_ITERATIONS, $userId]);
            }
            if (hasColumn($db, 'users', 'require_webauthn')) {
                $db->prepare('UPDATE users SET require_webauthn = 0 WHERE id = ?')->execute([$userId]);
            }
        } else {
            $db->prepare('UPDATE users SET email_verified_at = NULL WHERE id = ?')->execute([$userId]);
        }

        auditLog('admin_set_verified', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── SET TRUST LEVEL ─────────────────────────────────────
    if ($action === 'set_trust_level') {
        requireStrongAuth();

        $userId = intParam($body['user_id'] ?? 0, 0);
        $trustLevel = intParam($body['trust_level'] ?? 1, 1);
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);
        if (!in_array($trustLevel, [1,2,3], true)) jsonResponse(['error' => 'Invalid trust_level'], 400);

        $db = getDB();
        ensureTrustRow($db, $userId);
        $db->prepare('UPDATE user_trust SET trust_level = ?, last_level_change_at = NOW() WHERE user_id = ?')
           ->execute([$trustLevel, $userId]);

        auditLog('admin_set_trust_level', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DELETE USER ─────────────────────────────────────────
    if ($action === 'delete_user') {
        requireStrongAuth();

        $userId = intParam($body['user_id'] ?? 0, 0);
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);

        $db = getDB();

        $cur = $db->prepare('SELECT is_admin FROM users WHERE id = ?');
        $cur->execute([$userId]);
        $row = $cur->fetch();
        if (!$row) jsonResponse(['error' => 'User not found'], 404);

        if (!empty($row['is_admin'])) {
            $admins = (int)$db->query('SELECT COUNT(*) FROM users WHERE is_admin = 1')->fetchColumn();
            if ($admins <= 1) jsonResponse(['error' => 'Cannot delete the last admin user'], 400);
        }

        $db->prepare('DELETE FROM users WHERE id = ?')->execute([$userId]);

        auditLog('admin_delete_user', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── PACKAGES: CREATE ────────────────────────────────────
    if ($action === 'package_create') {
        requireStrongAuth();

        if (!hasPackagesTables()) {
            jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
        }

        $slug = strtolower(trim((string)($body['slug'] ?? '')));
        $name = trim((string)($body['name'] ?? ''));

        if ($slug === '' || !preg_match('/^[a-z0-9_\-]{2,60}$/', $slug)) jsonResponse(['error' => 'Invalid slug'], 400);
        if ($name === '' || strlen($name) > 120) jsonResponse(['error' => 'Invalid name'], 400);

        $maxLocks = max(0, intParam($body['max_active_locks'] ?? 1, 1));
        $maxRooms = max(0, intParam($body['max_active_rooms'] ?? 1, 1));
        $maxWallet = max(0, intParam($body['max_active_wallet_locks'] ?? 1, 1));
        $fast = !empty($body['fast_support']) ? 1 : 0;

        $db = getDB();
        try {
            $db->prepare('INSERT INTO packages (slug, name, max_active_locks, max_active_rooms, max_active_wallet_locks, fast_support, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW())')
               ->execute([$slug, $name, $maxLocks, $maxRooms, $maxWallet, $fast]);
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            if (str_contains($msg, 'Duplicate') || str_contains($msg, 'UNIQUE')) {
                jsonResponse(['error' => 'Package slug already exists'], 409);
            }
            jsonResponse(['error' => 'Storage failed'], 500);
        }

        auditLog('admin_package_create', null, getCurrentUserId());
        jsonResponse(['success' => true, 'package_id' => (int)$db->lastInsertId()]);
    }

    // ── PACKAGES: UPDATE ────────────────────────────────────
    if ($action === 'package_update') {
        requireStrongAuth();

        if (!hasPackagesTables()) {
            jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
        }

        $packageId = intParam($body['package_id'] ?? 0, 0);
        if ($packageId < 1) jsonResponse(['error' => 'package_id required'], 400);

        $slug = strtolower(trim((string)($body['slug'] ?? '')));
        $name = trim((string)($body['name'] ?? ''));
        if ($slug === '' || !preg_match('/^[a-z0-9_\-]{2,60}$/', $slug)) jsonResponse(['error' => 'Invalid slug'], 400);
        if ($name === '' || strlen($name) > 120) jsonResponse(['error' => 'Invalid name'], 400);

        $maxLocks = max(0, intParam($body['max_active_locks'] ?? 1, 1));
        $maxRooms = max(0, intParam($body['max_active_rooms'] ?? 1, 1));
        $maxWallet = max(0, intParam($body['max_active_wallet_locks'] ?? 1, 1));
        $fast = !empty($body['fast_support']) ? 1 : 0;
        $isActive = !empty($body['is_active']) ? 1 : 0;

        $db = getDB();
        try {
            $db->prepare('UPDATE packages SET slug = ?, name = ?, max_active_locks = ?, max_active_rooms = ?, max_active_wallet_locks = ?, fast_support = ?, is_active = ?, updated_at = NOW() WHERE id = ?')
               ->execute([$slug, $name, $maxLocks, $maxRooms, $maxWallet, $fast, $isActive, $packageId]);
        } catch (Throwable $e) {
            $msg = $e->getMessage();
            if (str_contains($msg, 'Duplicate') || str_contains($msg, 'UNIQUE')) {
                jsonResponse(['error' => 'Package slug already exists'], 409);
            }
            jsonResponse(['error' => 'Storage failed'], 500);
        }

        auditLog('admin_package_update', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── PACKAGES: ASSIGN (direct) ────────────────────────────
    if ($action === 'assign_package') {
        requireStrongAuth();

        if (!hasPackagesTables()) {
            jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
        }

        $email = strtolower(trim((string)($body['email'] ?? '')));
        $packageId = intParam($body['package_id'] ?? 0, 0);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['error' => 'Invalid email'], 400);
        if ($packageId < 1) jsonResponse(['error' => 'package_id required'], 400);

        $db = getDB();
        $u = $db->prepare('SELECT id FROM users WHERE email = ?');
        $u->execute([$email]);
        $userId = (int)($u->fetchColumn() ?: 0);
        if ($userId < 1) jsonResponse(['error' => 'User not found'], 404);

        $p = $db->prepare('SELECT id FROM packages WHERE id = ?');
        $p->execute([$packageId]);
        if (!$p->fetchColumn()) jsonResponse(['error' => 'Package not found'], 404);

        $db->prepare('INSERT INTO user_packages (user_id, package_id, purchase_id, assigned_by_user_id, is_active, assigned_at, updated_at)
                      VALUES (?, ?, NULL, ?, 1, NOW(), NOW())
                      ON DUPLICATE KEY UPDATE package_id = VALUES(package_id), assigned_by_user_id = VALUES(assigned_by_user_id), is_active = 1, updated_at = NOW()')
           ->execute([$userId, $packageId, (int)getCurrentUserId()]);

        auditLog('admin_assign_package', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── PACKAGES: APPROVE PURCHASE ───────────────────────────
    if ($action === 'approve_package_purchase') {
        requireStrongAuth();

        if (!hasPackagesTables()) {
            jsonResponse(['error' => 'Packages are unavailable on this server. Apply database migrations.'], 409);
        }

        $purchaseId = intParam($body['purchase_id'] ?? 0, 0);
        if ($purchaseId < 1) jsonResponse(['error' => 'purchase_id required'], 400);

        $db = getDB();
        $pp = $db->prepare("SELECT id, user_id, package_id, status FROM package_purchases WHERE id = ? LIMIT 1");
        $pp->execute([$purchaseId]);
        $row = $pp->fetch();
        if (!$row) jsonResponse(['error' => 'Purchase not found'], 404);
        if ((string)$row['status'] !== 'pending') {
            jsonResponse(['success' => true, 'already_decided' => 1]);
        }

        $db->beginTransaction();

        $db->prepare("UPDATE package_purchases SET status='approved', decided_at=NOW(), decided_by_user_id=? WHERE id = ? AND status='pending'")
           ->execute([(int)getCurrentUserId(), $purchaseId]);

        $db->prepare('INSERT INTO user_packages (user_id, package_id, purchase_id, assigned_by_user_id, is_active, assigned_at, updated_at)
                      VALUES (?, ?, ?, ?, 1, NOW(), NOW())
                      ON DUPLICATE KEY UPDATE package_id = VALUES(package_id), purchase_id = VALUES(purchase_id), assigned_by_user_id = VALUES(assigned_by_user_id), is_active = 1, updated_at = NOW()')
           ->execute([(int)$row['user_id'], (int)$row['package_id'], $purchaseId, (int)getCurrentUserId()]);

        $db->commit();

        auditLog('admin_approve_package_purchase', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── CARRIERS: CREATE ────────────────────────────────────
    if ($action === 'carrier_create') {
        requireStrongAuth();

        $name = trim((string)($body['name'] ?? ''));
        $country = trim((string)($body['country'] ?? ''));
        $pinType = (string)($body['pin_type'] ?? 'numeric');
        $pinLen = intParam($body['pin_length'] ?? 4, 4);
        $ussdChange = trim((string)($body['ussd_change_pin_template'] ?? ''));
        $ussdBalance = trim((string)($body['ussd_balance_template'] ?? ''));
        $isActive = !empty($body['is_active']) ? 1 : 0;

        if ($name === '') jsonResponse(['error' => 'Name required'], 400);
        if (!in_array($pinType, ['numeric','alphanumeric'], true)) jsonResponse(['error' => 'Invalid pin_type'], 400);
        if ($pinLen < 3 || $pinLen > 16) jsonResponse(['error' => 'Invalid pin_length'], 400);
        if ($ussdChange === '' || $ussdBalance === '') jsonResponse(['error' => 'USSD templates required'], 400);

        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

        $hasWalletCols = hasColumn($db, 'carriers', 'wallet_default_action')
            && hasColumn($db, 'carriers', 'wallet_allow_open_dialer')
            && hasColumn($db, 'carriers', 'wallet_allow_copy_ussd');

        $walletAllowOpen = $hasWalletCols ? (!empty($body['wallet_allow_open_dialer']) ? 1 : 0) : null;
        $walletAllowCopy = $hasWalletCols ? (!empty($body['wallet_allow_copy_ussd']) ? 1 : 0) : null;
        $walletDefault = $hasWalletCols ? (string)($body['wallet_default_action'] ?? 'open_dialer') : null;
        if ($hasWalletCols && !in_array($walletDefault, ['open_dialer','copy_ussd'], true)) $walletDefault = 'open_dialer';

        if ($hasWalletCols) {
            $db->prepare('INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, wallet_allow_open_dialer, wallet_allow_copy_ussd, wallet_default_action, is_active, created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())')
               ->execute([
                   sanitize($name),
                   $country !== '' ? sanitize($country) : null,
                   $pinType,
                   $pinLen,
                   $ussdChange,
                   $ussdBalance,
                   $walletAllowOpen,
                   $walletAllowCopy,
                   $walletDefault,
                   $isActive,
               ]);
        } else {
            $db->prepare('INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())')
               ->execute([
                   sanitize($name),
                   $country !== '' ? sanitize($country) : null,
                   $pinType,
                   $pinLen,
                   $ussdChange,
                   $ussdBalance,
                   $isActive,
               ]);
        }

        auditLog('admin_carrier_create', null, getCurrentUserId());
        jsonResponse(['success' => true, 'carrier_id' => (int)$db->lastInsertId()]);
    }

    // ── CARRIERS: UPDATE ────────────────────────────────────
    if ($action === 'carrier_update') {
        requireStrongAuth();

        $carrierId = intParam($body['carrier_id'] ?? 0, 0);
        if ($carrierId < 1) jsonResponse(['error' => 'carrier_id required'], 400);

        $name = trim((string)($body['name'] ?? ''));
        $country = trim((string)($body['country'] ?? ''));
        $pinType = (string)($body['pin_type'] ?? 'numeric');
        $pinLen = intParam($body['pin_length'] ?? 4, 4);
        $ussdChange = trim((string)($body['ussd_change_pin_template'] ?? ''));
        $ussdBalance = trim((string)($body['ussd_balance_template'] ?? ''));
        $isActive = !empty($body['is_active']) ? 1 : 0;

        if ($name === '') jsonResponse(['error' => 'Name required'], 400);
        if (!in_array($pinType, ['numeric','alphanumeric'], true)) jsonResponse(['error' => 'Invalid pin_type'], 400);
        if ($pinLen < 3 || $pinLen > 16) jsonResponse(['error' => 'Invalid pin_length'], 400);
        if ($ussdChange === '' || $ussdBalance === '') jsonResponse(['error' => 'USSD templates required'], 400);

        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

        $hasWalletCols = hasColumn($db, 'carriers', 'wallet_default_action')
            && hasColumn($db, 'carriers', 'wallet_allow_open_dialer')
            && hasColumn($db, 'carriers', 'wallet_allow_copy_ussd');

        $walletFieldsProvided = ($body !== null) && (array_key_exists('wallet_allow_open_dialer', $body) || array_key_exists('wallet_allow_copy_ussd', $body) || array_key_exists('wallet_default_action', $body));

        if ($hasWalletCols && $walletFieldsProvided) {
            $walletAllowOpen = !empty($body['wallet_allow_open_dialer']) ? 1 : 0;
            $walletAllowCopy = !empty($body['wallet_allow_copy_ussd']) ? 1 : 0;
            $walletDefault = (string)($body['wallet_default_action'] ?? 'open_dialer');
            if (!in_array($walletDefault, ['open_dialer','copy_ussd'], true)) $walletDefault = 'open_dialer';

            $db->prepare("UPDATE carriers
                          SET name = ?, country = ?, pin_type = ?, pin_length = ?,
                              ussd_change_pin_template = ?, ussd_balance_template = ?,
                              wallet_allow_open_dialer = ?, wallet_allow_copy_ussd = ?, wallet_default_action = ?,
                              is_active = ?, updated_at = NOW()
                          WHERE id = ?")
               ->execute([
                   sanitize($name),
                   $country !== '' ? sanitize($country) : null,
                   $pinType,
                   $pinLen,
                   $ussdChange,
                   $ussdBalance,
                   $walletAllowOpen,
                   $walletAllowCopy,
                   $walletDefault,
                   $isActive,
                   $carrierId,
               ]);
        } else {
            $db->prepare("UPDATE carriers
                          SET name = ?, country = ?, pin_type = ?, pin_length = ?,
                              ussd_change_pin_template = ?, ussd_balance_template = ?,
                              is_active = COALESCE(?, is_active), updated_at = NOW()
                          WHERE id = ?")
               ->execute([
                   sanitize($name),
                   $country !== '' ? sanitize($country) : null,
                   $pinType,
                   $pinLen,
                   $ussdChange,
                   $ussdBalance,
                   $isActive,
                   $carrierId,
               ]);
        }

        auditLog('admin_carrier_update', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── CARRIERS: SET ACTIVE ─────────────────────────────────
    if ($action === 'carrier_set_active') {
        requireStrongAuth();

        $carrierId = intParam($body['carrier_id'] ?? 0, 0);
        $isActive = !empty($body['is_active']) ? 1 : 0;
        if ($carrierId < 1) jsonResponse(['error' => 'carrier_id required'], 400);

        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

        $db->prepare('UPDATE carriers SET is_active = ?, updated_at = NOW() WHERE id = ?')->execute([$isActive, $carrierId]);
        auditLog('admin_carrier_set_active', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DESTINATION ACCOUNTS: CREATE ─────────────────────────
    if ($action === 'destination_account_create') {
        requireStrongAuth();

        $accountType = (string)($body['account_type'] ?? '');
        $carrierId = intParam($body['carrier_id'] ?? 0, 0);
        $mm = trim((string)($body['mobile_money_number'] ?? ''));
        $bankName = trim((string)($body['bank_name'] ?? ''));
        $bankAccName = trim((string)($body['bank_account_name'] ?? ''));
        $bankAccNum = trim((string)($body['bank_account_number'] ?? ''));
        $unlockCode = (string)($body['unlock_code'] ?? '');
        $isActive = !empty($body['is_active']) ? 1 : 0;

        if (!in_array($accountType, ['mobile_money','bank'], true)) jsonResponse(['error' => 'Invalid account_type'], 400);
        if ($unlockCode === '') jsonResponse(['error' => 'unlock_code required'], 400);

        if ($accountType === 'mobile_money') {
            if ($mm === '') jsonResponse(['error' => 'mobile_money_number required'], 400);
        } else {
            if ($bankName === '' || $bankAccNum === '') jsonResponse(['error' => 'bank_name and bank_account_number required'], 400);
        }

        $db = getDB();
        $enc = encryptForDb($unlockCode);

        $db->prepare("INSERT INTO platform_destination_accounts
                      (account_type, carrier_id, mobile_money_number, bank_name, bank_account_name, bank_account_number,
                       unlock_code_enc, code_rotated_at, code_rotation_version, is_active, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 1, ?, NOW(), NOW())")
           ->execute([
               $accountType,
               $accountType === 'mobile_money' ? ($carrierId > 0 ? $carrierId : null) : null,
               $accountType === 'mobile_money' ? $mm : null,
               $accountType === 'bank' ? $bankName : null,
               $accountType === 'bank' ? ($bankAccName !== '' ? $bankAccName : null) : null,
               $accountType === 'bank' ? $bankAccNum : null,
               $enc,
               $isActive,
           ]);

        auditLog('admin_destination_account_create', null, getCurrentUserId());
        jsonResponse(['success' => true, 'account_id' => (int)$db->lastInsertId()]);
    }

    // ── DESTINATION ACCOUNTS: ROTATE CODE ────────────────────
    if ($action === 'destination_account_rotate') {
        requireStrongAuth();

        $accountId = intParam($body['account_id'] ?? 0, 0);
        $unlockCode = (string)($body['unlock_code'] ?? '');
        if ($accountId < 1) jsonResponse(['error' => 'account_id required'], 400);
        if ($unlockCode === '') jsonResponse(['error' => 'unlock_code required'], 400);

        $db = getDB();
        $enc = encryptForDb($unlockCode);

        $db->prepare("UPDATE platform_destination_accounts
                      SET unlock_code_enc = ?, code_rotated_at = NOW(), code_rotation_version = code_rotation_version + 1, updated_at = NOW()
                      WHERE id = ?")
           ->execute([$enc, $accountId]);

        auditLog('admin_destination_account_rotate', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DESTINATION ACCOUNTS: TOGGLE ACTIVE ──────────────────
    if ($action === 'destination_account_set_active') {
        requireStrongAuth();

        $accountId = intParam($body['account_id'] ?? 0, 0);
        $isActive = !empty($body['is_active']) ? 1 : 0;
        if ($accountId < 1) jsonResponse(['error' => 'account_id required'], 400);

        $db = getDB();
        $db->prepare('UPDATE platform_destination_accounts SET is_active = ?, updated_at = NOW() WHERE id = ?')
           ->execute([$isActive, $accountId]);

        auditLog('admin_destination_account_set_active', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── ESCROW SETTLEMENTS: MARK PROCESSED ───────────────────
    if ($action === 'escrow_settlement_processed') {
        requireStrongAuth();

        $settlementId = intParam($body['settlement_id'] ?? 0, 0);
        if ($settlementId < 1) jsonResponse(['error' => 'settlement_id required'], 400);

        $db = getDB();
        $st = $db->prepare("SELECT s.id, s.room_id, s.removed_user_id, s.policy, s.status, r.maker_user_id
                            FROM saving_room_escrow_settlements s
                            JOIN saving_rooms r ON r.id = s.room_id
                            WHERE s.id = ?");
        $st->execute([$settlementId]);
        $row = $st->fetch();
        if (!$row) jsonResponse(['error' => 'Settlement not found'], 404);

        if ((string)$row['status'] === 'processed') {
            jsonResponse(['success' => true, 'already_processed' => 1]);
        }

        $db->beginTransaction();
        $upd = $db->prepare("UPDATE saving_room_escrow_settlements SET status='processed', processed_at=NOW() WHERE id = ? AND status='recorded'");
        $upd->execute([$settlementId]);
        if ($upd->rowCount() < 1) {
            $db->rollBack();
            jsonResponse(['error' => 'Settlement is not in a processable state'], 409);
        }

        roomActivity($db, (string)$row['room_id'], 'escrow_settlement_processed', ['settlement_id' => $settlementId]);
        $db->commit();

        $removedUserId = (int)$row['removed_user_id'];
        $makerId = (int)$row['maker_user_id'];
        $policy = (string)$row['policy'];

        notifyOnceAdmin(
            $db,
            $removedUserId,
            'escrow_settlement_processed_user',
            'important',
            'Escrow settlement processed',
            'Your escrow settlement has been processed according to the room policy.',
            ['room_id' => (string)$row['room_id'], 'settlement_id' => $settlementId, 'policy' => $policy],
            'escrow_settlement',
            (string)$settlementId
        );

        if ($makerId > 0) {
            notifyOnceAdmin(
                $db,
                $makerId,
                'escrow_settlement_processed_maker',
                'informational',
                'Escrow settlement processed',
                'An escrow settlement in your room was marked as processed.',
                ['room_id' => (string)$row['room_id'], 'settlement_id' => $settlementId, 'policy' => $policy],
                'escrow_settlement',
                (string)$settlementId
            );
        }

        auditLog('admin_escrow_settlement_processed', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DISPUTES: RESOLVE ────────────────────────────────────
    if ($action === 'dispute_resolve') {
        requireStrongAuth();

        $disputeId = intParam($body['dispute_id'] ?? 0, 0);
        $decision = (string)($body['decision'] ?? '');

        if ($disputeId < 1) jsonResponse(['error' => 'dispute_id required'], 400);
        if (!in_array($decision, ['validated','dismissed'], true)) jsonResponse(['error' => 'Invalid decision'], 400);

        $db = getDB();

        $dispStmt = $db->prepare('SELECT id, room_id, rotation_index, raised_by_user_id, status FROM saving_room_disputes WHERE id = ?');
        $dispStmt->execute([$disputeId]);
        $d = $dispStmt->fetch();
        if (!$d) jsonResponse(['error' => 'Dispute not found'], 404);

        if (in_array((string)$d['status'], ['validated','dismissed'], true)) {
            jsonResponse(['success' => true, 'already_resolved' => 1]);
        }

        $roomId = (string)$d['room_id'];
        $rotationIndex = (int)$d['rotation_index'];
        $raisedBy = (int)$d['raised_by_user_id'];

        // Find the turn user for this rotation.
        $turnStmt = $db->prepare('SELECT user_id FROM saving_room_rotation_windows WHERE room_id = ? AND rotation_index = ? LIMIT 1');
        $turnStmt->execute([$roomId, $rotationIndex]);
        $turnUserId = (int)($turnStmt->fetchColumn() ?: 0);

        $db->beginTransaction();

        $db->prepare('UPDATE saving_room_disputes SET status = ?, admin_decision_at = NOW(), admin_decision_by = ?, updated_at = NOW() WHERE id = ?')
           ->execute([$decision, (int)getCurrentUserId(), $disputeId]);

        if ($decision === 'validated') {
            if ($turnUserId > 0) {
                applyStrikeDb($db, $turnUserId, 'abandonment', $roomId);

                // Mark current rotation as expired and advance.
                $db->prepare("UPDATE saving_room_rotation_windows SET status='expired' WHERE room_id = ? AND rotation_index = ? AND status IN ('blocked_dispute','revealed','pending_votes')")
                   ->execute([$roomId, $rotationIndex]);
                $db->prepare("UPDATE saving_room_rotation_queue SET status='completed' WHERE room_id = ? AND user_id = ? AND status='active_window'")
                   ->execute([$roomId, $turnUserId]);

                advanceTypeBWindow($db, $roomId, $rotationIndex);

                roomActivity($db, $roomId, 'dispute_validated', ['dispute_id' => $disputeId, 'rotation_index' => $rotationIndex]);
            }
        } else {
            // Dismissed: strike raiser for false dispute, unblock the rotation.
            applyStrikeDb($db, $raisedBy, 'false_dispute', $roomId);
            $db->prepare("UPDATE saving_room_rotation_windows SET status='revealed' WHERE room_id = ? AND rotation_index = ? AND status='blocked_dispute'")
               ->execute([$roomId, $rotationIndex]);
            roomActivity($db, $roomId, 'dispute_dismissed', ['dispute_id' => $disputeId, 'rotation_index' => $rotationIndex]);
        }

        $db->commit();

        auditLog('admin_dispute_resolve', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DELETE CODE (deactivate) ─────────────────────────────
    if ($action === 'delete_code') {
        requireStrongAuth();

        $lockId = trim((string)($body['lock_id'] ?? ''));
        if ($lockId === '') jsonResponse(['error' => 'lock_id required'], 400);

        $db = getDB();
        $db->prepare('UPDATE locks SET is_active = 0 WHERE id = ?')->execute([$lockId]);

        auditLog('admin_delete_code', $lockId, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
