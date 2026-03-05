<?php
// ============================================================
//  API: /api/admin.php
//  Super admin dashboard data endpoints
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
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
                COUNT(l.id) AS codes_total,
                SUM(CASE WHEN l.is_active = 1 THEN 1 ELSE 0 END) AS codes_active
            FROM users u
            LEFT JOIN locks l ON l.user_id = u.id
            GROUP BY u.id, u.email, u.is_admin, u.email_verified_at, u.verification_sent_at, u.created_at, u.last_login
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

        $rows = $db->query("SELECT id, name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at FROM carriers ORDER BY name ASC")->fetchAll();
        jsonResponse(['success' => true, 'carriers' => $rows]);
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

    jsonResponse(['error' => 'Unknown action'], 400);
}

if ($method === 'POST') {
    requireCsrf();

    $body   = json_decode(file_get_contents('php://input'), true);
    $action = $body['action'] ?? '';

    // ── CREATE USER ──────────────────────────────────────────
    if ($action === 'create_user') {
        $email        = strtolower(trim($body['email'] ?? ''));
        $loginPwd     = $body['login_password'] ?? '';
        $makeAdmin    = !empty($body['is_admin']);
        $markVerified = !empty($body['mark_verified']);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) jsonResponse(['error' => 'Invalid email'], 400);
        if (strlen($loginPwd) < 8) jsonResponse(['error' => 'Login password must be at least 8 characters'], 400);

        $db = getDB();
        $check = $db->prepare("SELECT id FROM users WHERE email = ?");
        $check->execute([$email]);
        if ($check->fetch()) jsonResponse(['error' => 'Email already registered'], 409);

        $loginHash = hashLoginPassword($loginPwd);

        // Vault passphrase is never sent to the server.
        // Legacy schema still requires verifier fields, so we store non-usable placeholders.
        $vaultVerifierSalt = bin2hex(random_bytes(32));
        $vaultVerifier     = hashVaultVerifier(bin2hex(random_bytes(32)) . $vaultVerifierSalt);

        $emailVerifiedAt = $markVerified ? (new DateTime())->format('Y-m-d H:i:s') : null;

        $stmt = $db->prepare("
            INSERT INTO users (
                email, login_hash, vault_verifier, vault_verifier_salt,
                is_admin, email_verified_at, email_verification_hash, email_verification_expires_at, verification_sent_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
        ");
        $stmt->execute([
            $email,
            $loginHash,
            $vaultVerifier,
            $vaultVerifierSalt,
            $makeAdmin ? 1 : 0,
            $emailVerifiedAt,
        ]);

        $userId = (int)$db->lastInsertId();

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
        jsonResponse([
            'success' => true,
            'user_id' => $userId,
            'dev_verify_url' => $devVerifyUrl,
        ]);
    }

    // ── SET ADMIN FLAG ───────────────────────────────────────
    if ($action === 'set_admin') {
        $userId  = intParam($body['user_id'] ?? 0, 0);
        $isAdmin = !empty($body['is_admin']) ? 1 : 0;
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);

        $db = getDB();

        if ($isAdmin === 0) {
            $admins = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetchColumn();
            $cur = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
            $cur->execute([$userId]);
            $row = $cur->fetch();
            if (!empty($row['is_admin']) && $admins <= 1) {
                jsonResponse(['error' => 'Cannot remove admin from the last admin user'], 400);
            }
        }

        $db->prepare("UPDATE users SET is_admin = ? WHERE id = ?")->execute([$isAdmin, $userId]);

        // If the admin is modifying themselves, refresh the session.
        if ($userId === getCurrentUserId()) {
            $_SESSION['is_admin'] = $isAdmin;
        }

        auditLog('admin_set_admin', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── MARK VERIFIED / UNVERIFIED ───────────────────────────
    if ($action === 'set_verified') {
        $userId  = intParam($body['user_id'] ?? 0, 0);
        $verified = !empty($body['verified']) ? 1 : 0;
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);

        $db = getDB();
        if ($verified) {
            $db->prepare("UPDATE users SET email_verified_at = NOW(), email_verification_hash = NULL, email_verification_expires_at = NULL WHERE id = ?")
               ->execute([$userId]);

            // Ensure key defaults exist for optimal usage.
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
            $db->prepare("UPDATE users SET email_verified_at = NULL WHERE id = ?")
               ->execute([$userId]);
        }

        auditLog('admin_set_verified', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── DELETE USER ──────────────────────────────────────────
    if ($action === 'delete_user') {
        $userId  = intParam($body['user_id'] ?? 0, 0);
        if ($userId < 1) jsonResponse(['error' => 'user_id required'], 400);
        if ($userId === getCurrentUserId()) jsonResponse(['error' => 'Cannot delete your own account'], 400);

        $db = getDB();

        $admins = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetchColumn();
        $cur = $db->prepare("SELECT is_admin FROM users WHERE id = ?");
        $cur->execute([$userId]);
        $row = $cur->fetch();
        if (!empty($row['is_admin']) && $admins <= 1) {
            jsonResponse(['error' => 'Cannot delete the last admin user'], 400);
        }

        $db->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);

        auditLog('admin_delete_user', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── CARRIERS: CREATE ───────────────────────────────────
    if ($action === 'carrier_create') {
        $name = trim((string)($body['name'] ?? ''));
        $country = trim((string)($body['country'] ?? ''));
        $pinType = (string)($body['pin_type'] ?? 'numeric');
        $pinLen = intParam($body['pin_length'] ?? 0, 0);
        $ussdChange = trim((string)($body['ussd_change_pin_template'] ?? ''));
        $ussdBalance = trim((string)($body['ussd_balance_template'] ?? ''));
        $isActive = !empty($body['is_active']) ? 1 : 0;

        if ($name === '') jsonResponse(['error' => 'name required'], 400);
        if (!in_array($pinType, ['numeric','alphanumeric'], true)) jsonResponse(['error' => 'Invalid pin_type'], 400);
        if ($pinLen < 3 || $pinLen > 12) jsonResponse(['error' => 'pin_length must be 3–12'], 400);
        if ($ussdChange === '') jsonResponse(['error' => 'ussd_change_pin_template required'], 400);
        if ($ussdBalance === '') jsonResponse(['error' => 'ussd_balance_template required'], 400);

        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

        $db->prepare("INSERT INTO carriers (name, country, pin_type, pin_length, ussd_change_pin_template, ussd_balance_template, is_active, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NULL)")
           ->execute([
               sanitize($name),
               $country !== '' ? sanitize($country) : null,
               $pinType,
               $pinLen,
               $ussdChange,
               $ussdBalance,
               $isActive,
           ]);

        $carrierId = (int)$db->lastInsertId();
        auditLog('admin_carrier_create', null, getCurrentUserId());
        jsonResponse(['success' => true, 'carrier_id' => $carrierId]);
    }

    // ── CARRIERS: UPDATE ────────────────────────────────────
    if ($action === 'carrier_update') {
        $carrierId = intParam($body['carrier_id'] ?? 0, 0);
        if ($carrierId < 1) jsonResponse(['error' => 'carrier_id required'], 400);

        $name = trim((string)($body['name'] ?? ''));
        $country = trim((string)($body['country'] ?? ''));
        $pinType = (string)($body['pin_type'] ?? 'numeric');
        $pinLen = intParam($body['pin_length'] ?? 0, 0);
        $ussdChange = trim((string)($body['ussd_change_pin_template'] ?? ''));
        $ussdBalance = trim((string)($body['ussd_balance_template'] ?? ''));
        $isActive = isset($body['is_active']) ? (!empty($body['is_active']) ? 1 : 0) : null;

        if ($name === '') jsonResponse(['error' => 'name required'], 400);
        if (!in_array($pinType, ['numeric','alphanumeric'], true)) jsonResponse(['error' => 'Invalid pin_type'], 400);
        if ($pinLen < 3 || $pinLen > 12) jsonResponse(['error' => 'pin_length must be 3–12'], 400);
        if ($ussdChange === '') jsonResponse(['error' => 'ussd_change_pin_template required'], 400);
        if ($ussdBalance === '') jsonResponse(['error' => 'ussd_balance_template required'], 400);

        $db = getDB();
        $has = (bool)$db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'carriers' LIMIT 1")->fetchColumn();
        if (!$has) jsonResponse(['error' => 'Carriers are not available. Apply migrations in config/migrations/.'], 500);

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

        auditLog('admin_carrier_update', null, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    // ── CARRIERS: SET ACTIVE ─────────────────────────────────
    if ($action === 'carrier_set_active') {
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

    // ── DELETE CODE (deactivate) ─────────────────────────────
    if ($action === 'delete_code') {
        $lockId = trim((string)($body['lock_id'] ?? ''));
        if ($lockId === '') jsonResponse(['error' => 'lock_id required'], 400);

        $db = getDB();
        $db->prepare("UPDATE locks SET is_active = 0 WHERE id = ?")->execute([$lockId]);

        auditLog('admin_delete_code', $lockId, getCurrentUserId());
        jsonResponse(['success' => true]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
