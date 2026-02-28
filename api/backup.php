<?php
// ============================================================
//  API: /api/backup.php
//
//  Local export/import + cloud backups (snapshots).
//  NOTE: Backups contain ciphertext blobs only (still zero-knowledge).
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
requireLogin();
requireVerifiedEmail();

function exportPayload(int $userId): array {
    $db = getDB();
    $slotSel = hasLockVaultVerifierSlotColumn() ? 'vault_verifier_slot,' : '1 AS vault_verifier_slot,';
    $stmt = $db->prepare("SELECT id,label,cipher_blob,iv,auth_tag,kdf_salt,kdf_iterations,{$slotSel}password_type,password_length,hint,reveal_date,confirmation_status,copied_at,confirmed_at,rejected_at,auto_saved_at,revealed_at,is_active,created_at FROM locks WHERE user_id = ? ORDER BY created_at ASC");
    $stmt->execute([$userId]);
    $locks = $stmt->fetchAll();

    return [
        'app' => defined('APP_NAME') ? APP_NAME : 'LOCKSMITH',
        'export_version' => 2,
        'exported_at' => date('c'),
        'locks' => $locks,
    ];
}

function normalizeDateTime(?string $v): ?string {
    if ($v === null || trim($v) === '') return null;
    try {
        $dt = new DateTime($v);
        return $dt->format('Y-m-d H:i:s');
    } catch (Throwable $e) {
        return null;
    }
}

function importPayload(int $userId, array $payload): int {
    $v = (int)($payload['export_version'] ?? 0);
    if (!in_array($v, [1, 2], true)) {
        throw new RuntimeException('Unsupported export format.');
    }
    if (!isset($payload['locks']) || !is_array($payload['locks'])) {
        throw new RuntimeException('Invalid export: missing locks array.');
    }

    $db = getDB();
    $db->beginTransaction();

    try {
        $existsStmt = $db->prepare("SELECT id FROM locks WHERE id = ? AND user_id = ? LIMIT 1");

        $hasSlot = hasLockVaultVerifierSlotColumn();
        if ($hasSlot) {
            $insStmt = $db->prepare("INSERT INTO locks (id,user_id,label,cipher_blob,iv,auth_tag,kdf_salt,kdf_iterations,vault_verifier_slot,password_type,password_length,hint,reveal_date,confirmation_status,copied_at,confirmed_at,rejected_at,auto_saved_at,revealed_at,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        } else {
            $insStmt = $db->prepare("INSERT INTO locks (id,user_id,label,cipher_blob,iv,auth_tag,kdf_salt,kdf_iterations,password_type,password_length,hint,reveal_date,confirmation_status,copied_at,confirmed_at,rejected_at,auto_saved_at,revealed_at,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        }

        $count = 0;
        foreach ($payload['locks'] as $lock) {
            if (!is_array($lock)) continue;

            $lockId = (string)($lock['id'] ?? '');
            if ($lockId === '' || strlen($lockId) !== 36) {
                $lockId = generateUUID();
            }

            $existsStmt->execute([$lockId, $userId]);
            if ($existsStmt->fetch()) {
                $lockId = generateUUID();
            }

            $label = sanitize((string)($lock['label'] ?? 'Imported Code'));
            $cipher = (string)($lock['cipher_blob'] ?? '');
            $iv = (string)($lock['iv'] ?? '');
            $tag = (string)($lock['auth_tag'] ?? '');
            $salt  = (string)($lock['kdf_salt'] ?? '');
            $iters = (int)($lock['kdf_iterations'] ?? PBKDF2_ITERATIONS);
            $slot  = (int)($lock['vault_verifier_slot'] ?? 1);
            if (!in_array($slot, [1, 2], true)) $slot = 1;

            $ptype = (string)($lock['password_type'] ?? 'alphanumeric');
            $plen  = (int)($lock['password_length'] ?? 16);
            $hint  = isset($lock['hint']) ? trim((string)$lock['hint']) : null;
            $reveal = normalizeDateTime((string)($lock['reveal_date'] ?? ''));
            $status = (string)($lock['confirmation_status'] ?? 'pending');
            $copiedAt = normalizeDateTime($lock['copied_at'] ?? null);
            $confirmedAt = normalizeDateTime($lock['confirmed_at'] ?? null);
            $rejectedAt = normalizeDateTime($lock['rejected_at'] ?? null);
            $autoSavedAt = normalizeDateTime($lock['auto_saved_at'] ?? null);
            $revealedAt = normalizeDateTime($lock['revealed_at'] ?? null);
            $isActive = !empty($lock['is_active']) ? 1 : 0;
            $createdAt = normalizeDateTime($lock['created_at'] ?? null) ?? date('Y-m-d H:i:s');

            if ($cipher === '' || $iv === '' || $tag === '' || $salt === '' || $reveal === null) {
                continue;
            }

            $validTypes = ['numeric','alpha','alphanumeric','custom'];
            if (!in_array($ptype, $validTypes, true)) $ptype = 'alphanumeric';
            $validStatuses = ['pending','confirmed','rejected','auto_saved'];
            if (!in_array($status, $validStatuses, true)) $status = 'pending';

            $hintVal = ($hint !== null && $hint !== '') ? sanitize($hint) : null;

            $params = [
                $lockId, $userId, $label,
                $cipher, $iv, $tag, $salt, $iters,
            ];
            if ($hasSlot) $params[] = $slot;

            $params = array_merge($params, [
                $ptype, $plen,
                $hintVal,
                $reveal,
                $status,
                $copiedAt, $confirmedAt, $rejectedAt, $autoSavedAt, $revealedAt,
                $isActive,
                $createdAt,
            ]);

            $insStmt->execute($params);

            $count++;
        }

        $db->commit();
        return $count;

    } catch (Throwable $e) {
        $db->rollBack();
        throw $e;
    }
}

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';

    if ($action === 'export') {
        auditLog('backup_export');
        jsonResponse(['success' => true, 'export' => exportPayload((int)$userId)]);
    }

    if ($action === 'cloud_list') {
        try {
            $db = getDB();
            $stmt = $db->prepare('SELECT id, label, created_at, LENGTH(backup_blob) AS bytes FROM backups WHERE user_id = ? ORDER BY created_at DESC');
            $stmt->execute([(int)$userId]);
            $rows = $stmt->fetchAll();
            jsonResponse(['success' => true, 'backups' => $rows]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Cloud backups are not available (missing backups table). Apply migrations in config/migrations/.'], 500);
        }
    }

    if ($action === 'cloud_get') {
        $id = (int)($_GET['id'] ?? 0);
        if ($id <= 0) jsonResponse(['error' => 'id required'], 400);

        try {
            $db = getDB();
            $stmt = $db->prepare('SELECT id, label, created_at, backup_blob FROM backups WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, (int)$userId]);
            $row = $stmt->fetch();
            if (!$row) jsonResponse(['error' => 'Not found'], 404);

            jsonResponse(['success' => true, 'backup' => $row]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Cloud backups are not available (missing backups table). Apply migrations in config/migrations/.'], 500);
        }
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrf();

    $body = json_decode(file_get_contents('php://input'), true);
    $action = $body['action'] ?? '';

    if ($action === 'import') {
        $export = $body['export'] ?? null;
        if (!is_array($export)) jsonResponse(['error' => 'export object required'], 400);

        try {
            $n = importPayload((int)$userId, $export);
            auditLog('backup_import');
            jsonResponse(['success' => true, 'imported' => $n]);
        } catch (Throwable $e) {
            jsonResponse(['error' => $e->getMessage()], 400);
        }
    }

    if ($action === 'cloud_save') {
        $label = isset($body['label']) ? trim((string)$body['label']) : '';
        $label = $label !== '' ? sanitize($label) : null;

        $export = exportPayload((int)$userId);
        $blob = json_encode($export, JSON_UNESCAPED_UNICODE);
        if ($blob === false) jsonResponse(['error' => 'Failed to encode backup'], 500);

        try {
            $db = getDB();
            $stmt = $db->prepare('INSERT INTO backups (user_id, label, backup_blob) VALUES (?, ?, ?)');
            $stmt->execute([(int)$userId, $label, $blob]);

            auditLog('backup_cloud_save');
            jsonResponse(['success' => true, 'id' => (int)$db->lastInsertId()]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Cloud backups are not available (missing backups table). Apply migrations in config/migrations/.'], 500);
        }
    }

    if ($action === 'cloud_restore') {
        $id = (int)($body['id'] ?? 0);
        if ($id <= 0) jsonResponse(['error' => 'id required'], 400);

        try {
            $db = getDB();
            $stmt = $db->prepare('SELECT backup_blob FROM backups WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, (int)$userId]);
            $row = $stmt->fetch();
            if (!$row) jsonResponse(['error' => 'Not found'], 404);

            $export = json_decode($row['backup_blob'], true);
            if (!is_array($export)) jsonResponse(['error' => 'Backup is corrupted'], 400);

            try {
                $n = importPayload((int)$userId, $export);
                auditLog('backup_cloud_restore');
                jsonResponse(['success' => true, 'imported' => $n]);
            } catch (Throwable $e) {
                jsonResponse(['error' => $e->getMessage()], 400);
            }
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Cloud backups are not available (missing backups table). Apply migrations in config/migrations/.'], 500);
        }
    }

    if ($action === 'cloud_delete') {
        $id = (int)($body['id'] ?? 0);
        if ($id <= 0) jsonResponse(['error' => 'id required'], 400);

        try {
            $db = getDB();
            $stmt = $db->prepare('DELETE FROM backups WHERE id = ? AND user_id = ?');
            $stmt->execute([$id, (int)$userId]);
            if ($stmt->rowCount() === 0) jsonResponse(['error' => 'Not found'], 404);

            auditLog('backup_cloud_delete');
            jsonResponse(['success' => true]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Cloud backups are not available (missing backups table). Apply migrations in config/migrations/.'], 500);
        }
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
