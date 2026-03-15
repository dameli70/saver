<?php
// ============================================================
//  API: /api/kyc.php
//  KYC status + address + submission actions
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function hasColumnKyc(PDO $db, string $table, string $column): bool {
    $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? LIMIT 1");
    $stmt->execute([$table, $column]);
    return (bool)$stmt->fetchColumn();
}

function hasKycTables(PDO $db): bool {
    static $cached = null;
    if ($cached !== null) return $cached;

    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'kyc_submissions' LIMIT 1");
        $a = (bool)$stmt->fetchColumn();
        $stmt = $db->query("SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'kyc_documents' LIMIT 1");
        $b = (bool)$stmt->fetchColumn();
        $cached = $a && $b;
        return $cached;
    } catch (Throwable) {
        $cached = false;
        return false;
    }
}

function ensureKycSubmission(PDO $db, int $userId): array {
    $db->prepare("INSERT IGNORE INTO kyc_submissions (user_id, status, created_at) VALUES (?, 'draft', NOW())")
       ->execute([(int)$userId]);

    $st = $db->prepare('SELECT id, user_id, status, admin_note, created_at, submitted_at, decided_at, decided_by_user_id, updated_at FROM kyc_submissions WHERE user_id = ? LIMIT 1');
    $st->execute([(int)$userId]);
    $row = $st->fetch();
    return $row ? $row : ['id' => 0, 'user_id' => $userId, 'status' => 'draft'];
}

function kycDocs(PDO $db, int $submissionId): array {
    $st = $db->prepare('SELECT id, doc_kind, original_filename, content_type, size_bytes, created_at FROM kyc_documents WHERE submission_id = ? ORDER BY created_at DESC LIMIT 50');
    $st->execute([(int)$submissionId]);
    $out = [];
    foreach ($st->fetchAll() as $r) {
        $out[] = [
            'id' => (string)$r['id'],
            'doc_kind' => $r['doc_kind'] !== null ? (string)$r['doc_kind'] : null,
            'original_filename' => $r['original_filename'] !== null ? (string)$r['original_filename'] : null,
            'content_type' => (string)$r['content_type'],
            'size_bytes' => (int)$r['size_bytes'],
            'created_at' => (string)$r['created_at'],
            'download_url' => 'api/kyc_doc.php?id=' . rawurlencode((string)$r['id']),
        ];
    }
    return $out;
}

function cleanInput(?string $s, int $max): ?string {
    $s = trim((string)$s);
    if ($s === '') return null;
    if (function_exists('mb_substr')) {
        if (mb_strlen($s, 'UTF-8') > $max) $s = mb_substr($s, 0, $max, 'UTF-8');
    } else {
        if (strlen($s) > $max) $s = substr($s, 0, $max);
    }
    return $s;
}

$db = getDB();

if (!hasKycTables($db)) {
    jsonResponse(['error' => 'KYC is unavailable on this server. Apply database migrations.'], 409);
}

$requiredUserCols = ['address_line1','address_line2','address_city','address_region','address_postal_code','address_country'];
foreach ($requiredUserCols as $col) {
    if (!hasColumnKyc($db, 'users', $col)) {
        jsonResponse(['error' => 'KYC is unavailable on this server. Apply database migrations.'], 409);
    }
}

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

if ($method === 'GET') {
    $action = (string)($_GET['action'] ?? 'status');

    if ($action === 'status') {
        $sub = ensureKycSubmission($db, $userId);

        $u = $db->prepare('SELECT address_line1, address_line2, address_city, address_region, address_postal_code, address_country FROM users WHERE id = ?');
        $u->execute([$userId]);
        $userRow = $u->fetch() ?: [];

        $docs = ((int)($sub['id'] ?? 0) > 0) ? kycDocs($db, (int)$sub['id']) : [];

        jsonResponse([
            'success' => true,
            'available' => true,
            'submission' => [
                'id' => (int)($sub['id'] ?? 0),
                'status' => (string)($sub['status'] ?? 'draft'),
                'admin_note' => $sub['admin_note'] !== null ? (string)$sub['admin_note'] : null,
                'created_at' => $sub['created_at'] ?? null,
                'submitted_at' => $sub['submitted_at'] ?? null,
                'decided_at' => $sub['decided_at'] ?? null,
            ],
            'address' => [
                'line1' => $userRow['address_line1'] ?? null,
                'line2' => $userRow['address_line2'] ?? null,
                'city' => $userRow['address_city'] ?? null,
                'region' => $userRow['address_region'] ?? null,
                'postal_code' => $userRow['address_postal_code'] ?? null,
                'country' => $userRow['address_country'] ?? null,
            ],
            'documents' => $docs,
        ]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

if ($method === 'POST') {
    requireCsrf();

    $body = json_decode(file_get_contents('php://input'), true);
    $action = (string)($body['action'] ?? '');

    $sub = ensureKycSubmission($db, $userId);
    $status = (string)($sub['status'] ?? 'draft');

    if ($action === 'save_address') {
        if (in_array($status, ['submitted','approved'], true)) {
            jsonResponse(['error' => 'KYC submission is locked while in review.'], 409);
        }

        $line1 = cleanInput($body['line1'] ?? null, 255);
        $line2 = cleanInput($body['line2'] ?? null, 255);
        $city = cleanInput($body['city'] ?? null, 120);
        $region = cleanInput($body['region'] ?? null, 120);
        $postal = cleanInput($body['postal_code'] ?? null, 32);
        $country = cleanInput($body['country'] ?? null, 64);

        $db->prepare('UPDATE users SET address_line1 = ?, address_line2 = ?, address_city = ?, address_region = ?, address_postal_code = ?, address_country = ? WHERE id = ?')
           ->execute([$line1, $line2, $city, $region, $postal, $country, $userId]);

        auditLog('kyc_address_saved', null, $userId);

        jsonResponse(['success' => true]);
    }

    if ($action === 'submit') {
        if ($status === 'approved') {
            jsonResponse(['success' => true, 'already' => 1, 'status' => 'approved']);
        }
        if ($status === 'submitted') {
            jsonResponse(['success' => true, 'already' => 1, 'status' => 'submitted']);
        }

        $u = $db->prepare('SELECT address_line1, address_city, address_region, address_postal_code, address_country FROM users WHERE id = ?');
        $u->execute([$userId]);
        $a = $u->fetch() ?: [];

        $missing = [];
        if (empty($a['address_line1'])) $missing[] = 'line1';
        if (empty($a['address_city'])) $missing[] = 'city';
        if (empty($a['address_region'])) $missing[] = 'region';
        if (empty($a['address_postal_code'])) $missing[] = 'postal_code';
        if (empty($a['address_country'])) $missing[] = 'country';

        if (!empty($missing)) {
            jsonResponse(['error' => 'Address is incomplete.'], 400);
        }

        $docCountStmt = $db->prepare('SELECT COUNT(*) FROM kyc_documents WHERE submission_id = ?');
        $docCountStmt->execute([(int)$sub['id']]);
        $docs = (int)$docCountStmt->fetchColumn();
        if ($docs < 1) {
            jsonResponse(['error' => 'Upload at least one document before submitting.'], 400);
        }

        $db->prepare("UPDATE kyc_submissions
                      SET status = 'submitted', submitted_at = NOW(), decided_at = NULL, decided_by_user_id = NULL, admin_note = NULL, updated_at = NOW()
                      WHERE user_id = ?")
           ->execute([$userId]);

        auditLog('kyc_submitted', null, $userId);

        jsonResponse(['success' => true]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
