<?php
// ============================================================
//  API: /api/admin_kyc.php
//  Admin KYC review endpoints
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireAdmin();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

function hasKycTablesAdmin(PDO $db): bool {
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

function docsForSubmission(PDO $db, int $submissionId): array {
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

$db = getDB();
if (!hasKycTablesAdmin($db)) {
    jsonResponse(['error' => 'KYC is unavailable on this server. Apply database migrations.'], 409);
}

if ($method === 'GET') {
    $action = (string)($_GET['action'] ?? 'pending');

    if ($action === 'pending') {
        $rows = $db->query(
            "SELECT
                s.id,
                s.user_id,
                u.email,
                s.status,
                s.submitted_at,
                s.admin_note,
                s.created_at,
                (SELECT COUNT(*) FROM kyc_documents d WHERE d.submission_id = s.id) AS docs_count,
                u.address_line1, u.address_line2, u.address_city, u.address_region, u.address_postal_code, u.address_country
             FROM kyc_submissions s
             JOIN users u ON u.id = s.user_id
             WHERE s.status = 'submitted'
             ORDER BY s.submitted_at ASC
             LIMIT 500"
        )->fetchAll();

        jsonResponse(['success' => true, 'submissions' => $rows]);
    }

    if ($action === 'submission') {
        $id = (int)($_GET['id'] ?? 0);
        if ($id < 1) jsonResponse(['error' => 'id required'], 400);

        $st = $db->prepare(
            "SELECT
                s.id,
                s.user_id,
                u.email,
                s.status,
                s.admin_note,
                s.created_at,
                s.submitted_at,
                s.decided_at,
                s.decided_by_user_id,
                u.address_line1, u.address_line2, u.address_city, u.address_region, u.address_postal_code, u.address_country
             FROM kyc_submissions s
             JOIN users u ON u.id = s.user_id
             WHERE s.id = ?
             LIMIT 1"
        );
        $st->execute([$id]);
        $row = $st->fetch();
        if (!$row) jsonResponse(['error' => 'Not found'], 404);

        $docs = docsForSubmission($db, (int)$row['id']);
        jsonResponse(['success' => true, 'submission' => $row, 'documents' => $docs]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

if ($method === 'POST') {
    requireCsrf();

    $body = json_decode(file_get_contents('php://input'), true);
    $action = (string)($body['action'] ?? '');

    if ($action === 'approve' || $action === 'reject') {
        requireStrongAuth();

        $submissionId = (int)($body['submission_id'] ?? 0);
        if ($submissionId < 1) jsonResponse(['error' => 'submission_id required'], 400);

        $note = trim((string)($body['note'] ?? ''));
        if ($note === '') $note = null;
        if ($note !== null && function_exists('mb_substr') && mb_strlen($note, 'UTF-8') > 500) {
            $note = mb_substr($note, 0, 500, 'UTF-8');
        } elseif ($note !== null && strlen($note) > 500) {
            $note = substr($note, 0, 500);
        }

        $st = $db->prepare('SELECT id, user_id, status FROM kyc_submissions WHERE id = ? LIMIT 1');
        $st->execute([$submissionId]);
        $sub = $st->fetch();
        if (!$sub) jsonResponse(['error' => 'Not found'], 404);

        if ((string)$sub['status'] !== 'submitted') {
            jsonResponse(['error' => 'Submission is not pending'], 409);
        }

        $nextStatus = ($action === 'approve') ? 'approved' : 'rejected';

        $db->prepare("UPDATE kyc_submissions
                      SET status = ?, decided_at = NOW(), decided_by_user_id = ?, admin_note = ?, updated_at = NOW()
                      WHERE id = ?")
           ->execute([$nextStatus, (int)getCurrentUserId(), $note, $submissionId]);

        auditLog('admin_kyc_' . $nextStatus, null, (int)getCurrentUserId());

        jsonResponse(['success' => true]);
    }

    jsonResponse(['error' => 'Unknown action'], 400);
}

jsonResponse(['error' => 'Method not allowed'], 405);
