<?php
// ============================================================
//  API: /api/kyc_upload.php
//  Upload KYC documents (multipart/form-data)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/media_crypto.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireVerifiedEmail();
requireCsrf();

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$userId = (int)(getCurrentUserId() ?? 0);
if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

function hasKycTablesUpload(PDO $db): bool {
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

function ensureKycSubmissionUpload(PDO $db, int $userId): array {
    $db->prepare("INSERT IGNORE INTO kyc_submissions (user_id, status, created_at) VALUES (?, 'draft', NOW())")
       ->execute([(int)$userId]);

    $st = $db->prepare('SELECT id, status FROM kyc_submissions WHERE user_id = ? LIMIT 1');
    $st->execute([(int)$userId]);
    return $st->fetch() ?: ['id' => 0, 'status' => 'draft'];
}

$db = getDB();
if (!hasKycTablesUpload($db)) {
    jsonResponse(['error' => 'KYC is unavailable on this server. Apply database migrations.'], 409);
}

$sub = ensureKycSubmissionUpload($db, $userId);
$submissionId = (int)($sub['id'] ?? 0);
$status = (string)($sub['status'] ?? 'draft');

if ($submissionId < 1) jsonResponse(['error' => 'KYC unavailable'], 409);

if (in_array($status, ['submitted','approved'], true)) {
    jsonResponse(['error' => 'KYC submission is locked while in review.'], 409);
}

if (empty($_FILES['doc']) || !is_array($_FILES['doc'])) {
    jsonResponse(['error' => 'Missing document file'], 400);
}

$f = $_FILES['doc'];
$err = (int)($f['error'] ?? UPLOAD_ERR_NO_FILE);
if ($err !== UPLOAD_ERR_OK) {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$tmp = (string)($f['tmp_name'] ?? '');
if ($tmp === '' || !is_uploaded_file($tmp)) {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$maxBytes = 10 * 1024 * 1024;
$size = (int)($f['size'] ?? 0);
if ($size < 1 || $size > $maxBytes) {
    jsonResponse(['error' => 'Document must be 10MB or less'], 400);
}

$fi = new finfo(FILEINFO_MIME_TYPE);
$mime = (string)($fi->file($tmp) ?: '');

$allowed = [
    'application/pdf' => true,
    'image/png' => true,
    'image/jpeg' => true,
    'image/webp' => true,
];

if (!isset($allowed[$mime])) {
    jsonResponse(['error' => 'Unsupported document type (PDF/PNG/JPG/WebP only)'], 415);
}

$countStmt = $db->prepare('SELECT COUNT(*) FROM kyc_documents WHERE submission_id = ?');
$countStmt->execute([$submissionId]);
$cnt = (int)$countStmt->fetchColumn();
if ($cnt >= 10) {
    jsonResponse(['error' => 'Maximum number of documents reached'], 409);
}

$bytes = file_get_contents($tmp);
if ($bytes === false || $bytes === '') {
    jsonResponse(['error' => 'Upload failed'], 400);
}

$docKind = trim((string)($_POST['doc_kind'] ?? ''));
$kindAllowed = ['id' => 1, 'address' => 1, 'selfie' => 1, 'other' => 1];
if ($docKind === '' || !isset($kindAllowed[$docKind])) $docKind = null;

$name = (string)($f['name'] ?? '');
$name = str_replace(["\0", "\r", "\n"], '', $name);
$name = preg_replace('#[\\\\/]+#', '_', $name);
$name = trim((string)$name);
if ($name === '') $name = 'document';
if (function_exists('mb_substr') && mb_strlen($name, 'UTF-8') > 255) {
    $name = mb_substr($name, -255, null, 'UTF-8');
} elseif (strlen($name) > 255) {
    $name = substr($name, -255);
}

$sha = hash('sha256', $bytes, true);
$enc = mediaEncryptBytes($bytes);

$db->prepare('INSERT INTO kyc_documents (submission_id, user_id, doc_kind, original_filename, content_type, size_bytes, sha256, enc_cipher, iv, tag, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())')
   ->execute([
       $submissionId,
       $userId,
       $docKind,
       $name,
       $mime,
       $size,
       $sha,
       $enc['cipher'],
       $enc['iv'],
       $enc['tag'],
   ]);

auditLog('kyc_doc_uploaded', null, $userId);

jsonResponse(['success' => true, 'doc_id' => (string)$db->lastInsertId()]);
