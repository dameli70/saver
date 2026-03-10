<?php
// ============================================================
//  API: /api/share.php
//  Public share link viewer.
//
//  GET params:
//    - t: share token
//
//  The server enforces lock reveal_date before returning the
//  share ciphertext.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') jsonResponse(['error' => 'Method not allowed'], 405);

if (!hasLockSharesTable()) {
    jsonResponse(['error' => 'Sharing is unavailable on this server. Apply database migrations.'], 409);
}

$token = trim((string)($_GET['t'] ?? ''));
if ($token === '') jsonResponse(['error' => 'Missing token'], 400);

$hash = hash('sha256', $token);

$db = getDB();

$allowSel = hasLockSharesAllowRevealAfterDateColumn() ? 's.allow_reveal_after_date,' : '1 AS allow_reveal_after_date,';

$stmt = $db->prepare("SELECT s.id AS share_id,
                             s.revoked_at,
                             s.share_cipher_blob, s.share_iv, s.share_auth_tag, s.share_kdf_salt, s.share_kdf_iterations,
                             {$allowSel}
                             l.id AS lock_id, l.label, l.hint, l.reveal_date, l.confirmation_status, l.is_active
                      FROM lock_shares s
                      JOIN locks l ON l.id = s.lock_id
                      WHERE s.token_hash = ?
                      LIMIT 1");
$stmt->execute([$hash]);
$row = $stmt->fetch();

if (!$row) jsonResponse(['error' => 'Invalid link'], 404);
if (!empty($row['revoked_at'])) jsonResponse(['error' => 'This share link was revoked'], 410);
if ((int)($row['is_active'] ?? 0) !== 1) jsonResponse(['error' => 'This lock is inactive'], 410);
if ((string)($row['confirmation_status'] ?? '') !== 'confirmed') jsonResponse(['error' => 'This lock is not active yet'], 403);

$db->prepare('UPDATE lock_shares SET last_accessed_at = NOW() WHERE id = ?')->execute([(int)$row['share_id']]);

auditLog('share_view', (string)$row['lock_id'], null);

$allowRevealAfter = !empty($row['allow_reveal_after_date']);

$now = new DateTime('now', new DateTimeZone('UTC'));
$revealDate = new DateTime((string)$row['reveal_date'], new DateTimeZone('UTC'));
$lockedByTime = $now < $revealDate;
$locked = $lockedByTime || !$allowRevealAfter;

$out = [
    'success' => true,
    'locked' => $locked ? 1 : 0,
    'reveal_allowed' => $allowRevealAfter ? 1 : 0,
    'lock' => [
        'id' => (string)$row['lock_id'],
        'label' => normalizeDisplayText($row['label'] ?? null),
        'hint' => normalizeDisplayText($row['hint'] ?? null),
        'reveal_date' => (string)$row['reveal_date'],
    ],
];

if (!$lockedByTime && $allowRevealAfter) {
    $out['share'] = [
        'share_id' => (int)$row['share_id'],
        'share_cipher_blob' => (string)$row['share_cipher_blob'],
        'share_iv' => (string)$row['share_iv'],
        'share_auth_tag' => (string)$row['share_auth_tag'],
        'share_kdf_salt' => (string)$row['share_kdf_salt'],
        'share_kdf_iterations' => (int)$row['share_kdf_iterations'],
    ];
}

jsonResponse($out);
