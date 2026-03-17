<?php
// ============================================================
//  API: POST /api/reveal.php — Zero-Knowledge Edition
//
//  Server checks:
//  1. User is authenticated (session)
//  2. Lock belongs to user
//  3. Reveal date has passed (server clock — tamper-proof)
//  4. Step-up auth completed (TOTP or passkey)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$lockId = trim((string)($body['lock_id'] ?? ''));

if ($lockId === '') jsonResponse(['error' => 'lock_id required'], 400);

$userId = getCurrentUserId();
$db     = getDB();

$slotSel    = hasLockVaultVerifierSlotColumn() ? 'vault_verifier_slot,' : '1 AS vault_verifier_slot,';
$inboundSel = hasLockInboundLinkIdColumn() ? 'inbound_link_id,' : 'NULL AS inbound_link_id,';

$stmt = $db->prepare("
    SELECT id, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations,
           {$slotSel}
           {$inboundSel}
           reveal_date, revealed_at, label, hint, confirmation_status
    FROM locks
    WHERE id = ? AND user_id = ? AND is_active = 1
");
$stmt->execute([$lockId, $userId]);
$lock = $stmt->fetch();

if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);

if ($lock['confirmation_status'] !== 'confirmed') {
    jsonResponse(['error' => 'This lock was not confirmed — cannot reveal'], 403);
}

requireStrongAuth();

// Server-side time gate (tamper-proof — client clock irrelevant)
$now        = new DateTime('now', new DateTimeZone('UTC'));
$revealDate = new DateTime($lock['reveal_date'], new DateTimeZone('UTC'));

if ($now < $revealDate) {
    $diff = $now->diff($revealDate);
    jsonResponse([
        'error'          => 'Reveal date not reached',
        'locked_until'   => $lock['reveal_date'],
        'time_remaining' => sprintf('%dd %dh %dm', $diff->days, $diff->h, $diff->i),
    ], 403);
}

// Mark first reveal
if ($lock['revealed_at'] === null) {
    $db->prepare("UPDATE locks SET revealed_at = NOW() WHERE id = ?")->execute([$lockId]);
}

auditLog('reveal', $lockId);

$inbound = null;
if (!empty($lock['inbound_link_id']) && hasInboundLockLinksWrapColumns()) {
    $linkId = (string)$lock['inbound_link_id'];

    $keyCol = dbHasColumn('inbound_lock_links', 'link_id') ? 'link_id' : 'id';
    $selectLink = ($keyCol === 'link_id') ? 'link_id' : "{$keyCol} AS link_id";

    $where = "{$keyCol} = ?";
    $params = [$linkId];

    if (dbHasColumn('inbound_lock_links', 'user_id')) {
        $where .= ' AND user_id = ?';
        $params[] = $userId;
    }
    if (dbHasColumn('inbound_lock_links', 'lock_id')) {
        $where .= ' AND lock_id = ?';
        $params[] = $lockId;
    }

    try {
        $st2 = $db->prepare("SELECT {$selectLink}, secret_cipher_blob, secret_iv, secret_auth_tag, secret_kdf_salt, secret_kdf_iterations FROM inbound_lock_links WHERE {$where} LIMIT 1");
        $st2->execute($params);
        $row = $st2->fetch();

        if ($row && !empty($row['secret_cipher_blob']) && !empty($row['secret_iv']) && !empty($row['secret_auth_tag']) && !empty($row['secret_kdf_salt'])) {
            $inbound = [
                'link_id' => $row['link_id'],
                'secret_cipher_blob' => $row['secret_cipher_blob'],
                'secret_iv' => $row['secret_iv'],
                'secret_auth_tag' => $row['secret_auth_tag'],
                'secret_kdf_salt' => $row['secret_kdf_salt'],
                'secret_kdf_iterations' => (int)($row['secret_kdf_iterations'] ?? 0),
            ];
        }
    } catch (Throwable) {
        $inbound = null;
    }
}

$out = [
    'success'            => true,
    'label'              => normalizeDisplayText($lock['label'] ?? null),
    'hint'               => normalizeDisplayText($lock['hint'] ?? null),
    'cipher_blob'        => $lock['cipher_blob'],
    'iv'                 => $lock['iv'],
    'auth_tag'           => $lock['auth_tag'],
    'kdf_salt'           => $lock['kdf_salt'],
    'kdf_iterations'     => (int)$lock['kdf_iterations'],
    'vault_verifier_slot'=> (int)($lock['vault_verifier_slot'] ?? 1),
];

if ($inbound !== null) {
    $out['inbound'] = $inbound;
}

jsonResponse($out);
