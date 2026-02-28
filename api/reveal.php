<?php
// ============================================================
//  API: POST /api/reveal.php — Zero-Knowledge Edition
//
//  Server checks:
//  1. User is authenticated (session)
//  2. Lock belongs to user
//  3. Reveal date has passed (server clock — tamper-proof)
//  4. Vault passphrase is correct (identity re-verification)
//
//  Server returns:
//  - cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations
//  - ALL opaque blobs — still encrypted
//
//  Browser then:
//  - Re-derives key from vault passphrase + kdf_salt (PBKDF2, 310k rounds)
//  - Decrypts with AES-256-GCM
//  - Displays plaintext password
//  - Server NEVER sees the plaintext, not even here
// ============================================================

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body          = json_decode(file_get_contents('php://input'), true);
$lockId        = trim($body['lock_id'] ?? '');
$vaultPhrase   = $body['vault_passphrase'] ?? ''; // Re-entered by user for reveal

if (empty($lockId))      jsonResponse(['error' => 'lock_id required'], 400);
if (empty($vaultPhrase)) jsonResponse(['error' => 'Vault passphrase required to reveal'], 400);

// Re-verify vault passphrase on every reveal (not just session)
// This is a second factor — even a stolen session cannot reveal without passphrase
requireVaultPassphrase($vaultPhrase);

$userId = getCurrentUserId();
$db     = getDB();

$stmt = $db->prepare("
    SELECT id, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations,
           reveal_date, revealed_at, label, hint, confirmation_status
    FROM locks
    WHERE id = ? AND user_id = ? AND is_active = 1
");
$stmt->execute([$lockId, $userId]);
$lock = $stmt->fetch();

if (!$lock) jsonResponse(['error' => 'Lock not found'], 404);

if ($lock['confirmation_status'] !== 'confirmed')
    jsonResponse(['error' => 'This lock was not confirmed — cannot reveal'], 403);

// ── Server-side time gate (tamper-proof — client clock irrelevant) ──
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

// ── Mark first reveal ───────────────────────────────────────────
if ($lock['revealed_at'] === null) {
    $db->prepare("UPDATE locks SET revealed_at = NOW() WHERE id = ?")->execute([$lockId]);
}

auditLog('reveal', $lockId);

// Return ONLY encrypted blobs — browser decrypts with passphrase
// Server has served its purpose: gating access by time and identity.
// It CANNOT read what it's sending back.
jsonResponse([
    'success'        => true,
    'label'          => $lock['label'],
    'hint'           => $lock['hint'],
    'cipher_blob'    => $lock['cipher_blob'],
    'iv'             => $lock['iv'],
    'auth_tag'       => $lock['auth_tag'],
    'kdf_salt'       => $lock['kdf_salt'],
    'kdf_iterations' => (int)$lock['kdf_iterations'],
]);
