<?php
// ============================================================
//  API: POST /api/generate.php — Zero-Knowledge Edition
//
//  Client sends:
//    - label, type, length, reveal_date, hint (metadata)
//    - cipher_blob, iv, auth_tag (encrypted in browser, AES-256-GCM)
//    - kdf_salt (returned from /api/salt.php, used by browser for PBKDF2)
//
//  Server stores cipher_blob + iv + auth_tag + kdf_salt.
//  Server has ZERO ability to decrypt. No key. No passphrase. Nothing.
//
//  Even if this entire server is cloned by an attacker:
//    - cipher_blob is AES-256-GCM ciphertext
//    - kdf_salt is random bytes (useless without vault passphrase)
//    - auth_tag ensures tampering is detected
//    - Brute force requires 310,000 PBKDF2 iterations per attempt
// ============================================================

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
requireLogin();
requireCsrf();
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);

// ── Validate metadata ─────────────────────────────────────────
$label      = trim($body['label'] ?? '');
$type       = $body['type'] ?? 'alphanumeric';
$length     = (int)($body['length'] ?? 16);
$revealDate = $body['reveal_date'] ?? '';
$hint       = trim($body['hint'] ?? '');

// ── Validate zero-knowledge crypto fields (opaque blobs from browser) ──
$cipherBlob = trim($body['cipher_blob'] ?? '');
$iv         = trim($body['iv'] ?? '');
$authTag    = trim($body['auth_tag'] ?? '');
$kdfSalt    = trim($body['kdf_salt'] ?? '');

if (empty($label))      jsonResponse(['error' => 'Label is required'], 400);
if (empty($cipherBlob)) jsonResponse(['error' => 'cipher_blob missing'], 400);
if (empty($iv))         jsonResponse(['error' => 'iv missing'], 400);
if (empty($authTag))    jsonResponse(['error' => 'auth_tag missing'], 400);
if (empty($kdfSalt))    jsonResponse(['error' => 'kdf_salt missing'], 400);

// Verify salt was legitimately issued by this server for this user/session
$sessionKey = 'pending_salt_' . getCurrentUserId();
$issuedSalt = $_SESSION[$sessionKey] ?? null;
if (!$issuedSalt || !hash_equals($issuedSalt, $kdfSalt)) {
    jsonResponse(['error' => 'Invalid or expired KDF salt — request a new one'], 400);
}
unset($_SESSION[$sessionKey]); // One-time use

$validTypes = ['numeric','alpha','alphanumeric','custom'];
if (!in_array($type, $validTypes, true)) jsonResponse(['error' => 'Invalid type'], 400);
if ($length < 4 || $length > 128)        jsonResponse(['error' => 'Length must be 4–128'], 400);
if (strlen($hint) > 500)                 jsonResponse(['error' => 'Hint too long'], 400);
if (empty($revealDate))                  jsonResponse(['error' => 'Reveal date required'], 400);

try {
    $revealDt = new DateTime($revealDate);
    if ($revealDt <= new DateTime()) jsonResponse(['error' => 'Reveal date must be future'], 400);
} catch (Exception) {
    jsonResponse(['error' => 'Invalid reveal date'], 400);
}

// Basic sanity checks on cipher material (base64 format, expected sizes)
if (base64_decode($iv, true) === false || strlen(base64_decode($iv)) !== 12)
    jsonResponse(['error' => 'IV must be 12 bytes (base64)'], 400);
if (base64_decode($authTag, true) === false || strlen(base64_decode($authTag)) !== 16)
    jsonResponse(['error' => 'auth_tag must be 16 bytes (base64)'], 400);
if (base64_decode($kdfSalt, true) === false || strlen(base64_decode($kdfSalt)) !== 32)
    jsonResponse(['error' => 'kdf_salt must be 32 bytes (base64)'], 400);

// ── Store — server never touches key material ─────────────────
try {
    $userId = getCurrentUserId();
    $lockId = generateUUID();
    $db     = getDB();

    $db->prepare("
        INSERT INTO locks
            (id, user_id, label, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations,
             password_type, password_length, hint, reveal_date, confirmation_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    ")->execute([
        $lockId, $userId, sanitize($label),
        $cipherBlob, $iv, $authTag, $kdfSalt, PBKDF2_ITERATIONS,
        $type, $length,
        $hint ? sanitize($hint) : null,
        $revealDt->format('Y-m-d H:i:s'),
    ]);

    auditLog('generate', $lockId);

    jsonResponse([
        'success'     => true,
        'lock_id'     => $lockId,
        'label'       => sanitize($label),
        'reveal_date' => $revealDt->format('Y-m-d H:i:s'),
    ]);

} catch (Exception $e) {
    auditLog('generate_error');
    jsonResponse(['error' => 'Storage failed: ' . $e->getMessage()], 500);
}
