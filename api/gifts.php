<?php
// ============================================================
//  API: /api/gifts.php
//
//  Public "timed gift" links.
//
//  POST {action:'create', reveal_date, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations}
//    -> returns a view URL token (plaintext secret lives only in URL fragment client-side)
//
//  GET ?action=view&t=...
//    -> returns gift metadata; ciphertext is returned only after reveal_date
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');

if (!dbHasTable('public_gifts')) {
    jsonResponse(['error' => 'Gifts are unavailable on this server. Apply database migrations.'], 409);
}

$db = getDB();

function b64len(string $b64, int $expectedBytes): bool {
    $raw = base64_decode($b64, true);
    return ($raw !== false && strlen($raw) === $expectedBytes);
}

function parseUtcFutureOrJson(?string $s, string $errMsg): DateTimeImmutable {
    $v = trim((string)$s);
    if ($v === '') jsonResponse(['error' => $errMsg], 400);

    try {
        $dt = new DateTimeImmutable($v, new DateTimeZone('UTC'));
        $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
        if ($dt <= $now) jsonResponse(['error' => $errMsg], 400);
        return $dt->setTimezone(new DateTimeZone('UTC'));
    } catch (Throwable) {
        jsonResponse(['error' => $errMsg], 400);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = (string)($_GET['action'] ?? '');
    if ($action !== 'view') jsonResponse(['error' => 'Method not allowed'], 405);

    $token = trim((string)($_GET['t'] ?? ''));
    if ($token === '') jsonResponse(['error' => 'Missing token'], 400);

    $hash = hash('sha256', $token);

    $stmt = $db->prepare('SELECT token_hash, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations, reveal_date, created_at, expires_at, revoked_at
                          FROM public_gifts
                          WHERE token_hash = ?
                          LIMIT 1');
    $stmt->execute([$hash]);
    $row = $stmt->fetch();

    if (!$row) jsonResponse(['error' => 'Invalid link'], 404);
    if (!empty($row['revoked_at'])) jsonResponse(['error' => 'This gift was revoked'], 410);

    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if (!empty($row['expires_at'])) {
        try {
            $exp = new DateTimeImmutable((string)$row['expires_at'], new DateTimeZone('UTC'));
            if ($now >= $exp) jsonResponse(['error' => 'This gift expired'], 410);
        } catch (Throwable) {
            // ignore
        }
    }

    $revealDate = new DateTimeImmutable((string)$row['reveal_date'], new DateTimeZone('UTC'));
    $locked = $now < $revealDate;

    $out = [
        'success' => true,
        'locked' => $locked ? 1 : 0,
        'gift' => [
            'reveal_date' => (string)$row['reveal_date'],
            'kdf_salt' => (string)$row['kdf_salt'],
            'kdf_iterations' => (int)$row['kdf_iterations'],
        ],
    ];

    if (!$locked) {
        $out['gift'] += [
            'cipher_blob' => (string)$row['cipher_blob'],
            'iv' => (string)$row['iv'],
            'auth_tag' => (string)$row['auth_tag'],
        ];
    }

    jsonResponse($out);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

$body = json_decode(file_get_contents('php://input'), true);
$action = (string)($body['action'] ?? '');

if ($action !== 'create') {
    jsonResponse(['error' => 'Unknown action'], 400);
}

$revealDt = parseUtcFutureOrJson((string)($body['reveal_date'] ?? ''), 'Reveal date required');

$cipherBlob = trim((string)($body['cipher_blob'] ?? ''));
$iv         = trim((string)($body['iv'] ?? ''));
$authTag    = trim((string)($body['auth_tag'] ?? ''));
$kdfSalt    = trim((string)($body['kdf_salt'] ?? ''));
$kdfIters   = (int)($body['kdf_iterations'] ?? PBKDF2_ITERATIONS);

if ($cipherBlob === '' || $iv === '' || $authTag === '' || $kdfSalt === '') {
    jsonResponse(['error' => 'Missing encryption fields'], 400);
}

if (!b64len($iv, 12)) jsonResponse(['error' => 'iv must be 12 bytes (base64)'], 400);
if (!b64len($authTag, 16)) jsonResponse(['error' => 'auth_tag must be 16 bytes (base64)'], 400);
if (!b64len($kdfSalt, 32)) jsonResponse(['error' => 'kdf_salt must be 32 bytes (base64)'], 400);

if ($kdfIters < 50000) $kdfIters = 50000;
if ($kdfIters > 2000000) $kdfIters = 2000000;

$token = null;
$tokenHash = null;

$tries = 0;
while ($tries < 5) {
    $tries++;
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);

    try {
        $db->prepare('INSERT INTO public_gifts
                      (token_hash, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations, reveal_date, expires_at, revoked_at)
                      VALUES
                      (?, ?, ?, ?, ?, ?, ?, NULL, NULL)')
           ->execute([
               $tokenHash,
               $cipherBlob,
               $iv,
               $authTag,
               $kdfSalt,
               $kdfIters,
               $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
           ]);
        auditLog('gift_create', null, null);
        break;
    } catch (Throwable $e) {
        if (str_contains(strtolower($e->getMessage()), 'duplicate')) {
            $token = null;
            $tokenHash = null;
            continue;
        }
        throw $e;
    }
}

if (!$token || !$tokenHash) jsonResponse(['error' => 'Failed to create gift'], 500);

$url = getAppBaseUrl() . '/gift.php?t=' . rawurlencode($token);

jsonResponse([
    'success' => true,
    'token' => $token,
    'gift_url' => $url,
]);
