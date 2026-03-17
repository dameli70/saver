<?php
// ============================================================
//  API: /api/inbound_links.php
//
//  Inbound "receive via link" feature.
//
//  - Authenticated:
//      POST {action:'create_link', ...}  -> creates an inbound link
//  - Public:
//      GET  ?action=meta&t=...           -> returns non-sensitive link metadata
//      POST {action:'submit', t:..., ...} -> submits an encrypted secret to recipient
//
//  Zero-knowledge:
//   - The inbound secret used for encryption is never sent in plaintext to the server.
//   - Server stores only:
//        (1) payload ciphertext (for the lock)
//        (2) inbound secret ciphertext wrapped under recipient vault passphrase
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/packages.php';
header('Content-Type: application/json; charset=utf-8');

if (!hasInboundLockLinksTable()) {
    jsonResponse(['error' => 'Inbound links are unavailable on this server. Apply database migrations.'], 409);
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

// ─────────────────────────────────────────────────────────────
// Public: metadata
// ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = (string)($_GET['action'] ?? '');
    if ($action !== 'meta') jsonResponse(['error' => 'Method not allowed'], 405);

    $token = trim((string)($_GET['t'] ?? ''));
    if ($token === '') jsonResponse(['error' => 'Missing token'], 400);

    $hash = hash('sha256', $token);

    $stmt = $db->prepare("SELECT id, mode, reveal_date_fixed, max_uses, uses_count, expires_at, revoked_at, created_at
                          FROM inbound_lock_links
                          WHERE token_hash = ?
                          LIMIT 1");
    $stmt->execute([$hash]);
    $row = $stmt->fetch();

    if (!$row) jsonResponse(['error' => 'Invalid link'], 404);
    if (!empty($row['revoked_at'])) jsonResponse(['error' => 'This link was revoked'], 410);

    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    if (!empty($row['expires_at'])) {
        try {
            $exp = new DateTimeImmutable((string)$row['expires_at'], new DateTimeZone('UTC'));
            if ($now >= $exp) jsonResponse(['error' => 'This link expired'], 410);
        } catch (Throwable) {
            // ignore parse issues
        }
    }

    $maxUses = (int)($row['max_uses'] ?? 1);
    $uses = (int)($row['uses_count'] ?? 0);
    $exhausted = ($maxUses > 0 && $uses >= $maxUses);

    jsonResponse([
        'success' => true,
        'link' => [
            'id' => (string)$row['id'],
            'mode' => (string)$row['mode'],
            'reveal_date_fixed' => $row['reveal_date_fixed'],
            'max_uses' => $maxUses,
            'uses_count' => $uses,
            'exhausted' => $exhausted ? 1 : 0,
            'expires_at' => $row['expires_at'],
            'created_at' => $row['created_at'],
        ],
    ]);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

$body = json_decode(file_get_contents('php://input'), true);
$action = (string)($body['action'] ?? '');

// ─────────────────────────────────────────────────────────────
// Authenticated: create link
// ─────────────────────────────────────────────────────────────
if ($action === 'create_link') {
    requireLogin();
    requireCsrf();
    requireVerifiedEmail();

    if (!hasInboundLockLinksWrapColumns()) {
        jsonResponse(['error' => 'Inbound links are unavailable on this server. Apply database migrations.'], 409);
    }

    $userId = (int)(getCurrentUserId() ?? 0);
    if ($userId < 1) jsonResponse(['error' => 'Unauthorized'], 401);

    $mode = (string)($body['mode'] ?? 'recipient_sets_date');
    if (!in_array($mode, ['recipient_sets_date', 'sender_sets_date'], true)) {
        jsonResponse(['error' => 'Invalid mode'], 400);
    }

    $maxUses = (int)($body['max_uses'] ?? 1);
    if ($maxUses < 1) $maxUses = 1;
    if ($maxUses > 100) $maxUses = 100;

    $revealFixed = null;
    if ($mode === 'recipient_sets_date') {
        $dt = parseUtcFutureOrJson((string)($body['reveal_date_fixed'] ?? ''), 'Reveal date required');
        $revealFixed = $dt->format('Y-m-d H:i:s');
    }

    $expiresAt = null;
    if (!empty($body['expires_at'])) {
        $dt = parseUtcFutureOrJson((string)($body['expires_at'] ?? ''), 'Invalid expires_at');
        $expiresAt = $dt->format('Y-m-d H:i:s');
    }

    // Wrapped secret fields (encrypted in browser under vault passphrase-derived key)
    $wrap = is_array($body['secret_wrap'] ?? null) ? $body['secret_wrap'] : [];

    $secretCipher = trim((string)($body['secret_cipher_blob'] ?? ($wrap['cipher_blob'] ?? '')));
    $secretIv     = trim((string)($body['secret_iv'] ?? ($wrap['iv'] ?? '')));
    $secretTag    = trim((string)($body['secret_auth_tag'] ?? ($wrap['auth_tag'] ?? '')));
    $secretSalt   = trim((string)($body['secret_kdf_salt'] ?? ($wrap['kdf_salt'] ?? '')));
    $secretIters  = (int)($body['secret_kdf_iterations'] ?? ($wrap['kdf_iterations'] ?? PBKDF2_ITERATIONS));

    if ($secretCipher === '' || $secretIv === '' || $secretTag === '' || $secretSalt === '') {
        jsonResponse(['error' => 'Missing secret wrap fields'], 400);
    }

    if (!b64len($secretIv, 12)) jsonResponse(['error' => 'secret_iv must be 12 bytes (base64)'], 400);
    if (!b64len($secretTag, 16)) jsonResponse(['error' => 'secret_auth_tag must be 16 bytes (base64)'], 400);
    if (!b64len($secretSalt, 32)) jsonResponse(['error' => 'secret_kdf_salt must be 32 bytes (base64)'], 400);

    if ($secretIters < 50000) $secretIters = 50000;
    if ($secretIters > 2000000) $secretIters = 2000000;

    $token = null;
    $tokenHash = null;

    $tries = 0;
    while ($tries < 5) {
        $tries++;
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);

        try {
            $id = generateUUID();
            $db->prepare("INSERT INTO inbound_lock_links
                          (id, user_id, token_hash, mode, reveal_date_fixed, max_uses, uses_count, expires_at, revoked_at,
                           secret_cipher_blob, secret_iv, secret_auth_tag, secret_kdf_salt, secret_kdf_iterations)
                          VALUES
                          (?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?, ?, ?, ?)")
               ->execute([
                   $id,
                   $userId,
                   $tokenHash,
                   $mode,
                   $revealFixed,
                   $maxUses,
                   $expiresAt,
                   $secretCipher,
                   $secretIv,
                   $secretTag,
                   $secretSalt,
                   $secretIters,
               ]);
            auditLog('inbound_link_create', null, $userId);
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

    if (!$token || !$tokenHash) jsonResponse(['error' => 'Failed to create link'], 500);

    $submitUrl = getAppBaseUrl() . '/receive.php?t=' . rawurlencode($token);

    jsonResponse([
        'success' => true,
        'token' => $token,
        'submit_url' => $submitUrl,
    ]);
}

// ─────────────────────────────────────────────────────────────
// Public: submit encrypted payload
// ─────────────────────────────────────────────────────────────
if ($action === 'submit') {
    $token = trim((string)($body['t'] ?? ($body['token'] ?? '')));
    if ($token === '') jsonResponse(['error' => 'Missing token'], 400);

    $label = trim((string)($body['label'] ?? ''));
    if ($label === '') jsonResponse(['error' => 'Label is required'], 400);
    if (strlen($label) > 255) jsonResponse(['error' => 'Label too long'], 400);

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

    $hash = hash('sha256', $token);

    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));

    // Atomic max_uses enforcement.
    $db->beginTransaction();
    try {
        $stmt = $db->prepare("SELECT id, user_id, mode, reveal_date_fixed, max_uses, uses_count, expires_at, revoked_at
                              FROM inbound_lock_links
                              WHERE token_hash = ?
                              LIMIT 1
                              FOR UPDATE");
        $stmt->execute([$hash]);
        $link = $stmt->fetch();

        if (!$link) {
            $db->rollBack();
            jsonResponse(['error' => 'Invalid link'], 404);
        }
        if (!empty($link['revoked_at'])) {
            $db->rollBack();
            jsonResponse(['error' => 'This link was revoked'], 410);
        }

        if (!empty($link['expires_at'])) {
            try {
                $exp = new DateTimeImmutable((string)$link['expires_at'], new DateTimeZone('UTC'));
                if ($now >= $exp) {
                    $db->rollBack();
                    jsonResponse(['error' => 'This link expired'], 410);
                }
            } catch (Throwable) {
                // ignore
            }
        }

        $maxUses = (int)($link['max_uses'] ?? 1);
        $uses = (int)($link['uses_count'] ?? 0);

        if ($maxUses > 0 && $uses >= $maxUses) {
            $db->rollBack();
            jsonResponse(['error' => 'This link has been used'], 410);
        }

        $revealDt = null;

        if ((string)$link['mode'] === 'recipient_sets_date') {
            if (empty($link['reveal_date_fixed'])) {
                $db->rollBack();
                jsonResponse(['error' => 'Link is misconfigured'], 409);
            }

            $revealDt = new DateTimeImmutable((string)$link['reveal_date_fixed'], new DateTimeZone('UTC'));
            if ($revealDt <= $now) {
                $db->rollBack();
                jsonResponse(['error' => 'Reveal date must be future'], 400);
            }
        } else {
            $revealDt = parseUtcFutureOrJson((string)($body['reveal_date'] ?? ''), 'Reveal date required');
        }

        $recipientUserId = (int)($link['user_id'] ?? 0);
        if ($recipientUserId < 1) {
            $db->rollBack();
            jsonResponse(['error' => 'Link is misconfigured'], 409);
        }

        // Enforce package limits for recipient (without exiting mid-transaction).
        $limits = packagesGetUserLimits($recipientUserId);
        $usage = packagesGetUserUsage($recipientUserId);
        $limit = packagesLimitFor('locks', $limits);
        $cur = packagesUsageFor('locks', $usage);

        if ($limit > 0 && $cur >= $limit) {
            $db->rollBack();
            jsonResponse([
                'error' => 'Package limit reached',
                'error_code' => 'package_limit',
                'resource' => 'locks',
                'current_usage' => $cur,
                'limit' => $limit,
            ], 403);
        }

        $lockId = generateUUID();

        $hasSlot = hasLockVaultVerifierSlotColumn();
        $hasInboundCol = hasLockInboundLinkIdColumn();

        $cols = ['id', 'user_id'];
        $vals = [$lockId, $recipientUserId];

        if ($hasInboundCol) {
            $cols[] = 'inbound_link_id';
            $vals[] = (string)$link['id'];
        }

        $cols = array_merge($cols, [
            'label',
            'cipher_blob', 'iv', 'auth_tag', 'kdf_salt', 'kdf_iterations',
        ]);
        $vals = array_merge($vals, [
            $label,
            $cipherBlob, $iv, $authTag, $kdfSalt, $kdfIters,
        ]);

        if ($hasSlot) {
            $cols[] = 'vault_verifier_slot';
            $vals[] = 1;
        }

        $cols = array_merge($cols, [
            'password_type', 'password_length',
            'hint',
            'reveal_date',
            'confirmation_status',
            'confirmed_at',
        ]);
        $vals = array_merge($vals, [
            'custom', 16,
            null,
            $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
            'confirmed',
            (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
        ]);

        $ph = implode(',', array_fill(0, count($cols), '?'));
        $sql = 'INSERT INTO locks (' . implode(',', $cols) . ') VALUES (' . $ph . ')';
        $db->prepare($sql)->execute($vals);

        $db->prepare('UPDATE inbound_lock_links SET uses_count = uses_count + 1 WHERE id = ?')->execute([(string)$link['id']]);

        $db->commit();

        auditLog('inbound_link_submit', $lockId, $recipientUserId);

        jsonResponse([
            'success' => true,
            'lock_id' => $lockId,
            'reveal_date' => $revealDt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
        ]);

    } catch (Throwable $e) {
        try { if ($db->inTransaction()) $db->rollBack(); } catch (Throwable) {}
        jsonResponse(['error' => 'Failed to submit'], 500);
    }
}

jsonResponse(['error' => 'Unknown action'], 400);
