<?php
// ============================================================
//  API: /api/webauthn.php
//  Passkeys (WebAuthn):
//    - register (logged-in)
//    - step-up reauth (logged-in)
//    - passkey login (no password)
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/webauthn.php';

header('Content-Type: application/json; charset=utf-8');
startSecureSession();

if (!hasWebauthnCredentialsTable()) {
    jsonResponse(['error' => 'Passkeys are not available. Apply migrations in config/migrations/.'], 500);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

function storeChallenge(string $kind, string $challengeB64u): void {
    $_SESSION['webauthn_challenge_kind'] = $kind;
    $_SESSION['webauthn_challenge'] = $challengeB64u;
    $_SESSION['webauthn_challenge_ts'] = time();
}

function loadChallenge(string $kind): string {
    $ts = (int)($_SESSION['webauthn_challenge_ts'] ?? 0);
    $k = (string)($_SESSION['webauthn_challenge_kind'] ?? '');
    $c = (string)($_SESSION['webauthn_challenge'] ?? '');

    if ($k !== $kind || $c === '' || !$ts || (time() - $ts) > 300) {
        jsonResponse(['error' => 'Challenge expired. Try again.'], 400);
    }

    return $c;
}

$db = getDB();

// ── Passkey login (no session) ─────────────────────────────
if ($action === 'login_begin') {
    $challenge = webauthnNewChallenge();
    storeChallenge('login', $challenge);

    jsonResponse([
        'success' => true,
        'publicKey' => [
            'challenge' => $challenge,
            'rpId' => webauthnRpId(),
            'timeout' => 60000,
            'userVerification' => 'required',
        ],
    ]);
}

if ($action === 'login_finish') {
    $challenge = loadChallenge('login');

    $id = (string)($body['id'] ?? '');
    $rawId = (string)($body['rawId'] ?? '');
    $resp = $body['response'] ?? null;
    if ($id === '' || $rawId === '' || !is_array($resp)) jsonResponse(['error' => 'Invalid payload'], 400);

    $credId = b64urlDecode($rawId);
    if ($credId === '') jsonResponse(['error' => 'Invalid credential'], 400);

    $stmt = $db->prepare("SELECT c.id AS cred_row_id, c.user_id, c.public_key_pem, c.sign_count, u.email, u.email_verified_at, u.is_admin FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE c.credential_id = ? LIMIT 1");
    $stmt->execute([$credId]);
    $row = $stmt->fetch();
    if (!$row) jsonResponse(['error' => 'Unknown credential'], 401);

    $v = webauthnVerifyAssertion($resp, $challenge, (string)$row['public_key_pem'], (int)$row['sign_count']);

    $db->prepare('UPDATE webauthn_credentials SET sign_count = ?, last_used_at = NOW() WHERE id = ?')
       ->execute([(int)$v['signCount'], (int)$row['cred_row_id']]);

    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$row['user_id'];
    $_SESSION['email'] = (string)$row['email'];
    $_SESSION['email_verified'] = !empty($row['email_verified_at']) ? 1 : 0;
    $_SESSION['is_admin'] = !empty($row['is_admin']) ? 1 : 0;

    registerCurrentSession((int)$row['user_id']);
    $db->prepare('UPDATE users SET last_login = NOW() WHERE id = ?')->execute([(int)$row['user_id']]);

    setStrongAuth(900);
    auditLog('login_passkey', null, (int)$row['user_id']);

    jsonResponse([
        'success' => true,
        'email' => (string)$row['email'],
        'verified' => !empty($row['email_verified_at']),
        'is_admin' => !empty($row['is_admin']) ? true : false,
    ]);
}

// Remaining actions require login
requireLogin();
requireCsrf();
requireVerifiedEmail();

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'list') {
    $stmt = $db->prepare('SELECT id, label, created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at DESC');
    $stmt->execute([(int)$userId]);
    jsonResponse(['success' => true, 'passkeys' => $stmt->fetchAll()]);
}

if ($action === 'register_begin') {
    $challenge = webauthnNewChallenge();
    storeChallenge('register', $challenge);

    $stmt = $db->prepare('SELECT email FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();
    if (!$u) jsonResponse(['error' => 'Unauthorized'], 401);

    $exclude = [];
    $stmt = $db->prepare('SELECT credential_id FROM webauthn_credentials WHERE user_id = ?');
    $stmt->execute([(int)$userId]);
    foreach ($stmt->fetchAll() as $r) {
        $exclude[] = [
            'type' => 'public-key',
            'id' => b64urlEncode($r['credential_id']),
        ];
    }

    $userHandle = b64urlEncode(pack('N', (int)$userId));

    jsonResponse([
        'success' => true,
        'publicKey' => [
            'challenge' => $challenge,
            'rp' => [
                'name' => defined('APP_NAME') ? APP_NAME : 'LOCKSMITH',
                'id' => webauthnRpId(),
            ],
            'user' => [
                'id' => $userHandle,
                'name' => (string)$u['email'],
                'displayName' => (string)$u['email'],
            ],
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],
            ],
            'timeout' => 60000,
            'attestation' => 'none',
            'authenticatorSelection' => [
                'userVerification' => 'required',
                'residentKey' => 'preferred',
            ],
            'excludeCredentials' => $exclude,
        ],
    ]);
}

if ($action === 'register_finish') {
    $challenge = loadChallenge('register');

    $label = isset($body['label']) ? trim((string)$body['label']) : '';
    $label = $label !== '' ? sanitize($label) : null;

    $rawId = (string)($body['rawId'] ?? '');
    $resp = $body['response'] ?? null;
    if ($rawId === '' || !is_array($resp)) jsonResponse(['error' => 'Invalid payload'], 400);

    $reg = webauthnVerifyRegistration($resp, $challenge);

    $credId = b64urlDecode($rawId);
    if ($credId === '' || !hash_equals($reg['credentialId'], $credId)) {
        jsonResponse(['error' => 'Credential mismatch'], 400);
    }

    try {
        $stmt = $db->prepare('INSERT INTO webauthn_credentials (user_id, credential_id, public_key_pem, sign_count, label) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([(int)$userId, $credId, $reg['publicKeyPem'], (int)$reg['signCount'], $label]);
    } catch (PDOException $e) {
        jsonResponse(['error' => 'Credential already registered'], 409);
    }

    setStrongAuth(900);
    auditLog('passkey_add', null, (int)$userId);

    jsonResponse(['success' => true]);
}

if ($action === 'delete') {
    requireStrongAuth();

    $id = (int)($body['id'] ?? 0);
    if ($id <= 0) jsonResponse(['error' => 'id required'], 400);

    $stmt = $db->prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?');
    $stmt->execute([$id, (int)$userId]);
    if ($stmt->rowCount() === 0) jsonResponse(['error' => 'Not found'], 404);

    auditLog('passkey_delete', null, (int)$userId);
    jsonResponse(['success' => true]);
}

if ($action === 'reauth_begin') {
    $challenge = webauthnNewChallenge();
    storeChallenge('reauth', $challenge);

    $allow = [];
    $stmt = $db->prepare('SELECT credential_id FROM webauthn_credentials WHERE user_id = ?');
    $stmt->execute([(int)$userId]);
    foreach ($stmt->fetchAll() as $r) {
        $allow[] = [
            'type' => 'public-key',
            'id' => b64urlEncode($r['credential_id']),
        ];
    }

    jsonResponse([
        'success' => true,
        'publicKey' => [
            'challenge' => $challenge,
            'rpId' => webauthnRpId(),
            'timeout' => 60000,
            'userVerification' => 'required',
            'allowCredentials' => $allow,
        ],
    ]);
}

if ($action === 'reauth_finish') {
    $challenge = loadChallenge('reauth');

    $rawId = (string)($body['rawId'] ?? '');
    $resp = $body['response'] ?? null;
    if ($rawId === '' || !is_array($resp)) jsonResponse(['error' => 'Invalid payload'], 400);

    $credId = b64urlDecode($rawId);
    if ($credId === '') jsonResponse(['error' => 'Invalid credential'], 400);

    $stmt = $db->prepare('SELECT id, public_key_pem, sign_count FROM webauthn_credentials WHERE credential_id = ? AND user_id = ? LIMIT 1');
    $stmt->execute([$credId, (int)$userId]);
    $row = $stmt->fetch();
    if (!$row) jsonResponse(['error' => 'Unknown credential'], 401);

    $v = webauthnVerifyAssertion($resp, $challenge, (string)$row['public_key_pem'], (int)$row['sign_count']);

    $db->prepare('UPDATE webauthn_credentials SET sign_count = ?, last_used_at = NOW() WHERE id = ?')
       ->execute([(int)$v['signCount'], (int)$row['id']]);

    setStrongAuth(600);
    auditLog('passkey_reauth', null, (int)$userId);
    jsonResponse(['success' => true]);
}

if ($action === 'require_for_login') {
    requireStrongAuth();

    $on = !empty($body['enabled']) ? 1 : 0;

    $stmt = $db->prepare("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'require_webauthn' LIMIT 1");
    $has = (bool)$stmt->fetchColumn();
    if (!$has) jsonResponse(['error' => 'Feature not available. Apply migrations in config/migrations/.'], 500);

    $db->prepare('UPDATE users SET require_webauthn = ? WHERE id = ?')->execute([$on, (int)$userId]);
    auditLog('passkey_require_login_set', null, (int)$userId);
    jsonResponse(['success' => true, 'enabled' => $on ? true : false]);
}

jsonResponse(['error' => 'Unknown action'], 400);
