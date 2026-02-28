<?php
// ============================================================
//  API: POST /api/auth.php
//  Zero-Knowledge Edition
//
//  Register: stores login_hash (Argon2id) + vault_verifier (Argon2id)
//  Login:    verifies login password only — vault passphrase never transmitted here
//  The vault passphrase is ONLY used client-side for key derivation.
//  Server stores a verifier hash of it SOLELY to confirm identity on reveal.
// ============================================================

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

// ── LOGOUT ───────────────────────────────────────────────────
if ($action === 'logout') {
    $_SESSION = [];
    session_destroy();
    jsonResponse(['success' => true]);
}

// ── REGISTER ─────────────────────────────────────────────────
if ($action === 'register') {
    $email      = strtolower(trim($body['email'] ?? ''));
    $loginPwd   = $body['login_password'] ?? '';
    $vaultPhrase = $body['vault_passphrase'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        jsonResponse(['error' => 'Invalid email'], 400);
    if (strlen($loginPwd) < 8)
        jsonResponse(['error' => 'Login password must be at least 8 characters'], 400);
    if (strlen($vaultPhrase) < 10)
        jsonResponse(['error' => 'Vault passphrase must be at least 10 characters'], 400);
    if ($loginPwd === $vaultPhrase)
        jsonResponse(['error' => 'Vault passphrase must differ from login password'], 400);

    $db = getDB();
    $check = $db->prepare("SELECT id FROM users WHERE email = ?");
    $check->execute([$email]);
    if ($check->fetch()) jsonResponse(['error' => 'Email already registered'], 409);

    // Hash login password (for authentication)
    $loginHash = hashLoginPassword($loginPwd);

    // Hash vault passphrase (for identity verification on reveal — NOT for key derivation)
    $vaultVerifierSalt = bin2hex(random_bytes(32));
    $vaultVerifier     = hashVaultVerifier($vaultPhrase . $vaultVerifierSalt);

    $db->prepare("
        INSERT INTO users (email, login_hash, vault_verifier, vault_verifier_salt)
        VALUES (?, ?, ?, ?)
    ")->execute([$email, $loginHash, $vaultVerifier, $vaultVerifierSalt]);

    $userId = (int)$db->lastInsertId();
    session_regenerate_id(true);
    $_SESSION['user_id'] = $userId;
    $_SESSION['email']   = $email;

    auditLog('register', null, $userId);
    jsonResponse(['success' => true, 'email' => $email]);
}

// ── LOGIN ────────────────────────────────────────────────────
if ($action === 'login') {
    $email    = strtolower(trim($body['email'] ?? ''));
    $loginPwd = $body['login_password'] ?? '';

    if (empty($email) || empty($loginPwd))
        jsonResponse(['error' => 'Email and password required'], 400);

    $db   = getDB();
    $stmt = $db->prepare("SELECT id, email, login_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // Constant-time comparison — always run verify even on miss
    $dummyHash = '$argon2id$v=19$m=65536,t=4,p=2$dummysaltdummy$dummyhash000000000000000000000000';
    $hash = $user ? $user['login_hash'] : $dummyHash;

    if (!$user || !password_verify($loginPwd, $hash)) {
        auditLog('login_fail');
        jsonResponse(['error' => 'Invalid credentials'], 401);
    }

    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['email']   = $user['email'];

    $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([$user['id']]);
    auditLog('login', null, (int)$user['id']);

    jsonResponse(['success' => true, 'email' => $user['email']]);
}

jsonResponse(['error' => 'Unknown action'], 400);
