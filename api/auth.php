<?php
// ============================================================
//  API: POST /api/auth.php
//  Zero-Knowledge Edition
//
//  Register: stores login_hash (Argon2id)
//  Login:    verifies login password
//
//  Strong security mode:
//   - Vault passphrase is never sent to the server.
//   - Sensitive actions require step-up auth (TOTP or passkey).
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json');
startSecureSession();

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

// ── LOGOUT ───────────────────────────────────────────────────
if ($action === 'logout') {
    deleteCurrentSessionRecord();
    $_SESSION = [];
    session_destroy();
    jsonResponse(['success' => true]);
}

// ── REGISTER ─────────────────────────────────────────────────
if ($action === 'register') {
    $email    = strtolower(trim($body['email'] ?? ''));
    $loginPwd = $body['login_password'] ?? '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        jsonResponse(['error' => 'Invalid email'], 400);
    if (strlen($loginPwd) < 8)
        jsonResponse(['error' => 'Login password must be at least 8 characters'], 400);

    $db = getDB();
    $check = $db->prepare("SELECT id FROM users WHERE email = ?");
    $check->execute([$email]);
    if ($check->fetch()) jsonResponse(['error' => 'Email already registered'], 409);

    // Hash login password (for authentication)
    $loginHash = hashLoginPassword($loginPwd);

    // Vault passphrase is never sent to the server.
    // Legacy schema still requires verifier fields, so we store non-usable placeholders.
    $vaultVerifierSalt = bin2hex(random_bytes(32));
    $vaultVerifier     = hashVaultVerifier(bin2hex(random_bytes(32)) . $vaultVerifierSalt);

    $isAdmin = 0;

    // If the admin column exists, promote the first ever user to admin.
    $hasAdminCol = false;
    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'is_admin' LIMIT 1");
        $hasAdminCol = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $hasAdminCol = false;
    }

    if ($hasAdminCol) {
        $db->beginTransaction();

        $admins = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetchColumn();

        $db->prepare("
            INSERT INTO users (email, login_hash, vault_verifier, vault_verifier_salt)
            VALUES (?, ?, ?, ?)
        ")->execute([$email, $loginHash, $vaultVerifier, $vaultVerifierSalt]);

        $userId = (int)$db->lastInsertId();

        if ($admins === 0) {
            $db->prepare("UPDATE users SET is_admin = 1 WHERE id = ?")->execute([$userId]);
            $isAdmin = 1;
        }

        $db->commit();
    } else {
        $db->prepare("
            INSERT INTO users (email, login_hash, vault_verifier, vault_verifier_salt)
            VALUES (?, ?, ?, ?)
        ")->execute([$email, $loginHash, $vaultVerifier, $vaultVerifierSalt]);

        $userId = (int)$db->lastInsertId();
    }

    // Create session, but block vault usage until email is verified
    session_regenerate_id(true);
    $_SESSION['user_id']        = $userId;
    $_SESSION['email']          = $email;
    $_SESSION['email_verified'] = 0;
    $_SESSION['is_admin']       = $isAdmin;

    registerCurrentSession($userId);

    $devVerifyUrl = issueEmailVerification($userId, $email);

    auditLog('register', null, $userId);
    jsonResponse([
        'success'            => true,
        'email'              => $email,
        'verified'           => false,
        'needs_verification' => true,
        'dev_verify_url'     => $devVerifyUrl,
        'is_admin'           => $isAdmin ? true : false,
    ]);
}

// ── RESEND VERIFICATION ─────────────────────────────────────
if ($action === 'resend_verification') {
    requireLogin();

    $userId = getCurrentUserId();
    $db     = getDB();
    $stmt   = $db->prepare("SELECT email, email_verified_at FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $u = $stmt->fetch();

    if (!$u) jsonResponse(['error' => 'User not found'], 404);
    if (!empty($u['email_verified_at'])) {
        $_SESSION['email_verified'] = 1;
        jsonResponse(['success' => true, 'verified' => true]);
    }

    $devVerifyUrl = issueEmailVerification((int)$userId, $u['email']);
    jsonResponse(['success' => true, 'verified' => false, 'dev_verify_url' => $devVerifyUrl]);
}

// ── LOGIN (password) ─────────────────────────────────────────
if ($action === 'login') {
    $email    = strtolower(trim($body['email'] ?? ''));
    $loginPwd = $body['login_password'] ?? '';

    if (empty($email) || empty($loginPwd))
        jsonResponse(['error' => 'Email and password required'], 400);

    $db   = getDB();

    $hasAdminCol = false;
    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'is_admin' LIMIT 1");
        $hasAdminCol = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $hasAdminCol = false;
    }

    $hasTotp = hasTotpColumns();

    $hasReqWebauthn = false;
    try {
        $stmt = $db->query("SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'require_webauthn' LIMIT 1");
        $hasReqWebauthn = (bool)$stmt->fetchColumn();
    } catch (Throwable) {
        $hasReqWebauthn = false;
    }

    $sql = $hasAdminCol
        ? "SELECT id, email, login_hash, email_verified_at, is_admin" . ($hasTotp ? ", totp_enabled_at" : ", NULL AS totp_enabled_at") . ($hasReqWebauthn ? ", require_webauthn" : ", 0 AS require_webauthn") . " FROM users WHERE email = ?"
        : "SELECT id, email, login_hash, email_verified_at, 0 AS is_admin" . ($hasTotp ? ", totp_enabled_at" : ", NULL AS totp_enabled_at") . ($hasReqWebauthn ? ", require_webauthn" : ", 0 AS require_webauthn") . " FROM users WHERE email = ?";

    $stmt = $db->prepare($sql);
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    // Constant-time comparison — always run verify even on miss
    $dummyHash = '$argon2id$v=19$m=65536,t=4,p=2$dummysaltdummy$dummyhash000000000000000000000000';
    $hash = $user ? $user['login_hash'] : $dummyHash;

    if (!$user || !password_verify($loginPwd, $hash)) {
        auditLog('login_fail');
        jsonResponse(['error' => 'Invalid credentials'], 401);
    }

    $verified = !empty($user['email_verified_at']);

    if ($hasAdminCol) {
        $admins = (int)$db->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetchColumn();
        if ($admins === 0) {
            $db->prepare("UPDATE users SET is_admin = 1 WHERE id = ?")->execute([(int)$user['id']]);
            $user['is_admin'] = 1;
        }
    }

    // If the user has opted into passkey-only login, block password login.
    if (!empty($user['require_webauthn']) && userHasPasskeys((int)$user['id'])) {
        jsonResponse([
            'error' => 'Passkey required for login',
            'error_code' => 'passkey_required',
        ], 403);
    }

    // If TOTP is enabled, complete login in a second step.
    if (!empty($user['totp_enabled_at'])) {
        $_SESSION['pre_2fa_user_id'] = (int)$user['id'];
        $_SESSION['pre_2fa_email'] = (string)$user['email'];
        $_SESSION['pre_2fa_verified'] = $verified ? 1 : 0;
        $_SESSION['pre_2fa_is_admin'] = !empty($user['is_admin']) ? 1 : 0;
        $_SESSION['pre_2fa_ts'] = time();

        auditLog('login_totp_required', null, (int)$user['id']);

        jsonResponse([
            'success' => true,
            'needs_totp' => true,
        ]);
    }

    session_regenerate_id(true);
    $_SESSION['user_id']        = (int)$user['id'];
    $_SESSION['email']          = $user['email'];
    $_SESSION['email_verified'] = $verified ? 1 : 0;
    $_SESSION['is_admin']       = !empty($user['is_admin']) ? 1 : 0;

    setStrongAuth(900);

    registerCurrentSession((int)$user['id']);

    $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")->execute([(int)$user['id']]);
    auditLog('login', null, (int)$user['id']);

    jsonResponse([
        'success'  => true,
        'email'    => $user['email'],
        'verified' => $verified,
        'is_admin' => !empty($user['is_admin']) ? true : false,
    ]);
}

// ── LOGIN (TOTP step) ────────────────────────────────────────
if ($action === 'login_totp') {
    if (!hasTotpColumns()) jsonResponse(['error' => 'TOTP not available'], 500);

    $db = getDB();

    $code = trim((string)($body['code'] ?? ''));
    $uid = (int)($_SESSION['pre_2fa_user_id'] ?? 0);
    $ts  = (int)($_SESSION['pre_2fa_ts'] ?? 0);

    if ($uid <= 0 || !$ts || (time() - $ts) > 300) {
        jsonResponse(['error' => 'Login expired. Please sign in again.'], 401);
    }

    $stmt = $db->prepare('SELECT id, email, email_verified_at, is_admin, totp_secret_enc, totp_enabled_at, require_webauthn FROM users WHERE id = ?');
    $stmt->execute([$uid]);
    $u = $stmt->fetch();

    if (!$u || empty($u['totp_enabled_at']) || empty($u['totp_secret_enc'])) {
        jsonResponse(['error' => 'TOTP not enabled'], 401);
    }

    if (!empty($u['require_webauthn']) && userHasPasskeys((int)$u['id'])) {
        jsonResponse([
            'error' => 'Passkey required for login',
            'error_code' => 'passkey_required',
        ], 403);
    }

    $secret = decryptFromDb((string)$u['totp_secret_enc']);
    if (!verifyTotpCode($secret, $code, 1)) {
        auditLog('login_totp_fail', null, (int)$uid);
        jsonResponse(['error' => 'Invalid code'], 401);
    }

    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$u['id'];
    $_SESSION['email'] = (string)$u['email'];
    $_SESSION['email_verified'] = !empty($u['email_verified_at']) ? 1 : 0;
    $_SESSION['is_admin'] = !empty($u['is_admin']) ? 1 : 0;

    unset($_SESSION['pre_2fa_user_id'], $_SESSION['pre_2fa_email'], $_SESSION['pre_2fa_verified'], $_SESSION['pre_2fa_is_admin'], $_SESSION['pre_2fa_ts']);

    registerCurrentSession((int)$u['id']);
    $db->prepare('UPDATE users SET last_login = NOW() WHERE id = ?')->execute([(int)$u['id']]);

    setStrongAuth(900);
    auditLog('login_totp', null, (int)$u['id']);

    $verified = !empty($u['email_verified_at']);

    jsonResponse([
        'success'  => true,
        'email'    => (string)$u['email'],
        'verified' => $verified,
        'is_admin' => !empty($u['is_admin']) ? true : false,
    ]);
}

jsonResponse(['error' => 'Unknown action'], 400);
