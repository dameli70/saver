<?php
// ============================================================
//  API: POST /api/vault.php
//  Vault-level actions (zero-knowledge):
//   - rotate_prepare: list eligible codes (reveal_date <= now) with crypto blobs
//   - rotate_commit: commit client-side re-encryption (slot 1 -> slot 2)
//
//  Important: Rotation is restricted to already-unlocked codes (server time gate
//  passed) so it cannot be used to bypass time locks.
// ============================================================

require_once __DIR__ . '/../includes/install_guard.php';
requireInstalledForApi();

require_once __DIR__ . '/../includes/helpers.php';
header('Content-Type: application/json; charset=utf-8');
startSecureSession();

requireLogin();
requireCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

// Vault setup actions are allowed before email verification (they don't touch locks).
if (!in_array($action, ['setup_status', 'setup_save'], true)) {
    requireVerifiedEmail();
}

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'setup_status') {
    if (!hasVaultCheckColumns()) {
        jsonResponse(['success' => true, 'available' => false, 'initialized' => false]);
    }

    $db = getDB();

    $sel = 'vault_check_cipher, vault_check_iv, vault_check_auth_tag, vault_check_salt, vault_check_iterations';
    if (hasVaultActiveSlotColumn()) $sel .= ', vault_active_slot';

    $stmt = $db->prepare("SELECT {$sel} FROM users WHERE id = ?");
    $stmt->execute([(int)$userId]);
    $u = $stmt->fetch();

    if (!$u) jsonResponse(['error' => 'User not found'], 404);

    $initialized = !empty($u['vault_check_cipher']) && !empty($u['vault_check_iv']) && !empty($u['vault_check_auth_tag']) && !empty($u['vault_check_salt']);

    jsonResponse([
        'success' => true,
        'available' => true,
        'initialized' => $initialized,
        'vault_check' => $initialized ? [
            'cipher_blob' => $u['vault_check_cipher'],
            'iv' => $u['vault_check_iv'],
            'auth_tag' => $u['vault_check_auth_tag'],
            'kdf_salt' => $u['vault_check_salt'],
            'kdf_iterations' => (int)$u['vault_check_iterations'],
        ] : null,
        'active_slot' => hasVaultActiveSlotColumn() ? (int)($u['vault_active_slot'] ?? 1) : 1,
    ]);
}

if ($action === 'setup_save') {
    if (!hasVaultCheckColumns()) {
        jsonResponse(['error' => 'Vault passphrase setup is not available. Apply migrations in config/migrations/.'], 500);
    }

    $cipherBlob = trim((string)($body['cipher_blob'] ?? ''));
    $iv         = trim((string)($body['iv'] ?? ''));
    $authTag    = trim((string)($body['auth_tag'] ?? ''));
    $kdfSalt    = trim((string)($body['kdf_salt'] ?? ''));
    $iters      = (int)($body['kdf_iterations'] ?? PBKDF2_ITERATIONS);

    if ($cipherBlob === '') jsonResponse(['error' => 'cipher_blob missing'], 400);
    if ($iv === '')         jsonResponse(['error' => 'iv missing'], 400);
    if ($authTag === '')    jsonResponse(['error' => 'auth_tag missing'], 400);
    if ($kdfSalt === '')    jsonResponse(['error' => 'kdf_salt missing'], 400);
    if ($iters < 10000 || $iters > 2000000) jsonResponse(['error' => 'kdf_iterations out of range'], 400);

    if (base64_decode($iv, true) === false || strlen(base64_decode($iv)) !== 12)
        jsonResponse(['error' => 'IV must be 12 bytes (base64)'], 400);
    if (base64_decode($authTag, true) === false || strlen(base64_decode($authTag)) !== 16)
        jsonResponse(['error' => 'auth_tag must be 16 bytes (base64)'], 400);
    if (base64_decode($kdfSalt, true) === false || strlen(base64_decode($kdfSalt)) !== 32)
        jsonResponse(['error' => 'kdf_salt must be 32 bytes (base64)'], 400);

    $db = getDB();

    $stmt = $db->prepare('SELECT vault_check_cipher FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $row = $stmt->fetch();
    if (!$row) jsonResponse(['error' => 'User not found'], 404);

    if (!empty($row['vault_check_cipher'])) {
        jsonResponse(['error' => 'Vault passphrase is already set'], 409);
    }

    $db->prepare('UPDATE users SET vault_check_cipher = ?, vault_check_iv = ?, vault_check_auth_tag = ?, vault_check_salt = ?, vault_check_iterations = ?, vault_check_set_at = NOW() WHERE id = ?')
       ->execute([$cipherBlob, $iv, $authTag, $kdfSalt, $iters, (int)$userId]);

    auditLog('vault_setup', null, (int)$userId);
    jsonResponse(['success' => true]);
}

if ($action === 'rotate_prepare') {
    $db = getDB();

    $fromSlot = 1;
    $toSlot   = 2;

    if (hasLockVaultVerifierSlotColumn() && hasVaultActiveSlotColumn()) {
        $stmt = $db->prepare('SELECT vault_active_slot FROM users WHERE id = ?');
        $stmt->execute([(int)$userId]);
        $u = $stmt->fetch();
        $cur = (int)($u['vault_active_slot'] ?? 1);
        if (!in_array($cur, [1, 2], true)) $cur = 1;
        $fromSlot = $cur;
        $toSlot   = ($cur === 1) ? 2 : 1;
    }

    $slotFilter = hasLockVaultVerifierSlotColumn() ? ' AND vault_verifier_slot = ' . (int)$fromSlot : '';

    $stmt = $db->prepare("SELECT id, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations FROM locks WHERE user_id = ? AND is_active = 1 AND reveal_date <= NOW(){$slotFilter} ORDER BY created_at ASC");
    $stmt->execute([(int)$userId]);
    $locks = $stmt->fetchAll();

    auditLog('vault_rotate_prepare', null, (int)$userId);
    jsonResponse(['success' => true, 'from_slot' => $fromSlot, 'to_slot' => $toSlot, 'locks' => $locks]);
}

if ($action === 'rotate_commit') {
    $updates = $body['updates'] ?? null;
    if (!is_array($updates)) jsonResponse(['error' => 'updates array required'], 400);

    if (!hasLockVaultVerifierSlotColumn()) {
        jsonResponse(['error' => 'Vault rotation is not available (missing vault rotation columns). Apply migrations in config/migrations/.'], 500);
    }

    requireStrongAuth();

    $db = getDB();

    $vaultCheck = $body['vault_check'] ?? null;
    if (hasVaultCheckColumns()) {
        $stmt = $db->prepare('SELECT vault_check_cipher FROM users WHERE id = ?');
        $stmt->execute([(int)$userId]);
        $row = $stmt->fetch();
        if ($row && !empty($row['vault_check_cipher']) && !is_array($vaultCheck)) {
            jsonResponse([
                'error' => 'vault_check required to keep vault unlock working after rotation',
                'error_code' => 'vault_check_required',
            ], 400);
        }
    }

    $fromSlot = 1;
    $toSlot   = 2;

    if (hasVaultActiveSlotColumn()) {
        $stmt = $db->prepare('SELECT vault_active_slot FROM users WHERE id = ?');
        $stmt->execute([(int)$userId]);
        $u = $stmt->fetch();
        $cur = (int)($u['vault_active_slot'] ?? 1);
        if (!in_array($cur, [1, 2], true)) $cur = 1;
        $fromSlot = $cur;
        $toSlot   = ($cur === 1) ? 2 : 1;
    }

    $vaultCheckVals = null;
    if (is_array($vaultCheck) && hasVaultCheckColumns()) {
        $cipherBlob = trim((string)($vaultCheck['cipher_blob'] ?? ''));
        $iv         = trim((string)($vaultCheck['iv'] ?? ''));
        $authTag    = trim((string)($vaultCheck['auth_tag'] ?? ''));
        $kdfSalt    = trim((string)($vaultCheck['kdf_salt'] ?? ''));
        $iters      = (int)($vaultCheck['kdf_iterations'] ?? PBKDF2_ITERATIONS);

        if ($cipherBlob === '' || $iv === '' || $authTag === '' || $kdfSalt === '') {
            jsonResponse(['error' => 'Invalid vault_check payload'], 400);
        }

        if (base64_decode($iv, true) === false || strlen(base64_decode($iv)) !== 12)
            jsonResponse(['error' => 'vault_check.iv must be 12 bytes (base64)'], 400);
        if (base64_decode($authTag, true) === false || strlen(base64_decode($authTag)) !== 16)
            jsonResponse(['error' => 'vault_check.auth_tag must be 16 bytes (base64)'], 400);
        if (base64_decode($kdfSalt, true) === false || strlen(base64_decode($kdfSalt)) !== 32)
            jsonResponse(['error' => 'vault_check.kdf_salt must be 32 bytes (base64)'], 400);
        if ($iters < 10000 || $iters > 2000000) jsonResponse(['error' => 'vault_check.kdf_iterations out of range'], 400);

        $vaultCheckVals = [$cipherBlob, $iv, $authTag, $kdfSalt, $iters];
    }

    $db->beginTransaction();

    try {
        $check = $db->prepare('SELECT id FROM locks WHERE id = ? AND user_id = ? AND is_active = 1 AND reveal_date <= NOW() AND vault_verifier_slot = ?');
        $upd   = $db->prepare('UPDATE locks SET cipher_blob = ?, iv = ?, auth_tag = ?, vault_verifier_slot = ? WHERE id = ? AND user_id = ?');

        $count = 0;
        foreach ($updates as $u) {
            if (!is_array($u)) continue;

            $id = (string)($u['id'] ?? '');
            $cipher = (string)($u['cipher_blob'] ?? '');
            $iv = (string)($u['iv'] ?? '');
            $tag = (string)($u['auth_tag'] ?? '');

            if ($id === '' || strlen($id) !== 36) continue;
            if ($cipher === '' || $iv === '' || $tag === '') continue;

            $check->execute([$id, (int)$userId, (int)$fromSlot]);
            if (!$check->fetch()) continue;

            $upd->execute([$cipher, $iv, $tag, (int)$toSlot, $id, (int)$userId]);
            if ($upd->rowCount() > 0) $count++;
        }

        if ($vaultCheckVals !== null && hasVaultCheckColumns()) {
            $db->prepare('UPDATE users SET vault_check_cipher = ?, vault_check_iv = ?, vault_check_auth_tag = ?, vault_check_salt = ?, vault_check_iterations = ?, vault_check_set_at = NOW() WHERE id = ?')
               ->execute([$vaultCheckVals[0], $vaultCheckVals[1], $vaultCheckVals[2], $vaultCheckVals[3], $vaultCheckVals[4], (int)$userId]);
        }

        if (hasVaultActiveSlotColumn()) {
            $db->prepare('UPDATE users SET vault_active_slot = ? WHERE id = ?')->execute([(int)$toSlot, (int)$userId]);
        }

        $db->commit();

        auditLog('vault_rotate_commit', null, (int)$userId);
        jsonResponse(['success' => true, 'updated' => $count, 'from_slot' => $fromSlot, 'to_slot' => $toSlot]);

    } catch (Throwable $e) {
        $db->rollBack();
        throw $e;
    }
}

jsonResponse(['error' => 'Unknown action'], 400);
