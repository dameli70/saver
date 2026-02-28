<?php
// ============================================================
//  API: POST /api/vault.php
//  Vault-level actions (zero-knowledge):
//   - rotate_prepare: list eligible codes (reveal_date <= now) with crypto blobs
//   - rotate_commit: commit client-side re-encryption + store new passphrase as alt verifier (slot 2)
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
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

if ($action === 'rotate_prepare') {
    $db = getDB();
    $slotFilter = hasLockVaultVerifierSlotColumn() ? ' AND vault_verifier_slot = 1' : '';

    $stmt = $db->prepare("SELECT id, cipher_blob, iv, auth_tag, kdf_salt, kdf_iterations FROM locks WHERE user_id = ? AND is_active = 1 AND reveal_date <= NOW(){$slotFilter} ORDER BY created_at ASC");
    $stmt->execute([(int)$userId]);
    $locks = $stmt->fetchAll();

    auditLog('vault_rotate_prepare', null, (int)$userId);
    jsonResponse(['success' => true, 'locks' => $locks]);
}

if ($action === 'rotate_commit') {
    $updates = $body['updates'] ?? null;
    if (!is_array($updates)) jsonResponse(['error' => 'updates array required'], 400);

    $current = (string)($body['current_vault_passphrase'] ?? '');
    $next    = (string)($body['new_vault_passphrase'] ?? '');

    if (strlen($current) < 10) jsonResponse(['error' => 'Current vault passphrase required'], 400);
    if (strlen($next) < 10) jsonResponse(['error' => 'New vault passphrase must be at least 10 characters'], 400);
    if ($current === $next) jsonResponse(['error' => 'New vault passphrase must differ from current'], 400);

    if (!hasVaultAltVerifierColumns() || !hasLockVaultVerifierSlotColumn()) {
        jsonResponse(['error' => 'Vault rotation is not available (missing vault rotation columns). Apply migrations in config/migrations/.'], 500);
    }

    // Re-verify CURRENT (slot 1) vault passphrase before committing any rotation.
    requireVaultPassphrase($current, 1);

    $db = getDB();
    $db->beginTransaction();

    try {
        // Ensure the rotation target (slot 2) is stable.
        $uStmt = $db->prepare('SELECT vault_verifier_alt, vault_verifier_alt_salt FROM users WHERE id = ? FOR UPDATE');
        $uStmt->execute([(int)$userId]);
        $u = $uStmt->fetch();
        if (!$u) throw new RuntimeException('Unauthorized');

        if (!empty($u['vault_verifier_alt']) && !empty($u['vault_verifier_alt_salt'])) {
            if (!verifyVaultPassphrase($next . $u['vault_verifier_alt_salt'], $u['vault_verifier_alt'])) {
                throw new RuntimeException('A vault rotation is already in progress with a different new passphrase');
            }
        } else {
            $altSalt = bin2hex(random_bytes(32));
            $altHash = hashVaultVerifier($next . $altSalt);
            $db->prepare('UPDATE users SET vault_verifier_alt = ?, vault_verifier_alt_salt = ?, vault_verifier_alt_set_at = NOW() WHERE id = ?')
               ->execute([$altHash, $altSalt, (int)$userId]);
        }

        $check = $db->prepare('SELECT id FROM locks WHERE id = ? AND user_id = ? AND is_active = 1 AND reveal_date <= NOW() AND vault_verifier_slot = 1');
        $upd   = $db->prepare('UPDATE locks SET cipher_blob = ?, iv = ?, auth_tag = ?, vault_verifier_slot = 2 WHERE id = ? AND user_id = ?');

        $count = 0;
        foreach ($updates as $u) {
            if (!is_array($u)) continue;

            $id = (string)($u['id'] ?? '');
            $cipher = (string)($u['cipher_blob'] ?? '');
            $iv = (string)($u['iv'] ?? '');
            $tag = (string)($u['auth_tag'] ?? '');

            if ($id === '' || strlen($id) !== 36) continue;
            if ($cipher === '' || $iv === '' || $tag === '') continue;

            $check->execute([$id, (int)$userId]);
            if (!$check->fetch()) continue;

            $upd->execute([$cipher, $iv, $tag, $id, (int)$userId]);
            if ($upd->rowCount() > 0) $count++;
        }

        $db->commit();

        auditLog('vault_rotate_commit', null, (int)$userId);
        jsonResponse(['success' => true, 'updated' => $count]);

    } catch (Throwable $e) {
        $db->rollBack();
        if ($e instanceof RuntimeException) {
            jsonResponse(['error' => $e->getMessage()], 400);
        }
        throw $e;
    }
}

jsonResponse(['error' => 'Unknown action'], 400);
