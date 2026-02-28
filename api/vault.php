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
requireVerifiedEmail();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') jsonResponse(['error' => 'Method not allowed'], 405);

$body   = json_decode(file_get_contents('php://input'), true);
$action = $body['action'] ?? '';

$userId = getCurrentUserId();
if (!$userId) jsonResponse(['error' => 'Unauthorized'], 401);

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
